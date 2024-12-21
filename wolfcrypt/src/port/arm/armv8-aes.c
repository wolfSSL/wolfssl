/* armv8-aes.c
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
 * There are two versions one for 64 (Aarch64) and one for 32 bit (Aarch32).
 * If changing one check the other.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(NO_AES) && defined(WOLFSSL_ARMASM)

#if FIPS_VERSION3_LT(6,0,0) && defined(HAVE_FIPS)
    #undef HAVE_FIPS
#else
    #if defined(HAVE_FIPS) && FIPS_VERSION3_GE(6,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
        #define FIPS_NO_WRAPPERS
    #endif
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>

/* Enable Hardware Callback */
#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)
    /* Revert back to SW so HW CB works */
    /* HW only works for AES: ECB, CBC, and partial via ECB for other modes */
    #include <wolfssl/wolfcrypt/port/maxim/max3266x-cryptocb.h>
#endif
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/logging.h>

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_aes_ro_sanity[2] =
                                             { 0x1a2b3c4d, 0x00000002 };
    int wolfCrypt_FIPS_AES_sanity(void)
    {
        return 0;
    }
#endif

#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef _MSC_VER
    /* 4127 warning constant while(1)  */
    #pragma warning(disable: 4127)
#endif

static const byte rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,0x1B, 0x36
    /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

#ifdef __aarch64__
/* get table value from hardware */
    #define SBOX(x)                      \
        do {                             \
            __asm__ volatile (           \
                "DUP v1.4s, %w[in]  \n"  \
                "MOVI v0.16b, #0     \n" \
                "AESE v0.16b, v1.16b \n" \
                "UMOV %w[out], v0.s[0] \n" \
                : [out] "=r"((x))        \
                : [in] "r" ((x))         \
                : "cc", "memory", "v0", "v1"\
            ); \
        } while(0)

    #define IMIX(x) \
        do {        \
            __asm__ volatile (             \
                "LD1 {v0.16b}, [%[in]] \n" \
                "AESIMC v0.16b, v0.16b \n" \
                "ST1 {v0.16b}, [%[out]]\n" \
                : [out] "=r" ((x))         \
                : [in] "0" ((x))           \
                : "cc", "memory", "v0"     \
            );                             \
        } while(0)
#else /* if not defined __aarch64__ then use 32 bit version */
    #define SBOX(x)                      \
        do {                             \
            __asm__ volatile (           \
                "VDUP.32 q1, %[in]   \n" \
                "VMOV.i32 q0, #0     \n" \
                "AESE.8 q0, q1      \n" \
                "VMOV.32 %[out], d0[0] \n" \
                : [out] "=r"((x))        \
                : [in] "r" ((x))         \
                : "cc", "memory", "q0", "q1"\
            ); \
        } while(0)

    #define IMIX(x) \
        do {        \
            __asm__ volatile (           \
                "VLD1.32 {q0}, [%[in]] \n" \
                "AESIMC.8 q0, q0    \n" \
                "VST1.32 {q0}, [%[out]] \n" \
                : [out] "=r" ((x))       \
                : [in] "0" ((x))         \
                : "cc", "memory", "q0"   \
            );                           \
        } while(0)
#endif /* aarch64 */


#ifdef HAVE_AESGCM

#if !defined(__aarch64__) || defined(WOLFSSL_AESGCM_STREAM)
static WC_INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = WC_AES_BLOCK_SIZE - 1; i >= WC_AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}


static WC_INLINE void FlattenSzInBits(byte* buf, word32 sz)
{
    /* Multiply the sz by 8 */
    word32 szHi = (sz >> (8*sizeof(sz) - 3));
    sz <<= 3;

    /* copy over the words of the sz into the destination buffer */
    buf[0] = (szHi >> 24) & 0xff;
    buf[1] = (szHi >> 16) & 0xff;
    buf[2] = (szHi >>  8) & 0xff;
    buf[3] = szHi & 0xff;
    buf[4] = (sz >> 24) & 0xff;
    buf[5] = (sz >> 16) & 0xff;
    buf[6] = (sz >>  8) & 0xff;
    buf[7] = sz & 0xff;
}
#endif

#endif /* HAVE_AESGCM */

#if defined(__aarch64__)

int AES_set_key_AARCH64(const unsigned char *userKey, const int keylen,
    Aes* aes, int dir)
{
    word32 temp;
    word32* rk = aes->key;
    unsigned int i = 0;

    XMEMCPY(rk, userKey, keylen);

    switch (keylen) {
#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 128 && \
        defined(WOLFSSL_AES_128)
    case 16:
        while (1) {
            temp  = rk[3];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[4] = rk[0] ^ temp ^ rcon[i];
            rk[5] = rk[4] ^ rk[1];
            rk[6] = rk[5] ^ rk[2];
            rk[7] = rk[6] ^ rk[3];
            if (++i == 10)
                break;
            rk += 4;
        }
        break;
#endif /* 128 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 192 && \
        defined(WOLFSSL_AES_192)
    case 24:
        /* for (;;) here triggers a bug in VC60 SP4 w/ Pro Pack */
        while (1) {
            temp  = rk[5];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[ 6] = rk[ 0] ^ temp ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8)
                break;
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
        break;
#endif /* 192 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 256 && \
        defined(WOLFSSL_AES_256)
    case 32:
        while (1) {
            temp  = rk[7];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[8] = rk[0] ^ temp ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7)
                break;
            temp  = rk[11];
            SBOX(temp);
            rk[12] = rk[ 4] ^ temp;
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
        }
        break;
#endif /* 256 */

    default:
        return BAD_FUNC_ARG;
    }

    if (dir == AES_DECRYPTION) {
#ifdef HAVE_AES_DECRYPT
        unsigned int j;
        rk = aes->key;

        /* invert the order of the round keys: */
        for (i = 0, j = 4* aes->rounds; i < j; i += 4, j -= 4) {
            temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
            temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
            temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
            temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
        }
        /* apply the inverse MixColumn transform to all round keys but the
           first and the last: */
        for (i = 1; i < aes->rounds; i++) {
            rk += 4;
            IMIX(rk);
        }
#else
    WOLFSSL_MSG("AES Decryption not compiled in");
    return BAD_FUNC_ARG;
#endif /* HAVE_AES_DECRYPT */
    }

    return 0;
}

#else

/* Similar to wolfSSL software implementation of expanding the AES key.
 * Changed out the locations of where table look ups where made to
 * use hardware instruction. Also altered decryption key to match. */
int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
            const byte* iv, int dir)
{
    word32 temp;
    word32 *rk;
    unsigned int i = 0;

#if defined(AES_MAX_KEY_SIZE)
    const word32 max_key_len = (AES_MAX_KEY_SIZE / 8);
#endif

    if (!((keylen == 16) || (keylen == 24) || (keylen == 32)) ||
           aes == NULL || userKey == NULL)
        return BAD_FUNC_ARG;

    rk = aes->key;
#if defined(AES_MAX_KEY_SIZE)
    /* Check key length */
    if (keylen > max_key_len) {
        return BAD_FUNC_ARG;
    }
#endif

    #if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
        defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS)
        aes->left = 0;
    #endif /* WOLFSSL_AES_COUNTER */

    aes->keylen = keylen;
    aes->rounds = keylen/4 + 6;
    XMEMCPY(rk, userKey, keylen);

    switch(keylen)
    {
#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 128 && \
        defined(WOLFSSL_AES_128)
    case 16:
        while (1)
        {
            temp  = rk[3];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[4] = rk[0] ^ temp ^ rcon[i];
            rk[5] = rk[4] ^ rk[1];
            rk[6] = rk[5] ^ rk[2];
            rk[7] = rk[6] ^ rk[3];
            if (++i == 10)
                break;
            rk += 4;
        }
        break;
#endif /* 128 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 192 && \
        defined(WOLFSSL_AES_192)
    case 24:
        /* for (;;) here triggers a bug in VC60 SP4 w/ Pro Pack */
        while (1)
        {
            temp  = rk[5];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[ 6] = rk[ 0] ^ temp ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8)
                break;
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
        break;
#endif /* 192 */

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 256 && \
        defined(WOLFSSL_AES_256)
    case 32:
        while (1)
        {
            temp  = rk[7];
            SBOX(temp);
            temp = rotrFixed(temp, 8);
            rk[8] = rk[0] ^ temp ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7)
                break;
            temp  = rk[11];
            SBOX(temp);
            rk[12] = rk[ 4] ^ temp;
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
        }
        break;
#endif /* 256 */

    default:
        return BAD_FUNC_ARG;
    }

    if (dir == AES_DECRYPTION)
    {
#ifdef HAVE_AES_DECRYPT
        unsigned int j;
        rk = aes->key;

        /* invert the order of the round keys: */
        for (i = 0, j = 4* aes->rounds; i < j; i += 4, j -= 4) {
            temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
            temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
            temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
            temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
        }
        /* apply the inverse MixColumn transform to all round keys but the
           first and the last: */
        for (i = 1; i < aes->rounds; i++) {
            rk += 4;
            IMIX(rk);
        }
#else
    WOLFSSL_MSG("AES Decryption not compiled in");
    return BAD_FUNC_ARG;
#endif /* HAVE_AES_DECRYPT */
    }

    return wc_AesSetIV(aes, iv);
}


#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
    int wc_AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir)
    {
        return wc_AesSetKey(aes, userKey, keylen, iv, dir);
    }
#endif

/* wc_AesSetIV is shared between software and hardware */
int wc_AesSetIV(Aes* aes, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    if (iv)
        XMEMCPY(aes->reg, iv, WC_AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg,  0, WC_AES_BLOCK_SIZE);

    return 0;
}

#endif /* __aarch64__ */

#ifdef __aarch64__
/* AES CCM/GCM use encrypt direct but not decrypt */
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC)

void AES_encrypt_AARCH64(const byte* inBlock, byte* outBlock, byte* key, int nr)
{
    /*
      AESE exor's input with round key
           shift rows of exor'ed result
           sub bytes for shifted rows
     */

    __asm__ __volatile__ (
        "LD1 {v0.16b}, [%[in]] \n"
        "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"

        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"

        "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"

        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b  \n"

        "#subtract rounds done so far and see if should continue\n"
        "MOV w12, %w[nr]    \n"
        "SUB w12, w12, #10 \n"
        "CBZ w12, 1f       \n"
        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b  \n"

        "SUB w12, w12, #2 \n"
        "CBZ w12, 1f      \n"
        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b  \n"

        "#Final AddRoundKey then store result \n"
    "1: \n"
        "LD1 {v1.2d}, [%[key]], #16 \n"
        "EOR v0.16b, v0.16b, v1.16b  \n"
        "ST1 {v0.16b}, [%[out]]   \n"

        : [key] "+r" (key)
        : [in] "r" (inBlock), [out] "r" (outBlock), [nr] "r" (nr)
        : "cc", "memory", "w12", "v0", "v1", "v2", "v3", "v4"
    );
}
#endif /* AES_GCM, AES_CCM, DIRECT or COUNTER */
#if !defined(WC_AES_BITSLICED) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLFSSL_AES_COUNTER)
#ifdef HAVE_AES_DECRYPT
void AES_decrypt_AARCH64(const byte* inBlock, byte* outBlock, byte* key, int nr)
{
    /*
      AESE exor's input with round key
           shift rows of exor'ed result
           sub bytes for shifted rows
     */

    __asm__ __volatile__ (
        "LD1 {v0.16b}, [%[in]] \n"
        "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"

        "AESD v0.16b, v1.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v2.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v3.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v4.16b   \n"
        "AESIMC v0.16b, v0.16b \n"

        "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
        "AESD v0.16b, v1.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v2.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v3.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v4.16b   \n"
        "AESIMC v0.16b, v0.16b \n"

        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESD v0.16b, v1.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v2.16b   \n"

        "#subtract rounds done so far and see if should continue\n"
        "MOV w12, %w[nr]    \n"
        "SUB w12, w12, #10 \n"
        "CBZ w12, 1f       \n"
        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v1.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v2.16b   \n"

        "SUB w12, w12, #2  \n"
        "CBZ w12, 1f       \n"
        "LD1 {v1.2d-v2.2d}, [%[key]], #32  \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v1.16b   \n"
        "AESIMC v0.16b, v0.16b \n"
        "AESD v0.16b, v2.16b   \n"

        "#Final AddRoundKey then store result \n"
    "1: \n"
        "LD1 {v1.2d}, [%[key]], #16 \n"
        "EOR v0.16b, v0.16b, v1.16b  \n"
        "ST1 {v0.4s}, [%[out]]    \n"

        : [key] "+r" (key)
        : [in] "r" (inBlock), [out] "r" (outBlock), [nr] "r" (nr)
        : "cc", "memory", "w12", "v0", "v1", "v2", "v3", "v4"
    );
}
#endif /* HAVE_AES_DECRYPT */
#endif /* DIRECT or COUNTER */

/* AES-CBC */
#ifdef HAVE_AES_CBC
void AES_CBC_encrypt_AARCH64(const byte* in, byte* out, word32 sz, byte* reg,
    byte* key, int rounds)
{
    word32 numBlocks = sz / WC_AES_BLOCK_SIZE;

    /*
    AESE exor's input with round key
    shift rows of exor'ed result
            sub bytes for shifted rows

    note: grouping AESE & AESMC together as pairs reduces latency
    */
    switch (rounds) {
#ifdef WOLFSSL_AES_128
    case 10: /* AES 128 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
            "LD1 {v5.2d-v8.2d}, [%[key]], #64  \n"
            "LD1 {v9.2d-v11.2d},[%[key]], #48  \n"
            "LD1 {v0.2d}, [%[reg]] \n"

            "LD1 {v12.2d}, [%[in]], #16 \n"
        "1:\n"
            "#CBC operations, xorbuf in with current reg \n"
            "EOR v0.16b, v0.16b, v12.16b \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v5.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v6.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v7.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v8.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v9.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v10.16b  \n"
            "SUB w11, w11, #1 \n"
            "EOR v0.16b, v0.16b, v11.16b  \n"
            "ST1 {v0.2d}, [%[out]], #16   \n"

            "CBZ w11, 2f \n"
            "LD1 {v12.2d}, [%[in]], #16 \n"
            "B 1b \n"

        "2:\n"
            "#store current counter value at the end \n"
            "ST1 {v0.2d}, [%[reg]] \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13"
        );
        break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
    case 12: /* AES 192 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
            "LD1 {v5.2d-v8.2d}, [%[key]], #64  \n"
            "LD1 {v9.2d-v12.2d},[%[key]], #64  \n"
            "LD1 {v13.2d}, [%[key]], #16 \n"
            "LD1 {v0.2d}, [%[reg]] \n"

            "LD1 {v14.2d}, [%[in]], #16  \n"
        "1:\n"
            "#CBC operations, xorbuf in with current reg \n"
            "EOR v0.16b, v0.16b, v14.16b \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v5.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v6.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v7.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v8.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v9.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v10.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v11.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v12.16b \n"
            "EOR v0.16b, v0.16b, v13.16b  \n"
            "SUB w11, w11, #1 \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, 2f \n"
            "LD1 {v14.2d}, [%[in]], #16\n"
            "B 1b \n"

        "2:\n"
            "#store current counter value at the end \n"
            "ST1 {v0.2d}, [%[reg]]   \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14"
        );
        break;
#endif /* WOLFSSL_AES_192*/
#ifdef WOLFSSL_AES_256
    case 14: /* AES 256 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d},   [%[key]], #64 \n"

            "LD1 {v5.2d-v8.2d},   [%[key]], #64 \n"
            "LD1 {v9.2d-v12.2d},  [%[key]], #64 \n"
            "LD1 {v13.2d-v15.2d}, [%[key]], #48 \n"
            "LD1 {v0.2d}, [%[reg]] \n"

            "LD1 {v16.2d}, [%[in]], #16  \n"
        "1: \n"
            "#CBC operations, xorbuf in with current reg \n"
            "EOR v0.16b, v0.16b, v16.16b \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v5.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v6.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v7.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v8.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v9.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v10.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v11.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v12.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v13.16b \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v14.16b \n"
            "EOR v0.16b, v0.16b, v15.16b \n"
            "SUB w11, w11, #1     \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, 2f \n"
            "LD1 {v16.2d}, [%[in]], #16 \n"
            "B 1b \n"

        "2: \n"
            "#store current counter value at the end \n"
            "ST1 {v0.2d}, [%[reg]]   \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14","v15",
            "v16"
        );
        break;
#endif /* WOLFSSL_AES_256 */
    }
}

#ifdef HAVE_AES_DECRYPT
void AES_CBC_decrypt_AARCH64(const byte* in, byte* out, word32 sz,
    byte* reg, byte* key, int rounds)
{
    word32 numBlocks = sz / WC_AES_BLOCK_SIZE;

    switch (rounds) {
#ifdef WOLFSSL_AES_128
    case 10: /* AES 128 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
            "LD1 {v5.2d-v8.2d}, [%[key]], #64  \n"
            "LD1 {v9.2d-v11.2d},[%[key]], #48  \n"
            "LD1 {v13.2d}, [%[reg]] \n"

        "1:\n"
            "LD1 {v0.2d}, [%[in]], #16  \n"
            "MOV v12.16b, v0.16b \n"
            "AESD v0.16b, v1.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v2.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v3.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v4.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v5.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v6.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v7.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v8.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v9.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v10.16b  \n"
            "EOR v0.16b, v0.16b, v11.16b \n"

            "EOR v0.16b, v0.16b, v13.16b \n"
            "SUB w11, w11, #1            \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"
            "MOV v13.16b, v12.16b        \n"

            "CBZ w11, 2f \n"
            "B 1b      \n"

        "2: \n"
            "#store current counter value at the end \n"
            "ST1 {v13.2d}, [%[reg]] \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13"
        );
        break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
    case 12: /* AES 192 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[key]], #64  \n"
            "LD1 {v5.2d-v8.2d}, [%[key]], #64  \n"
            "LD1 {v9.2d-v12.2d},[%[key]], #64  \n"
            "LD1 {v13.16b}, [%[key]], #16 \n"
            "LD1 {v15.2d}, [%[reg]]       \n"

            "LD1 {v0.2d}, [%[in]], #16  \n"
        "1:    \n"
            "MOV v14.16b, v0.16b   \n"
            "AESD v0.16b, v1.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v2.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v3.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v4.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v5.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v6.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v7.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v8.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v9.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v10.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v11.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v12.16b  \n"
            "EOR v0.16b, v0.16b, v13.16b \n"

            "EOR v0.16b, v0.16b, v15.16b \n"
            "SUB w11, w11, #1            \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"
            "MOV v15.16b, v14.16b        \n"

            "CBZ w11, 2f \n"
            "LD1 {v0.2d}, [%[in]], #16 \n"
            "B 1b \n"

        "2:\n"
            "#store current counter value at the end \n"
            "ST1 {v15.2d}, [%[reg]] \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"
        );
        break;
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
    case 14: /* AES 256 BLOCK */
        __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d},   [%[key]], #64  \n"
            "LD1 {v5.2d-v8.2d},   [%[key]], #64  \n"
            "LD1 {v9.2d-v12.2d},  [%[key]], #64  \n"
            "LD1 {v13.2d-v15.2d}, [%[key]], #48  \n"
            "LD1 {v17.2d}, [%[reg]] \n"

            "LD1 {v0.2d}, [%[in]], #16  \n"
        "1:    \n"
            "MOV v16.16b, v0.16b   \n"
            "AESD v0.16b, v1.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v2.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v3.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v4.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v5.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v6.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v7.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v8.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v9.16b   \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v10.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v11.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v12.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v13.16b  \n"
            "AESIMC v0.16b, v0.16b \n"
            "AESD v0.16b, v14.16b  \n"
            "EOR v0.16b, v0.16b, v15.16b \n"

            "EOR v0.16b, v0.16b, v17.16b \n"
            "SUB w11, w11, #1            \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"
            "MOV v17.16b, v16.16b        \n"

            "CBZ w11, 2f \n"
            "LD1 {v0.2d}, [%[in]], #16  \n"
            "B 1b \n"

        "2:\n"
            "#store current counter value at the end \n"
            "ST1 {v17.2d}, [%[reg]]   \n"

            : [out] "+r" (out), [in] "+r" (in), [key] "+r" (key)
            : [reg] "r" (reg), [blocks] "r" (numBlocks)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14","v15",
            "v16", "v17"
        );
        break;
#endif /* WOLFSSL_AES_256 */
    }
}
#endif

#endif /* HAVE_AES_CBC */

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
static void wc_aes_ctr_encrypt_asm(Aes* aes, byte* out, const byte* in,
                                   byte* keyPt, word32 numBlocks)
{
    switch(aes->rounds) {
#ifdef WOLFSSL_AES_128
    case 10: /* AES 128 BLOCK */
        __asm__ __volatile__ (
        "MOV w11, %w[blocks] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"

        "#Create vector with the value 1  \n"
        "MOVI v15.16b, #1                 \n"
        "USHR v15.2d, v15.2d, #56         \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "EOR v14.16b, v14.16b, v14.16b    \n"
        "EXT v14.16b, v15.16b, v14.16b, #8\n"

        "LD1 {v9.2d-v11.2d}, [%[Key]], #48\n"
        "LD1 {v13.2d}, %[reg]             \n"

        /* double block */
        "1:      \n"
        "CMP w11, #1 \n"
        "BEQ 2f    \n"
        "CMP w11, #0 \n"
        "BEQ 3f    \n"

        "MOV v0.16b, v13.16b  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v13.16b, v13.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "SUB w11, w11, #2     \n"
        "ADD v15.2d, v13.2d, v14.2d \n" /* add 1 to counter */
        "CMEQ v12.2d, v15.2d, #0 \n"
        "EXT v12.16b, v14.16b, v12.16b, #8 \n"
        "SUB v15.2d, v15.2d, v12.2d \n"
        "ADD v13.2d, v15.2d, v14.2d \n" /* add 1 to counter */
        "CMEQ v12.2d, v13.2d, #0 \n"
        "EXT v12.16b, v14.16b, v12.16b, #8 \n"
        "SUB v13.2d, v13.2d, v12.2d \n"

        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"

        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v15.16b, v15.16b \n" /* revert from network order */
        "REV64 v13.16b, v13.16b \n" /* revert from network order */

        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v15.16b, v1.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v15.16b, v2.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v15.16b, v3.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v15.16b, v4.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v15.16b, v5.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "AESE v0.16b, v10.16b  \n"
        "AESE v15.16b, v6.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "EOR v0.16b, v0.16b, v11.16b \n"
        "AESE v15.16b, v7.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "LD1 {v12.2d}, [%[input]], #16  \n"
        "AESE v15.16b, v8.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "EOR v0.16b, v0.16b, v12.16b \n"
        "AESE v15.16b, v9.16b  \n"
        "AESMC v15.16b, v15.16b \n"

        "LD1 {v12.2d}, [%[input]], #16  \n"
        "AESE v15.16b, v10.16b  \n"
        "ST1 {v0.2d}, [%[out]], #16  \n"
        "EOR v15.16b, v15.16b, v11.16b \n"
        "EOR v15.16b, v15.16b, v12.16b \n"
        "ST1 {v15.2d}, [%[out]], #16  \n"

        "B 1b \n"

        /* single block */
        "2: \n"
        "MOV v0.16b, v13.16b  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v13.16b, v13.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "ADD v13.2d, v13.2d, v14.2d \n" /* add 1 to counter */
        "CMEQ v15.2d, v13.2d, #0 \n"
        "EXT v15.16b, v14.16b, v15.16b, #8 \n"
        "SUB v13.2d, v13.2d, v15.2d \n"
        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #1     \n"
        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v13.16b, v13.16b \n" /* revert from network order */
        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n"
        "#CTR operations, increment counter and xorbuf \n"
        "LD1 {v12.2d}, [%[input]], #16  \n"
        "EOR v0.16b, v0.16b, v12.16b \n"
        "ST1 {v0.2d}, [%[out]], #16  \n"

        "3: \n"
        "#store current counter value at the end \n"
        "ST1 {v13.2d}, %[regOut]   \n"

        :[out] "=r" (out), "=r" (keyPt), [regOut] "=m" (aes->reg),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
        : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
        "v6", "v7", "v8", "v9", "v10","v11","v12","v13","v14","v15"
        );
        break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
    case 12: /* AES 192 BLOCK */
        __asm__ __volatile__ (
        "MOV w11, %w[blocks]              \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"

        "#Create vector with the value 1  \n"
        "MOVI v16.16b, #1                 \n"
        "USHR v16.2d, v16.2d, #56         \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "EOR v14.16b, v14.16b, v14.16b    \n"
        "EXT v16.16b, v16.16b, v14.16b, #8\n"

        "LD1 {v9.2d-v12.2d}, [%[Key]], #64\n"
        "LD1 {v15.2d}, %[reg]             \n"
        "LD1 {v13.16b}, [%[Key]], #16     \n"

        /* double block */
        "1:      \n"
        "CMP w11, #1 \n"
        "BEQ 2f    \n"
        "CMP w11, #0 \n"
        "BEQ 3f    \n"

        "MOV v0.16b, v15.16b  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v15.16b, v15.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "SUB w11, w11, #2     \n"
        "ADD v17.2d, v15.2d, v16.2d \n" /* add 1 to counter */
        "CMEQ v14.2d, v17.2d, #0 \n"
        "EXT v14.16b, v16.16b, v14.16b, #8 \n"
        "SUB v17.2d, v17.2d, v14.2d \n"
        "ADD v15.2d, v17.2d, v16.2d \n" /* add 1 to counter */
        "CMEQ v14.2d, v15.2d, #0 \n"
        "EXT v14.16b, v16.16b, v14.16b, #8 \n"
        "SUB v15.2d, v15.2d, v14.2d \n"

        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v17.16b, v17.16b, v17.16b, #8 \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"

        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v17.16b, v17.16b \n" /* revert from network order */
        "REV64 v15.16b, v15.16b \n" /* revert from network order */

        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v1.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v2.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v3.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v4.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v5.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v10.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v6.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v11.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v17.16b, v7.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "AESE v0.16b, v12.16b  \n"
        "AESE v17.16b, v8.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "EOR v0.16b, v0.16b, v13.16b \n"
        "AESE v17.16b, v9.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "LD1 {v14.2d}, [%[input]], #16  \n"
        "AESE v17.16b, v10.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "EOR v0.16b, v0.16b, v14.16b \n"
        "AESE v17.16b, v11.16b  \n"
        "AESMC v17.16b, v17.16b \n"

        "LD1 {v14.2d}, [%[input]], #16  \n"
        "AESE v17.16b, v12.16b  \n"
        "ST1 {v0.2d}, [%[out]], #16  \n"
        "EOR v17.16b, v17.16b, v13.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "ST1 {v17.2d}, [%[out]], #16  \n"

        "B 1b \n"

        "2:      \n"
        "LD1 {v14.2d}, [%[input]], #16    \n"
        "MOV v0.16b, v15.16b  \n"

        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v15.16b, v15.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "ADD v15.2d, v15.2d, v16.2d \n" /* add 1 to counter */
        "CMEQ v17.2d, v15.2d, #0 \n"
        "EXT v17.16b, v16.16b, v17.16b, #8 \n"
        "SUB v15.2d, v15.2d, v17.2d \n"
        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #1     \n"
        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v15.16b, v15.16b \n" /* revert from network order */
        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n"
        "#CTR operations, increment counter and xorbuf \n"
        "EOR v0.16b, v0.16b, v14.16b \n"
        "ST1 {v0.2d}, [%[out]], #16  \n"

        "3: \n"
        "#store current counter value at the end \n"
        "ST1 {v15.2d}, %[regOut] \n"

        :[out] "=r" (out), "=r" (keyPt), [regOut] "=m" (aes->reg),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
        : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
        "v6", "v7", "v8", "v9", "v10","v11","v12","v13","v14","v15",
        "v16", "v17"
        );
        break;
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
    case 14: /* AES 256 BLOCK */
        __asm__ __volatile__ (
        "MOV w11, %w[blocks] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"

        "#Create vector with the value 1  \n"
        "MOVI v18.16b, #1                 \n"
        "USHR v18.2d, v18.2d, #56         \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "EOR v19.16b, v19.16b, v19.16b    \n"
        "EXT v18.16b, v18.16b, v19.16b, #8\n"

        "LD1 {v9.2d-v12.2d}, [%[Key]], #64  \n"
        "LD1 {v13.2d-v15.2d}, [%[Key]], #48 \n"
        "LD1 {v17.2d}, %[reg]               \n"

        /* double block */
        "1:      \n"
        "CMP w11, #1 \n"
        "BEQ 2f    \n"
        "CMP w11, #0 \n"
        "BEQ 3f    \n"

        "MOV v0.16b, v17.16b  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v17.16b, v17.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v17.16b, v17.16b, v17.16b, #8 \n"
        "SUB w11, w11, #2     \n"
        "ADD v19.2d, v17.2d, v18.2d \n" /* add 1 to counter */
        "CMEQ v16.2d, v19.2d, #0 \n"
        "EXT v16.16b, v18.16b, v16.16b, #8 \n"
        "SUB v19.2d, v19.2d, v16.2d \n"
        "ADD v17.2d, v19.2d, v18.2d \n" /* add 1 to counter */
        "CMEQ v16.2d, v17.2d, #0 \n"
        "EXT v16.16b, v18.16b, v16.16b, #8 \n"
        "SUB v17.2d, v17.2d, v16.2d \n"

        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "EXT v17.16b, v17.16b, v17.16b, #8 \n"

        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v19.16b, v19.16b \n" /* revert from network order */
        "REV64 v17.16b, v17.16b \n" /* revert from network order */

        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v1.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v2.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v3.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v4.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v5.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v10.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v6.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v11.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v7.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v12.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v8.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v13.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v19.16b, v9.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v0.16b, v14.16b  \n"
        "AESE v19.16b, v10.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v19.16b, v11.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "LD1 {v16.2d}, [%[input]], #16 \n"
        "AESE v19.16b, v12.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "EOR v0.16b, v0.16b, v16.16b \n"
        "AESE v19.16b, v13.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "LD1 {v16.2d}, [%[input]], #16 \n"
        "AESE v19.16b, v14.16b  \n"
        "ST1 {v0.2d}, [%[out]], #16  \n"
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v19.16b, v19.16b, v16.16b \n"
        "ST1 {v19.2d}, [%[out]], #16  \n"

        "B 1b \n"

        "2:      \n"
        "LD1 {v16.2d}, [%[input]], #16 \n"
        "MOV v0.16b, v17.16b  \n"
        "AESE v0.16b, v1.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v17.16b, v17.16b \n" /* network order */
        "AESE v0.16b, v2.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v17.16b, v17.16b, v17.16b, #8 \n"
        "AESE v0.16b, v3.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "ADD v17.2d, v17.2d, v18.2d \n" /* add 1 to counter */
        "CMEQ v19.2d, v17.2d, #0 \n"
        "EXT v19.16b, v18.16b, v19.16b, #8 \n"
        "SUB v17.2d, v17.2d, v19.2d \n"
        "AESE v0.16b, v4.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v5.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v17.16b, v17.16b, v17.16b, #8 \n"
        "AESE v0.16b, v6.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "REV64 v17.16b, v17.16b \n" /* revert from network order */
        "AESE v0.16b, v7.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b  \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "#CTR operations, increment counter and xorbuf \n"
        "EOR v0.16b, v0.16b, v16.16b \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"

        "3: \n"
        "#store current counter value at the end \n"
        "ST1 {v17.2d}, %[regOut] \n"


        :[out] "=r" (out), "=r" (keyPt), [regOut] "=m" (aes->reg),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
        : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
        "v6", "v7", "v8", "v9", "v10","v11","v12","v13","v14","v15",
        "v16", "v17", "v18", "v19"
        );
        break;
#endif /* WOLFSSL_AES_256 */
    }
}

void AES_CTR_encrypt_AARCH64(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte* tmp;
    word32 numBlocks;

    /* do as many block size ops as possible */
    numBlocks = sz / WC_AES_BLOCK_SIZE;
    if (numBlocks > 0) {
        wc_aes_ctr_encrypt_asm(aes, out, in, (byte*)aes->key, numBlocks);

        sz  -= numBlocks * WC_AES_BLOCK_SIZE;
        out += numBlocks * WC_AES_BLOCK_SIZE;
        in  += numBlocks * WC_AES_BLOCK_SIZE;
    }

    /* handle non block size remaining */
    if (sz) {
        byte zeros[WC_AES_BLOCK_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0 };
        wc_aes_ctr_encrypt_asm(aes, (byte*)aes->tmp, zeros, (byte*)aes->key, 1);

        aes->left = WC_AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;

        while (sz--) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }
}

#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM

/*
 * Based from GCM implementation in wolfcrypt/src/aes.c
 */

/* START script replace AES-GCM Aarch64 with hardware crypto. */

/* PMULL and RBIT only with AArch64 */
/* Use ARM hardware for polynomial multiply */
void GMULT_AARCH64(byte* X, byte* Y)
{
    __asm__ volatile (
        "LD1 {v0.16b}, [%[X]] \n"
        "LD1 {v1.16b}, [%[Y]] \n" /* v1 already reflected from set key */
        "MOVI v2.16b, #0x87 \n"
        "RBIT v0.16b, v0.16b \n"
        "USHR v2.2d, v2.2d, #56 \n"

        "PMULL  v3.1q, v0.1d, v1.1d \n"
        "PMULL2 v4.1q, v0.2d, v1.2d \n"
        "EXT v5.16b, v1.16b, v1.16b, #8 \n"
        "PMULL  v6.1q, v0.1d, v5.1d \n"
        "PMULL2 v5.1q, v0.2d, v5.2d \n"
        "EOR v5.16b, v5.16b, v6.16b \n"
        "EXT v6.16b, v3.16b, v4.16b, #8 \n"
        "EOR v6.16b, v6.16b, v5.16b \n"
        "# Reduce \n"
        "PMULL2 v5.1q, v4.2d, v2.2d \n"
        "EOR v6.16b, v6.16b, v5.16b \n"
        "PMULL2 v5.1q, v6.2d, v2.2d \n"
        "MOV v3.D[1], v6.D[0] \n"
        "EOR v0.16b, v3.16b, v5.16b \n"

        "RBIT v0.16b, v0.16b \n"
        "STR q0, [%[X]] \n"
        :
        : [X] "r" (X), [Y] "r" (Y)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6"
    );
}

static void GHASH_AARCH64(Gcm* gcm, const byte* a, word32 aSz, const byte* c,
    word32 cSz, byte* s, word32 sSz)
{
    byte scratch[WC_AES_BLOCK_SIZE];

    __asm__ __volatile__ (
        "LD1 {v3.16b}, %[h] \n"
        "MOVI v7.16b, #0x87 \n"
        "EOR v0.16b, v0.16b, v0.16b \n"
        "USHR v7.2d, v7.2d, #56 \n"

        "# AAD \n"
        "CBZ %[a], 20f \n"
        "CBZ %w[aSz], 20f \n"
        "MOV w12, %w[aSz] \n"

        "CMP x12, #64 \n"
        "BLT 15f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v11.1q, v3.2d, v3.2d \n"
        "PMULL  v10.1q, v3.1d, v3.1d \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v11.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v4.16b, v10.16b, v11.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v10.1q, v4.1d, v3.1d \n"
        "PMULL2 v11.1q, v4.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v4.1d, v12.1d \n"
        "PMULL2 v12.1q, v4.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v5.16b, v10.16b, v12.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v11.1q, v4.2d, v4.2d \n"
        "PMULL  v10.1q, v4.1d, v4.1d \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v11.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v6.16b, v10.16b, v11.16b \n"
        "14: \n"
        "LD1 {v10.2d-v13.2d}, [%[a]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v10.16b, v10.16b \n"
        "RBIT v11.16b, v11.16b \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "EOR v10.16b, v10.16b, v0.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v0.1q, v13.1d, v3.1d \n"
        "PMULL2 v1.1q, v13.2d, v3.2d \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v2.1q, v13.1d, v3.1d \n"
        "PMULL2 v9.1q, v13.2d, v3.2d \n"
        "EOR v2.16b, v2.16b, v9.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v8.1q, v12.1d, v4.1d \n"
        "PMULL2 v9.1q, v12.2d, v4.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v9.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v12.16b, v9.16b \n"
#else
        "EOR v12.16b, v12.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v8.1q, v11.1d, v5.1d \n"
        "PMULL2 v9.1q, v11.2d, v5.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v11.16b, v11.16b, v11.16b, #8 \n"
        "PMULL  v9.1q, v11.1d, v5.1d \n"
        "PMULL2 v11.1q, v11.2d, v5.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v11.16b, v9.16b \n"
#else
        "EOR v11.16b, v11.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v11.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v8.1q, v10.1d, v6.1d \n"
        "PMULL2 v9.1q, v10.2d, v6.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v10.16b, v10.16b, v10.16b, #8 \n"
        "PMULL  v9.1q, v10.1d, v6.1d \n"
        "PMULL2 v10.1q, v10.2d, v6.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v10.16b, v9.16b \n"
#else
        "EOR v10.16b, v10.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v10.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v9.16b, v0.16b, v1.16b, #8 \n"
        "PMULL2 v8.1q, v1.2d, v7.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v9.16b, v9.16b, v2.16b, v8.16b \n"
#else
        "EOR v9.16b, v9.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v9.16b, v9.16b, v8.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v8.1q, v9.2d, v7.2d \n"
        "MOV v0.D[1], v9.D[0] \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "CMP x12, #64 \n"
        "BGE 14b \n"
        "CBZ x12, 20f \n"
        "15: \n"
        "CMP x12, #16 \n"
        "BLT 12f \n"
        "11: \n"
        "LD1 {v14.2d}, [%[a]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v14.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v14.16b \n"
        "PMULL  v10.1q, v0.1d, v3.1d \n"
        "PMULL2 v11.1q, v0.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v0.1d, v12.1d \n"
        "PMULL2 v12.1q, v0.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v0.16b, v10.16b, v12.16b \n"
        "CMP x12, #16 \n"
        "BGE 11b \n"
        "CBZ x12, 120f \n"
        "12: \n"
        "# Partial AAD \n"
        "EOR v14.16b, v14.16b, v14.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v14.2d}, [%[scratch]] \n"
        "13: \n"
        "LDRB w13, [%[a]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 13b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v14.2d}, [%[scratch]] \n"
        "RBIT v14.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v14.16b \n"
        "PMULL  v10.1q, v0.1d, v3.1d \n"
        "PMULL2 v11.1q, v0.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v0.1d, v12.1d \n"
        "PMULL2 v12.1q, v0.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v0.16b, v10.16b, v12.16b \n"

        "20: \n"
        "# Cipher Text \n"
        "CBZ %[c], 120f \n"
        "CBZ %w[cSz], 120f \n"
        "MOV w12, %w[cSz] \n"

        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v11.1q, v3.2d, v3.2d \n"
        "PMULL  v10.1q, v3.1d, v3.1d \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v11.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v4.16b, v10.16b, v11.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v10.1q, v4.1d, v3.1d \n"
        "PMULL2 v11.1q, v4.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v4.1d, v12.1d \n"
        "PMULL2 v12.1q, v4.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v5.16b, v10.16b, v12.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v11.1q, v4.2d, v4.2d \n"
        "PMULL  v10.1q, v4.1d, v4.1d \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v11.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v6.16b, v10.16b, v11.16b \n"
        "114: \n"
        "LD1 {v10.2d-v13.2d}, [%[c]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v10.16b, v10.16b \n"
        "RBIT v11.16b, v11.16b \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "EOR v10.16b, v10.16b, v0.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v0.1q, v13.1d, v3.1d \n"
        "PMULL2 v1.1q, v13.2d, v3.2d \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v2.1q, v13.1d, v3.1d \n"
        "PMULL2 v9.1q, v13.2d, v3.2d \n"
        "EOR v2.16b, v2.16b, v9.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v8.1q, v12.1d, v4.1d \n"
        "PMULL2 v9.1q, v12.2d, v4.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v9.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v12.16b, v9.16b \n"
#else
        "EOR v12.16b, v12.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v8.1q, v11.1d, v5.1d \n"
        "PMULL2 v9.1q, v11.2d, v5.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v11.16b, v11.16b, v11.16b, #8 \n"
        "PMULL  v9.1q, v11.1d, v5.1d \n"
        "PMULL2 v11.1q, v11.2d, v5.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v11.16b, v9.16b \n"
#else
        "EOR v11.16b, v11.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v11.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v8.1q, v10.1d, v6.1d \n"
        "PMULL2 v9.1q, v10.2d, v6.2d \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "EOR v1.16b, v1.16b, v9.16b \n"
        "EXT v10.16b, v10.16b, v10.16b, #8 \n"
        "PMULL  v9.1q, v10.1d, v6.1d \n"
        "PMULL2 v10.1q, v10.2d, v6.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v2.16b, v2.16b, v10.16b, v9.16b \n"
#else
        "EOR v10.16b, v10.16b, v9.16b \n"
        "EOR v2.16b, v2.16b, v10.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v9.16b, v0.16b, v1.16b, #8 \n"
        "PMULL2 v8.1q, v1.2d, v7.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v9.16b, v9.16b, v2.16b, v8.16b \n"
#else
        "EOR v9.16b, v9.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v9.16b, v9.16b, v8.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v8.1q, v9.2d, v7.2d \n"
        "MOV v0.D[1], v9.D[0] \n"
        "EOR v0.16b, v0.16b, v8.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v14.2d}, [%[c]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v14.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v14.16b \n"
        "PMULL  v10.1q, v0.1d, v3.1d \n"
        "PMULL2 v11.1q, v0.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v0.1d, v12.1d \n"
        "PMULL2 v12.1q, v0.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v0.16b, v10.16b, v12.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial cipher text \n"
        "EOR v14.16b, v14.16b, v14.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v14.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[c]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v14.2d}, [%[scratch]] \n"
        "RBIT v14.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v14.16b \n"
        "PMULL  v10.1q, v0.1d, v3.1d \n"
        "PMULL2 v11.1q, v0.2d, v3.2d \n"
        "EXT v12.16b, v3.16b, v3.16b, #8 \n"
        "PMULL  v13.1q, v0.1d, v12.1d \n"
        "PMULL2 v12.1q, v0.2d, v12.2d \n"
        "EOR v12.16b, v12.16b, v13.16b \n"
        "EXT v13.16b, v10.16b, v11.16b, #8 \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "# Reduce \n"
        "PMULL2 v12.1q, v11.2d, v7.2d \n"
        "EOR v13.16b, v13.16b, v12.16b \n"
        "PMULL2 v12.1q, v13.2d, v7.2d \n"
        "MOV v10.D[1], v13.D[0] \n"
        "EOR v0.16b, v10.16b, v12.16b \n"
        "120: \n"
        "RBIT v0.16b, v0.16b \n"
        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[cSz], %x[cSz], #3 \n"
        "MOV v10.D[0], %x[aSz] \n"
        "MOV v10.D[1], %x[cSz] \n"
        "REV64 v10.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v10.16b \n"
        "ST1 {v0.16b}, [%[scratch]] \n"
        : [cSz] "+r" (cSz), [c] "+r" (c), [aSz] "+r" (aSz), [a] "+r" (a)
        : [scratch] "r" (scratch), [h] "m" (gcm->H)
        : "cc", "memory", "w12", "w13", "x14",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14"
    );

    XMEMCPY(s, scratch, sSz);
}

#ifdef WOLFSSL_AESGCM_STREAM
    /* Access initialization counter data. */
    #define AES_INITCTR(aes)        ((aes)->streamData + 0 * WC_AES_BLOCK_SIZE)
    /* Access counter data. */
    #define AES_COUNTER(aes)        ((aes)->streamData + 1 * WC_AES_BLOCK_SIZE)
    /* Access tag data. */
    #define AES_TAG(aes)            ((aes)->streamData + 2 * WC_AES_BLOCK_SIZE)
    /* Access last GHASH block. */
    #define AES_LASTGBLOCK(aes)     ((aes)->streamData + 3 * WC_AES_BLOCK_SIZE)
    /* Access last encrypted block. */
    #define AES_LASTBLOCK(aes)      ((aes)->streamData + 4 * WC_AES_BLOCK_SIZE)

/* GHASH one block of data.
 *
 * XOR block into tag and GMULT with H.
 *
 * @param [in, out] aes    AES GCM object.
 * @param [in]      block  Block of AAD or cipher text.
 */
#define GHASH_ONE_BLOCK_AARCH64(aes, block)             \
    do {                                                \
        xorbuf(AES_TAG(aes), block, WC_AES_BLOCK_SIZE);    \
        GMULT_AARCH64(AES_TAG(aes), aes->gcm.H);        \
    }                                                   \
    while (0)

/* Hash in the lengths of the AAD and cipher text in bits.
 *
 * Default implementation.
 *
 * @param [in, out] aes  AES GCM object.
 */
#define GHASH_LEN_BLOCK_AARCH64(aes)            \
    do {                                        \
        byte scratch[WC_AES_BLOCK_SIZE];        \
        FlattenSzInBits(&scratch[0], aes->aSz); \
        FlattenSzInBits(&scratch[8], aes->cSz); \
        GHASH_ONE_BLOCK_AARCH64(aes, scratch);  \
    }                                           \
    while (0)

/* Update the GHASH with AAD and/or cipher text.
 *
 * @param [in,out] aes   AES GCM object.
 * @param [in]     a     Additional authentication data buffer.
 * @param [in]     aSz   Size of data in AAD buffer.
 * @param [in]     c     Cipher text buffer.
 * @param [in]     cSz   Size of data in cipher text buffer.
 */
void GHASH_UPDATE_AARCH64(Aes* aes, const byte* a, word32 aSz, const byte* c,
    word32 cSz)
{
    word32 blocks;
    word32 partial;

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        /* Update count of AAD we have hashed. */
        aes->aSz += aSz;
        /* Check if we have unprocessed data. */
        if (aes->aOver > 0) {
            /* Calculate amount we can use - fill up the block. */
            byte sz = WC_AES_BLOCK_SIZE - aes->aOver;
            if (sz > aSz) {
                sz = aSz;
            }
            /* Copy extra into last GHASH block array and update count. */
            XMEMCPY(AES_LASTGBLOCK(aes) + aes->aOver, a, sz);
            aes->aOver += sz;
            if (aes->aOver == WC_AES_BLOCK_SIZE) {
                /* We have filled up the block and can process. */
                GHASH_ONE_BLOCK_AARCH64(aes, AES_LASTGBLOCK(aes));
                /* Reset count. */
                aes->aOver = 0;
            }
            /* Used up some data. */
            aSz -= sz;
            a += sz;
        }

        /* Calculate number of blocks of AAD and the leftover. */
        blocks = aSz / WC_AES_BLOCK_SIZE;
        partial = aSz % WC_AES_BLOCK_SIZE;
        /* GHASH full blocks now. */
        while (blocks--) {
            GHASH_ONE_BLOCK_AARCH64(aes, a);
            a += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            /* Cache the partial block. */
            XMEMCPY(AES_LASTGBLOCK(aes), a, partial);
            aes->aOver = (byte)partial;
        }
    }
    if (aes->aOver > 0 && cSz > 0 && c != NULL) {
        /* No more AAD coming and we have a partial block. */
        /* Fill the rest of the block with zeros. */
        byte sz = WC_AES_BLOCK_SIZE - aes->aOver;
        XMEMSET(AES_LASTGBLOCK(aes) + aes->aOver, 0, sz);
        /* GHASH last AAD block. */
        GHASH_ONE_BLOCK_AARCH64(aes, AES_LASTGBLOCK(aes));
        /* Clear partial count for next time through. */
        aes->aOver = 0;
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        /* Update count of cipher text we have hashed. */
        aes->cSz += cSz;
        if (aes->cOver > 0) {
            /* Calculate amount we can use - fill up the block. */
            byte sz = WC_AES_BLOCK_SIZE - aes->cOver;
            if (sz > cSz) {
                sz = cSz;
            }
            XMEMCPY(AES_LASTGBLOCK(aes) + aes->cOver, c, sz);
            /* Update count of unused encrypted counter. */
            aes->cOver += sz;
            if (aes->cOver == WC_AES_BLOCK_SIZE) {
                /* We have filled up the block and can process. */
                GHASH_ONE_BLOCK_AARCH64(aes, AES_LASTGBLOCK(aes));
                /* Reset count. */
                aes->cOver = 0;
            }
            /* Used up some data. */
            cSz -= sz;
            c += sz;
        }

        /* Calculate number of blocks of cipher text and the leftover. */
        blocks = cSz / WC_AES_BLOCK_SIZE;
        partial = cSz % WC_AES_BLOCK_SIZE;
        /* GHASH full blocks now. */
        while (blocks--) {
            GHASH_ONE_BLOCK_AARCH64(aes, c);
            c += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            /* Cache the partial block. */
            XMEMCPY(AES_LASTGBLOCK(aes), c, partial);
            aes->cOver = (byte)partial;
        }
    }
}

/* Finalize the GHASH calculation.
 *
 * Complete hashing cipher text and hash the AAD and cipher text lengths.
 *
 * @param [in, out] aes  AES GCM object.
 * @param [out]     s    Authentication tag.
 * @param [in]      sSz  Size of authentication tag required.
 */
static void GHASH_FINAL_AARCH64(Aes* aes, byte* s, word32 sSz)
{
    /* AAD block incomplete when > 0 */
    byte over = aes->aOver;

    if (aes->cOver > 0) {
        /* Cipher text block incomplete. */
        over = aes->cOver;
    }
    if (over > 0) {
        /* Zeroize the unused part of the block. */
        XMEMSET(AES_LASTGBLOCK(aes) + over, 0, WC_AES_BLOCK_SIZE - over);
        /* Hash the last block of cipher text. */
        GHASH_ONE_BLOCK_AARCH64(aes, AES_LASTGBLOCK(aes));
    }
    /* Hash in the lengths of AAD and cipher text in bits */
    GHASH_LEN_BLOCK_AARCH64(aes);
    /* Copy the result into s. */
    XMEMCPY(s, AES_TAG(aes), sSz);
}

void AES_GCM_init_AARCH64(Aes* aes, const byte* iv, word32 ivSz)
{
    ALIGN32 byte counter[WC_AES_BLOCK_SIZE];

    if (ivSz == GCM_NONCE_MID_SZ) {
        /* Counter is IV with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
        XMEMCPY(counter, iv, ivSz);
        XMEMSET(counter + GCM_NONCE_MID_SZ, 0,
                                      WC_AES_BLOCK_SIZE - GCM_NONCE_MID_SZ - 1);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        /* Counter is GHASH of IV. */
    #ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
    #endif
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    #ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
    #endif
    }

    /* Copy in the counter for use with cipher. */
    XMEMCPY(AES_COUNTER(aes), counter, WC_AES_BLOCK_SIZE);
    /* Encrypt initial counter into a buffer for GCM. */
    AES_encrypt_AARCH64(counter, AES_INITCTR(aes), (byte*)aes->key,
        (int)aes->rounds);
}

void AES_GCM_crypt_update_AARCH64(Aes* aes, byte* out, const byte* in,
    word32 sz)
{
    word32 blocks;
    word32 partial;

    /* Check if previous encrypted block was not used up. */
    if (aes->over > 0) {
        byte pSz = WC_AES_BLOCK_SIZE - aes->over;
        if (pSz > sz) pSz = sz;

        /* Use some/all of last encrypted block. */
        xorbufout(out, AES_LASTBLOCK(aes) + aes->over, in, pSz);
        aes->over = (aes->over + pSz) & (WC_AES_BLOCK_SIZE - 1);

        /* Some data used. */
        sz  -= pSz;
        in  += pSz;
        out += pSz;
    }

    /* Calculate the number of blocks needing to be encrypted and any leftover.
     */
    blocks  = sz / WC_AES_BLOCK_SIZE;
    partial = sz & (WC_AES_BLOCK_SIZE - 1);

    /* Encrypt block by block. */
    while (blocks--) {
        ALIGN32 byte scratch[WC_AES_BLOCK_SIZE];
        IncrementGcmCounter(AES_COUNTER(aes));
        /* Encrypt counter into a buffer. */
        AES_encrypt_AARCH64(AES_COUNTER(aes), scratch, (byte*)aes->key,
            (int)aes->rounds);
        /* XOR plain text into encrypted counter into cipher text buffer. */
        xorbufout(out, scratch, in, WC_AES_BLOCK_SIZE);
        /* Data complete. */
        in  += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }

    if (partial != 0) {
        /* Generate an extra block and use up as much as needed. */
        IncrementGcmCounter(AES_COUNTER(aes));
        /* Encrypt counter into cache. */
        AES_encrypt_AARCH64(AES_COUNTER(aes), AES_LASTBLOCK(aes),
            (byte*)aes->key, (int)aes->rounds);
        /* XOR plain text into encrypted counter into cipher text buffer. */
        xorbufout(out, AES_LASTBLOCK(aes), in, partial);
        /* Keep amount of encrypted block used. */
        aes->over = partial;
    }
}

/* Calculates authentication tag for AES GCM. C implementation.
 *
 * @param [in, out] aes        AES object.
 * @param [out]     authTag    Buffer to store authentication tag in.
 * @param [in]      authTagSz  Length of tag to create.
 */
void AES_GCM_final_AARCH64(Aes* aes, byte* authTag, word32 authTagSz)
{
    /* Calculate authentication tag. */
    GHASH_FINAL_AARCH64(aes, authTag, authTagSz);
    /* XOR in as much of encrypted counter as is required. */
    xorbuf(authTag, AES_INITCTR(aes), authTagSz);
#ifdef OPENSSL_EXTRA
    /* store AAD size for next call */
    aes->gcm.aadLen = aes->aSz;
#endif
    /* Zeroize last block to protect sensitive data. */
    ForceZero(AES_LASTBLOCK(aes), WC_AES_BLOCK_SIZE);
}
#endif /* WOLFSSL_AESGCM_STREAM */

#ifdef WOLFSSL_AES_128
/* internal function : see wc_AesGcmEncrypt */
static void Aes128GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* keyPt = (byte*)aes->key;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Encrypt plaintext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v10.1d, v16.1d \n"
        "PMULL2 v19.1q, v10.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v10.1d, v20.1d \n"
        "PMULL2 v20.1q, v10.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v19.16b \n"

        "# First encrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First encrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "EOR v27.16b, v27.16b, v11.16b \n"
        "AESE v28.16b, v10.16b \n"
        "EOR v28.16b, v28.16b, v11.16b \n"
        "AESE v29.16b, v10.16b \n"
        "EOR v29.16b, v29.16b, v11.16b \n"
        "AESE v30.16b, v10.16b \n"
        "EOR v30.16b, v30.16b, v11.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "EOR v27.16b, v27.16b, v11.16b \n"
        "AESE v28.16b, v10.16b \n"
        "EOR v28.16b, v28.16b, v11.16b \n"
        "AESE v29.16b, v10.16b \n"
        "EOR v29.16b, v29.16b, v11.16b \n"
        "AESE v30.16b, v10.16b \n"
        "EOR v30.16b, v30.16b, v11.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"

        "10: \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "# Encrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v31.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"

        "# When only one full block to encrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"

        "# Interweave GHASH and encrypt if more then 1 block \n"
        "2: \n"
        "RBIT v15.16b, v15.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"
        "B 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "MOV x15, #16 \n"
        "EOR w14, w14, w14 \n"
        "SUB x15, x15, x11 \n"
        "25: \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 25b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.2d}, [%[ctr]] \n"
        "ST1 {v22.2d}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v15.d[0], %x[aSz] \n"
        "MOV v15.d[1], %x[sz] \n"
        "REV64 v15.16b, v15.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "ST1 {v0.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, %x[tagSz] \n"
        "44: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[tag]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 44b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "41: \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );
}
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
/* internal function : see wc_AesGcmEncrypt */
static void Aes192GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* keyPt = (byte*)aes->key;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Encrypt plaintext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v10.1d, v16.1d \n"
        "PMULL2 v19.1q, v10.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v10.1d, v20.1d \n"
        "PMULL2 v20.1q, v10.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v19.16b \n"

        "# First encrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "LD1 {v12.2d-v13.2d}, [%[Key]], #32 \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First encrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v12.16b \n"
        "EOR v27.16b, v27.16b, v13.16b \n"
        "AESE v28.16b, v12.16b \n"
        "EOR v28.16b, v28.16b, v13.16b \n"
        "AESE v29.16b, v12.16b \n"
        "EOR v29.16b, v29.16b, v13.16b \n"
        "AESE v30.16b, v12.16b \n"
        "EOR v30.16b, v30.16b, v13.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v12.16b \n"
        "EOR v27.16b, v27.16b, v13.16b \n"
        "AESE v28.16b, v12.16b \n"
        "EOR v28.16b, v28.16b, v13.16b \n"
        "AESE v29.16b, v12.16b \n"
        "EOR v29.16b, v29.16b, v13.16b \n"
        "AESE v30.16b, v12.16b \n"
        "EOR v30.16b, v30.16b, v13.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"

        "10: \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "# Encrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v31.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"

        "# When only one full block to encrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"

        "# Interweave GHASH and encrypt if more then 1 block \n"
        "2: \n"
        "RBIT v15.16b, v15.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"
        "B 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "MOV x15, #16 \n"
        "EOR w14, w14, w14 \n"
        "SUB x15, x15, x11 \n"
        "25: \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 25b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.2d}, [%[ctr]] \n"
        "ST1 {v22.2d}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v15.d[0], %x[aSz] \n"
        "MOV v15.d[1], %x[sz] \n"
        "REV64 v15.16b, v15.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "ST1 {v0.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, %x[tagSz] \n"
        "44: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[tag]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 44b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "41: \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );
}
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
/* internal function : see wc_AesGcmEncrypt */
static void Aes256GcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    /* Noticed different optimization levels treated head of array different.
     * Some cases was stack pointer plus offset others was a register containing
     * address. To make uniform for passing in to inline assembly code am using
     * pointers to the head of each local array.
     */
    byte* ctr  = counter;
    byte* keyPt = (byte*)aes->key;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Encrypt plaintext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v10.1d, v16.1d \n"
        "PMULL2 v19.1q, v10.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v10.1d, v20.1d \n"
        "PMULL2 v20.1q, v10.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v19.16b \n"

        "# First encrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #192] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #208] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #192] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #208] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v12.16b, v12.16b, v5.16b \n"
        "EOR v13.16b, v13.16b, v6.16b \n"
        "EOR v14.16b, v14.16b, v7.16b \n"
        "EOR v15.16b, v15.16b, v8.16b \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "ST1 {v12.2d-v15.2d}, [%[out]], #64 \n \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v9.1d \n"
        "PMULL2 v3.1q, v15.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v9.1d \n"
        "PMULL2 v15.1q, v15.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v10.1d \n"
        "PMULL2 v3.1q, v14.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v10.1d \n"
        "PMULL2 v14.1q, v14.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v11.1d \n"
        "PMULL2 v3.1q, v13.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v11.1d \n"
        "PMULL2 v13.1q, v13.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v4.1d \n"
        "PMULL2 v3.1q, v12.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v4.1d \n"
        "PMULL2 v12.1q, v12.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "LD1 {v12.2d-v13.2d}, [%[Key]], #32 \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First encrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v12.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v12.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v12.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v12.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"
        "AESE v27.16b, v13.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v13.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v13.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v13.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v14.16b \n"
        "EOR v27.16b, v27.16b, v15.16b \n"
        "AESE v28.16b, v14.16b \n"
        "EOR v28.16b, v28.16b, v15.16b \n"
        "AESE v29.16b, v14.16b \n"
        "EOR v29.16b, v29.16b, v15.16b \n"
        "AESE v30.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v12.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v12.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v12.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v12.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"
        "AESE v27.16b, v13.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v13.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v13.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v13.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v14.16b \n"
        "EOR v27.16b, v27.16b, v15.16b \n"
        "AESE v28.16b, v14.16b \n"
        "EOR v28.16b, v28.16b, v15.16b \n"
        "AESE v29.16b, v14.16b \n"
        "EOR v29.16b, v29.16b, v15.16b \n"
        "AESE v30.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"

        "# XOR in input \n"
        "EOR v18.16b, v18.16b, v27.16b \n"
        "EOR v19.16b, v19.16b, v28.16b \n"
        "EOR v20.16b, v20.16b, v29.16b \n"
        "EOR v21.16b, v21.16b, v30.16b \n"
        "# Store cipher text \n"
        "ST1 {v18.2d-v21.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"

        "10: \n"
        "SUB %[Key], %[Key], #32 \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "# Encrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v31.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]] \n"
        "SUB %[Key], %[Key], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"

        "# When only one full block to encrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"

        "# Interweave GHASH and encrypt if more then 1 block \n"
        "2: \n"
        "RBIT v15.16b, v15.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]] \n"
        "SUB %[Key], %[Key], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[out]], #16 \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "LD1 {v31.2d}, [%[input]], #16 \n"
        "B 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]] \n"
        "SUB %[Key], %[Key], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v15.16b, v0.16b, v31.16b \n \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "MOV x15, #16 \n"
        "EOR w14, w14, w14 \n"
        "SUB x15, x15, x11 \n"
        "25: \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 25b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.2d}, [%[ctr]] \n"
        "ST1 {v22.2d}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v15.d[0], %x[aSz] \n"
        "MOV v15.d[1], %x[sz] \n"
        "REV64 v15.16b, v15.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v12.2d, v13.2d}, [%[Key]] \n"
        "SUB %[Key], %[Key], #32 \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "ST1 {v0.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, %x[tagSz] \n"
        "44: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[tag]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 44b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "41: \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );
}
#endif /* WOLFSSL_AES_256 */

/* aarch64 with PMULL and PMULL2
 * Encrypt and tag data using AES with GCM mode.
 * aes: Aes structure having already been set with set key function
 * out: encrypted data output buffer
 * in:  plain text input buffer
 * sz:  size of plain text and out buffer
 * iv:  initialization vector
 * ivSz:      size of iv buffer
 * authTag:   buffer to hold tag
 * authTagSz: size of tag buffer
 * authIn:    additional data buffer
 * authInSz:  size of additional data buffer
 *
 * Notes:
 * GHASH multiplication based from Algorithm 1 from Intel GCM white paper.
 * "Carry-Less Multiplication and Its Usage for Computing the GCM Mode"
 *
 * GHASH reduction Based from White Paper "Implementing GCM on ARMv8"
 * by Conrado P.L. Gouvea and Julio Lopez reduction on 256bit value using
 * Algorithm 5
 */
void AES_GCM_encrypt_AARCH64(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    switch (aes->rounds) {
#ifdef WOLFSSL_AES_128
        case 10:
            Aes128GcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                authIn, authInSz);
            break;
#endif
#ifdef WOLFSSL_AES_192
        case 12:
            Aes192GcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                 authIn, authInSz);
            break;
#endif
#ifdef WOLFSSL_AES_256
        case 14:
            Aes256GcmEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                authIn, authInSz);
            break;
#endif
    }
}

#ifdef HAVE_AES_DECRYPT
#ifdef WOLFSSL_AES_128
/* internal function : see wc_AesGcmDecrypt */
static int Aes128GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    byte *ctr = counter;
    byte* keyPt = (byte*)aes->key;
    int ret = 0;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Decrypt ciphertext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v9.1d, v16.1d \n"
        "PMULL2 v19.1q, v9.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v9.1d, v20.1d \n"
        "PMULL2 v20.1q, v9.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v19.16b \n"

        "# First decrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First decrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "EOR v27.16b, v27.16b, v11.16b \n"
        "AESE v28.16b, v10.16b \n"
        "EOR v28.16b, v28.16b, v11.16b \n"
        "AESE v29.16b, v10.16b \n"
        "EOR v29.16b, v29.16b, v11.16b \n"
        "AESE v30.16b, v10.16b \n"
        "EOR v30.16b, v30.16b, v11.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "EOR v27.16b, v27.16b, v11.16b \n"
        "AESE v28.16b, v10.16b \n"
        "EOR v28.16b, v28.16b, v11.16b \n"
        "AESE v29.16b, v10.16b \n"
        "EOR v29.16b, v29.16b, v11.16b \n"
        "AESE v30.16b, v10.16b \n"
        "EOR v30.16b, v30.16b, v11.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"

        "10: \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "# Decrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"

        "# When only one full block to decrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "# Interweave GHASH and decrypt if more then 1 block \n"
        "2: \n"
        "RBIT v28.16b, v28.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"
        "CMP w11, #16 \n"
        "BGE 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "RBIT v31.16b, v31.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v31.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "RBIT v31.16b, v31.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "EOR v0.16b, v0.16b, v31.16b \n \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "SUB %[scratch], %[scratch], x11 \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.16b}, [%[ctr]] \n"
        "ST1 {v22.16b}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v28.d[0], %x[aSz] \n"
        "MOV v28.d[1], %x[sz] \n"
        "REV64 v28.16b, v28.16b \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "EOR v0.16b, v0.16b, v11.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "LD1 {v1.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "EOR v1.16b, v1.16b, v1.16b \n"
        "MOV x15, %x[tagSz] \n"
        "ST1 {v1.2d}, [%[scratch]] \n"
        "43: \n"
        "LDRB w14, [%[tag]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 43b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "LD1 {v1.2d}, [%[scratch]] \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV w14, #16 \n"
        "SUB w14, w14, %w[tagSz] \n"
        "ADD %[scratch], %[scratch], %x[tagSz] \n"
        "44: \n"
        "STRB wzr, [%[scratch]], #1 \n"
        "SUB w14, w14, #1 \n"
        "CBNZ w14, 44b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v0.2d}, [%[scratch]] \n"
        "41: \n"
        "EOR v0.16b, v0.16b, v1.16b \n"
        "MOV v1.D[0], v0.D[1] \n"
        "EOR v0.8b, v0.8b, v1.8b \n"
        "MOV %x[ret], v0.D[0] \n"
        "CMP %x[ret], #0 \n"
        "MOV w11, #-180 \n"
        "CSETM %w[ret], ne \n"
        "AND %w[ret], %w[ret], w11 \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn),
          [ret] "+r" (ret)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return ret;
}
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
/* internal function : see wc_AesGcmDecrypt */
static int Aes192GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    byte *ctr = counter;
    byte* keyPt = (byte*)aes->key;
    int ret = 0;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Decrypt ciphertext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v9.1d, v16.1d \n"
        "PMULL2 v19.1q, v9.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v9.1d, v20.1d \n"
        "PMULL2 v20.1q, v9.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v19.16b \n"

        "# First decrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "LD1 {v12.2d-v13.2d}, [%[Key]], #32 \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First decrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v12.16b \n"
        "EOR v27.16b, v27.16b, v13.16b \n"
        "AESE v28.16b, v12.16b \n"
        "EOR v28.16b, v28.16b, v13.16b \n"
        "AESE v29.16b, v12.16b \n"
        "EOR v29.16b, v29.16b, v13.16b \n"
        "AESE v30.16b, v12.16b \n"
        "EOR v30.16b, v30.16b, v13.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v12.16b \n"
        "EOR v27.16b, v27.16b, v13.16b \n"
        "AESE v28.16b, v12.16b \n"
        "EOR v28.16b, v28.16b, v13.16b \n"
        "AESE v29.16b, v12.16b \n"
        "EOR v29.16b, v29.16b, v13.16b \n"
        "AESE v30.16b, v12.16b \n"
        "EOR v30.16b, v30.16b, v13.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"

        "10: \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "# Decrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"

        "# When only one full block to decrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "# Interweave GHASH and decrypt if more then 1 block \n"
        "2: \n"
        "RBIT v28.16b, v28.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"
        "CMP w11, #16 \n"
        "BGE 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "RBIT v31.16b, v31.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v31.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "RBIT v31.16b, v31.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "EOR v0.16b, v0.16b, v31.16b \n \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "SUB %[scratch], %[scratch], x11 \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.16b}, [%[ctr]] \n"
        "ST1 {v22.16b}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v28.d[0], %x[aSz] \n"
        "MOV v28.d[1], %x[sz] \n"
        "REV64 v28.16b, v28.16b \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "EOR v0.16b, v0.16b, v13.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "LD1 {v1.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "EOR v1.16b, v1.16b, v1.16b \n"
        "MOV x15, %x[tagSz] \n"
        "ST1 {v1.2d}, [%[scratch]] \n"
        "43: \n"
        "LDRB w14, [%[tag]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 43b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "LD1 {v1.2d}, [%[scratch]] \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV w14, #16 \n"
        "SUB w14, w14, %w[tagSz] \n"
        "ADD %[scratch], %[scratch], %x[tagSz] \n"
        "44: \n"
        "STRB wzr, [%[scratch]], #1 \n"
        "SUB w14, w14, #1 \n"
        "CBNZ w14, 44b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v0.2d}, [%[scratch]] \n"
        "41: \n"
        "EOR v0.16b, v0.16b, v1.16b \n"
        "MOV v1.D[0], v0.D[1] \n"
        "EOR v0.8b, v0.8b, v1.8b \n"
        "MOV %x[ret], v0.D[0] \n"
        "CMP %x[ret], #0 \n"
        "MOV w11, #-180 \n"
        "CSETM %w[ret], ne \n"
        "AND %w[ret], %w[ret], w11 \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn),
          [ret] "+r" (ret)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return ret;
}
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
/* internal function : see wc_AesGcmDecrypt */
static int Aes256GcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    byte counter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    byte *ctr = counter;
    byte* keyPt = (byte*)aes->key;
    int ret = 0;

    XMEMSET(counter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(counter, iv, GCM_NONCE_MID_SZ);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    }

    __asm__ __volatile__ (
        "LD1 {v16.16b}, %[h] \n"
        "# v23 = 0x00000000000000870000000000000087 reflected 0xe1.... \n"
        "MOVI v23.16b, #0x87 \n"
        "EOR v17.16b, v17.16b, v17.16b \n"
        "USHR v23.2d, v23.2d, #56 \n"
        "CBZ %w[aSz], 120f \n"

        "MOV w12, %w[aSz] \n"

        "# GHASH AAD \n"
        "CMP x12, #64 \n"
        "BLT 115f \n"
        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "114: \n"
        "LD1 {v18.2d-v21.2d}, [%[aad]], #64 \n"
        "SUB x12, x12, #64 \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v30.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v30.16b, #8 \n"
        "PMULL2 v14.1q, v30.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "CMP x12, #64 \n"
        "BGE 114b \n"
        "CBZ x12, 120f \n"
        "115: \n"
        "CMP x12, #16 \n"
        "BLT 112f \n"
        "111: \n"
        "LD1 {v15.2d}, [%[aad]], #16 \n"
        "SUB x12, x12, #16 \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "CMP x12, #16 \n"
        "BGE 111b \n"
        "CBZ x12, 120f \n"
        "112: \n"
        "# Partial AAD \n"
        "EOR v15.16b, v15.16b, v15.16b \n"
        "MOV x14, x12 \n"
        "ST1 {v15.2d}, [%[scratch]] \n"
        "113: \n"
        "LDRB w13, [%[aad]], #1 \n"
        "STRB w13, [%[scratch]], #1 \n"
        "SUB x14, x14, #1 \n"
        "CBNZ x14, 113b \n"
        "SUB %[scratch], %[scratch], x12 \n"
        "LD1 {v15.2d}, [%[scratch]] \n"
        "RBIT v15.16b, v15.16b \n"
        "EOR v17.16b, v17.16b, v15.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "120: \n"

        "# Decrypt ciphertext and GHASH ciphertext \n"
        "LDR w12, [%[ctr], #12] \n"
        "MOV w11, %w[sz] \n"
        "REV w12, w12 \n"
        "CMP w11, #64 \n"
        "BLT 80f \n"
        "CMP %w[aSz], #64 \n"
        "BGE 82f \n"

        "# Calculate H^[1-4] - GMULT partials \n"
        "# Square H => H^2 \n"
        "PMULL2 v19.1q, v16.2d, v16.2d \n"
        "PMULL  v18.1q, v16.1d, v16.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v24.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^2 => H^3 \n"
        "PMULL  v18.1q, v24.1d, v16.1d \n"
        "PMULL2 v19.1q, v24.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v24.1d, v20.1d \n"
        "PMULL2 v20.1q, v24.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v25.16b, v18.16b, v20.16b \n"
        "# Square H^2 => H^4 \n"
        "PMULL2 v19.1q, v24.2d, v24.2d \n"
        "PMULL  v18.1q, v24.1d, v24.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v26.16b, v18.16b, v19.16b \n"
        "82: \n"
        "# Should we do 8 blocks at a time? \n"
        "CMP w11, #512 \n"
        "BLT 80f \n"

        "# Calculate H^[5-8] - GMULT partials \n"
        "# Multiply H and H^4 => H^5 \n"
        "PMULL  v18.1q, v26.1d, v16.1d \n"
        "PMULL2 v19.1q, v26.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v26.1d, v20.1d \n"
        "PMULL2 v20.1q, v26.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v4.16b, v18.16b, v20.16b \n"
        "# Square H^3 - H^6 \n"
        "PMULL2 v19.1q, v25.2d, v25.2d \n"
        "PMULL  v18.1q, v25.1d, v25.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v9.16b, v18.16b, v19.16b \n"
        "# Multiply H and H^6 => H^7 \n"
        "PMULL  v18.1q, v9.1d, v16.1d \n"
        "PMULL2 v19.1q, v9.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v9.1d, v20.1d \n"
        "PMULL2 v20.1q, v9.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v10.16b, v18.16b, v20.16b \n"
        "# Square H^4 => H^8 \n"
        "PMULL2 v19.1q, v26.2d, v26.2d \n"
        "PMULL  v18.1q, v26.1d, v26.1d \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v19.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v11.16b, v18.16b, v19.16b \n"

        "# First decrypt - no GHASH \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #192] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #208] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "81: \n"
        "LDR q1, [%[Key]] \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "LD1 {v5.2d}, [%[ctr]] \n"
        "ADD w14, w12, #2 \n"
        "MOV v6.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v7.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v8.16b, v5.16b \n"
        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w15, w15 \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "REV w13, w13 \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "REV w16, w12 \n"
        "MOV v5.S[3], w15 \n"
        "MOV v6.S[3], w14 \n"
        "MOV v7.S[3], w13 \n"
        "MOV v8.S[3], w16 \n"
        "# Calculate next 4 counters (+5-8) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v5.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v5.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v5.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v5.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "REV w15, w15 \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "REV w14, w14 \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "REV w13, w13 \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 8 counters \n"
        "LDR q22, [%[Key], #16] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "LDR q1, [%[Key], #32] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "LDR q22, [%[Key], #48] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "LDR q1, [%[Key], #64] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
        "LDR q22, [%[Key], #80] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #128 \n"
        "LDR q1, [%[Key], #96] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #112] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #128] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #144] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #160] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q22, [%[Key], #176] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LDR q1, [%[Key], #192] \n"
        "AESE v5.16b, v22.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v22.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v22.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v22.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v22.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v22.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v22.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v22.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v12.2d-v15.2d}, [%[input]], #64 \n"
        "LDP q22, q31, [%[Key], #208] \n"
        "AESE v5.16b, v1.16b \n"
        "AESMC v5.16b, v5.16b \n"
        "AESE v6.16b, v1.16b \n"
        "AESMC v6.16b, v6.16b \n"
        "AESE v7.16b, v1.16b \n"
        "AESMC v7.16b, v7.16b \n"
        "AESE v8.16b, v1.16b \n"
        "AESMC v8.16b, v8.16b \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v5.16b, v22.16b \n"
        "EOR v5.16b, v5.16b, v31.16b \n"
        "AESE v6.16b, v22.16b \n"
        "EOR v6.16b, v6.16b, v31.16b \n"
        "AESE v7.16b, v22.16b \n"
        "EOR v7.16b, v7.16b, v31.16b \n"
        "AESE v8.16b, v22.16b \n"
        "EOR v8.16b, v8.16b, v31.16b \n"
        "AESE v27.16b, v22.16b \n"
        "EOR v27.16b, v27.16b, v31.16b \n"
        "AESE v28.16b, v22.16b \n"
        "EOR v28.16b, v28.16b, v31.16b \n"
        "AESE v29.16b, v22.16b \n"
        "EOR v29.16b, v29.16b, v31.16b \n"
        "AESE v30.16b, v22.16b \n"
        "EOR v30.16b, v30.16b, v31.16b \n"

        "# XOR in input \n"
        "EOR v5.16b, v5.16b, v12.16b \n"
        "EOR v6.16b, v6.16b, v13.16b \n"
        "EOR v7.16b, v7.16b, v14.16b \n"
        "EOR v8.16b, v8.16b, v15.16b \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "ST1 {v5.2d-v8.2d}, [%[out]], #64 \n \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"

        "CMP w11, #128 \n"
        "BGE 81b \n"

        "# GHASH - 8 blocks \n"
        "RBIT v12.16b, v12.16b \n"
        "RBIT v13.16b, v13.16b \n"
        "RBIT v14.16b, v14.16b \n"
        "RBIT v15.16b, v15.16b \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v12.16b, v12.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v3.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v3.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v2.1q, v20.1d, v24.1d \n"
        "PMULL2 v3.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v3.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v3.16b \n"
#else
        "EOR v20.16b, v20.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v2.1q, v19.1d, v25.1d \n"
        "PMULL2 v3.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v3.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v3.16b \n"
#else
        "EOR v19.16b, v19.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v2.1q, v18.1d, v26.1d \n"
        "PMULL2 v3.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v3.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v3.16b \n"
#else
        "EOR v18.16b, v18.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^5 \n"
        "PMULL  v2.1q, v15.1d, v4.1d \n"
        "PMULL2 v3.1q, v15.2d, v4.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v15.16b, v15.16b, v15.16b, #8 \n"
        "PMULL  v3.1q, v15.1d, v4.1d \n"
        "PMULL2 v15.1q, v15.2d, v4.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v15.16b, v3.16b \n"
#else
        "EOR v15.16b, v15.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^6 \n"
        "PMULL  v2.1q, v14.1d, v9.1d \n"
        "PMULL2 v3.1q, v14.2d, v9.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v14.16b, v14.16b, v14.16b, #8 \n"
        "PMULL  v3.1q, v14.1d, v9.1d \n"
        "PMULL2 v14.1q, v14.2d, v9.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v14.16b, v3.16b \n"
#else
        "EOR v14.16b, v14.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^7 \n"
        "PMULL  v2.1q, v13.1d, v10.1d \n"
        "PMULL2 v3.1q, v13.2d, v10.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v13.16b, v13.16b, v13.16b, #8 \n"
        "PMULL  v3.1q, v13.1d, v10.1d \n"
        "PMULL2 v13.1q, v13.2d, v10.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v13.16b, v3.16b \n"
#else
        "EOR v13.16b, v13.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v13.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^8 \n"
        "PMULL  v2.1q, v12.1d, v11.1d \n"
        "PMULL2 v3.1q, v12.2d, v11.2d \n"
        "EOR v17.16b, v17.16b, v2.16b \n"
        "EOR v0.16b, v0.16b, v3.16b \n"
        "EXT v12.16b, v12.16b, v12.16b, #8 \n"
        "PMULL  v3.1q, v12.1d, v11.1d \n"
        "PMULL2 v12.1q, v12.2d, v11.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v12.16b, v3.16b \n"
#else
        "EOR v12.16b, v12.16b, v3.16b \n"
        "EOR v31.16b, v31.16b, v12.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v3.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v2.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v3.16b, v3.16b, v31.16b, v2.16b \n"
#else
        "EOR v3.16b, v3.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v3.16b, v3.16b, v2.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v2.1q, v3.2d, v23.2d \n"
        "MOV v17.D[1], v3.D[0] \n"
        "EOR v17.16b, v17.16b, v2.16b \n"

        "80: \n"
        "LD1 {v22.2d}, [%[ctr]] \n"
        "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"
        "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
        "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
        "LD1 {v12.2d-v13.2d}, [%[Key]], #32 \n"
        "LD1 {v14.2d-v15.2d}, [%[Key]] \n"
        "# Can we do 4 blocks at a time? \n"
        "CMP w11, #64 \n"
        "BLT 10f \n"

        "# First decrypt - no GHASH \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "REV w15, w15 \n"
        "REV w14, w14 \n"
        "REV w13, w13 \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v12.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v12.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v12.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v12.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"
        "AESE v27.16b, v13.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v13.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v13.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v13.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v14.16b \n"
        "EOR v27.16b, v27.16b, v15.16b \n"
        "AESE v28.16b, v14.16b \n"
        "EOR v28.16b, v28.16b, v15.16b \n"
        "AESE v29.16b, v14.16b \n"
        "EOR v29.16b, v29.16b, v15.16b \n"
        "AESE v30.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BLT 12f \n"

        "11: \n"
        "# Calculate next 4 counters (+1-4) \n"
        "ADD w15, w12, #1 \n"
        "MOV v27.16b, v22.16b \n"
        "ADD w14, w12, #2 \n"
        "MOV v28.16b, v22.16b \n"
        "ADD w13, w12, #3 \n"
        "MOV v29.16b, v22.16b \n"
        "ADD w12, w12, #4 \n"
        "MOV v30.16b, v22.16b \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "REV w15, w15 \n"
        "RBIT v19.16b, v19.16b \n"
        "REV w14, w14 \n"
        "RBIT v20.16b, v20.16b \n"
        "REV w13, w13 \n"
        "RBIT v21.16b, v21.16b \n"
        "REV w16, w12 \n"
        "MOV v27.S[3], w15 \n"
        "MOV v28.S[3], w14 \n"
        "MOV v29.S[3], w13 \n"
        "MOV v30.S[3], w16 \n"

        "# Encrypt 4 counters \n"
        "AESE v27.16b, v1.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "AESE v28.16b, v1.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "AESE v29.16b, v1.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "AESE v30.16b, v1.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "AESE v27.16b, v2.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "AESE v28.16b, v2.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "AESE v29.16b, v2.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v30.16b, v2.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "AESE v27.16b, v3.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
        "AESE v28.16b, v3.16b \n"
        "AESMC v28.16b, v28.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v29.16b, v3.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "AESE v30.16b, v3.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v27.16b, v4.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "AESE v28.16b, v4.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
        "AESE v29.16b, v4.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v4.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "AESE v27.16b, v5.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "AESE v28.16b, v5.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "AESE v29.16b, v5.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
        "AESE v30.16b, v5.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "SUB w11, w11, #64 \n"
        "AESE v27.16b, v6.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "AESE v28.16b, v6.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
        "AESE v29.16b, v6.16b \n"
        "AESMC v29.16b, v29.16b \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v30.16b, v6.16b \n"
        "AESMC v30.16b, v30.16b \n"
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "AESE v27.16b, v7.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "AESE v28.16b, v7.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "AESE v29.16b, v7.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v7.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v8.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v8.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v8.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v8.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v9.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v9.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v9.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v9.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v10.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v10.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v10.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v10.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v11.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v11.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v11.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v11.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "# Load plaintext \n"
        "LD1 {v18.2d-v21.2d}, [%[input]], #64 \n"
        "AESE v27.16b, v12.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v12.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v12.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v12.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"
        "AESE v27.16b, v13.16b \n"
        "AESMC v27.16b, v27.16b \n"
        "AESE v28.16b, v13.16b \n"
        "AESMC v28.16b, v28.16b \n"
        "AESE v29.16b, v13.16b \n"
        "AESMC v29.16b, v29.16b \n"
        "AESE v30.16b, v13.16b \n"
        "AESMC v30.16b, v30.16b \n"
        "AESE v27.16b, v14.16b \n"
        "EOR v27.16b, v27.16b, v15.16b \n"
        "AESE v28.16b, v14.16b \n"
        "EOR v28.16b, v28.16b, v15.16b \n"
        "AESE v29.16b, v14.16b \n"
        "EOR v29.16b, v29.16b, v15.16b \n"
        "AESE v30.16b, v14.16b \n"
        "EOR v30.16b, v30.16b, v15.16b \n"

        "# XOR in input \n"
        "EOR v27.16b, v27.16b, v18.16b \n"
        "EOR v28.16b, v28.16b, v19.16b \n"
        "EOR v29.16b, v29.16b, v20.16b \n"
        "EOR v30.16b, v30.16b, v21.16b \n"
        "# Store cipher text \n"
        "ST1 {v27.2d-v30.2d}, [%[out]], #64 \n \n"
        "CMP w11, #64 \n"
        "BGE 11b \n"

        "12: \n"
        "# GHASH - 4 blocks \n"
        "RBIT v18.16b, v18.16b \n"
        "RBIT v19.16b, v19.16b \n"
        "RBIT v20.16b, v20.16b \n"
        "RBIT v21.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v17.16b \n"
        "# x[0-2] = C * H^1 \n"
        "PMULL  v17.1q, v21.1d, v16.1d \n"
        "PMULL2 v0.1q, v21.2d, v16.2d \n"
        "EXT v21.16b, v21.16b, v21.16b, #8 \n"
        "PMULL  v31.1q, v21.1d, v16.1d \n"
        "PMULL2 v15.1q, v21.2d, v16.2d \n"
        "EOR v31.16b, v31.16b, v15.16b \n"
        "# x[0-2] += C * H^2 \n"
        "PMULL  v14.1q, v20.1d, v24.1d \n"
        "PMULL2 v15.1q, v20.2d, v24.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v20.16b, v20.16b, v20.16b, #8 \n"
        "PMULL  v15.1q, v20.1d, v24.1d \n"
        "PMULL2 v20.1q, v20.2d, v24.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v20.16b, v15.16b \n"
#else
        "EOR v20.16b, v20.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v20.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^3 \n"
        "PMULL  v14.1q, v19.1d, v25.1d \n"
        "PMULL2 v15.1q, v19.2d, v25.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v19.16b, v19.16b, v19.16b, #8 \n"
        "PMULL  v15.1q, v19.1d, v25.1d \n"
        "PMULL2 v19.1q, v19.2d, v25.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v19.16b, v15.16b \n"
#else
        "EOR v19.16b, v19.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v19.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# x[0-2] += C * H^4 \n"
        "PMULL  v14.1q, v18.1d, v26.1d \n"
        "PMULL2 v15.1q, v18.2d, v26.2d \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n"
        "EXT v18.16b, v18.16b, v18.16b, #8 \n"
        "PMULL  v15.1q, v18.1d, v26.1d \n"
        "PMULL2 v18.1q, v18.2d, v26.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v31.16b, v31.16b, v18.16b, v15.16b \n"
#else
        "EOR v18.16b, v18.16b, v15.16b \n"
        "EOR v31.16b, v31.16b, v18.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "# Reduce X = x[0-2] \n"
        "EXT v15.16b, v17.16b, v0.16b, #8 \n"
        "PMULL2 v14.1q, v0.2d, v23.2d \n"
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR3 v15.16b, v15.16b, v31.16b, v14.16b \n"
#else
        "EOR v15.16b, v15.16b, v31.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef WOLFSSL_ARMASM_CRYPTO_SHA3
        "EOR v15.16b, v15.16b, v14.16b \n"
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
        "PMULL2 v14.1q, v15.2d, v23.2d \n"
        "MOV v17.D[1], v15.D[0] \n"
        "EOR v17.16b, v17.16b, v14.16b \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"

        "10: \n"
        "CBZ w11, 30f \n"
        "CMP w11, #16 \n"
        "BLT 20f \n"
        "LD1 {v14.2d, v15.2d}, [%[Key]] \n"
        "# Decrypt first block for GHASH \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"

        "# When only one full block to decrypt go straight to GHASH \n"
        "CMP w11, 16 \n"
        "BLT 1f \n"

        "# Interweave GHASH and decrypt if more then 1 block \n"
        "2: \n"
        "RBIT v28.16b, v28.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "SUB w11, w11, #16 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "LD1 {v28.2d}, [%[input]], #16 \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n \n"
        "EOR v0.16b, v0.16b, v28.16b \n \n"
        "ST1 {v0.2d}, [%[out]], #16 \n"
        "CMP w11, #16 \n"
        "BGE 2b \n"

        "# GHASH on last block \n"
        "1: \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "MOV v18.D[1], v21.D[0] \n"
        "EOR v17.16b, v18.16b, v20.16b \n"

        "20: \n"
        "CBZ w11, 30f \n"
        "EOR v31.16b, v31.16b, v31.16b \n"
        "MOV x15, x11 \n"
        "ST1 {v31.2d}, [%[scratch]] \n"
        "23: \n"
        "LDRB w14, [%[input]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 23b \n"
        "SUB %[scratch], %[scratch], x11 \n"
        "LD1 {v31.2d}, [%[scratch]] \n"
        "RBIT v31.16b, v31.16b \n"
        "ADD w12, w12, #1 \n"
        "MOV v0.16b, v22.16b \n"
        "REV w13, w12 \n"
        "MOV v0.S[3], w13 \n"
        "EOR v17.16b, v17.16b, v31.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "RBIT v31.16b, v31.16b \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n \n"
        "EOR v0.16b, v0.16b, v31.16b \n \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV x15, x11 \n"
        "24: \n"
        "LDRB w14, [%[scratch]], #1 \n"
        "STRB w14, [%[out]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 24b \n"
        "SUB %[scratch], %[scratch], x11 \n"

        "30: \n"
        "# store current counter value at the end \n"
        "REV w13, w12 \n"
        "MOV v22.S[3], w13 \n"
        "LD1 {v0.16b}, [%[ctr]] \n"
        "ST1 {v22.16b}, [%[ctr]] \n"

        "LSL %x[aSz], %x[aSz], #3 \n"
        "LSL %x[sz], %x[sz], #3 \n"
        "MOV v28.d[0], %x[aSz] \n"
        "MOV v28.d[1], %x[sz] \n"
        "REV64 v28.16b, v28.16b \n"
        "RBIT v28.16b, v28.16b \n"
        "EOR v17.16b, v17.16b, v28.16b \n"
        "PMULL  v18.1q, v17.1d, v16.1d \n"
        "PMULL2 v19.1q, v17.2d, v16.2d \n"
        "EXT v20.16b, v16.16b, v16.16b, #8 \n"
        "AESE v0.16b, v1.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL  v21.1q, v17.1d, v20.1d \n"
        "PMULL2 v20.1q, v17.2d, v20.2d \n"
        "AESE v0.16b, v2.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v20.16b, v20.16b, v21.16b \n"
        "AESE v0.16b, v3.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EXT v21.16b, v18.16b, v19.16b, #8 \n"
        "AESE v0.16b, v4.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v5.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "# Reduce \n"
        "PMULL2 v20.1q, v19.2d, v23.2d \n"
        "AESE v0.16b, v6.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v21.16b, v21.16b, v20.16b \n"
        "AESE v0.16b, v7.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "PMULL2 v20.1q, v21.2d, v23.2d \n"
        "AESE v0.16b, v8.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "MOV v18.D[1], v21.D[0] \n"
        "AESE v0.16b, v9.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "EOR v17.16b, v18.16b, v20.16b \n"
        "AESE v0.16b, v10.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v11.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v12.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v13.16b \n"
        "AESMC v0.16b, v0.16b \n"
        "AESE v0.16b, v14.16b \n"
        "EOR v0.16b, v0.16b, v15.16b \n \n"
        "RBIT v17.16b, v17.16b \n"
        "EOR v0.16b, v0.16b, v17.16b \n \n"
        "CMP %w[tagSz], #16 \n"
        "BNE 40f \n"
        "LD1 {v1.2d}, [%[tag]] \n"
        "B 41f \n"
        "40: \n"
        "EOR v1.16b, v1.16b, v1.16b \n"
        "MOV x15, %x[tagSz] \n"
        "ST1 {v1.2d}, [%[scratch]] \n"
        "43: \n"
        "LDRB w14, [%[tag]], #1 \n"
        "STRB w14, [%[scratch]], #1 \n"
        "SUB x15, x15, #1 \n"
        "CBNZ x15, 43b \n"
        "SUB %[scratch], %[scratch], %x[tagSz] \n"
        "LD1 {v1.2d}, [%[scratch]] \n"
        "ST1 {v0.2d}, [%[scratch]] \n"
        "MOV w14, #16 \n"
        "SUB w14, w14, %w[tagSz] \n"
        "ADD %[scratch], %[scratch], %x[tagSz] \n"
        "44: \n"
        "STRB wzr, [%[scratch]], #1 \n"
        "SUB w14, w14, #1 \n"
        "CBNZ w14, 44b \n"
        "SUB %[scratch], %[scratch], #16 \n"
        "LD1 {v0.2d}, [%[scratch]] \n"
        "41: \n"
        "EOR v0.16b, v0.16b, v1.16b \n"
        "MOV v1.D[0], v0.D[1] \n"
        "EOR v0.8b, v0.8b, v1.8b \n"
        "MOV %x[ret], v0.D[0] \n"
        "CMP %x[ret], #0 \n"
        "MOV w11, #-180 \n"
        "CSETM %w[ret], ne \n"
        "AND %w[ret], %w[ret], w11 \n"

        : [out] "+r" (out), [input] "+r" (in), [Key] "+r" (keyPt),
          [aSz] "+r" (authInSz), [sz] "+r" (sz), [aad] "+r" (authIn),
          [ret] "+r" (ret)
        : [ctr] "r" (ctr), [scratch] "r" (scratch),
          [h] "m" (aes->gcm.H), [tag] "r" (authTag), [tagSz] "r" (authTagSz)
        : "cc", "memory", "x11", "x12", "w13", "x14", "x15", "w16",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
          "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return ret;
}
#endif /* WOLFSSL_AES_256 */
/*
 * Check tag and decrypt data using AES with GCM mode.
 * aes: Aes structure having already been set with set key function
 * out: decrypted data output buffer
 * in:  cipher text buffer
 * sz:  size of plain text and out buffer
 * iv:  initialization vector
 * ivSz:      size of iv buffer
 * authTag:   buffer holding tag
 * authTagSz: size of tag buffer
 * authIn:    additional data buffer
 * authInSz:  size of additional data buffer
 */
int AES_GCM_decrypt_AARCH64(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    /* sanity checks */
    switch (aes->rounds) {
#ifdef WOLFSSL_AES_128
        case 10:
            return Aes128GcmDecrypt(aes, out, in, sz, iv, ivSz, authTag,
                authTagSz, authIn, authInSz);
#endif
#ifdef WOLFSSL_AES_192
        case 12:
            return Aes192GcmDecrypt(aes, out, in, sz, iv, ivSz, authTag,
                authTagSz, authIn, authInSz);
#endif
#ifdef WOLFSSL_AES_256
        case 14:
            return Aes256GcmDecrypt(aes, out, in, sz, iv, ivSz, authTag,
                authTagSz, authIn, authInSz);
#endif
    }

    return BAD_FUNC_ARG;
}

#endif /* HAVE_AES_DECRYPT */

/* END script replace AES-GCM Aarch64 with hardware crypto. */

#endif /* HAVE_AESGCM */


/***************************************
 * not 64 bit so use 32 bit mode
****************************************/
#else

/* AES CCM/GCM use encrypt direct but not decrypt */
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
    static int wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
    {
            /*
              AESE exor's input with round key
                   shift rows of exor'ed result
                   sub bytes for shifted rows
             */

            word32* keyPt = aes->key;
            __asm__ __volatile__ (
                "VLD1.32 {q0}, [%[CtrIn]] \n"
                "VLDM %[Key]!, {q1-q4}    \n"

                "AESE.8 q0, q1\n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESE.8 q0, q3\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESE.8 q0, q4\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "AESE.8 q0, q1\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "AESE.8 q0, q2\n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q3\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESE.8 q0, q4\n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESE.8 q0, q1\n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2\n"

                "MOV r12, %[R]    \n"
                "CMP r12, #10 \n"
                "BEQ 1f    \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESE.8 q0, q1\n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2\n"

                "CMP r12, #12 \n"
                "BEQ 1f    \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESE.8 q0, q1\n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2\n"

                "#Final AddRoundKey then store result \n"
                "1: \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VEOR.32 q0, q0, q1\n"
                "VST1.32 {q0}, [%[CtrOut]]   \n"

                :[CtrOut] "=r" (outBlock), "=r" (keyPt), "=r" (aes->rounds),
                 "=r" (inBlock)
                :"0" (outBlock), [Key] "1" (keyPt), [R] "2" (aes->rounds),
                 [CtrIn] "3" (inBlock)
                : "cc", "memory", "r12", "q0", "q1", "q2", "q3", "q4"
            );

        return 0;
    }
#endif /* AES_GCM, AES_CCM, DIRECT or COUNTER */
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
    #ifdef HAVE_AES_DECRYPT
    static int wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
    {
            /*
              AESE exor's input with round key
                   shift rows of exor'ed result
                   sub bytes for shifted rows
             */

            word32* keyPt = aes->key;
            __asm__ __volatile__ (
                "VLD1.32 {q0}, [%[CtrIn]] \n"
                "VLDM %[Key]!, {q1-q4}    \n"

                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESD.8 q0, q3\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESD.8 q0, q4\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "AESD.8 q0, q2\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q3\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESD.8 q0, q4\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"

                "MOV r12, %[R] \n"
                "CMP r12, #10  \n"
                "BEQ 1f \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"

                "CMP r12, #12  \n"
                "BEQ 1f \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"

                "#Final AddRoundKey then store result \n"
                "1: \n"
                "VLD1.32 {q1}, [%[Key]]! \n"
                "VEOR.32 q0, q0, q1\n"
                "VST1.32 {q0}, [%[CtrOut]]    \n"

                :[CtrOut] "=r" (outBlock), "=r" (keyPt), "=r" (aes->rounds),
                 "=r" (inBlock)
                :"0" (outBlock), [Key] "1" (keyPt), [R] "2" (aes->rounds),
                 [CtrIn] "3" (inBlock)
                : "cc", "memory", "r12", "q0", "q1", "q2", "q3", "q4"
            );

        return 0;
}
    #endif /* HAVE_AES_DECRYPT */
#endif /* DIRECT or COUNTER */

/* AES-CBC */
#ifdef HAVE_AES_CBC
    int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 numBlocks = sz / WC_AES_BLOCK_SIZE;

        if (aes == NULL || out == NULL || in == NULL) {
            return BAD_FUNC_ARG;
        }

        if (sz == 0) {
            return 0;
        }

#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        if (sz % WC_AES_BLOCK_SIZE) {
            return BAD_LENGTH_E;
        }
#endif

        /* do as many block size ops as possible */
        if (numBlocks > 0) {
            word32* keyPt = aes->key;
            word32* regPt = aes->reg;
            /*
            AESE exor's input with round key
            shift rows of exor'ed result
            sub bytes for shifted rows

            note: grouping AESE & AESMC together as pairs reduces latency
            */
            switch(aes->rounds) {
#ifdef WOLFSSL_AES_128
            case 10: /* AES 128 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q0}, [%[reg]]   \n"
                "VLD1.32 {q12}, [%[input]]!\n"

                "1:\n"
                "#CBC operations, xorbuf in with current aes->reg \n"
                "VEOR.32 q0, q0, q12 \n"
                "AESE.8 q0, q1 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q3 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q4 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q5 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q6 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q7 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q8 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q9 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q10\n"
                "VEOR.32 q0, q0, q11 \n"
                "SUB r11, r11, #1    \n"
                "VST1.32 {q0}, [%[out]]!   \n"

                "CMP r11, #0   \n"
                "BEQ 2f \n"
                "VLD1.32 {q12}, [%[input]]! \n"
                "B 1b \n"

                "2:\n"
                "#store current counter value at the end \n"
                "VST1.32 {q0}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt)
                :"0" (out), [Key] "r" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12"
                );
                break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
            case 12: /* AES 192 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q0}, [%[reg]]   \n"
                "VLD1.32 {q12}, [%[input]]!\n"
                "VLD1.32 {q13}, [%[Key]]!  \n"
                "VLD1.32 {q14}, [%[Key]]!  \n"

                "1:\n"
                "#CBC operations, xorbuf in with current aes->reg \n"
                "VEOR.32 q0, q0, q12 \n"
                "AESE.8 q0, q1 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q3 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q4 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q5 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q6 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q7 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q8 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q9 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q10 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q11 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q13\n"
                "VEOR.32 q0, q0, q14 \n"
                "SUB r11, r11, #1    \n"
                "VST1.32 {q0}, [%[out]]!   \n"

                "CMP r11, #0   \n"
                "BEQ 2f \n"
                "VLD1.32 {q12}, [%[input]]! \n"
                "B 1b \n"

                "2:\n"
                "#store current counter qalue at the end \n"
                "VST1.32 {q0}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt)
                :"0" (out), [Key] "r" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14"
                );
                break;
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
            case 14: /* AES 256 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q0}, [%[reg]]   \n"
                "VLD1.32 {q12}, [%[input]]!\n"
                "VLD1.32 {q13}, [%[Key]]!  \n"
                "VLD1.32 {q14}, [%[Key]]!  \n"

                "1:\n"
                "#CBC operations, xorbuf in with current aes->reg \n"
                "VEOR.32 q0, q0, q12 \n"
                "AESE.8 q0, q1 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q2 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q3 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q4 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q5 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q6 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q7 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q8 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q9 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q10 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q11 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q13 \n"
                "AESMC.8 q0, q0\n"
                "VLD1.32 {q15}, [%[Key]]!  \n"
                "AESE.8 q0, q14 \n"
                "AESMC.8 q0, q0\n"
                "AESE.8 q0, q15\n"
                "VLD1.32 {q15}, [%[Key]]   \n"
                "VEOR.32 q0, q0, q15 \n"
                "SUB r11, r11, #1    \n"
                "VST1.32 {q0}, [%[out]]!   \n"
                "SUB %[Key], %[Key], #16   \n"

                "CMP r11, #0   \n"
                "BEQ 2f \n"
                "VLD1.32 {q12}, [%[input]]! \n"
                "B 1b \n"

                "2:\n"
                "#store current counter qalue at the end \n"
                "VST1.32 {q0}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt), "=r" (keyPt)
                :"0" (out), [Key] "2" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15"
                );
                break;
#endif /* WOLFSSL_AES_256 */
            default:
                WOLFSSL_MSG("Bad AES-CBC round value");
                return BAD_FUNC_ARG;
            }
        }

        return 0;
    }

    #ifdef HAVE_AES_DECRYPT
    int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 numBlocks = sz / WC_AES_BLOCK_SIZE;

        if (aes == NULL || out == NULL || in == NULL) {
            return BAD_FUNC_ARG;
        }

        if (sz == 0) {
            return 0;
        }

        if (sz % WC_AES_BLOCK_SIZE) {
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
            return BAD_LENGTH_E;
#else
            return BAD_FUNC_ARG;
#endif
        }

        /* do as many block size ops as possible */
        if (numBlocks > 0) {
            word32* keyPt = aes->key;
            word32* regPt = aes->reg;
            switch(aes->rounds) {
#ifdef WOLFSSL_AES_128
            case 10: /* AES 128 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q13}, [%[reg]]  \n"
                "VLD1.32 {q0}, [%[input]]!\n"

                "1:\n"
                "VMOV.32 q12, q0 \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q3\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q4\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q5\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q6\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q7\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q8\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q9\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q10\n"
                "VEOR.32 q0, q0, q11\n"

                "VEOR.32 q0, q0, q13\n"
                "SUB r11, r11, #1            \n"
                "VST1.32 {q0}, [%[out]]!  \n"
                "VMOV.32 q13, q12        \n"

                "CMP r11, #0 \n"
                "BEQ 2f \n"
                "VLD1.32 {q0}, [%[input]]!  \n"
                "B 1b      \n"

                "2: \n"
                "#store current counter qalue at the end \n"
                "VST1.32 {q13}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt)
                :"0" (out), [Key] "r" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13"
                );
                break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
            case 12: /* AES 192 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q12}, [%[Key]]! \n"
                "VLD1.32 {q13}, [%[Key]]! \n"
                "VLD1.32 {q14}, [%[reg]]  \n"
                "VLD1.32 {q0}, [%[input]]!\n"

                "1:    \n"
                "VMOV.32 q15, q0 \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q3\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q4\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q5\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q6\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q7\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q8\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q9\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q10\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q11\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q12\n"
                "VEOR.32 q0, q0, q13\n"

                "VEOR.32 q0, q0, q14\n"
                "SUB r11, r11, #1        \n"
                "VST1.32 {q0}, [%[out]]! \n"
                "VMOV.32 q14, q15        \n"

                "CMP r11, #0 \n"
                "BEQ 2f \n"
                "VLD1.32 {q0}, [%[input]]!  \n"
                "B 1b \n"

                "2:\n"
                "#store current counter value at the end \n"
                "VST1.32 {q15}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt)
                :"0" (out), [Key] "r" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15"
                );
                break;
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
            case 14: /* AES 256 BLOCK */
                __asm__ __volatile__ (
                "MOV r11, %[blocks] \n"
                "VLD1.32 {q1}, [%[Key]]!  \n"
                "VLD1.32 {q2}, [%[Key]]!  \n"
                "VLD1.32 {q3}, [%[Key]]!  \n"
                "VLD1.32 {q4}, [%[Key]]!  \n"
                "VLD1.32 {q5}, [%[Key]]!  \n"
                "VLD1.32 {q6}, [%[Key]]!  \n"
                "VLD1.32 {q7}, [%[Key]]!  \n"
                "VLD1.32 {q8}, [%[Key]]!  \n"
                "VLD1.32 {q9}, [%[Key]]!  \n"
                "VLD1.32 {q10}, [%[Key]]! \n"
                "VLD1.32 {q11}, [%[Key]]! \n"
                "VLD1.32 {q12}, [%[Key]]! \n"
                "VLD1.32 {q14}, [%[reg]]  \n"
                "VLD1.32 {q0}, [%[input]]!\n"

                "1:\n"
                "VMOV.32 q15, q0 \n"
                "AESD.8 q0, q1\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q2\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q3\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q4\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q5\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q6\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q7\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q8\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q9\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q10\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q11\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q13}, [%[Key]]!  \n"
                "AESD.8 q0, q12\n"
                "AESIMC.8 q0, q0\n"
                "AESD.8 q0, q13\n"
                "AESIMC.8 q0, q0\n"
                "VLD1.32 {q13}, [%[Key]]!  \n"
                "AESD.8 q0, q13\n"
                "VLD1.32 {q13}, [%[Key]]  \n"
                "VEOR.32 q0, q0, q13\n"
                "SUB %[Key], %[Key], #32 \n"

                "VEOR.32 q0, q0, q14\n"
                "SUB r11, r11, #1            \n"
                "VST1.32 {q0}, [%[out]]!  \n"
                "VMOV.32 q14, q15        \n"

                "CMP r11, #0 \n"
                "BEQ 2f \n"
                "VLD1.32 {q0}, [%[input]]!  \n"
                "B 1b \n"

                "2:\n"
                "#store current counter value at the end \n"
                "VST1.32 {q15}, [%[regOut]] \n"

                :[out] "=r" (out), [regOut] "=r" (regPt)
                :"0" (out), [Key] "r" (keyPt), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "1" (regPt)
                : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
                "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15"
                );
                break;
#endif /* WOLFSSL_AES_256 */
            default:
                WOLFSSL_MSG("Bad AES-CBC round value");
                return BAD_FUNC_ARG;
            }
        }

        return 0;
    }
    #endif

#endif /* HAVE_AES_CBC */

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
static void wc_aes_ctr_encrypt_asm(Aes* aes, byte* out, const byte* in,
                                   word32 numBlocks)
{
    word32*  keyPt  = aes->key;
    word32*  regPt  = aes->reg;

    switch(aes->rounds) {
#ifdef WOLFSSL_AES_128
    case 10: /* AES 128 BLOCK */
        __asm__ __volatile__ (
        "MOV r11, %[blocks] \n"
        "VLDM %[Key]!, {q1-q4} \n"

        "#Create vector with the value 1  \n"
        "VMOV.u32 q15, #1                 \n"
        "VSHR.u64 q15, q15, #32  \n"
        "VLDM %[Key]!, {q5-q8} \n"
        "VEOR.32 q14, q14, q14    \n"
        "VLDM %[Key]!, {q9-q11} \n"
        "VEXT.8 q14, q15, q14, #8\n"

        "VLD1.32 {q13}, [%[reg]]\n"

        /* double block */
        "1:      \n"
        "CMP r11, #1 \n"
        "BEQ 2f    \n"
        "CMP r11, #0 \n"
        "BEQ 3f    \n"

        "VMOV.32 q0, q13  \n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "SUB r11, r11, #2     \n"

        /* Comparison value to check whether carry is going to happen */
        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q15, q13, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q13, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q13, q14, q12, #12 \n"
        "VAND.32 d27, d27, d24 \n"
        "VSUB.i32 q15, q15, q13 \n"

        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q13, q15, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q15, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d25, d24, d25, #4 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d24, d29, d24, #4 \n"
        "VSUB.i32 q13, q13, q12 \n"

        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q15, q15, q15, #8 \n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q15, q15\n" /* revert from network order */
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q1\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q2\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q3\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q4\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q5\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q10\n"
        "AESE.8 q15, q6\n"
        "AESMC.8 q15, q15\n"
        "VEOR.32 q0, q0, q11\n"

        "AESE.8 q15, q7\n"
        "AESMC.8 q15, q15\n"
        "VLD1.32 {q12}, [%[input]]!  \n"
        "AESE.8 q15, q8\n"
        "AESMC.8 q15, q15\n"

        "VEOR.32 q0, q0, q12\n"
        "AESE.8 q15, q9\n"
        "AESMC.8 q15, q15\n"

        "VLD1.32 {q12}, [%[input]]!  \n"
        "AESE.8 q15, q10\n"
        "VST1.32 {q0}, [%[out]]!  \n"
        "VEOR.32 q15, q15, q11\n"
        "VEOR.32 q15, q15, q12\n"
        "VST1.32 {q15}, [%[out]]!  \n"

        "B 1b \n"

        /* single block */
        "2:      \n"
        "VMOV.32 q0, q13  \n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"

        "VMOV.u32 q15, #0xffffffff  \n"
        "VCEQ.i32 q12, q13, q15 \n"
        "VADD.i32 q13, q13, q14 \n" /* add 1 to counter */
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q15, q14, q12, #12 \n"
        "VAND.32 d31, d31, d24 \n"
        "VSUB.i32 q13, q13, q15 \n"

        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "SUB r11, r11, #1     \n"
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q10\n"
        "VLD1.32 {q12}, [%[input]]!  \n"
        "VEOR.32 q0, q0, q11\n"
        "#CTR operations, increment counter and xorbuf \n"
        "VEOR.32 q0, q0, q12\n"
        "VST1.32 {q0}, [%[out]]!  \n"

        "3: \n"
        "#store current counter qalue at the end \n"
        "VST1.32 {q13}, [%[regOut]]   \n"

        :[out] "=r" (out), "=r" (keyPt), [regOut] "=r" (regPt),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "2" (regPt)
        : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
        "q6", "q7", "q8", "q9", "q10","q11","q12","q13","q14", "q15"
        );
        break;
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_192
    case 12: /* AES 192 BLOCK */
        __asm__ __volatile__ (
        "MOV r11, %[blocks] \n"
        "VLDM %[Key]!, {q1-q4} \n"

        "#Create vector with the value 1  \n"
        "VMOV.u32 q15, #1                 \n"
        "VSHR.u64 q15, q15, #32  \n"
        "VLDM %[Key]!, {q5-q8} \n"
        "VEOR.32 q14, q14, q14    \n"
        "VEXT.8 q14, q15, q14, #8\n"

        "VLDM %[Key]!, {q9-q10} \n"
        "VLD1.32 {q13}, [%[reg]]\n"

        /* double block */
        "1:   \n"
        "CMP r11, #1 \n"
        "BEQ 2f \n"
        "CMP r11, #0 \n"
        "BEQ 3f   \n"

        "VMOV.32 q0, q13\n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "SUB r11, r11, #2     \n"

        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q15, q13, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q13, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q13, q14, q12, #12 \n"
        "VAND.32 d27, d27, d24 \n"
        "VSUB.i32 q15, q15, q13 \n"

        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q13, q15, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q15, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d25, d24, d25, #4 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d24, d29, d24, #4 \n"
        "VSUB.i32 q13, q13, q12 \n"

        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q15, q15, q15, #8 \n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q15, q15\n" /* revert from network order */
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q1\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q2\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q3\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q4\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q5\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q10\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q11}, [%[Key]]! \n"
        "AESE.8 q15, q6\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q11\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q7\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q15, q8\n"
        "AESMC.8 q15, q15\n"

        "VLD1.32 {q12}, [%[Key]]! \n"
        "AESE.8 q15, q9\n"
        "AESMC.8 q15, q15\n"
        "AESE.8 q15, q10\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q15, q11\n"
        "AESMC.8 q15, q15\n"
        "VLD1.32 {q11}, [%[Key]] \n"
        "AESE.8 q0, q12\n"
        "AESE.8 q15, q12\n"

        "VLD1.32 {q12}, [%[input]]!  \n"
        "VEOR.32 q0, q0, q11\n"
        "VEOR.32 q15, q15, q11\n"
        "VEOR.32 q0, q0, q12\n"

        "VLD1.32 {q12}, [%[input]]!  \n"
        "VST1.32 {q0}, [%[out]]!  \n"
        "VEOR.32 q15, q15, q12\n"
        "VST1.32 {q15}, [%[out]]!  \n"
        "SUB %[Key], %[Key], #32 \n"

        "B 1b \n"


        /* single block */
        "2:      \n"
        "VLD1.32 {q11}, [%[Key]]! \n"
        "VMOV.32 q0, q13  \n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"

        "VMOV.u32 q15, #0xffffffff  \n"
        "VCEQ.i32 q12, q13, q15 \n"
        "VADD.i32 q13, q13, q14 \n" /* add 1 to counter */
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q15, q14, q12, #12 \n"
        "VAND.32 d31, d31, d24 \n"
        "VSUB.i32 q13, q13, q15 \n"

        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "SUB r11, r11, #1     \n"
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q10\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q12}, [%[Key]]! \n"
        "AESE.8 q0, q11\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q11}, [%[Key]] \n"
        "AESE.8 q0, q12\n"
        "VLD1.32 {q12}, [%[input]]! \n"
        "VEOR.32 q0, q0, q11\n"
        "#CTR operations, increment counter and xorbuf \n"
        "VEOR.32 q0, q0, q12\n"
        "VST1.32 {q0}, [%[out]]!  \n"

        "3: \n"
        "#store current counter qalue at the end \n"
        "VST1.32 {q13}, [%[regOut]]   \n"

        :[out] "=r" (out), "=r" (keyPt), [regOut] "=r" (regPt),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "2" (regPt)
        : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
        "q6", "q7", "q8", "q9", "q10","q11","q12","q13","q14"
        );
        break;
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_256
    case 14: /* AES 256 BLOCK */
        __asm__ __volatile__ (
        "MOV r11, %[blocks] \n"
        "VLDM %[Key]!, {q1-q4} \n"

        "#Create vector with the value 1  \n"
        "VMOV.u32 q15, #1                 \n"
        "VSHR.u64 q15, q15, #32  \n"
        "VLDM %[Key]!, {q5-q8} \n"
        "VEOR.32 q14, q14, q14    \n"
        "VEXT.8 q14, q15, q14, #8\n"

        "VLDM %[Key]!, {q9-q10} \n"
        "VLD1.32 {q13}, [%[reg]]\n"

        /* double block */
        "1:      \n"
        "CMP r11, #1 \n"
        "BEQ 2f    \n"
        "CMP r11, #0 \n"
        "BEQ 3f    \n"

        "VMOV.32 q0, q13  \n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "SUB r11, r11, #2     \n"

        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q15, q13, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q13, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q13, q14, q12, #12 \n"
        "VAND.32 d27, d27, d24 \n"
        "VSUB.i32 q15, q15, q13 \n"

        "VMOV.u32 q12, #0xffffffff  \n"
        "VADD.i32 q13, q15, q14 \n" /* add 1 to counter */
        /* Carry across 32-bit lanes */
        "VCEQ.i32 q12, q15, q12 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d25, d24, d25, #4 \n"
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 d24, d29, d24, #4 \n"
        "VSUB.i32 q13, q13, q12 \n"

        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q15, q15, q15, #8 \n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q15, q15\n" /* revert from network order */
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q15, q1\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q2\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q3\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q4\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q5\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q10\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q11}, [%[Key]]! \n"
        "AESE.8 q15, q6\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q0, q11\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q7\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q15, q8\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q15, q9\n"
        "AESMC.8 q15, q15\n"
        "VLD1.32 {q12}, [%[Key]]!  \n"
        "AESE.8 q15, q10\n"
        "AESMC.8 q15, q15\n"

        "AESE.8 q15, q11\n"
        "AESMC.8 q15, q15\n"

        "VLD1.32 {q11}, [%[Key]]! \n"
        "AESE.8 q0, q12\n" /* rnd 12*/
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q12\n" /* rnd 12 */
        "AESMC.8 q15, q15\n"

        "VLD1.32 {q12}, [%[Key]]!  \n"
        "AESE.8 q0, q11\n" /* rnd 13 */
        "AESMC.8 q0, q0\n"
        "AESE.8 q15, q11\n" /* rnd 13 */
        "AESMC.8 q15, q15\n"

        "VLD1.32 {q11}, [%[Key]] \n"
        "AESE.8 q0, q12\n" /* rnd 14 */
        "AESE.8 q15, q12\n" /* rnd 14 */

        "VLD1.32 {q12}, [%[input]]!  \n"
        "VEOR.32 q0, q0, q11\n" /* rnd 15 */
        "VEOR.32 q15, q15, q11\n" /* rnd 15 */
        "VEOR.32 q0, q0, q12\n"

        "VLD1.32 {q12}, [%[input]]!  \n"
        "VST1.32 {q0}, [%[out]]!  \n"
        "VEOR.32 q15, q15, q12\n"
        "VST1.32 {q15}, [%[out]]!  \n"
        "SUB %[Key], %[Key], #64 \n"

        /* single block */
        "B 1b \n"

        "2:      \n"
        "VLD1.32 {q11}, [%[Key]]! \n"
        "VMOV.32 q0, q13  \n"
        "AESE.8 q0, q1\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13 \n" /* network order */
        "AESE.8 q0, q2\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q3\n"
        "AESMC.8 q0, q0\n"

        "VMOV.u32 q15, #0xffffffff  \n"
        "VCEQ.i32 q12, q13, q15 \n"
        "VADD.i32 q13, q13, q14 \n" /* add 1 to counter */
        "VAND.32 d25, d25, d24 \n"
        "VEXT.8 q15, q14, q12, #12 \n"
        "VAND.32 d31, d31, d24 \n"
        "VSUB.i32 q13, q13, q15 \n"

        "AESE.8 q0, q4\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q5\n"
        "AESMC.8 q0, q0\n"
        "VEXT.8 q13, q13, q13, #8 \n"
        "AESE.8 q0, q6\n"
        "AESMC.8 q0, q0\n"
        "VREV64.8 q13, q13\n" /* revert from network order */
        "AESE.8 q0, q7\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q8\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q9\n"
        "AESMC.8 q0, q0\n"
        "AESE.8 q0, q10\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q12}, [%[Key]]! \n"
        "AESE.8 q0, q11\n"
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q11}, [%[Key]]! \n"
        "AESE.8 q0, q12\n" /* rnd 12 */
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q12}, [%[Key]]! \n"
        "AESE.8 q0, q11\n" /* rnd 13 */
        "AESMC.8 q0, q0\n"
        "VLD1.32 {q11}, [%[Key]] \n"
        "AESE.8 q0, q12\n" /* rnd 14 */
        "VLD1.32 {q12}, [%[input]]! \n"
        "VEOR.32 q0, q0, q11\n" /* rnd 15 */
        "#CTR operations, increment counter and xorbuf \n"
        "VEOR.32 q0, q0, q12\n"
        "VST1.32 {q0}, [%[out]]!  \n"

        "3: \n"
        "#store current counter qalue at the end \n"
        "VST1.32 {q13}, [%[regOut]]   \n"

        :[out] "=r" (out), "=r" (keyPt), [regOut] "=r" (regPt),
         "=r" (in)
        :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
         [blocks] "r" (numBlocks), [reg] "2" (regPt)
        : "cc", "memory", "r11", "q0", "q1", "q2", "q3", "q4", "q5",
        "q6", "q7", "q8", "q9", "q10","q11","q12","q13","q14"
        );
        break;
#endif /* WOLFSSL_AES_256 */
    }
}

int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte* tmp;
    word32 numBlocks;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    switch(aes->rounds) {
    #ifdef WOLFSSL_AES_128
        case 10: /* AES 128 BLOCK */
    #endif /* WOLFSSL_AES_128 */
    #ifdef WOLFSSL_AES_192
        case 12: /* AES 192 BLOCK */
    #endif /* WOLFSSL_AES_192 */
    #ifdef WOLFSSL_AES_256
        case 14: /* AES 256 BLOCK */
    #endif /* WOLFSSL_AES_256 */
            break;
        default:
            WOLFSSL_MSG("Bad AES-CTR round value");
            return BAD_FUNC_ARG;
    }


    tmp = (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left;

    /* consume any unused bytes left in aes->tmp */
    while ((aes->left != 0) && (sz != 0)) {
       *(out++) = *(in++) ^ *(tmp++);
       aes->left--;
       sz--;
    }

    /* do as many block size ops as possible */
    numBlocks = sz / WC_AES_BLOCK_SIZE;
    if (numBlocks > 0) {
        wc_aes_ctr_encrypt_asm(aes, out, in, numBlocks);

        sz  -= numBlocks * WC_AES_BLOCK_SIZE;
        out += numBlocks * WC_AES_BLOCK_SIZE;
        in  += numBlocks * WC_AES_BLOCK_SIZE;
    }

    /* handle non block size remaining */
    if (sz) {
        byte zeros[WC_AES_BLOCK_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0 };
        wc_aes_ctr_encrypt_asm(aes, (byte*)aes->tmp, zeros, 1);

        aes->left = WC_AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;

        while (sz--) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }
    return 0;
}

int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len,
        const byte* iv, int dir)
{
    (void)dir;
    return wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);
}

#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM
/*
 * Uses Karatsuba algorithm. Reduction algorithm is based on "Implementing GCM
 * on ARMv8". Shifting left to account for bit reflection is based on
 * "Carry-Less Multiplication and Its Usage for Computing the GCM mode"
 */
void GMULT(byte* X, byte* Y)
{
    __asm__ __volatile__ (
        "VLD1.32 {q0}, [%[x]] \n"

        /* In GCM format bits are big endian, switch location of bytes to
         * allow for logical shifts and carries.
         */
        "VREV64.8 q0, q0 \n"
        "VLD1.32 {q1}, [%[y]] \n" /* converted on set key */
        "VSWP.8 d0, d1 \n"

        "VMULL.p64  q5, d0, d2 \n"
        "VMULL.p64  q6, d1, d3 \n"
        "VEOR d15, d2, d3 \n"
        "VEOR d14, d0, d1 \n"
        "VMULL.p64  q7, d15, d14 \n"
        "VEOR q7, q5 \n"
        "VEOR q7, q6 \n"
        "VEOR d11, d14 \n"
        "VEOR d12, d15\n"

        /* shift to left by 1 to account for reflection */
        "VMOV q7, q6 \n"
        "VSHL.u64 q6, q6, #1 \n"
        "VSHR.u64 q7, q7, #63 \n"
        "VEOR d13, d14 \n"
        "VMOV q8, q5 \n"
        "VSHL.u64 q5, q5, #1 \n"
        "VSHR.u64 q8, q8, #63 \n"
        "VEOR d12, d17 \n"
        "VEOR d11, d16 \n"

        /* create constant 0xc200000000000000 */
        "VMOV.i32 d16, 0xc2000000 \n"
        "VSHL.u64 d16, d16, #32 \n"

        /* reduce product of multiplication */
        "VMULL.p64 q9, d10, d16 \n"
        "VEOR d11, d18 \n"
        "VEOR d12, d19 \n"
        "VMULL.p64 q9, d11, d16 \n"
        "VEOR q6, q9 \n"
        "VEOR q10, q5, q6 \n"

        /* convert to GCM format */
        "VREV64.8 q10, q10 \n"
        "VSWP.8 d20, d21 \n"

        "VST1.32 {q10}, [%[xOut]] \n"

        : [xOut] "=r" (X), [yOut] "=r" (Y)
        : [x] "0" (X), [y] "1" (Y)
        : "cc", "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6" ,"q7", "q8",
        "q9", "q10", "q11" ,"q12", "q13", "q14", "q15"
    );
}


void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c, word32 cSz,
    byte* s, word32 sSz)
{
    byte x[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    word32 blocks, partial;
    byte* h = gcm->H;

    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / WC_AES_BLOCK_SIZE;
        partial = aSz % WC_AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf(x, a, WC_AES_BLOCK_SIZE);
            GMULT(x, h);
            a += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            xorbuf(x, scratch, WC_AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / WC_AES_BLOCK_SIZE;
        partial = cSz % WC_AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf(x, c, WC_AES_BLOCK_SIZE);
            GMULT(x, h);
            c += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            xorbuf(x, scratch, WC_AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    xorbuf(x, scratch, WC_AES_BLOCK_SIZE);
    GMULT(x, h);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}


/* Aarch32
 * Encrypt and tag data using AES with GCM mode.
 * aes: Aes structure having already been set with set key function
 * out: encrypted data output buffer
 * in:  plain text input buffer
 * sz:  size of plain text and out buffer
 * iv:  initialization vector
 * ivSz:      size of iv buffer
 * authTag:   buffer to hold tag
 * authTagSz: size of tag buffer
 * authIn:    additional data buffer
 * authInSz:  size of additional data buffer
 */
int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks = sz / WC_AES_BLOCK_SIZE;
    word32 partial = sz % WC_AES_BLOCK_SIZE;
    const byte* p = in;
    byte* c = out;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte *ctr ;
    byte scratch[WC_AES_BLOCK_SIZE];
    ctr = counter ;

    /* sanity checks */
    if (aes == NULL || (iv == NULL && ivSz > 0) ||
                       (authTag == NULL) ||
                       (authIn == NULL && authInSz > 0) ||
                       (ivSz == 0)) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ || authTagSz > WC_AES_BLOCK_SIZE) {
        WOLFSSL_MSG("GcmEncrypt authTagSz error");
        return BAD_FUNC_ARG;
    }

    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(&aes->gcm, NULL, 0, iv, ivSz, initialCounter, WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, WC_AES_BLOCK_SIZE);

    while (blocks--) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, p, WC_AES_BLOCK_SIZE);
        XMEMCPY(c, scratch, WC_AES_BLOCK_SIZE);
        p += WC_AES_BLOCK_SIZE;
        c += WC_AES_BLOCK_SIZE;
    }

    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, p, partial);
        XMEMCPY(c, scratch, partial);

    }

    GHASH(&aes->gcm, authIn, authInSz, out, sz, authTag, authTagSz);
    wc_AesEncrypt(aes, initialCounter, scratch);
    if (authTagSz > WC_AES_BLOCK_SIZE) {
        xorbuf(authTag, scratch, WC_AES_BLOCK_SIZE);
    }
    else {
        xorbuf(authTag, scratch, authTagSz);
    }

    return 0;
}


#ifdef HAVE_AES_DECRYPT
/*
 * Check tag and decrypt data using AES with GCM mode.
 * aes: Aes structure having already been set with set key function
 * out: decrypted data output buffer
 * in:  cipher text buffer
 * sz:  size of plain text and out buffer
 * iv:  initialization vector
 * ivSz:      size of iv buffer
 * authTag:   buffer holding tag
 * authTagSz: size of tag buffer
 * authIn:    additional data buffer
 * authInSz:  size of additional data buffer
 */
int  wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks = sz / WC_AES_BLOCK_SIZE;
    word32 partial = sz % WC_AES_BLOCK_SIZE;
    const byte* c = in;
    byte* p = out;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte *ctr ;
    byte scratch[WC_AES_BLOCK_SIZE];
    ctr = counter ;

    /* sanity checks */
    if (aes == NULL || iv == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        authTag == NULL || authTagSz > WC_AES_BLOCK_SIZE || authTagSz == 0 ||
        ivSz == 0) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        return BAD_FUNC_ARG;
    }

    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(&aes->gcm, NULL, 0, iv, ivSz, initialCounter, WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, WC_AES_BLOCK_SIZE);

    /* Calculate the authTag again using the received auth data and the
     * cipher text. */
    {
        byte Tprime[WC_AES_BLOCK_SIZE];
        byte EKY0[WC_AES_BLOCK_SIZE];

        GHASH(&aes->gcm, authIn, authInSz, in, sz, Tprime, sizeof(Tprime));
        wc_AesEncrypt(aes, ctr, EKY0);
        xorbuf(Tprime, EKY0, sizeof(Tprime));

        if (ConstantCompare(authTag, Tprime, authTagSz) != 0) {
            return AES_GCM_AUTH_E;
        }
    }

    while (blocks--) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
#endif
        xorbuf(scratch, c, WC_AES_BLOCK_SIZE);
        XMEMCPY(p, scratch, WC_AES_BLOCK_SIZE);
        p += WC_AES_BLOCK_SIZE;
        c += WC_AES_BLOCK_SIZE;
    }
    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);

        /* check if pointer is null after main AES-GCM blocks
         * helps static analysis */
        if (p == NULL || c == NULL) {
            return BAD_STATE_E;
        }
        xorbuf(scratch, c, partial);
        XMEMCPY(p, scratch, partial);
    }
    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESGCM
#ifdef WOLFSSL_AESGCM_STREAM
#ifndef __aarch64__
    /* Access initialization counter data. */
    #define AES_INITCTR(aes)        ((aes)->streamData + 0 * WC_AES_BLOCK_SIZE)
    /* Access counter data. */
    #define AES_COUNTER(aes)        ((aes)->streamData + 1 * WC_AES_BLOCK_SIZE)
    /* Access tag data. */
    #define AES_TAG(aes)            ((aes)->streamData + 2 * WC_AES_BLOCK_SIZE)
    /* Access last GHASH block. */
    #define AES_LASTGBLOCK(aes)     ((aes)->streamData + 3 * WC_AES_BLOCK_SIZE)
    /* Access last encrypted block. */
    #define AES_LASTBLOCK(aes)      ((aes)->streamData + 4 * WC_AES_BLOCK_SIZE)

/* GHASH one block of data.
 *
 * XOR block into tag and GMULT with H.
 *
 * @param [in, out] aes    AES GCM object.
 * @param [in]      block  Block of AAD or cipher text.
 */
#define GHASH_ONE_BLOCK(aes, block)                     \
    do {                                                \
        xorbuf(AES_TAG(aes), block, WC_AES_BLOCK_SIZE);    \
        GMULT(AES_TAG(aes), aes->gcm.H);                \
    }                                                   \
    while (0)

/* Hash in the lengths of the AAD and cipher text in bits.
 *
 * Default implementation.
 *
 * @param [in, out] aes  AES GCM object.
 */
#define GHASH_LEN_BLOCK(aes)                    \
    do {                                        \
        byte scratch[WC_AES_BLOCK_SIZE];           \
        FlattenSzInBits(&scratch[0], aes->aSz); \
        FlattenSzInBits(&scratch[8], aes->cSz); \
        GHASH_ONE_BLOCK(aes, scratch);          \
    }                                           \
    while (0)

static WC_INLINE void IncCtr(byte* ctr, word32 ctrSz)
{
    int i;
    for (i = ctrSz-1; i >= 0; i--) {
        if (++ctr[i])
            break;
    }
}

/* Initialize a GHASH for streaming operations.
 *
 * @param [in, out] aes  AES GCM object.
 */
static void GHASH_INIT(Aes* aes) {
    /* Set tag to all zeros as initial value. */
    XMEMSET(AES_TAG(aes), 0, WC_AES_BLOCK_SIZE);
    /* Reset counts of AAD and cipher text. */
    aes->aOver = 0;
    aes->cOver = 0;
}

/* Update the GHASH with AAD and/or cipher text.
 *
 * @param [in,out] aes   AES GCM object.
 * @param [in]     a     Additional authentication data buffer.
 * @param [in]     aSz   Size of data in AAD buffer.
 * @param [in]     c     Cipher text buffer.
 * @param [in]     cSz   Size of data in cipher text buffer.
 */
static void GHASH_UPDATE(Aes* aes, const byte* a, word32 aSz, const byte* c,
    word32 cSz)
{
    word32 blocks;
    word32 partial;

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        /* Update count of AAD we have hashed. */
        aes->aSz += aSz;
        /* Check if we have unprocessed data. */
        if (aes->aOver > 0) {
            /* Calculate amount we can use - fill up the block. */
            byte sz = WC_AES_BLOCK_SIZE - aes->aOver;
            if (sz > aSz) {
                sz = aSz;
            }
            /* Copy extra into last GHASH block array and update count. */
            XMEMCPY(AES_LASTGBLOCK(aes) + aes->aOver, a, sz);
            aes->aOver += sz;
            if (aes->aOver == WC_AES_BLOCK_SIZE) {
                /* We have filled up the block and can process. */
                GHASH_ONE_BLOCK(aes, AES_LASTGBLOCK(aes));
                /* Reset count. */
                aes->aOver = 0;
            }
            /* Used up some data. */
            aSz -= sz;
            a += sz;
        }

        /* Calculate number of blocks of AAD and the leftover. */
        blocks = aSz / WC_AES_BLOCK_SIZE;
        partial = aSz % WC_AES_BLOCK_SIZE;
        /* GHASH full blocks now. */
        while (blocks--) {
            GHASH_ONE_BLOCK(aes, a);
            a += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            /* Cache the partial block. */
            XMEMCPY(AES_LASTGBLOCK(aes), a, partial);
            aes->aOver = (byte)partial;
        }
    }
    if (aes->aOver > 0 && cSz > 0 && c != NULL) {
        /* No more AAD coming and we have a partial block. */
        /* Fill the rest of the block with zeros. */
        byte sz = WC_AES_BLOCK_SIZE - aes->aOver;
        XMEMSET(AES_LASTGBLOCK(aes) + aes->aOver, 0, sz);
        /* GHASH last AAD block. */
        GHASH_ONE_BLOCK(aes, AES_LASTGBLOCK(aes));
        /* Clear partial count for next time through. */
        aes->aOver = 0;
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        /* Update count of cipher text we have hashed. */
        aes->cSz += cSz;
        if (aes->cOver > 0) {
            /* Calculate amount we can use - fill up the block. */
            byte sz = WC_AES_BLOCK_SIZE - aes->cOver;
            if (sz > cSz) {
                sz = cSz;
            }
            XMEMCPY(AES_LASTGBLOCK(aes) + aes->cOver, c, sz);
            /* Update count of unused encrypted counter. */
            aes->cOver += sz;
            if (aes->cOver == WC_AES_BLOCK_SIZE) {
                /* We have filled up the block and can process. */
                GHASH_ONE_BLOCK(aes, AES_LASTGBLOCK(aes));
                /* Reset count. */
                aes->cOver = 0;
            }
            /* Used up some data. */
            cSz -= sz;
            c += sz;
        }

        /* Calculate number of blocks of cipher text and the leftover. */
        blocks = cSz / WC_AES_BLOCK_SIZE;
        partial = cSz % WC_AES_BLOCK_SIZE;
        /* GHASH full blocks now. */
        while (blocks--) {
            GHASH_ONE_BLOCK(aes, c);
            c += WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            /* Cache the partial block. */
            XMEMCPY(AES_LASTGBLOCK(aes), c, partial);
            aes->cOver = (byte)partial;
        }
    }
}

/* Finalize the GHASH calculation.
 *
 * Complete hashing cipher text and hash the AAD and cipher text lengths.
 *
 * @param [in, out] aes  AES GCM object.
 * @param [out]     s    Authentication tag.
 * @param [in]      sSz  Size of authentication tag required.
 */
static void GHASH_FINAL(Aes* aes, byte* s, word32 sSz)
{
    /* AAD block incomplete when > 0 */
    byte over = aes->aOver;

    if (aes->cOver > 0) {
        /* Cipher text block incomplete. */
        over = aes->cOver;
    }
    if (over > 0) {
        /* Zeroize the unused part of the block. */
        XMEMSET(AES_LASTGBLOCK(aes) + over, 0, WC_AES_BLOCK_SIZE - over);
        /* Hash the last block of cipher text. */
        GHASH_ONE_BLOCK(aes, AES_LASTGBLOCK(aes));
    }
    /* Hash in the lengths of AAD and cipher text in bits */
    GHASH_LEN_BLOCK(aes);
    /* Copy the result into s. */
    XMEMCPY(s, AES_TAG(aes), sSz);
}

/* Initialize the AES GCM cipher with an IV. C implementation.
 *
 * @param [in, out] aes   AES object.
 * @param [in]      iv    IV/nonce buffer.
 * @param [in]      ivSz  Length of IV/nonce data.
 */
static void AesGcmInit_C(Aes* aes, const byte* iv, word32 ivSz)
{
    ALIGN32 byte counter[WC_AES_BLOCK_SIZE];

    if (ivSz == GCM_NONCE_MID_SZ) {
        /* Counter is IV with bottom 4 bytes set to: 0x00,0x00,0x00,0x01. */
        XMEMCPY(counter, iv, ivSz);
        XMEMSET(counter + GCM_NONCE_MID_SZ, 0,
                                         WC_AES_BLOCK_SIZE - GCM_NONCE_MID_SZ - 1);
        counter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        /* Counter is GHASH of IV. */
    #ifdef OPENSSL_EXTRA
        word32 aadTemp = aes->gcm.aadLen;
        aes->gcm.aadLen = 0;
    #endif
    #ifdef __aarch64__
        GHASH_AARCH64(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT_AARCH64(counter, aes->gcm.H);
    #else
        GHASH(&aes->gcm, NULL, 0, iv, ivSz, counter, WC_AES_BLOCK_SIZE);
        GMULT(counter, aes->gcm.H);
    #endif
    #ifdef OPENSSL_EXTRA
        aes->gcm.aadLen = aadTemp;
    #endif
    }

    /* Copy in the counter for use with cipher. */
    XMEMCPY(AES_COUNTER(aes), counter, WC_AES_BLOCK_SIZE);
    /* Encrypt initial counter into a buffer for GCM. */
#ifdef __aarch64__
    AES_encrypt_AARCH64(counter, AES_INITCTR(aes), (byte*)aes->key,
        aes->rounds);
#else
    wc_AesEncrypt(aes, counter, AES_INITCTR(aes));
#endif
    /* Reset state fields. */
    aes->over = 0;
    aes->aSz = 0;
    aes->cSz = 0;
    /* Initialization for GHASH. */
    GHASH_INIT(aes);
}

/* Update the AES GCM cipher with data. C implementation.
 *
 * Only enciphers data.
 *
 * @param [in, out] aes  AES object.
 * @param [in]      out  Cipher text or plaintext buffer.
 * @param [in]      in   Plaintext or cipher text buffer.
 * @param [in]      sz   Length of data.
 */
static void AesGcmCryptUpdate_C(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 blocks;
    word32 partial;

    /* Check if previous encrypted block was not used up. */
    if (aes->over > 0) {
        byte pSz = WC_AES_BLOCK_SIZE - aes->over;
        if (pSz > sz) pSz = sz;

        /* Use some/all of last encrypted block. */
        xorbufout(out, AES_LASTBLOCK(aes) + aes->over, in, pSz);
        aes->over = (aes->over + pSz) & (WC_AES_BLOCK_SIZE - 1);

        /* Some data used. */
        sz  -= pSz;
        in  += pSz;
        out += pSz;
    }

    /* Calculate the number of blocks needing to be encrypted and any leftover.
     */
    blocks  = sz / WC_AES_BLOCK_SIZE;
    partial = sz & (WC_AES_BLOCK_SIZE - 1);

    /* Encrypt block by block. */
    while (blocks--) {
        ALIGN32 byte scratch[WC_AES_BLOCK_SIZE];
        IncrementGcmCounter(AES_COUNTER(aes));
        /* Encrypt counter into a buffer. */
    #ifdef __aarch64__
        AES_encrypt_AARCH64(AES_COUNTER(aes), scratch, (byte*)aes->key,
             aes->rounds);
    #else
        wc_AesEncrypt(aes, AES_COUNTER(aes), scratch);
    #endif
        /* XOR plain text into encrypted counter into cipher text buffer. */
        xorbufout(out, scratch, in, WC_AES_BLOCK_SIZE);
        /* Data complete. */
        in  += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }

    if (partial != 0) {
        /* Generate an extra block and use up as much as needed. */
        IncrementGcmCounter(AES_COUNTER(aes));
        /* Encrypt counter into cache. */
    #ifdef __aarch64__
        AES_encrypt_AARCH64(AES_COUNTER(aes), AES_LASTBLOCK(aes),
            (byte*)aes->key, (int)aes->rounds);
    #else
        wc_AesEncrypt(aes, AES_COUNTER(aes), AES_LASTBLOCK(aes));
    #endif
        /* XOR plain text into encrypted counter into cipher text buffer. */
        xorbufout(out, AES_LASTBLOCK(aes), in, partial);
        /* Keep amount of encrypted block used. */
        aes->over = partial;
    }
}

/* Calculates authentication tag for AES GCM. C implementation.
 *
 * @param [in, out] aes        AES object.
 * @param [out]     authTag    Buffer to store authentication tag in.
 * @param [in]      authTagSz  Length of tag to create.
 */
static void AesGcmFinal_C(Aes* aes, byte* authTag, word32 authTagSz)
{
    /* Calculate authentication tag. */
    GHASH_FINAL(aes, authTag, authTagSz);
    /* XOR in as much of encrypted counter as is required. */
    xorbuf(authTag, AES_INITCTR(aes), authTagSz);
#ifdef OPENSSL_EXTRA
    /* store AAD size for next call */
    aes->gcm.aadLen = aes->aSz;
#endif
    /* Zeroize last block to protect sensitive data. */
    ForceZero(AES_LASTBLOCK(aes), WC_AES_BLOCK_SIZE);
}

/* Initialize an AES GCM cipher for encryption or decryption.
 *
 * Must call wc_AesInit() before calling this function.
 *
 * @param [in, out] aes   AES object.
 * @param [in]      key   Buffer holding key.
 * @param [in]      len   Length of key in bytes.
 * @param [in]      iv    Buffer holding IV/nonce.
 * @param [in]      ivSz  Length of IV/nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL, or the IV is NULL and no previous IV has been set.
 * @return  MEMORY_E when dynamic memory allocation fails. (WOLFSSL_SMALL_STACK)
 */
int wc_AesGcmInit(Aes* aes, const byte* key, word32 len, const byte* iv,
    word32 ivSz)
{
    int ret = 0;

    /* Check validity of parameters. */
    if ((aes == NULL) || ((len > 0) && (key == NULL)) ||
            ((ivSz == 0) && (iv != NULL)) || ((ivSz > 0) && (iv == NULL))) {
        ret = BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_AESNI)
    if ((ret == 0) && (aes->streamData == NULL)) {
        /* Allocate buffers for streaming. */
        aes->streamData = (byte*)XMALLOC(5 * WC_AES_BLOCK_SIZE, aes->heap,
                                                              DYNAMIC_TYPE_AES);
        if (aes->streamData == NULL) {
            ret = MEMORY_E;
        }
    }
#endif

    /* Set the key if passed in. */
    if ((ret == 0) && (key != NULL)) {
        ret = wc_AesGcmSetKey(aes, key, len);
    }

    if (ret == 0) {
        /* Set the IV passed in if it is smaller than a block. */
        if ((iv != NULL) && (ivSz <= WC_AES_BLOCK_SIZE)) {
            XMEMMOVE((byte*)aes->reg, iv, ivSz);
            aes->nonceSz = ivSz;
        }
        /* No IV passed in, check for cached IV. */
        if ((iv == NULL) && (aes->nonceSz != 0)) {
            /* Use the cached copy. */
            iv = (byte*)aes->reg;
            ivSz = aes->nonceSz;
        }

        if (iv != NULL) {
            /* Initialize with the IV. */
            AesGcmInit_C(aes, iv, ivSz);

            aes->nonceSet = 1;
        }
    }

    return ret;
}

/* Initialize an AES GCM cipher for encryption.
 *
 * Must call wc_AesInit() before calling this function.
 *
 * @param [in, out] aes   AES object.
 * @param [in]      key   Buffer holding key.
 * @param [in]      len   Length of key in bytes.
 * @param [in]      iv    Buffer holding IV/nonce.
 * @param [in]      ivSz  Length of IV/nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL, or the IV is NULL and no previous IV has been set.
 */
int wc_AesGcmEncryptInit(Aes* aes, const byte* key, word32 len, const byte* iv,
    word32 ivSz)
{
    return wc_AesGcmInit(aes, key, len, iv, ivSz);
}

/* Initialize an AES GCM cipher for encryption or decryption. Get IV.
 *
 * Must call wc_AesInit() before calling this function.
 *
 * @param [in, out] aes   AES object.
 * @param [in]      key   Buffer holding key.
 * @param [in]      len   Length of key in bytes.
 * @param [in]      iv    Buffer holding IV/nonce.
 * @param [in]      ivSz  Length of IV/nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL, or the IV is NULL and no previous IV has been set.
 */
int wc_AesGcmEncryptInit_ex(Aes* aes, const byte* key, word32 len, byte* ivOut,
    word32 ivOutSz)
{
    XMEMCPY(ivOut, aes->reg, ivOutSz);
    return wc_AesGcmInit(aes, key, len, NULL, 0);
}

/* Update the AES GCM for encryption with data and/or authentication data.
 *
 * All the AAD must be passed to update before the plaintext.
 * Last part of AAD can be passed with first part of plaintext.
 *
 * Must set key and IV before calling this function.
 * Must call wc_AesGcmInit() before calling this function.
 *
 * @param [in, out] aes       AES object.
 * @param [out]     out       Buffer to hold cipher text.
 * @param [in]      in        Buffer holding plaintext.
 * @param [in]      sz        Length of plaintext in bytes.
 * @param [in]      authIn    Buffer holding authentication data.
 * @param [in]      authInSz  Length of authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL.
 */
int wc_AesGcmEncryptUpdate(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* authIn, word32 authInSz)
{
    int ret = 0;

    /* Check validity of parameters. */
    if ((aes == NULL) || ((authInSz > 0) && (authIn == NULL)) || ((sz > 0) &&
            ((out == NULL) || (in == NULL)))) {
        ret = BAD_FUNC_ARG;
    }

    /* Check key has been set. */
    if ((ret == 0) && (!aes->gcmKeySet)) {
        ret = MISSING_KEY;
    }
    /* Check IV has been set. */
    if ((ret == 0) && (!aes->nonceSet)) {
        ret = MISSING_IV;
    }

    if ((ret == 0) && aes->ctrSet && (aes->aSz == 0) && (aes->cSz == 0)) {
        aes->invokeCtr[0]++;
        if (aes->invokeCtr[0] == 0) {
            aes->invokeCtr[1]++;
            if (aes->invokeCtr[1] == 0)
                ret = AES_GCM_OVERFLOW_E;
        }
    }

    if (ret == 0) {
        /* Encrypt the plaintext. */
        AesGcmCryptUpdate_C(aes, out, in, sz);
        /* Update the authentication tag with any authentication data and the
         * new cipher text. */
        GHASH_UPDATE(aes, authIn, authInSz, out, sz);
    }

    return ret;
}

/* Finalize the AES GCM for encryption and return the authentication tag.
 *
 * Must set key and IV before calling this function.
 * Must call wc_AesGcmInit() before calling this function.
 *
 * @param [in, out] aes        AES object.
 * @param [out]     authTag    Buffer to hold authentication tag.
 * @param [in]      authTagSz  Length of authentication tag in bytes.
 * @return  0 on success.
 */
int wc_AesGcmEncryptFinal(Aes* aes, byte* authTag, word32 authTagSz)
{
    int ret = 0;

    /* Check validity of parameters. */
    if ((aes == NULL) || (authTag == NULL) || (authTagSz > WC_AES_BLOCK_SIZE) ||
            (authTagSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check key has been set. */
    if ((ret == 0) && (!aes->gcmKeySet)) {
        ret = MISSING_KEY;
    }
    /* Check IV has been set. */
    if ((ret == 0) && (!aes->nonceSet)) {
        ret = MISSING_IV;
    }

    if (ret == 0) {
        /* Calculate authentication tag. */
        AesGcmFinal_C(aes, authTag, authTagSz);
    }

    if ((ret == 0) && aes->ctrSet) {
        IncCtr((byte*)aes->reg, aes->nonceSz);
    }

    return ret;
}

#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AESGCM_DECRYPT)
/* Initialize an AES GCM cipher for decryption.
 *
 * Must call wc_AesInit() before calling this function.
 *
 * @param [in, out] aes   AES object.
 * @param [in]      key   Buffer holding key.
 * @param [in]      len   Length of key in bytes.
 * @param [in]      iv    Buffer holding IV/nonce.
 * @param [in]      ivSz  Length of IV/nonce in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL, or the IV is NULL and no previous IV has been set.
 */
int wc_AesGcmDecryptInit(Aes* aes, const byte* key, word32 len, const byte* iv,
    word32 ivSz)
{
    return wc_AesGcmInit(aes, key, len, iv, ivSz);
}

/* Update the AES GCM for decryption with data and/or authentication data.
 *
 * All the AAD must be passed to update before the cipher text.
 * Last part of AAD can be passed with first part of cipher text.
 *
 * Must set key and IV before calling this function.
 * Must call wc_AesGcmInit() before calling this function.
 *
 * @param [in, out] aes       AES object.
 * @param [out]     out       Buffer to hold plaintext.
 * @param [in]      in        Buffer holding cipher text.
 * @param [in]      sz        Length of cipher text in bytes.
 * @param [in]      authIn    Buffer holding authentication data.
 * @param [in]      authInSz  Length of authentication data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when aes is NULL, or a length is non-zero but buffer
 *          is NULL.
 */
int wc_AesGcmDecryptUpdate(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* authIn, word32 authInSz)
{
    int ret = 0;

    /* Check validity of parameters. */
    if ((aes == NULL) || ((authInSz > 0) && (authIn == NULL)) || ((sz > 0) &&
            ((out == NULL) || (in == NULL)))) {
        ret = BAD_FUNC_ARG;
    }

    /* Check key has been set. */
    if ((ret == 0) && (!aes->gcmKeySet)) {
        ret = MISSING_KEY;
    }
    /* Check IV has been set. */
    if ((ret == 0) && (!aes->nonceSet)) {
        ret = MISSING_IV;
    }

    if (ret == 0) {
        /* Decrypt with AAD and/or cipher text. */
        /* Update the authentication tag with any authentication data and
         * cipher text. */
        GHASH_UPDATE(aes, authIn, authInSz, in, sz);
        /* Decrypt the cipher text. */
        AesGcmCryptUpdate_C(aes, out, in, sz);
    }

    return ret;
}

/* Finalize the AES GCM for decryption and check the authentication tag.
 *
 * Must set key and IV before calling this function.
 * Must call wc_AesGcmInit() before calling this function.
 *
 * @param [in, out] aes        AES object.
 * @param [in]      authTag    Buffer holding authentication tag.
 * @param [in]      authTagSz  Length of authentication tag in bytes.
 * @return  0 on success.
 */
int wc_AesGcmDecryptFinal(Aes* aes, const byte* authTag, word32 authTagSz)
{
    int ret = 0;

    /* Check validity of parameters. */
    if ((aes == NULL) || (authTag == NULL) || (authTagSz > WC_AES_BLOCK_SIZE) ||
            (authTagSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check key has been set. */
    if ((ret == 0) && (!aes->gcmKeySet)) {
        ret = MISSING_KEY;
    }
    /* Check IV has been set. */
    if ((ret == 0) && (!aes->nonceSet)) {
        ret = MISSING_IV;
    }

    if (ret == 0) {
        /* Calculate authentication tag and compare with one passed in.. */
        ALIGN32 byte calcTag[WC_AES_BLOCK_SIZE];
        /* Calculate authentication tag. */
        AesGcmFinal_C(aes, calcTag, authTagSz);
        /* Check calculated tag matches the one passed in. */
        if (ConstantCompare(authTag, calcTag, authTagSz) != 0) {
            ret = AES_GCM_AUTH_E;
        }
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT || HAVE_AESGCM_DECRYPT */
#endif /* !__aarch64__ */
#endif /* WOLFSSL_AESGCM_STREAM */
#endif /* HAVE_AESGCM */


#ifdef HAVE_AESCCM
#ifndef __aarch64__
/* Software version of AES-CCM from wolfcrypt/src/aes.c
 * Gets some speed up from hardware acceleration of wc_AesEncrypt */

static void roll_x(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    /* process the bulk of the data */
    while (inSz >= WC_AES_BLOCK_SIZE) {
        xorbuf(out, in, WC_AES_BLOCK_SIZE);
        in += WC_AES_BLOCK_SIZE;
        inSz -= WC_AES_BLOCK_SIZE;

        wc_AesEncrypt(aes, out, out);
    }

    /* process remainder of the data */
    if (inSz > 0) {
        xorbuf(out, in, inSz);
        wc_AesEncrypt(aes, out, out);
    }
}


static void roll_auth(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    word32 authLenSz;
    word32 remainder;

    /* encode the length in */
    if (inSz <= 0xFEFF) {
        authLenSz = 2;
        out[0] ^= ((inSz & 0xFF00) >> 8);
        out[1] ^=  (inSz & 0x00FF);
    }
    else if (inSz <= 0xFFFFFFFF) {
        authLenSz = 6;
        out[0] ^= 0xFF; out[1] ^= 0xFE;
        out[2] ^= ((inSz & 0xFF000000) >> 24);
        out[3] ^= ((inSz & 0x00FF0000) >> 16);
        out[4] ^= ((inSz & 0x0000FF00) >>  8);
        out[5] ^=  (inSz & 0x000000FF);
    }
    /* Note, the protocol handles auth data up to 2^64, but we are
     * using 32-bit sizes right now, so the bigger data isn't handled
     * else if (inSz <= 0xFFFFFFFFFFFFFFFF) {} */
    else
        return;

    /* start fill out the rest of the first block */
    remainder = WC_AES_BLOCK_SIZE - authLenSz;
    if (inSz >= remainder) {
        /* plenty of bulk data to fill the remainder of this block */
        xorbuf(out + authLenSz, in, remainder);
        inSz -= remainder;
        in += remainder;
    }
    else {
        /* not enough bulk data, copy what is available, and pad zero */
        xorbuf(out + authLenSz, in, inSz);
        inSz = 0;
    }
    wc_AesEncrypt(aes, out, out);

    if (inSz > 0)
        roll_x(aes, in, inSz, out);
}


static WC_INLINE void AesCcmCtrInc(byte* B, word32 lenSz)
{
    word32 i;

    for (i = 0; i < lenSz; i++) {
        if (++B[WC_AES_BLOCK_SIZE - 1 - i] != 0) return;
    }
}


/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[WC_AES_BLOCK_SIZE];
    byte B[WC_AES_BLOCK_SIZE];
    byte lenSz;
    word32 i;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || (inSz != 0 && (in == NULL || out == NULL)) ||
        nonce == NULL || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    if (wc_AesCcmCheckTagSize(authTagSz) != 0) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int crypto_cb_ret =
            wc_CryptoCb_AesCcmEncrypt(aes, out, in, inSz, nonce, nonceSz,
                                      authTag, authTagSz, authIn, authInSz);
        if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return crypto_cb_ret;
        /* fall-through when unavailable */
    }
#endif

    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = WC_AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[WC_AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, in, inSz, A);
    XMEMCPY(authTag, A, authTagSz);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);
    xorbuf(authTag, A, authTagSz);

    B[15] = 1;
    while (inSz >= WC_AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, WC_AES_BLOCK_SIZE);
        XMEMCPY(out, A, WC_AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        inSz -= WC_AES_BLOCK_SIZE;
        in += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, inSz);
        XMEMCPY(out, A, inSz);
    }

    ForceZero(A, WC_AES_BLOCK_SIZE);
    ForceZero(B, WC_AES_BLOCK_SIZE);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[WC_AES_BLOCK_SIZE];
    byte B[WC_AES_BLOCK_SIZE];
    byte* o;
    byte lenSz;
    word32 i, oSz;
    int result = 0;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || (inSz != 0 && (in == NULL || out == NULL)) ||
        nonce == NULL || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    if (wc_AesCcmCheckTagSize(authTagSz) != 0) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int crypto_cb_ret =
            wc_CryptoCb_AesCcmDecrypt(aes, out, in, inSz, nonce, nonceSz,
            authTag, authTagSz, authIn, authInSz);
        if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return crypto_cb_ret;
        /* fall-through when unavailable */
    }
#endif

    o = out;
    oSz = inSz;
    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = WC_AES_BLOCK_SIZE - 1 - (byte)nonceSz;

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    B[15] = 1;

    while (oSz >= WC_AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, WC_AES_BLOCK_SIZE);
        XMEMCPY(o, A, WC_AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        oSz -= WC_AES_BLOCK_SIZE;
        in += WC_AES_BLOCK_SIZE;
        o += WC_AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, oSz);
        XMEMCPY(o, A, oSz);
    }

    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);

    o = out;
    oSz = inSz;

    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[WC_AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, o, oSz, A);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, B);
    xorbuf(A, B, authTagSz);

    if (ConstantCompare(A, authTag, authTagSz) != 0) {
        /* If the authTag check fails, don't keep the decrypted data.
         * Unfortunately, you need the decrypted data to calculate the
         * check value. */
        XMEMSET(out, 0, inSz);
        result = AES_CCM_AUTH_E;
    }

    ForceZero(A, WC_AES_BLOCK_SIZE);
    ForceZero(B, WC_AES_BLOCK_SIZE);
    o = NULL;

    return result;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* !__aarch64__ */
#endif /* HAVE_AESCCM */



#ifdef HAVE_AESGCM /* common GCM functions 32 and 64 bit */
#if defined(__aarch64__)
void AES_GCM_set_key_AARCH64(Aes* aes, byte* iv)
{

    AES_encrypt_AARCH64(iv, aes->gcm.H, (byte*)aes->key, aes->rounds);
    {
        word32* pt = (word32*)aes->gcm.H;
        __asm__ volatile (
            "LD1 {v0.16b}, [%[h]] \n"
            "RBIT v0.16b, v0.16b \n"
            "ST1 {v0.16b}, [%[out]] \n"
            : [out] "=r" (pt)
            : [h] "0" (pt)
            : "cc", "memory", "v0"
        );
    }
}
#else
int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[WC_AES_BLOCK_SIZE];

    if (!((len == 16) || (len == 24) || (len == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(iv, 0, WC_AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    if (ret == 0) {
#ifdef WOLFSSL_AESGCM_STREAM
        aes->gcmKeySet = 1;
#endif

        wc_AesEncrypt(aes, iv, aes->gcm.H);
        {
            word32* pt = (word32*)aes->gcm.H;
            __asm__ volatile (
                "VLD1.32 {q0}, [%[h]] \n"
                "VREV64.8 q0, q0 \n"
                "VSWP.8 d0, d1 \n"
                "VST1.32 {q0}, [%[out]] \n"
                : [out] "=r" (pt)
                : [h] "0" (pt)
                : "cc", "memory", "q0"
            );
        }
    }

    return ret;
}
#endif

#endif /* HAVE_AESGCM */

#ifndef __aarch64__
/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
        /* Allow direct access to one block encrypt */
        int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
        {
            if (aes == NULL || out == NULL || in == NULL) {
                WOLFSSL_MSG("Invalid input to wc_AesEncryptDirect");
                return BAD_FUNC_ARG;
            }
            return wc_AesEncrypt(aes, in, out);
        }
    #ifdef HAVE_AES_DECRYPT
        /* Allow direct access to one block decrypt */
        int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
        {
            if (aes == NULL || out == NULL || in == NULL) {
                WOLFSSL_MSG("Invalid input to wc_AesDecryptDirect");
                return BAD_FUNC_ARG;
            }
            return wc_AesDecrypt(aes, in, out);
        }
    #endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT */
#endif /* !__aarch64__ */

#ifdef WOLFSSL_AES_XTS

#ifdef __aarch64__

#define AES_ENCRYPT_UPDATE_TWEAK(label)                             \
        "AESE v0.16b, v1.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AND x11, x19, x10, ASR #63\n"                              \
        "AESE v0.16b, v2.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v3.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "EXTR x10, x10, x9, #63 \n"                                 \
        "AESE v0.16b, v4.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "AESE v0.16b, v5.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "EOR x9, x11, x9, LSL #1 \n"                                \
        "AESE v0.16b, v6.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v7.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v8.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "AESE v0.16b, v9.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "SUBS WZR, %w[rounds], #10 \n"                              \
        "BLE " #label "f      \n"                                   \
        "AESE v0.16b, v10.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v11.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "SUBS WZR, %w[rounds], #12 \n"                              \
        "BLE " #label "f      \n"                                   \
        "AESE v0.16b, v12.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v13.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        #label ": \n"                                               \
        "AESE v0.16b, v14.16b \n"                                   \
        "EOR v0.16b, v0.16b, v15.16b \n"

#define AES_ENCRYPT(label)                                          \
        "AESE v0.16b, v1.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v2.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v3.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v4.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "AESE v0.16b, v5.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v6.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v7.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v8.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "AESE v0.16b, v9.16b  \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "SUBS WZR, %w[rounds], #10 \n"                              \
        "BLE " #label "f      \n"                                   \
        "AESE v0.16b, v10.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v11.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        "SUBS WZR, %w[rounds], #12 \n"                              \
        "BLE " #label "f      \n"                                   \
        "AESE v0.16b, v12.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
        "AESE v0.16b, v13.16b \n"                                   \
        "AESMC v0.16b, v0.16b \n"                                   \
                                                                    \
        #label ": \n"                                               \
        "AESE v0.16b, v14.16b \n"                                   \
        "EOR v0.16b, v0.16b, v15.16b \n"

#define AES_DECRYPT_UPDATE_TWEAK(label)                             \
        "AESD v0.16b, v1.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AND x11, x19, x10, ASR #63\n"                              \
        "AESD v0.16b, v2.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v3.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "EXTR x10, x10, x9, #63 \n"                                 \
        "AESD v0.16b, v4.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "AESD v0.16b, v5.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "EOR x9, x11, x9, LSL #1 \n"                                \
        "AESD v0.16b, v6.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v7.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v8.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "AESD v0.16b, v9.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "SUBS WZR, %w[rounds], #10 \n"                              \
        "BLE " #label "f       \n"                                  \
        "AESD v0.16b, v10.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v11.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "SUBS WZR, %w[rounds], #12 \n"                              \
        "BLE " #label "f       \n"                                  \
        "AESD v0.16b, v12.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v13.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        #label ": \n"                                               \
        "AESD v0.16b, v14.16b  \n"                                  \
        "EOR v0.16b, v0.16b, v15.16b \n"

#define AES_DECRYPT(label)                                          \
        "AESD v0.16b, v1.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v2.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v3.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v4.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "AESD v0.16b, v5.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v6.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v7.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v8.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "AESD v0.16b, v9.16b   \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "SUBS WZR, %w[rounds], #10 \n"                              \
        "BLE " #label "f       \n"                                  \
        "AESD v0.16b, v10.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v11.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        "SUBS WZR, %w[rounds], #12 \n"                              \
        "BLE " #label "f       \n"                                  \
        "AESD v0.16b, v12.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
        "AESD v0.16b, v13.16b  \n"                                  \
        "AESIMC v0.16b, v0.16b \n"                                  \
                                                                    \
        #label ": \n"                                               \
        "AESD v0.16b, v14.16b  \n"                                  \
        "EOR v0.16b, v0.16b, v15.16b \n"

/* AES with XTS mode. (XTS) XEX encryption with Tweak and cipher text Stealing.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold cipher text
 * in    input plain text buffer to encrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be WC_AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
void AES_XTS_encrypt_AARCH64(XtsAes* xaes, byte* out, const byte* in, word32 sz,
        const byte* i)
{
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    byte tmp[WC_AES_BLOCK_SIZE];

    __asm__ __volatile__ (
        "MOV x19, 0x87 \n"

        "# Load tweak calculation key\n"
        "LD1 {v0.16b}, [%[i]] \n"
        "MOV x10, %[key2] \n"
        "LD1 {v1.2d-v4.2d}, [x10], #64  \n"
        "LD1 {v5.2d-v8.2d}, [x10], #64  \n"
        "LD1 {v9.2d-v12.2d}, [x10], #64  \n"
        "LD1 {v13.2d-v15.2d}, [x10]  \n"

        "# Put last 2 blocks of keys based on rounds into v14, v15\n"
        "SUBS WZR, %w[rounds], #14 \n"
        "BEQ 40f \n"
        "SUBS WZR, %w[rounds], #12 \n"
        "MOV v14.16b, v12.16b \n"
        "MOV v15.16b, v13.16b \n"
        "BEQ 40f \n"
        "MOV v14.16b, v10.16b \n"
        "MOV v15.16b, v11.16b \n"
        "40: \n"

        AES_ENCRYPT(10)

        "MOV x9, v0.d[0] \n"
        "MOV x10, v0.d[1] \n"
        "MOV v20.16b, v0.16b \n"

        "# Load encryption key\n"
        "MOV x11, %[key] \n"
        "LD1 {v1.2d-v4.2d}, [x11], #64  \n"
        "LD1 {v5.2d-v8.2d}, [x11], #64  \n"
        "LD1 {v9.2d-v12.2d}, [x11], #64  \n"
        "LD1 {v13.2d-v15.2d}, [x11]  \n"

        "# Put last 2 blocks of keys based on rounds into v14, v15\n"
        "SUBS WZR, %w[rounds], #14 \n"
        "BEQ 41f \n"
        "SUBS WZR, %w[rounds], #10 \n"
        "MOV v14.16b, v10.16b \n"
        "MOV v15.16b, v11.16b \n"
        "BEQ 41f \n"
        "MOV v14.16b, v12.16b \n"
        "MOV v15.16b, v13.16b \n"
        "41: \n"

        "SUBS WZR, %w[blocks], #4 \n"
        "BLT 1f \n"

        "AND %w[sz], %w[sz], 0x3f \n"

        "AND x17, x19, x10, ASR #63\n"
        "EXTR x12, x10, x9, #63 \n"
        "EOR x11, x17, x9, LSL #1 \n"

        "AND x17, x19, x12, ASR #63\n"
        "EXTR x14, x12, x11, #63 \n"
        "EOR x13, x17, x11, LSL #1 \n"

        "AND x17, x19, x14, ASR #63\n"
        "EXTR x16, x14, x13, #63 \n"
        "EOR x15, x17, x13, LSL #1 \n"

        "SUB %w[blocks], %w[blocks], #4 \n"

        "#Four blocks at a time\n"
        "20:\n"

        "LD1 {v16.16b-v19.16b}, [%[in]], #64 \n"

        "MOV v21.d[0], x11 \n"
        "MOV v21.d[1], x12 \n"
        "MOV v22.d[0], x13 \n"
        "MOV v22.d[1], x14 \n"
        "MOV v23.d[0], x15 \n"
        "MOV v23.d[1], x16 \n"

        "EOR v16.16b, v16.16b, v20.16b \n"
        "EOR v17.16b, v17.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v22.16b \n"
        "EOR v19.16b, v19.16b, v23.16b \n"

        "AESE v16.16b, v1.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "AND x17, x19, x16, ASR #63\n"
        "AESE v17.16b, v1.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v1.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "EXTR x10, x16, x15, #63 \n"
        "AESE v19.16b, v1.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v2.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "EOR x9, x17, x15, LSL #1 \n"
        "AESE v17.16b, v2.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v2.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "AND x17, x19, x10, ASR #63\n"
        "AESE v19.16b, v2.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v3.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "EXTR x12, x10, x9, #63 \n"
        "AESE v17.16b, v3.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v3.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "EOR x11, x17, x9, LSL #1 \n"
        "AESE v19.16b, v3.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v4.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "AND x17, x19, x12, ASR #63\n"
        "AESE v17.16b, v4.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v4.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "EXTR x14, x12, x11, #63 \n"
        "AESE v19.16b, v4.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v16.16b, v5.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "EOR x13, x17, x11, LSL #1 \n"
        "AESE v17.16b, v5.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v5.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "AND x17, x19, x14, ASR #63\n"
        "AESE v19.16b, v5.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v6.16b  \n"
        "AESMC v16.16b, v16.16b \n"
          "EXTR x16, x14, x13, #63 \n"
        "AESE v17.16b, v6.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v6.16b  \n"
        "AESMC v18.16b, v18.16b \n"
          "EOR x15, x17, x13, LSL #1 \n"
        "AESE v19.16b, v6.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v7.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v7.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v7.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v7.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v8.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v8.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v8.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v8.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "AESE v16.16b, v9.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v9.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v9.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v9.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "SUBS WZR, %w[rounds], #10 \n"
        "BEQ 21f \n"
        "AESE v16.16b, v10.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v10.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v10.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v10.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v11.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v11.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v11.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v11.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "SUBS WZR, %w[rounds], #12 \n"
        "BEQ 21f \n"
        "AESE v16.16b, v12.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v12.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v12.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v12.16b  \n"
        "AESMC v19.16b, v19.16b \n"
        "AESE v16.16b, v13.16b  \n"
        "AESMC v16.16b, v16.16b \n"
        "AESE v17.16b, v13.16b  \n"
        "AESMC v17.16b, v17.16b \n"
        "AESE v18.16b, v13.16b  \n"
        "AESMC v18.16b, v18.16b \n"
        "AESE v19.16b, v13.16b  \n"
        "AESMC v19.16b, v19.16b \n"

        "21: \n"
        "AESE v16.16b, v14.16b  \n"
        "EOR v16.16b, v16.16b, v15.16b   \n"
        "AESE v17.16b, v14.16b  \n"
        "EOR v17.16b, v17.16b, v15.16b   \n"
        "AESE v18.16b, v14.16b  \n"
        "EOR v18.16b, v18.16b, v15.16b   \n"
        "AESE v19.16b, v14.16b  \n"
        "EOR v19.16b, v19.16b, v15.16b   \n"

        "EOR v16.16b, v16.16b, v20.16b \n"
        "EOR v17.16b, v17.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v22.16b \n"
        "EOR v19.16b, v19.16b, v23.16b \n"
        "MOV v20.d[0], x9 \n"
        "MOV v20.d[1], x10 \n"

        "ST1 {v16.16b-v19.16b}, [%[out]], #64 \n"

        "SUBS %w[blocks], %w[blocks], #4 \n"
        "BGE 20b \n"
        "ADD %w[blocks], %w[blocks], #4 \n"

        "CBZ %w[sz], 3f \n"

        "CBZ %w[blocks], 30f \n"

        "1: \n"
        "LD1 {v0.16b}, [%[in]], #16 \n"

        "MOV x9, v20.d[0] \n"
        "MOV x10, v20.d[1] \n"

        "EOR v0.16b, v0.16b, v20.16b \n"

        AES_ENCRYPT_UPDATE_TWEAK(2)

        "EOR v0.16b, v0.16b, v20.16b \n"

        "ST1 {v0.16b}, [%[out]], #16 \n"

        "MOV v20.d[0], x9 \n"
        "MOV v20.d[1], x10 \n"

        "SUBS %w[blocks], %w[blocks], #1 \n"
        "SUB %w[sz], %w[sz], #16 \n"
        "BGT 1b \n"

        "CBZ %w[sz], 3f \n"

        "30: \n"
        "#Partial block \n"
        "SUB %[out], %[out], #16 \n"
        "LD1 {v0.16b}, [%[out]], #16 \n"
        "ST1 {v0.16b}, [%[tmp]] \n"

        "MOV w12, %w[sz] \n"
        "4: \n"
        "LDRB w13, [%[tmp]] \n"
        "LDRB w14, [%[in]], #1 \n"
        "STRB w13, [%[out]], #1 \n"
        "STRB w14, [%[tmp]], #1 \n"
        "SUBS w12, w12, #1 \n"
        "BGT 4b \n"

        "SUB %[out], %[out], %x[sz] \n"
        "SUB %[tmp], %[tmp], %x[sz] \n"
        "SUB %[out], %[out], #16 \n"

        "LD1 {v0.16b}, [%[tmp]] \n"

        "EOR v0.16b, v0.16b, v20.16b \n"

        AES_ENCRYPT(5)

        "EOR v0.16b, v0.16b, v20.16b \n"

        "STR q0, [%[out]] \n"

        "3: \n"

        : [blocks] "+r" (blocks), [in] "+r" (in), [out] "+r" (out),
          [sz] "+r" (sz)
        : [key] "r" (xaes->aes.key), [rounds] "r" (xaes->aes.rounds),
          [key2] "r" (xaes->tweak.key), [i] "r" (i),
          [tmp] "r" (tmp)
        : "cc", "memory",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x19",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23"
    );
}

/* Same process as encryption but Aes key is AES_DECRYPTION type.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold plain text
 * in    input cipher text buffer to decrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be WC_AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
void AES_XTS_decrypt_AARCH64(XtsAes* xaes, byte* out, const byte* in, word32 sz,
     const byte* i)
{
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    byte tmp[WC_AES_BLOCK_SIZE];
    byte stl = (sz % WC_AES_BLOCK_SIZE);

    /* if Stealing then break out of loop one block early to handle special
     * case */
    blocks -= (stl > 0);

    __asm__ __volatile__ (
        "MOV x19, 0x87 \n"

        "LD1 {v0.16b}, [%[i]] \n"
        "MOV x10, %[key2] \n"
        "LD1 {v1.2d-v4.2d}, [x10], #64  \n"
        "LD1 {v5.2d-v8.2d}, [x10], #64  \n"
        "LD1 {v9.2d-v12.2d}, [x10], #64  \n"
        "LD1 {v13.2d-v15.2d}, [x10]  \n"

        "SUBS WZR, %w[rounds], #14 \n"
        "BEQ 40f \n"
        "SUBS WZR, %w[rounds], #12 \n"
        "MOV v14.16b, v12.16b \n"
        "MOV v15.16b, v13.16b \n"
        "BEQ 40f \n"
        "MOV v14.16b, v10.16b \n"
        "MOV v15.16b, v11.16b \n"
        "40: \n"

        AES_ENCRYPT(10)

        "MOV x9, v0.d[0] \n"
        "MOV x10, v0.d[1] \n"
        "MOV v20.16b, v0.16b \n"

        "MOV x11, %[key] \n"
        "LD1 {v1.2d-v4.2d}, [x11], #64  \n"
        "LD1 {v5.2d-v8.2d}, [x11], #64  \n"
        "LD1 {v9.2d-v12.2d}, [x11], #64  \n"
        "LD1 {v13.2d-v15.2d}, [x11]  \n"

        "SUBS WZR, %w[rounds], #14 \n"
        "BEQ 41f \n"
        "SUBS WZR, %w[rounds], #12 \n"
        "MOV v14.16b, v12.16b \n"
        "MOV v15.16b, v13.16b \n"
        "BEQ 41f \n"
        "MOV v14.16b, v10.16b \n"
        "MOV v15.16b, v11.16b \n"
        "41: \n"

        "CBZ %w[blocks], 3f \n"

        "SUBS WZR, %w[blocks], #4 \n"
        "BLT 1f \n"

        "AND x17, x19, x10, ASR #63\n"
        "EXTR x12, x10, x9, #63 \n"
        "EOR x11, x17, x9, LSL #1 \n"

        "AND x17, x19, x12, ASR #63\n"
        "EXTR x14, x12, x11, #63 \n"
        "EOR x13, x17, x11, LSL #1 \n"

        "AND x17, x19, x14, ASR #63\n"
        "EXTR x16, x14, x13, #63 \n"
        "EOR x15, x17, x13, LSL #1 \n"

        "SUB %w[blocks], %w[blocks], #4 \n"

        "#Four blocks at a time\n"
        "20:\n"

        "LD1 {v16.16b-v19.16b}, [%[in]], #64 \n"

        "MOV v21.d[0], x11 \n"
        "MOV v21.d[1], x12 \n"
        "MOV v22.d[0], x13 \n"
        "MOV v22.d[1], x14 \n"
        "MOV v23.d[0], x15 \n"
        "MOV v23.d[1], x16 \n"

        "EOR v16.16b, v16.16b, v20.16b \n"
        "EOR v17.16b, v17.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v22.16b \n"
        "EOR v19.16b, v19.16b, v23.16b \n"

        "AESD v16.16b, v1.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "AND x17, x19, x16, ASR #63\n"
        "AESD v17.16b, v1.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v1.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "EXTR x10, x16, x15, #63 \n"
        "AESD v19.16b, v1.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v2.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "EOR x9, x17, x15, LSL #1 \n"
        "AESD v17.16b, v2.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v2.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "AND x17, x19, x10, ASR #63\n"
        "AESD v19.16b, v2.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v3.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "EXTR x12, x10, x9, #63 \n"
        "AESD v17.16b, v3.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v3.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "EOR x11, x17, x9, LSL #1 \n"
        "AESD v19.16b, v3.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v4.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "AND x17, x19, x12, ASR #63\n"
        "AESD v17.16b, v4.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v4.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "EXTR x14, x12, x11, #63 \n"
        "AESD v19.16b, v4.16b  \n"
        "AESIMC v19.16b, v19.16b \n"

        "AESD v16.16b, v5.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "EOR x13, x17, x11, LSL #1 \n"
        "AESD v17.16b, v5.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v5.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "AND x17, x19, x14, ASR #63\n"
        "AESD v19.16b, v5.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v6.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
          "EXTR x16, x14, x13, #63 \n"
        "AESD v17.16b, v6.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v6.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
          "EOR x15, x17, x13, LSL #1 \n"
        "AESD v19.16b, v6.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v7.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v7.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v7.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v7.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v8.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v8.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v8.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v8.16b  \n"
        "AESIMC v19.16b, v19.16b \n"

        "AESD v16.16b, v9.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v9.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v9.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v9.16b  \n"
        "AESIMC v19.16b, v19.16b \n"

        "SUBS WZR, %w[rounds], #10 \n"
        "BEQ 21f \n"
        "AESD v16.16b, v10.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v10.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v10.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v10.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v11.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v11.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v11.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v11.16b  \n"
        "AESIMC v19.16b, v19.16b \n"

        "SUBS WZR, %w[rounds], #12 \n"
        "BEQ 21f \n"
        "AESD v16.16b, v12.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v12.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v12.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v12.16b  \n"
        "AESIMC v19.16b, v19.16b \n"
        "AESD v16.16b, v13.16b  \n"
        "AESIMC v16.16b, v16.16b \n"
        "AESD v17.16b, v13.16b  \n"
        "AESIMC v17.16b, v17.16b \n"
        "AESD v18.16b, v13.16b  \n"
        "AESIMC v18.16b, v18.16b \n"
        "AESD v19.16b, v13.16b  \n"
        "AESIMC v19.16b, v19.16b \n"

        "21: \n"
        "AESD v16.16b, v14.16b  \n"
        "EOR v16.16b, v16.16b, v15.16b   \n"
        "AESD v17.16b, v14.16b  \n"
        "EOR v17.16b, v17.16b, v15.16b   \n"
        "AESD v18.16b, v14.16b  \n"
        "EOR v18.16b, v18.16b, v15.16b   \n"
        "AESD v19.16b, v14.16b  \n"
        "EOR v19.16b, v19.16b, v15.16b   \n"

        "EOR v16.16b, v16.16b, v20.16b \n"
        "EOR v17.16b, v17.16b, v21.16b \n"
        "EOR v18.16b, v18.16b, v22.16b \n"
        "EOR v19.16b, v19.16b, v23.16b \n"
        "MOV v20.d[0], x9 \n"
        "MOV v20.d[1], x10 \n"

        "ST1 {v16.16b-v19.16b}, [%[out]], #64 \n"

        "SUBS %w[blocks], %w[blocks], #4 \n"
        "SUB %w[sz], %w[sz], #64 \n"
        "BGE 20b \n"
        "ADD %w[blocks], %w[blocks], #4 \n"

        "CBZ %w[sz], 4f \n"

        "CBZ %w[blocks], 3f \n"

        "1: \n"
        "LD1 {v0.16b}, [%[in]], #16 \n"

        "EOR v0.16b, v0.16b, v20.16b \n"

        AES_DECRYPT_UPDATE_TWEAK(2)

        "EOR v0.16b, v0.16b, v20.16b \n"

        "ST1 {v0.16b}, [%[out]], #16 \n"

        "MOV v20.d[0], x9 \n"
        "MOV v20.d[1], x10 \n"

        "SUBS %w[blocks], %w[blocks], #1 \n"
        "SUB %w[sz], %w[sz], #16 \n"
        "BGT 1b \n"

        "CBZ %w[sz], 4f \n"

        "3: \n"

        "AND x11, x19, x10, ASR #63\n"
        "EXTR x10, x10, x9, #63 \n"
        "EOR x9, x11, x9, LSL #1 \n"
        "MOV v21.d[0], x9 \n"
        "MOV v21.d[1], x10 \n"

        "LD1 {v0.16b}, [%[in]], #16 \n"

        "EOR v0.16b, v0.16b, v21.16b \n"

        AES_DECRYPT(5)

        "EOR v0.16b, v0.16b, v21.16b \n"

        "SUB %w[sz], %w[sz], #16 \n"

        "ST1 {v0.16b}, [%[tmp]] \n"
        "ADD %[out], %[out], #16 \n"
        "MOV w12, %w[sz] \n"
        "6: \n"
        "LDRB w13, [%[tmp]] \n"
        "LDRB w14, [%[in]], #1 \n"
        "STRB w13, [%[out]], #1 \n"
        "STRB w14, [%[tmp]], #1 \n"
        "SUBS w12, w12, #1 \n"
        "BGT 6b \n"
        "SUB %[out], %[out], %x[sz] \n"
        "SUB %[tmp], %[tmp], %x[sz] \n"
        "SUB %[out], %[out], #16 \n"

        "LD1 {v0.16b}, [%[tmp]] \n"

        "EOR v0.16b, v0.16b, v20.16b \n"

        AES_DECRYPT(7)

        "EOR v0.16b, v0.16b, v20.16b \n"

        "ST1 {v0.16b}, [%[out]] \n"

        "4: \n"

        : [blocks] "+r" (blocks), [in] "+r" (in), [out] "+r" (out),
          [sz] "+r" (sz)
        : [key] "r" (xaes->aes.key), [rounds] "r" (xaes->aes.rounds),
          [key2] "r" (xaes->tweak.key), [i] "r" (i),
          [tmp] "r" (tmp)
        : "cc", "memory",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x19",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
          "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23"
    );
}
#else

#define AES_ENCRYPT_UPDATE_TWEAK(label)                             \
        "AESE.8 q0, q1  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "AND %[i], r14, r12, ASR #31 \n"                            \
        "AESE.8 q0, q2  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "LSL r12, r12, #1 \n"                                       \
        "AESE.8 q0, q3  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "ORR r12, r12, r11, LSR #31 \n"                             \
        "AESE.8 q0, q4  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "LSL r11, r11, #1 \n"                                       \
                                                                    \
        "AESE.8 q0, q5  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "ORR r11, r11, r10, LSR #31 \n"                             \
        "AESE.8 q0, q6  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "LSL r10, r10, #1 \n"                                       \
        "AESE.8 q0, q7  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "ORR r10, r10, r9, LSR #31 \n"                              \
        "AESE.8 q0, q8  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "EOR r9, %[i], r9, LSL #1 \n"                               \
                                                                    \
        "AESE.8 q0, q9  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #10 \n"                                     \
        "BLE " #label "f      \n"                                   \
        "AESE.8 q0, q10 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q11 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #12 \n"                                     \
        "BLE " #label "f      \n"                                   \
        "AESE.8 q0, q10 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q11 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        #label ": \n"                                               \
        "AESE.8 q0, q10 \n"                                         \
        "VEOR q0, q0, q11 \n"

#define AES_ENCRYPT(label)                                          \
        "AESE.8 q0, q1 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q2 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q3 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q4 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
                                                                    \
        "AESE.8 q0, q5 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q6 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q7 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q8 \n"                                          \
        "AESMC.8 q0, q0 \n"                                         \
                                                                    \
        "AESE.8 q0, q9  \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #10 \n"                                     \
        "BLE " #label "f      \n"                                   \
        "AESE.8 q0, q10 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q11 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #12 \n"                                     \
        "BLE " #label "f      \n"                                   \
        "AESE.8 q0, q10 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "AESE.8 q0, q11 \n"                                         \
        "AESMC.8 q0, q0 \n"                                         \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        #label ": \n"                                               \
        "AESE.8 q0, q10 \n"                                         \
        "VEOR q0, q0, q11 \n"

#define AES_DECRYPT_UPDATE_TWEAK(label)                             \
        "AESD.8 q0, q1   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AND %[i], r14, r12, ASR #31 \n"                            \
        "AESD.8 q0, q2  \n"                                         \
        "AESIMC.8 q0, q0 \n"                                        \
        "LSL r12, r12, #1 \n"                                       \
        "AESD.8 q0, q3   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "ORR r12, r12, r11, LSR #31 \n"                             \
        "AESD.8 q0, q4   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "LSL r11, r11, #1 \n"                                       \
                                                                    \
        "AESD.8 q0, q5   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "ORR r11, r11, r10, LSR #31 \n"                             \
        "AESD.8 q0, q6   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "LSL r10, r10, #1 \n"                                       \
        "AESD.8 q0, q7   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "ORR r10, r10, r9, LSR #31 \n"                              \
        "AESD.8 q0, q8   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "EOR r9, %[i], r9, LSL #1 \n"                               \
                                                                    \
        "AESD.8 q0, q9   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #10 \n"                                     \
        "BLE " #label "f       \n"                                  \
        "AESD.8 q0, q10  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q11  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #12 \n"                                     \
        "BLE " #label "f       \n"                                  \
        "AESD.8 q0, q10  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q11  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        #label ": \n"                                               \
        "AESD.8 q0, q10  \n"                                        \
        "VEOR q0, q0, q11 \n"

#define AES_DECRYPT(label)                                          \
        "AESD.8 q0, q1  \n"                                         \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q2  \n"                                         \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q3   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q4   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
                                                                    \
        "AESD.8 q0, q5   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q6   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q7   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q8   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
                                                                    \
        "AESD.8 q0, q9   \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #10 \n"                                     \
        "BLE " #label "f       \n"                                  \
        "AESD.8 q0, q10  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q11  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        "CMP %[rounds], #12 \n"                                     \
        "BLE " #label "f       \n"                                  \
        "AESD.8 q0, q10  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "AESD.8 q0, q11  \n"                                        \
        "AESIMC.8 q0, q0 \n"                                        \
        "VLD1.32 {d20, d21, d22, d23}, [%[key2]]! \n"               \
                                                                    \
        #label ": \n"                                               \
        "AESD.8 q0, q10  \n"                                        \
        "VEOR q0, q0, q11 \n"

/* AES with XTS mode. (XTS) XEX encryption with Tweak and cipher text Stealing.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold cipher text
 * in    input plain text buffer to encrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be WC_AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
int wc_AesXtsEncrypt(XtsAes* xaes, byte* out, const byte* in, word32 sz,
        const byte* i, word32 iSz)
{
    int ret = 0;
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    byte tmp[WC_AES_BLOCK_SIZE];
    word32* key2 = xaes->tweak.key;

    if (xaes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (iSz < WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (blocks == 0) {
        WOLFSSL_MSG("Plain text input too small for encryption");
        return BAD_FUNC_ARG;
    }

    __asm__ __volatile__ (
        "MOV r14, #0x87 \n"

        "# Load tweak calculation key\n"
        "VLD1.32 {q0}, [%[i]] \n"
        "VLD1.32 {d2, d3, d4, d5}, [%[key2]]!  \n"
        "VLD1.32 {d6, d7, d8, d9}, [%[key2]]!  \n"
        "VLD1.32 {d10, d11, d12, d13}, [%[key2]]!  \n"
        "VLD1.32 {d14, d15, d16, d17}, [%[key2]]!  \n"
        "VLD1.32 {d18, d19}, [%[key2]]!  \n"

        AES_ENCRYPT(10)

        "VMOV.32 r9, d0[0] \n"
        "VMOV.32 r10, d0[1] \n"
        "VMOV.32 r11, d1[0] \n"
        "VMOV.32 r12, d1[1] \n"
        "VMOV q14, q0 \n"

        "# Load encryption key\n"
        "MOV %[key2], %[key] \n"
        "VLD1.32 {d2, d3, d4, d5}, [%[key2]]!  \n"
        "VLD1.32 {d6, d7, d8, d9}, [%[key2]]!  \n"
        "VLD1.32 {d10, d11, d12, d13}, [%[key2]]!  \n"
        "VLD1.32 {d14, d15, d16, d17}, [%[key2]]!  \n"
        "VLD1.32 {d18, d19}, [%[key2]]!  \n"

        "1: \n"
        "VLD1.32 {q0}, [%[in]]! \n"
        "ADD %[key2], %[key], #144 \n"

        "VMOV.32 r9, d28[0] \n"
        "VMOV.32 r10, d28[1] \n"
        "VMOV.32 r11, d29[0] \n"
        "VMOV.32 r12, d29[1] \n"

        "VEOR q0, q0, q14 \n"

        AES_ENCRYPT_UPDATE_TWEAK(2)

        "VEOR q0, q0, q14 \n"

        "VST1.32 {q0}, [%[out]]! \n"

        "VMOV.32 d28[0], r9 \n"
        "VMOV.32 d28[1], r10 \n"
        "VMOV.32 d29[0], r11 \n"
        "VMOV.32 d29[1], r12 \n"

        "SUBS %[blocks], %[blocks], #1 \n"
        "SUB %[sz], %[sz], #16 \n"
        "BGT 1b \n"

        "CMP %[sz], #0 \n"
        "BEQ 3f \n"

        "30: \n"
        "#Partial block \n"
        "SUB %[out], %[out], #16 \n"
        "VLD1.32 {q0}, [%[out]]! \n"
        "VST1.32 {q0}, [%[tmp]] \n"

        "MOV r9, %[sz] \n"
        "4: \n"
        "LDRB r10, [%[tmp]] \n"
        "LDRB r11, [%[in]], #1 \n"
        "STRB r10, [%[out]], #1 \n"
        "STRB r11, [%[tmp]], #1 \n"
        "SUBS r9, r9, #1 \n"
        "BGT 4b \n"

        "SUB %[out], %[out], %[sz] \n"
        "SUB %[tmp], %[tmp], %[sz] \n"
        "SUB %[out], %[out], #16 \n"

        "VLD1.32 {q0}, [%[tmp]] \n"
        "ADD %[key2], %[key], #144 \n"

        "VEOR q0, q0, q14 \n"

        AES_ENCRYPT(5)

        "VEOR q0, q0, q14 \n"

        "VST1.32 {q0}, [%[out]] \n"

        "3: \n"

        : [blocks] "+r" (blocks), [in] "+r" (in), [out] "+r" (out),
          [sz] "+r" (sz), [i] "+r" (i), [key2] "+r" (key2)
        : [key] "r" (xaes->aes.key), [rounds] "r" (xaes->aes.rounds),
          [tmp] "r" (tmp)
        : "cc", "memory",
          "r9", "r10", "r11", "r12", "r14",
          "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
          "q8", "q9", "q10", "q11", "q14"
    );

    return ret;
}

/* Same process as encryption but Aes key is AES_DECRYPTION type.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold plain text
 * in    input cipher text buffer to decrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be WC_AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
int wc_AesXtsDecrypt(XtsAes* xaes, byte* out, const byte* in, word32 sz,
        const byte* i, word32 iSz)
{
    int ret = 0;
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    byte tmp[WC_AES_BLOCK_SIZE];
    byte stl = (sz % WC_AES_BLOCK_SIZE);
    word32* key2 = xaes->tweak.key;

    if (xaes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (iSz < WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (blocks == 0) {
        WOLFSSL_MSG("Plain text input too small for encryption");
        return BAD_FUNC_ARG;
    }

    /* if Stealing then break out of loop one block early to handle special
     * case */
    blocks -= (stl > 0);

    __asm__ __volatile__ (
        "MOV r14, #0x87 \n"

        "VLD1.32 {q0}, [%[i]] \n"
        "VLD1.32 {d2, d3, d4, d5}, [%[key2]]!  \n"
        "VLD1.32 {d6, d7, d8, d9}, [%[key2]]!  \n"
        "VLD1.32 {d10, d11, d12, d13}, [%[key2]]!  \n"
        "VLD1.32 {d14, d15, d16, d17}, [%[key2]]!  \n"
        "VLD1.32 {d18, d19}, [%[key2]]!  \n"

        AES_ENCRYPT(10)

        "VMOV.32 r9, d0[0] \n"
        "VMOV.32 r10, d0[1] \n"
        "VMOV.32 r11, d1[0] \n"
        "VMOV.32 r12, d1[1] \n"
        "VMOV q14, q0 \n"

        "# Load decryption key\n"
        "MOV %[key2], %[key] \n"
        "VLD1.32 {d2, d3, d4, d5}, [%[key2]]!  \n"
        "VLD1.32 {d6, d7, d8, d9}, [%[key2]]!  \n"
        "VLD1.32 {d10, d11, d12, d13}, [%[key2]]!  \n"
        "VLD1.32 {d14, d15, d16, d17}, [%[key2]]!  \n"
        "VLD1.32 {d18, d19}, [%[key2]]!  \n"

        "CMP %[blocks], #0 \n"
        "BEQ 3f \n"

        "1: \n"
        "VLD1.32 {q0}, [%[in]]! \n"
        "ADD %[key2], %[key], #144 \n"

        "VEOR q0, q0, q14 \n"

        AES_DECRYPT_UPDATE_TWEAK(2)

        "VEOR q0, q0, q14 \n"

        "VST1.32 {q0}, [%[out]]! \n"

        "VMOV.32 d28[0], r9 \n"
        "VMOV.32 d28[1], r10 \n"
        "VMOV.32 d29[0], r11 \n"
        "VMOV.32 d29[1], r12 \n"

        "SUBS %[blocks], %[blocks], #1 \n"
        "SUB %[sz], %[sz], #16 \n"
        "BGT 1b \n"

        "CMP %[sz], #0 \n"
        "BEQ 4f \n"

        "3: \n"

        "AND %[i], r14, r12, ASR #31 \n"
        "LSL r12, r12, #1 \n"
        "ORR r12, r12, r11, LSR #31 \n"
        "LSL r11, r11, #1 \n"
        "ORR r11, r11, r10, LSR #31 \n"
        "LSL r10, r10, #1 \n"
        "ORR r10, r10, r9, LSR #31 \n"\
        "EOR r9, %[i], r9, LSL #1 \n"
        "VMOV.32 d30[0], r9 \n"
        "VMOV.32 d30[1], r10 \n"
        "VMOV.32 d31[0], r11 \n"
        "VMOV.32 d31[1], r12 \n"

        "VLD1.32 {q0}, [%[in]]! \n"
        "ADD %[key2], %[key], #144 \n"

        "VEOR q0, q0, q15 \n"

        AES_DECRYPT(5)

        "VEOR q0, q0, q15 \n"

        "SUB %[sz], %[sz], #16 \n"

        "VST1.32 {q0}, [%[tmp]] \n"
        "ADD %[out], %[out], #16 \n"
        "MOV r9, %[sz] \n"
        "6: \n"
        "LDRB r10, [%[tmp]] \n"
        "LDRB r11, [%[in]], #1 \n"
        "STRB r10, [%[out]], #1 \n"
        "STRB r11, [%[tmp]], #1 \n"
        "SUBS r9, r9, #1 \n"
        "BGT 6b \n"
        "SUB %[out], %[out], %[sz] \n"
        "SUB %[tmp], %[tmp], %[sz] \n"
        "SUB %[out], %[out], #16 \n"

        "VLD1.32 {q0}, [%[tmp]] \n"
        "ADD %[key2], %[key], #144 \n"

        "VEOR q0, q0, q14 \n"

        AES_DECRYPT(7)

        "VEOR q0, q0, q14 \n"

        "VST1.32 {q0}, [%[out]] \n"

        "4: \n"

        : [blocks] "+r" (blocks), [in] "+r" (in), [out] "+r" (out),
          [sz] "+r" (sz), [i] "+r" (i), [key2] "+r" (key2)
        : [key] "r" (xaes->aes.key), [rounds] "r" (xaes->aes.rounds),
          [tmp] "r" (tmp)
        : "cc", "memory",
          "r9", "r10", "r11", "r12", "r14",
          "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
          "q8", "q9", "q10", "q11", "q14", "q15"
    );

    return ret;
}

#endif /* __aach64__ */
#endif /* WOLFSSL_AES_XTS */

#else /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

extern void AES_set_encrypt_key(const unsigned char* key, word32 len,
    unsigned char* ks);
extern void AES_invert_key(unsigned char* ks, word32 rounds);
extern void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr);
extern void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr);
extern void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
extern void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
extern void AES_CTR_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);
#if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
/* in pre-C2x C, constness conflicts for dimensioned arrays can't be resolved. */
extern void GCM_gmult_len(byte* x, /* const */ byte m[32][WC_AES_BLOCK_SIZE],
    const unsigned char* data, unsigned long len);
#endif
extern void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);

#ifndef __aarch64__
int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
            const byte* iv, int dir)
{
#if defined(AES_MAX_KEY_SIZE)
    const word32 max_key_len = (AES_MAX_KEY_SIZE / 8);
    word32 userKey_aligned[AES_MAX_KEY_SIZE / WOLFSSL_BIT_SIZE / sizeof(word32)];
#endif

    if (((keylen != 16) && (keylen != 24) && (keylen != 32)) ||
           (aes == NULL) || (userKey == NULL)) {
        return BAD_FUNC_ARG;
    }

#if defined(AES_MAX_KEY_SIZE)
    /* Check key length */
    if (keylen > max_key_len) {
        return BAD_FUNC_ARG;
    }
#endif

#if !defined(AES_MAX_KEY_SIZE)
    /* Check alignment */
    if ((unsigned long)userKey & (sizeof(aes->key[0]) - 1U)) {
        return BAD_FUNC_ARG;
    }
#endif

#ifdef WOLF_CRYPTO_CB
    if (aes->devId != INVALID_DEVID) {
        if (keylen > sizeof(aes->devKey)) {
            return BAD_FUNC_ARG;
        }
        XMEMCPY(aes->devKey, userKey, keylen);
    }
#endif
#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS)
    aes->left = 0;
#endif

    aes->keylen = keylen;
    aes->rounds = keylen/4 + 6;

#if defined(AES_MAX_KEY_SIZE)
    if ((unsigned long)userKey & (sizeof(aes->key[0]) - 1U)) {
        XMEMCPY(userKey_aligned, userKey, keylen);
        AES_set_encrypt_key((byte *)userKey_aligned, keylen * 8, (byte*)aes->key);
    }
    else
#endif
    {
        AES_set_encrypt_key(userKey, keylen * 8, (byte*)aes->key);
    }

#ifdef HAVE_AES_DECRYPT
    if (dir == AES_DECRYPTION) {
        AES_invert_key((byte*)aes->key, aes->rounds);
    }
#else
    (void)dir;
#endif

    return wc_AesSetIV(aes, iv);
}

#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
int wc_AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
    const byte* iv, int dir)
{
    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */

/* wc_AesSetIV is shared between software and hardware */
int wc_AesSetIV(Aes* aes, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    if (iv)
        XMEMCPY(aes->reg, iv, WC_AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg,  0, WC_AES_BLOCK_SIZE);

    return 0;
}

#if defined(HAVE_AESCCM) || defined(WOLFSSL_AES_DIRECT)
static int wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }

#ifdef MAX3266X_CB /* Can do a basic ECB block */
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int ret_cb = wc_CryptoCb_AesEcbEncrypt(aes, outBlock, inBlock,
                                            WC_AES_BLOCK_SIZE);
        if (ret_cb != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return ret_cb;
        }
        /* fall-through when unavailable */
    }
#endif

    AES_ECB_encrypt(inBlock, outBlock, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    return 0;
}
#endif /* HAVE_AESCCM && WOLFSSL_AES_DIRECT */

#if defined(HAVE_AES_DECRYPT) && defined(WOLFSSL_AES_DIRECT)
static int wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }

#ifdef MAX3266X_CB /* Can do a basic ECB block */
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int ret_cb = wc_CryptoCb_AesEcbDecrypt(aes, outBlock, inBlock,
                                            WC_AES_BLOCK_SIZE);
        if (ret_cb != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret_cb;
        /* fall-through when unavailable */
    }
#endif

    AES_ECB_decrypt(inBlock, outBlock, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    return 0;
}
#endif /* HAVE_AES_DECRYPT && WOLFSSL_AES_DIRECT */

/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
/* Allow direct access to one block encrypt */
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
    if (aes == NULL || out == NULL || in == NULL) {
        WOLFSSL_MSG("Invalid input to wc_AesEncryptDirect");
        return BAD_FUNC_ARG;
    }
    return wc_AesEncrypt(aes, in, out);
}

#ifdef HAVE_AES_DECRYPT
/* Allow direct access to one block decrypt */
int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
    if (aes == NULL || out == NULL || in == NULL) {
        WOLFSSL_MSG("Invalid input to wc_AesDecryptDirect");
        return BAD_FUNC_ARG;
    }
    return wc_AesDecrypt(aes, in, out);
}
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT */

#ifdef HAVE_AES_CBC
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }

    if (sz == 0) {
        return 0;
    }
    if (sz % WC_AES_BLOCK_SIZE) {
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        return BAD_LENGTH_E;
#else
        return BAD_FUNC_ARG;
#endif
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int crypto_cb_ret = wc_CryptoCb_AesCbcEncrypt(aes, out, in, sz);
        if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return crypto_cb_ret;
        /* fall-through when unavailable */
    }
#endif

    AES_CBC_encrypt(in, out, sz, (const unsigned char*)aes->key, aes->rounds,
        (unsigned char*)aes->reg);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }

    if (sz == 0) {
        return 0;
    }
    if (sz % WC_AES_BLOCK_SIZE) {
#ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        return BAD_LENGTH_E;
#else
        return BAD_FUNC_ARG;
#endif
    }

    #ifdef WOLF_CRYPTO_CB
        #ifndef WOLF_CRYPTO_CB_FIND
        if (aes->devId != INVALID_DEVID)
        #endif
        {
            int crypto_cb_ret = wc_CryptoCb_AesCbcDecrypt(aes, out, in, sz);
            if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return crypto_cb_ret;
            /* fall-through when unavailable */
        }
    #endif

    AES_CBC_decrypt(in, out, sz, (const unsigned char*)aes->key, aes->rounds,
        (unsigned char*)aes->reg);

    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte* tmp;
    word32 numBlocks;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }
    #ifdef WOLF_CRYPTO_CB
        #ifndef WOLF_CRYPTO_CB_FIND
        if (aes->devId != INVALID_DEVID)
        #endif
        {
            int crypto_cb_ret = wc_CryptoCb_AesCtrEncrypt(aes, out, in, sz);
            if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return crypto_cb_ret;
            /* fall-through when unavailable */
        }
    #endif


    tmp = (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left;
    /* consume any unused bytes left in aes->tmp */
    while ((aes->left != 0) && (sz != 0)) {
       *(out++) = *(in++) ^ *(tmp++);
       aes->left--;
       sz--;
    }

    /* do as many block size ops as possible */
    numBlocks = sz / WC_AES_BLOCK_SIZE;
    if (numBlocks > 0) {
        AES_CTR_encrypt(in, out, numBlocks * WC_AES_BLOCK_SIZE, (byte*)aes->key,
            aes->rounds, (byte*)aes->reg);

        sz  -= numBlocks * WC_AES_BLOCK_SIZE;
        out += numBlocks * WC_AES_BLOCK_SIZE;
        in  += numBlocks * WC_AES_BLOCK_SIZE;
    }

    /* handle non block size remaining */
    if (sz) {
        byte zeros[WC_AES_BLOCK_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0 };

        AES_CTR_encrypt(zeros, (byte*)aes->tmp, WC_AES_BLOCK_SIZE, (byte*)aes->key,
            aes->rounds, (byte*)aes->reg);

        aes->left = WC_AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;

        while (sz--) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }
    return 0;
}

int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len,
        const byte* iv, int dir)
{
    (void)dir;
    return wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESCCM
/* Software version of AES-CCM from wolfcrypt/src/aes.c
 * Gets some speed up from hardware acceleration of wc_AesEncrypt */

static void roll_x(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    /* process the bulk of the data */
    while (inSz >= WC_AES_BLOCK_SIZE) {
        xorbuf(out, in, WC_AES_BLOCK_SIZE);
        in += WC_AES_BLOCK_SIZE;
        inSz -= WC_AES_BLOCK_SIZE;

        wc_AesEncrypt(aes, out, out);
    }

    /* process remainder of the data */
    if (inSz > 0) {
        xorbuf(out, in, inSz);
        wc_AesEncrypt(aes, out, out);
    }
}


static void roll_auth(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    word32 authLenSz;
    word32 remainder;

    /* encode the length in */
    if (inSz <= 0xFEFF) {
        authLenSz = 2;
        out[0] ^= ((inSz & 0xFF00) >> 8);
        out[1] ^=  (inSz & 0x00FF);
    }
    else if (inSz <= 0xFFFFFFFF) {
        authLenSz = 6;
        out[0] ^= 0xFF; out[1] ^= 0xFE;
        out[2] ^= ((inSz & 0xFF000000) >> 24);
        out[3] ^= ((inSz & 0x00FF0000) >> 16);
        out[4] ^= ((inSz & 0x0000FF00) >>  8);
        out[5] ^=  (inSz & 0x000000FF);
    }
    /* Note, the protocol handles auth data up to 2^64, but we are
     * using 32-bit sizes right now, so the bigger data isn't handled
     * else if (inSz <= 0xFFFFFFFFFFFFFFFF) {} */
    else
        return;

    /* start fill out the rest of the first block */
    remainder = WC_AES_BLOCK_SIZE - authLenSz;
    if (inSz >= remainder) {
        /* plenty of bulk data to fill the remainder of this block */
        xorbuf(out + authLenSz, in, remainder);
        inSz -= remainder;
        in += remainder;
    }
    else {
        /* not enough bulk data, copy what is available, and pad zero */
        xorbuf(out + authLenSz, in, inSz);
        inSz = 0;
    }
    wc_AesEncrypt(aes, out, out);

    if (inSz > 0)
        roll_x(aes, in, inSz, out);
}


static WC_INLINE void AesCcmCtrInc(byte* B, word32 lenSz)
{
    word32 i;

    for (i = 0; i < lenSz; i++) {
        if (++B[WC_AES_BLOCK_SIZE - 1 - i] != 0) return;
    }
}


/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[WC_AES_BLOCK_SIZE];
    byte B[WC_AES_BLOCK_SIZE];
    byte lenSz;
    word32 i;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || ((inSz > 0) && (in == NULL)) ||
        nonce == NULL || authTag == NULL || nonceSz < 7 || nonceSz > 13)
    {
        return BAD_FUNC_ARG;
    }

    if (wc_AesCcmCheckTagSize(authTagSz) != 0) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = WC_AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[WC_AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, in, inSz, A);
    XMEMCPY(authTag, A, authTagSz);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);
    xorbuf(authTag, A, authTagSz);

    B[15] = 1;
    while (inSz >= WC_AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, WC_AES_BLOCK_SIZE);
        XMEMCPY(out, A, WC_AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        inSz -= WC_AES_BLOCK_SIZE;
        in += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, inSz);
        XMEMCPY(out, A, inSz);
    }

    ForceZero(A, WC_AES_BLOCK_SIZE);
    ForceZero(B, WC_AES_BLOCK_SIZE);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[WC_AES_BLOCK_SIZE];
    byte B[WC_AES_BLOCK_SIZE];
    byte* o;
    byte lenSz;
    word32 i, oSz;
    int result = 0;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || ((inSz > 0) && (in == NULL)) ||
        nonce == NULL || authTag == NULL || nonceSz < 7 || nonceSz > 13)
    {
        return BAD_FUNC_ARG;
    }

    if (wc_AesCcmCheckTagSize(authTagSz) != 0) {
        return BAD_FUNC_ARG;
    }

    o = out;
    oSz = inSz;
    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = WC_AES_BLOCK_SIZE - 1 - (byte)nonceSz;

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    B[15] = 1;

    while (oSz >= WC_AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, WC_AES_BLOCK_SIZE);
        XMEMCPY(o, A, WC_AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        oSz -= WC_AES_BLOCK_SIZE;
        in += WC_AES_BLOCK_SIZE;
        o += WC_AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, oSz);
        XMEMCPY(o, A, oSz);
    }

    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);

    o = out;
    oSz = inSz;

    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[WC_AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, o, oSz, A);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[WC_AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, B);
    xorbuf(A, B, authTagSz);

    if (ConstantCompare(A, authTag, authTagSz) != 0) {
        /* If the authTag check fails, don't keep the decrypted data.
         * Unfortunately, you need the decrypted data to calculate the
         * check value. */
        XMEMSET(out, 0, inSz);
        result = AES_CCM_AUTH_E;
    }

    ForceZero(A, WC_AES_BLOCK_SIZE);
    ForceZero(B, WC_AES_BLOCK_SIZE);
    o = NULL;

    return result;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESCCM */

#ifdef HAVE_AESGCM
static WC_INLINE void RIGHTSHIFTX(byte* x)
{
    int i;
    int carryIn = 0;
    byte borrow = (0x00 - (x[15] & 0x01)) & 0xE1;

    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        int carryOut = (x[i] & 0x01) << 7;
        x[i] = (byte) ((x[i] >> 1) | carryIn);
        carryIn = carryOut;
    }
    x[0] ^= borrow;
}

#if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)

#if defined(__aarch64__) && !defined(BIG_ENDIAN_ORDER)
static WC_INLINE void Shift4_M0(byte *r8, byte *z8)
{
    int i;
    for (i = 15; i > 0; i--)
        r8[i] = (byte)(z8[i-1] << 4) | (byte)(z8[i] >> 4);
    r8[0] = (byte)(z8[0] >> 4);
}
#endif

void GenerateM0(Gcm* gcm)
{
#if !defined(__aarch64__) || !defined(BIG_ENDIAN_ORDER)
    int i;
#endif
    byte (*m)[WC_AES_BLOCK_SIZE] = gcm->M0;

    /* 0 times -> 0x0 */
    XMEMSET(m[0x0], 0, WC_AES_BLOCK_SIZE);
    /* 1 times -> 0x8 */
    XMEMCPY(m[0x8], gcm->H, WC_AES_BLOCK_SIZE);
    /* 2 times -> 0x4 */
    XMEMCPY(m[0x4], m[0x8], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x4]);
    /* 4 times -> 0x2 */
    XMEMCPY(m[0x2], m[0x4], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x2]);
    /* 8 times -> 0x1 */
    XMEMCPY(m[0x1], m[0x2], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x1]);

    /* 0x3 */
    XMEMCPY(m[0x3], m[0x2], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x3], m[0x1], WC_AES_BLOCK_SIZE);

    /* 0x5 -> 0x7 */
    XMEMCPY(m[0x5], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x5], m[0x1], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0x6], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x6], m[0x2], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0x7], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x7], m[0x3], WC_AES_BLOCK_SIZE);

    /* 0x9 -> 0xf */
    XMEMCPY(m[0x9], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x9], m[0x1], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xa], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xa], m[0x2], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xb], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xb], m[0x3], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xc], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xc], m[0x4], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xd], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xd], m[0x5], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xe], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xe], m[0x6], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xf], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xf], m[0x7], WC_AES_BLOCK_SIZE);

#ifndef __aarch64__
    for (i = 0; i < 16; i++) {
        word32* m32 = (word32*)gcm->M0[i];
        m32[0] = ByteReverseWord32(m32[0]);
        m32[1] = ByteReverseWord32(m32[1]);
        m32[2] = ByteReverseWord32(m32[2]);
        m32[3] = ByteReverseWord32(m32[3]);
    }
#elif !defined(BIG_ENDIAN_ORDER)
    for (i = 0; i < 16; i++) {
        Shift4_M0(m[16+i], m[i]);
    }
#endif
}
#endif /* GCM_TABLE */

int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[WC_AES_BLOCK_SIZE];

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((len != 16) && (len != 24) && (len != 32)) {
        return BAD_FUNC_ARG;
    }


    #ifdef WOLF_CRYPTO_CB
        if (aes->devId != INVALID_DEVID) {
            XMEMCPY(aes->devKey, key, len);
        }
    #endif

    XMEMSET(iv, 0, WC_AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    if (ret == 0) {
        AES_ECB_encrypt(iv, aes->gcm.H, WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds);
        #if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
            GenerateM0(&aes->gcm);
        #endif /* GCM_TABLE */
    }

    return ret;
}

#ifndef __aarch64__
static WC_INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = WC_AES_BLOCK_SIZE - 1; i >= WC_AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}
#endif

static WC_INLINE void FlattenSzInBits(byte* buf, word32 sz)
{
    /* Multiply the sz by 8 */
    word32 szHi = (sz >> (8*sizeof(sz) - 3));
    sz <<= 3;

    /* copy over the words of the sz into the destination buffer */
    buf[0] = (szHi >> 24) & 0xff;
    buf[1] = (szHi >> 16) & 0xff;
    buf[2] = (szHi >>  8) & 0xff;
    buf[3] = szHi & 0xff;
    buf[4] = (sz >> 24) & 0xff;
    buf[5] = (sz >> 16) & 0xff;
    buf[6] = (sz >>  8) & 0xff;
    buf[7] = sz & 0xff;
}

#if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
    /* GCM_gmult_len implementation in armv8-32-aes-asm or thumb2-aes-asm */
    #define GCM_GMULT_LEN(aes, x, a, len) GCM_gmult_len(x, aes->gcm.M0, a, len)
#elif defined(GCM_SMALL)
    static void GCM_gmult_len(byte* x, const byte* h,
        const unsigned char* a, unsigned long len)
    {
        byte Z[WC_AES_BLOCK_SIZE];
        byte V[WC_AES_BLOCK_SIZE];
        int i, j;

        while (len >= WC_AES_BLOCK_SIZE) {
            xorbuf(x, a, WC_AES_BLOCK_SIZE);

            XMEMSET(Z, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(V, x, WC_AES_BLOCK_SIZE);
            for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
                byte y = h[i];
                for (j = 0; j < 8; j++) {
                    if (y & 0x80) {
                        xorbuf(Z, V, WC_AES_BLOCK_SIZE);
                    }

                    RIGHTSHIFTX(V);
                    y = y << 1;
                }
            }
            XMEMCPY(x, Z, WC_AES_BLOCK_SIZE);

            len -= WC_AES_BLOCK_SIZE;
            a += WC_AES_BLOCK_SIZE;
        }
    }
    #define GCM_GMULT_LEN(aes, x, a, len) GCM_gmult_len(x, aes->gcm.H, a, len)
#else
    #error ARMv8 AES only supports GCM_TABLE or GCM_TABLE_4BIT or GCM_SMALL
#endif /* GCM_TABLE */

static void gcm_ghash_arm32(Aes* aes, const byte* a, word32 aSz, const byte* c,
    word32 cSz, byte* s, word32 sSz)
{
    byte x[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    word32 blocks, partial;

    if (aes == NULL) {
        return;
    }

    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / WC_AES_BLOCK_SIZE;
        partial = aSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, a, blocks * WC_AES_BLOCK_SIZE);
            a += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / WC_AES_BLOCK_SIZE;
        partial = cSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, c, blocks * WC_AES_BLOCK_SIZE);
            c += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}

int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks;
    word32 partial;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte x[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];

    /* sanity checks */
    if (aes == NULL || (iv == NULL && ivSz > 0) || (authTag == NULL) ||
            (authIn == NULL && authInSz > 0) || (ivSz == 0)) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ || authTagSz > WC_AES_BLOCK_SIZE) {
        WOLFSSL_MSG("GcmEncrypt authTagSz error");
        return BAD_FUNC_ARG;
    }

    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        WOLFSSL_ERROR_VERBOSE(KEYUSAGE_E);
        return KEYUSAGE_E;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int crypto_cb_ret =
            wc_CryptoCb_AesGcmEncrypt(aes, out, in, sz, iv, ivSz, authTag,
                                      authTagSz, authIn, authInSz);
        if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return crypto_cb_ret;
        /* fall-through when unavailable */
    }
#endif

    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        gcm_ghash_arm32(aes, NULL, 0, iv, ivSz, initialCounter, WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(counter, initialCounter, WC_AES_BLOCK_SIZE);

    /* Hash in the Additional Authentication Data */
    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);
    if (authInSz != 0 && authIn != NULL) {
        blocks = authInSz / WC_AES_BLOCK_SIZE;
        partial = authInSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, authIn, blocks * WC_AES_BLOCK_SIZE);
            authIn += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, authIn, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* do as many blocks as possible */
    blocks = sz / WC_AES_BLOCK_SIZE;
    partial = sz % WC_AES_BLOCK_SIZE;
    if (blocks > 0) {
        AES_GCM_encrypt(in, out, blocks * WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        GCM_GMULT_LEN(aes, x, out, blocks * WC_AES_BLOCK_SIZE);
        in += blocks * WC_AES_BLOCK_SIZE;
        out += blocks * WC_AES_BLOCK_SIZE;
    }

    /* take care of partial block sizes leftover */
    if (partial != 0) {
        AES_GCM_encrypt(in, scratch, WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        XMEMCPY(out, scratch, partial);

        XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
        XMEMCPY(scratch, out, partial);
        GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    }

    /* Hash in the lengths of A and C in bits */
    XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
    FlattenSzInBits(&scratch[0], authInSz);
    FlattenSzInBits(&scratch[8], sz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    if (authTagSz > WC_AES_BLOCK_SIZE) {
        XMEMCPY(authTag, x, WC_AES_BLOCK_SIZE);
    }
    else {
        /* authTagSz can be smaller than WC_AES_BLOCK_SIZE */
        XMEMCPY(authTag, x, authTagSz);
    }

    /* Auth tag calculation. */
    AES_ECB_encrypt(initialCounter, scratch, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    xorbuf(authTag, scratch, authTagSz);

    return 0;
}

int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    word32 blocks;
    word32 partial;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    byte x[WC_AES_BLOCK_SIZE];

    /* sanity checks */
    if (aes == NULL || iv == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        authTag == NULL || authTagSz > WC_AES_BLOCK_SIZE || authTagSz == 0 ||
        ivSz == 0) {
        WOLFSSL_MSG("a NULL parameter passed in when size is larger than 0");
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (aes->devId != INVALID_DEVID)
    #endif
    {
        int crypto_cb_ret =
            wc_CryptoCb_AesGcmDecrypt(aes, out, in, sz, iv, ivSz,
                                      authTag, authTagSz, authIn, authInSz);
        if (crypto_cb_ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return crypto_cb_ret;
        /* fall-through when unavailable */
    }
#endif

    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        gcm_ghash_arm32(aes, NULL, 0, iv, ivSz, initialCounter, WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(counter, initialCounter, WC_AES_BLOCK_SIZE);

    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);
    /* Hash in the Additional Authentication Data */
    if (authInSz != 0 && authIn != NULL) {
        blocks = authInSz / WC_AES_BLOCK_SIZE;
        partial = authInSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, authIn, blocks * WC_AES_BLOCK_SIZE);
            authIn += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, authIn, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    blocks = sz / WC_AES_BLOCK_SIZE;
    partial = sz % WC_AES_BLOCK_SIZE;
    /* do as many blocks as possible */
    if (blocks > 0) {
        GCM_GMULT_LEN(aes, x, in, blocks * WC_AES_BLOCK_SIZE);

        AES_GCM_encrypt(in, out, blocks * WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        in += blocks * WC_AES_BLOCK_SIZE;
        out += blocks * WC_AES_BLOCK_SIZE;
    }
    if (partial != 0) {
        XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
        XMEMCPY(scratch, in, partial);
        GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);

        AES_GCM_encrypt(in, scratch, WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        XMEMCPY(out, scratch, partial);
    }

    XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
    FlattenSzInBits(&scratch[0], authInSz);
    FlattenSzInBits(&scratch[8], sz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    AES_ECB_encrypt(initialCounter, scratch, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    xorbuf(x, scratch, authTagSz);
    if (authTag != NULL) {
        if (ConstantCompare(authTag, x, authTagSz) != 0) {
            return AES_GCM_AUTH_E;
        }
    }

    return 0;
}
#endif /* HAVE_AESGCM */
#endif /* !__aarch64__ */

#endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#endif /* !NO_AES && WOLFSSL_ARMASM */
