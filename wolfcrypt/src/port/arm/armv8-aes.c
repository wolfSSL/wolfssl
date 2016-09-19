/* armv8-aes.c
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

#if !defined(NO_AES) && defined(WOLFSSL_ARMASM)

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
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

            __asm__ __volatile__ (
                "LD1 {v0.16b}, [%[CtrIn]] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"

                "AESE v0.16b, v1.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v2.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v3.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v4.16b  \n"
                "AESMC v0.16b, v0.16b \n"

                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "AESE v0.16b, v1.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v2.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v3.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v4.16b  \n"
                "AESMC v0.16b, v0.16b \n"

                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESE v0.16b, v1.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v2.16b  \n"

                "#subtract rounds done so far and see if should continue\n"
                "MOV w12, %w[R]    \n"
                "SUB w12, w12, #10 \n"
                "CBZ w12, final    \n"
                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v1.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v2.16b  \n"

                "SUB w12, w12, #2 \n"
                "CBZ w12, final   \n"
                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v1.16b  \n"
                "AESMC v0.16b, v0.16b \n"
                "AESE v0.16b, v2.16b  \n"

                "#Final AddRoundKey then store result \n"
                "final: \n"
                "LD1 {v1.2d}, %[Key], #16 \n"
                "EOR v0.16b, v0.16b, v1.16b  \n"
                "ST1 {v0.16b}, [%[CtrOut]]   \n"

                :[CtrOut] "=r" (outBlock)
                :"0" (outBlock), [Key] "m" (aes->key), [R] "r" (aes->rounds),
                 [CtrIn] "r" (inBlock)
                : "cc", "memory", "w12", "v0", "v1", "v2", "v3", "v4"
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

            __asm__ __volatile__ (
                "LD1 {v0.16b}, [%[CtrIn]] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"

                "AESD v0.16b, v1.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v2.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v3.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v4.16b   \n"
                "AESIMC v0.16b, v0.16b \n"

                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "AESD v0.16b, v1.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v2.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v3.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v4.16b   \n"
                "AESIMC v0.16b, v0.16b \n"

                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESD v0.16b, v1.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v2.16b   \n"

                "#subtract rounds done so far and see if should continue\n"
                "MOV w12, %w[R]    \n"
                "SUB w12, w12, #10 \n"
                "CBZ w12, finalDec \n"
                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v1.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v2.16b   \n"

                "SUB w12, w12, #2  \n"
                "CBZ w12, finalDec \n"
                "LD1 {v1.2d-v2.2d}, %[Key], #32  \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v1.16b   \n"
                "AESIMC v0.16b, v0.16b \n"
                "AESD v0.16b, v2.16b   \n"

                "#Final AddRoundKey then store result \n"
                "finalDec: \n"
                "LD1 {v1.2d}, %[Key], #16 \n"
                "EOR v0.16b, v0.16b, v1.16b  \n"
                "ST1 {v0.4s}, [%[CtrOut]]    \n"

                :[CtrOut] "=r" (outBlock)
                :[Key] "m" (aes->key), "0" (outBlock), [R] "r" (aes->rounds),
                 [CtrIn] "r" (inBlock)
                : "cc", "memory", "w12", "v0", "v1", "v2", "v3", "v4"
            );

        return 0;
}
    #endif /* HAVE_AES_DECRYPT */
#endif /* DIRECT or COUNTER */

    static const byte rcon[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,0x1B, 0x36
        /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
    };


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

        #ifdef WOLFSSL_AES_COUNTER
            aes->left = 0;
        #endif /* WOLFSSL_AES_COUNTER */

        aes->rounds = keylen/4 + 6;
        XMEMCPY(rk, userKey, keylen);

        switch(keylen)
        {
#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 128
        case 16:
            while (1)
            {
                temp  = rk[3];

                /* get table value from hardware */
                __asm__ volatile (
                    "DUP v1.4s, %w[in]  \n"
                    "MOVI v0.16b, #0     \n"
                    "AESE v0.16b, v1.16b \n"
                    "UMOV %w[out], v0.4s[0] \n"
                    : [out] "=r"(temp)
                    : [in] "r" (temp)
                    : "cc", "memory", "v0", "v1"
                );
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

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 192
        case 24:
            /* for (;;) here triggers a bug in VC60 SP4 w/ Pro Pack */
            while (1)
            {
                temp  = rk[5];

                /* get table value from hardware */
                __asm__ volatile (
                    "DUP v1.4s, %w[in]  \n"
                    "MOVI v0.16b, #0     \n"
                    "AESE v0.16b, v1.16b \n"
                    "UMOV %w[out], v0.4s[0] \n"
                    : [out] "=r"(temp)
                    : [in] "r" (temp)
                    : "cc", "memory", "v0", "v1"
                );
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

#if defined(AES_MAX_KEY_SIZE) && AES_MAX_KEY_SIZE >= 256
        case 32:
            while (1)
            {
                temp  = rk[7];

                /* get table value from hardware */
                __asm__ volatile (
                    "DUP v1.4s, %w[in]  \n"
                    "MOVI v0.16b, #0     \n"
                    "AESE v0.16b, v1.16b \n"
                    "UMOV %w[out], v0.4s[0] \n"
                    : [out] "=r"(temp)
                    : [in] "r" (temp)
                    : "cc", "memory", "v0", "v1"
                );
                temp = rotrFixed(temp, 8);
                rk[8] = rk[0] ^ temp ^ rcon[i];
                rk[ 9] = rk[ 1] ^ rk[ 8];
                rk[10] = rk[ 2] ^ rk[ 9];
                rk[11] = rk[ 3] ^ rk[10];
                if (++i == 7)
                    break;
                temp  = rk[11];

                /* get table value from hardware */
                __asm__ volatile (
                    "DUP v1.4s, %w[in]  \n"
                    "MOVI v0.16b, #0     \n"
                    "AESE v0.16b, v1.16b \n"
                    "UMOV %w[out], v0.4s[0] \n"
                    : [out] "=r"(temp)
                    : [in] "r" (temp)
                    : "cc", "memory", "v0", "v1"
                );
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
                __asm__ volatile (
                    "LD1 {v0.16b}, [%[in]] \n"
                    "AESIMC v0.16b, v0.16b \n"
                    "ST1 {v0.16b}, [%[out]]\n"
                    : [out] "=r" (rk)
                    : [in] "0" (rk)
                    : "cc", "memory", "v0"
                );
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
        XMEMCPY(aes->reg, iv, AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg,  0, AES_BLOCK_SIZE);

    return 0;
}


/* set the heap hint for aes struct */
int wc_InitAes_h(Aes* aes, void* h)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    aes->heap = h;

    return 0;
}


/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
        /* Allow direct access to one block encrypt */
        void wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
        {
            if (aes == NULL || out == NULL || in == NULL) {
                WOLFSSL_MSG("Invalid input to wc_AesEncryptDirect");
                return;
            }
            wc_AesEncrypt(aes, in, out);
        }
    #ifdef HAVE_AES_DECRYPT
        /* Allow direct access to one block decrypt */
        void wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
        {
            if (aes == NULL || out == NULL || in == NULL) {
                WOLFSSL_MSG("Invalid input to wc_AesDecryptDirect");
                return;
            }
            wc_AesDecrypt(aes, in, out);
        }
    #endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_DIRECT */


/* AES-CBC */
#ifdef HAVE_AES_CBC
    int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
        word32 numBlocks = sz / AES_BLOCK_SIZE;

        if (aes == NULL || out == NULL || (in == NULL && sz > 0)) {
            return BAD_FUNC_ARG;
        }

        /* do as many block size ops as possible */
        if (numBlocks > 0) {
            /*
            AESE exor's input with round key
            shift rows of exor'ed result
            sub bytes for shifted rows

            note: grouping AESE & AESMC together as pairs reduces latency
            */
            switch(aes->rounds) {
            case 10: /* AES 128 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "LD1 {v5.2d-v8.2d}, %[Key], #64  \n"
                "LD1 {v9.2d-v11.2d},%[Key], #48  \n"
                "LD1 {v0.2d}, %[reg] \n"
                "LD1 {v12.2d}, [%[input]],  #16  \n"

                "AESCBC128Block:\n"
                "#CBC operations, xorbuf in with current aes->reg \n"
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
                "EOR v0.16b, v0.16b, v11.16b  \n"
                "SUB w11, w11, #1 \n"
                "ST1 {v0.2d}, [%[out]], #16   \n"

                "CBZ w11, AESCBC128end \n"
                "LD1 {v12.2d}, [%[input]], #16 \n"
                "B AESCBC128Block \n"

                "AESCBC128end:\n"
                "#store current counter value at the end \n"
                "ST1 {v0.2d}, %[regOut] \n"

                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12"
                );
                break;

            case 12: /* AES 192 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "LD1 {v5.2d-v8.2d}, %[Key], #64  \n"
                "LD1 {v9.2d-v12.2d},%[Key], #64  \n"
                "LD1 {v13.2d}, %[Key], #16 \n"
                "LD1 {v0.2d}, %[reg] \n"

                "LD1 {v14.2d}, [%[input]], #16  \n"
                "AESCBC192Block:\n"
                "#CBC operations, xorbuf in with current aes->reg \n"
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

                "CBZ w11, AESCBC192end \n"
                "LD1 {v14.2d}, [%[input]], #16\n"
                "B AESCBC192Block \n"

                "AESCBC192end:\n"
                "#store current counter value at the end \n"
                "ST1 {v0.2d}, %[regOut]   \n"


                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14"
                );
                break;

            case 14: /* AES 256 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d},   %[Key], #64 \n"
                "LD1 {v5.2d-v8.2d},   %[Key], #64 \n"
                "LD1 {v9.2d-v12.2d},  %[Key], #64 \n"
                "LD1 {v13.2d-v15.2d}, %[Key], #48 \n"
                "LD1 {v0.2d}, %[reg] \n"

                "LD1 {v16.2d}, [%[input]], #16  \n"
                "AESCBC256Block: \n"
                "#CBC operations, xorbuf in with current aes->reg \n"
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

                "CBZ w11, AESCBC256end \n"
                "LD1 {v16.2d}, [%[input]], #16 \n"
                "B AESCBC256Block \n"

                "AESCBC256end: \n"
                "#store current counter value at the end \n"
                "ST1 {v0.2d}, %[regOut]   \n"


                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14","v15",
                "v16"
                );
                break;

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
        word32 numBlocks = sz / AES_BLOCK_SIZE;

        if (aes == NULL || out == NULL || (in == NULL && sz > 0)) {
            return BAD_FUNC_ARG;
        }

        /* do as many block size ops as possible */
        if (numBlocks > 0) {
            switch(aes->rounds) {
            case 10: /* AES 128 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "LD1 {v5.2d-v8.2d}, %[Key], #64  \n"
                "LD1 {v9.2d-v11.2d},%[Key], #48  \n"
                "LD1 {v13.2d}, %[reg] \n"

                "AESCBC128BlockDec:\n"
                "LD1 {v0.2d}, [%[input]], #16  \n"
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

                "CBZ w11, AESCBC128endDec \n"
                "B AESCBC128BlockDec      \n"

                "AESCBC128endDec: \n"
                "#store current counter value at the end \n"
                "ST1 {v13.2d}, %[regOut] \n"

                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13"
                );
                break;

            case 12: /* AES 192 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d}, %[Key], #64  \n"
                "LD1 {v5.2d-v8.2d}, %[Key], #64  \n"
                "LD1 {v9.2d-v12.2d},%[Key], #64  \n"
                "LD1 {v13.16b}, %[Key], #16 \n"
                "LD1 {v15.2d}, %[reg]       \n"

                "LD1 {v0.2d}, [%[input]], #16  \n"
                "AESCBC192BlockDec:    \n"
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

                "CBZ w11, AESCBC192endDec \n"
                "LD1 {v0.2d}, [%[input]], #16 \n"
                "B AESCBC192BlockDec \n"

                "AESCBC192endDec:\n"
                "#store current counter value at the end \n"
                "ST1 {v15.2d}, %[regOut] \n"

                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"
                );
                break;

            case 14: /* AES 256 BLOCK */
                __asm__ __volatile__ (
                "MOV w11, %w[blocks] \n"
                "LD1 {v1.2d-v4.2d},   %[Key], #64  \n"
                "LD1 {v5.2d-v8.2d},   %[Key], #64  \n"
                "LD1 {v9.2d-v12.2d},  %[Key], #64  \n"
                "LD1 {v13.2d-v15.2d}, %[Key], #48  \n"
                "LD1 {v17.2d}, %[reg] \n"

                "LD1 {v0.2d}, [%[input]], #16  \n"
                "AESCBC256BlockDec:    \n"
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

                "CBZ w11, AESCBC256endDec \n"
                "LD1 {v0.2d}, [%[input]], #16  \n"
                "B AESCBC256BlockDec \n"

                "AESCBC256endDec:\n"
                "#store current counter value at the end \n"
                "ST1 {v17.2d}, %[regOut]   \n"

                :[out] "=r" (out), [regOut] "=m" (aes->reg)
                :"0" (out), [Key] "m" (aes->key), [input] "r" (in),
                 [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14","v15",
                "v16", "v17"
                );
                break;

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

        /* Increment AES counter */
        static INLINE void IncrementAesCounter(byte* inOutCtr)
        {
            int i;

            /* in network byte order so start at end and work back */
            for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                if (++inOutCtr[i])  /* we're done unless we overflow */
                    return;
            }
        }

        void wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
        {
            byte* tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
            word32 numBlocks;

            /* consume any unused bytes left in aes->tmp */
            while (aes->left && sz) {
               *(out++) = *(in++) ^ *(tmp++);
               aes->left--;
               sz--;
            }

            /* do as many block size ops as possible */
            numBlocks = sz/AES_BLOCK_SIZE;
            if (numBlocks > 0) {
                /* pointer needed because it is incremented when read, causing
                 * an issue with call to encrypt/decrypt leftovers */
                byte*  keyPt  = (byte*)aes->key;
                sz           -= numBlocks * AES_BLOCK_SIZE;
                switch(aes->rounds) {
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
    
                    "LD1 {v12.2d}, [%[input]], #16    \n"
                    "AESCTR128Block:      \n"
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
                    "EOR v0.16b, v0.16b, v12.16b \n"
                    "ST1 {v0.2d}, [%[out]], #16  \n"
    
                    "CBZ w11, AESCTRend \n"
                    "LD1 {v12.2d}, [%[input]], #16  \n"
                    "B AESCTR128Block \n"
    
                    "AESCTRend: \n"
                    "#store current counter value at the end \n"
                    "ST1 {v13.2d}, %[regOut]   \n"
    
                    :[out] "=r" (out), "=r" (keyPt), [regOut] "=m" (aes->reg), 
                     "=r" (in)
                    :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
                     [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                    : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                    "v6", "v7", "v8", "v9", "v10","v11","v12","v13","v14"
                    );
                    break;

                case 12: /* AES 192 BLOCK */
                    __asm__ __volatile__ (
                    "MOV w11, %w[blocks]              \n"
                    "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"

                    "#Create vector with the value 1  \n"
                    "MOVI v16.16b, #1                 \n"
                    "USHR v16.2d, v16.2d, #56         \n"
                    "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
                    "EOR v14.16b, v14.16b, v14.16b    \n"
                    "EXT v16.16b, v18.16b, v14.16b, #8\n"

                    "LD1 {v9.2d-v12.2d}, [%[Key]], #64\n"
                    "LD1 {v15.2d}, %[reg]             \n"
                    "LD1 {v13.16b}, [%[Key]], #16     \n"
                    "LD1 {v14.2d}, [%[input]], #16    \n"

                    "AESCTR192Block:      \n"
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

                    "CBZ w11, AESCTR192end \n"
                    "LD1 {v14.2d}, [%[input]], #16 \n"
                    "B AESCTR192Block \n"

                    "AESCTR192end: \n"
                    "#store current counter value at the end \n"
                    "ST1 {v15.2d}, %[regOut] \n"

                    :[out] "=r" (out), "=r" (keyPt), [regOut] "=m" (aes->reg),
                     "=r" (in)
                    :"0" (out), [Key] "1" (keyPt), [input] "3" (in),
                     [blocks] "r" (numBlocks), [reg] "m" (aes->reg)
                    : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
                    "v6", "v7", "v8", "v9", "v10","v11","v12","v13","v14","v15",
                    "v16"
                    );
                    break;

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

                    "LD1 {v16.2d}, [%[input]], #16 \n"
                    "AESCTR256Block:      \n"
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
                    "AESE v0.16b, v4.16b  \n"
                    "AESMC v0.16b, v0.16b \n"
                    "SUB w11, w11, #1     \n"
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

                    "CBZ w11, AESCTR256end \n"
                    "LD1 {v16.2d}, [%[input]], #16 \n"
                    "B AESCTR256Block \n"

                    "AESCTR256end: \n"
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

                default:
                    WOLFSSL_MSG("Bad AES-CTR round value");
                    return;
                }

                aes->left = 0;
            }

            /* handle non block size remaining */
            if (sz) {
                wc_AesEncrypt(aes, (byte*)aes->reg, (byte*)aes->tmp);
                IncrementAesCounter((byte*)aes->reg);

                aes->left = AES_BLOCK_SIZE;
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

enum {
    NONCE_SZ = 12,
    CTR_SZ   = 4
};


static INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = AES_BLOCK_SIZE - 1; i >= AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}


static INLINE void FlattenSzInBits(byte* buf, word32 sz)
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


#if !defined(__aarch64__)
static INLINE void RIGHTSHIFTX(byte* x)
{
    int i;
    int carryOut = 0;
    int carryIn = 0;
    int borrow = x[15] & 0x01;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        carryOut = x[i] & 0x01;
        x[i] = (x[i] >> 1) | (carryIn ? 0x80 : 0);
        carryIn = carryOut;
    }
    if (borrow) x[0] ^= 0xE1;
}
#endif

int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[AES_BLOCK_SIZE];

    if (!((len == 16) || (len == 24) || (len == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(iv, 0, AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    if (ret == 0) {
        wc_AesEncrypt(aes, iv, aes->H);
    #if defined(__aarch64__)
        {
            word32* pt = (word32*)aes->H;
            __asm__ volatile (
                "LD1 {v0.16b}, [%[h]] \n"
                "RBIT v0.16b, v0.16b \n"
                "ST1 {v0.16b}, [%[out]] \n"
                : [out] "=r" (pt)
                : [h] "0" (pt)
                : "cc", "memory"
            );
        }
    #endif
    }

    return ret;
}


#if defined(__aarch64__)
/* PMULL and RBIT only with AArch64 */
/* Use ARM hardware for polynomial multiply */
static void GMULT(byte* X, byte* Y)
{
    __asm__ volatile (
        "LD1 {v0.16b}, [%[inX]] \n"
        "LD1 {v1.16b}, [%[inY]] \n" /* v1 already reflected from set key */
        "RBIT v0.16b, v0.16b \n"


        /* Algorithm 1 from Intel GCM white paper.
           "Carry-Less Multiplication and Its Usage for Computing the GCM Mode"
         */
        "PMULL  v3.1q, v0.1d, v1.1d \n"     /* a0 * b0 = C */
        "PMULL2 v4.1q, v0.2d, v1.2d \n"     /* a1 * b1 = D */
        "EXT v5.16b, v1.16b, v1.16b, #8 \n" /* b0b1 -> b1b0 */
        "PMULL  v6.1q, v0.1d, v5.1d \n"     /* a0 * b1 = E */
        "PMULL2 v5.1q, v0.2d, v5.2d \n"     /* a1 * b0 = F */

        "#Set a register to all 0s using EOR \n"
        "EOR v7.16b, v7.16b, v7.16b \n"
        "EOR v5.16b, v5.16b, v6.16b \n"     /* F ^ E */
        "EXT v6.16b, v7.16b, v5.16b, #8 \n" /* get (F^E)[0] */
        "EOR v3.16b, v3.16b, v6.16b \n"     /* low 128 bits in v3 */
        "EXT v6.16b, v5.16b, v7.16b, #8 \n" /* get (F^E)[1] */
        "EOR v4.16b, v4.16b, v6.16b \n"     /* high 128 bits in v4 */


        /* Based from White Paper "Implementing GCM on ARMv8"
           by Conrado P.L. Gouvea and Julio Lopez
           reduction on 256bit value using Algorithm 5 */
        "MOVI v8.16b, #0x87 \n"
        "USHR v8.2d, v8.2d, #56 \n"
        /* v8 is now 0x00000000000000870000000000000087 reflected 0xe1....*/
        "PMULL2 v5.1q, v4.2d, v8.2d \n"
        "EXT v6.16b, v5.16b, v7.16b, #8 \n" /* v7 is all 0's */
        "EOR v4.16b, v4.16b, v6.16b \n"
        "EXT v6.16b, v7.16b, v5.16b, #8 \n"
        "EOR v3.16b, v3.16b, v6.16b \n"
        "PMULL v5.1q, v4.1d, v8.1d  \n"
        "EOR v4.16b, v3.16b, v5.16b \n"

        "RBIT v4.16b, v4.16b \n"
        "STR q4, [%[out]] \n"
        : [out] "=r" (X), "=r" (Y)
        : [inX] "0" (X), [inY] "1" (Y)
        : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"
    );
}
#else
static void GMULT(byte* X, byte* Y)
{
    byte Z[AES_BLOCK_SIZE];
    byte V[AES_BLOCK_SIZE];
    int i, j;

    XMEMSET(Z, 0, AES_BLOCK_SIZE);
    XMEMCPY(V, X, AES_BLOCK_SIZE);
    for (i = 0; i < AES_BLOCK_SIZE; i++)
    {
        byte y = Y[i];
        for (j = 0; j < 8; j++)
        {
            if (y & 0x80) {
                xorbuf(Z, V, AES_BLOCK_SIZE);
            }

            RIGHTSHIFTX(V);
            y = y << 1;
        }
    }
    XMEMCPY(X, Z, AES_BLOCK_SIZE);
}
#endif

/* Currently is a copy from GCM_SMALL wolfSSL version. Duplicated and set
 * seperate for future optimizations. */
static void GHASH(Aes* aes, const byte* a, word32 aSz,
                                const byte* c, word32 cSz, byte* s, word32 sSz)
{
    byte x[AES_BLOCK_SIZE];
    byte scratch[AES_BLOCK_SIZE];
    word32 blocks, partial;
    byte* h = aes->H;

    XMEMSET(x, 0, AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / AES_BLOCK_SIZE;
        partial = aSz % AES_BLOCK_SIZE;
        /* do as many blocks as possible */
        while (blocks--) {
            xorbuf(x, a, AES_BLOCK_SIZE);
            GMULT(x, h);
            a += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            xorbuf(x, scratch, AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / AES_BLOCK_SIZE;
        partial = cSz % AES_BLOCK_SIZE;
        while (blocks--) {
            xorbuf(x, c, AES_BLOCK_SIZE);
            GMULT(x, h);
            c += AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            xorbuf(x, scratch, AES_BLOCK_SIZE);
            GMULT(x, h);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    xorbuf(x, scratch, AES_BLOCK_SIZE);
    GMULT(x, h);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}


int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* p = in;
    byte* c = out;
    byte counter[AES_BLOCK_SIZE];
    byte initialCounter[AES_BLOCK_SIZE];
    byte *ctr ;
    byte scratch[AES_BLOCK_SIZE];

    ctr = counter ;

    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    if (ivSz == NONCE_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(aes, NULL, 0, iv, ivSz, initialCounter, AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, AES_BLOCK_SIZE);

    /* do as many blocks as possible */
    if (blocks > 0) {
        /* pointer needed because it is incremented when read, causing
         * an issue with call to encrypt/decrypt leftovers */
        byte*  keyPt  = (byte*)aes->key;
        switch(aes->rounds) {
        case 10: /* AES 128 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64 \n"

            "#Create vector with the value 1  \n"
            "MOVI v14.16b, #1                 \n"
            "USHR v14.2d, v14.2d, #56         \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
            "EOR v13.16b, v13.16b, v13.16b    \n"
            "EXT v14.16b, v14.16b, v13.16b, #8\n"

            "LD1 {v9.2d-v11.2d}, [%[Key]], #48\n"
            "LD1 {v13.2d}, [%[ctr]] \n"

            "LD1 {v12.2d}, [%[input]], #16 \n"
            "AESGCM128Block: \n"
            "REV64 v13.16b, v13.16b \n" /* network order */
            "EXT v13.16b, v13.16b, v13.16b, #8 \n"
            "ADD v13.2d, v13.2d, v14.2d \n" /* add 1 to counter */
            "EXT v13.16b, v13.16b, v13.16b, #8 \n"
            "REV64 v13.16b, v13.16b \n" /* revert from network order */
            "MOV v0.16b, v13.16b  \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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
            "EOR v0.16b, v0.16b, v11.16b \n"

            "EOR v0.16b, v0.16b, v12.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCMend \n"
            "LD1 {v12.2d}, [%[input]], #16 \n"
            "B AESGCM128Block \n"

            "AESGCMend: \n"
            "#store current counter value at the end \n"
            "ST1 {v13.2d}, [%[ctrOut]] \n"

            :[out] "=r" (c), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (p)
            :"0" (c), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (p)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14"
            );
            break;

        case 12: /* AES 192 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64\n"

            "#Create vector with the value 1  \n"
            "MOVI v16.16b, #1                 \n"
            "USHR v16.2d, v16.2d, #56         \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64 \n"
            "EOR v14.16b, v14.16b, v14.16b    \n"
            "EXT v16.16b, v16.16b, v14.16b, #8\n"

            "LD1 {v9.2d-v12.2d}, [%[Key]], #64\n"
            "LD1 {v13.2d}, [%[Key]], #16      \n"
            "LD1 {v14.2d}, [%[input]], #16    \n"
            "LD1 {v15.2d}, [%[ctr]]           \n"

            "AESGCM192Block: \n"
            "REV64 v15.16b, v15.16b \n" /* network order */
            "EXT v15.16b, v15.16b, v15.16b, #8 \n"
            "ADD v15.2d, v15.2d, v16.2d \n" /* add 1 to counter */
            "EXT v15.16b, v15.16b, v15.16b, #8 \n"
            "REV64 v15.16b, v15.16b \n" /* revert from network order */
            "MOV v0.16b, v15.16b  \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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
            "EOR v0.16b, v0.16b, v13.16b \n"

            "EOR v0.16b, v0.16b, v14.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCM192end \n"
            "LD1 {v14.2d}, [%[input]], #16 \n"
            "B AESGCM192Block \n"

            "AESGCM192end: \n"
            "#store current counter value at the end \n"
            "ST1 {v15.16b}, [%[ctrOut]]   \n"

            :[out] "=r" (c), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (p)
            :"0" (c), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (p)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16"
            );
            break;
        case 14: /* AES 256 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64  \n"

            "#Create vector with the value 1   \n"
            "MOVI v18.16b, #1                  \n"
            "USHR v18.2d, v18.2d, #56          \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64  \n"
            "EOR v19.16b, v19.16b, v19.16b     \n"
            "EXT v18.16b, v18.16b, v19.16b, #8 \n"

            "LD1 {v9.2d-v12.2d}, [%[Key]], #64  \n"
            "LD1 {v17.2d}, [%[ctr]]             \n"
            "LD1 {v13.2d-v15.2d}, [%[Key]], #48 \n"
            "LD1 {v16.2d}, [%[input]], #16      \n"

            "AESGCM256Block: \n"
            "REV64 v17.16b, v17.16b \n" /* network order */
            "EXT v17.16b, v17.16b, v17.16b, #8 \n"
            "ADD v17.2d, v17.2d, v18.2d \n" /* add 1 to counter */
            "EXT v17.16b, v17.16b, v17.16b, #8 \n"
            "REV64 v17.16b, v17.16b \n" /* revert from network order */
            "MOV v0.16b, v17.16b \n"

            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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

            "EOR v0.16b, v0.16b, v16.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCM256end \n"
            "LD1 {v16.2d}, [%[input]], #16 \n"
            "B AESGCM256Block \n"

            "AESGCM256end:\n"
            "#store current counter value at the end \n"
            "ST1 {v17.2d}, [%[ctrOut]] \n"

            :[out] "=r" (c), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (p)
            :"0" (c), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (p)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19"
            );
            break;

        default:
            WOLFSSL_MSG("Bad AES-GCM round value");
            return BAD_FUNC_ARG;
        }
    }

    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, p, partial);
        XMEMCPY(c, scratch, partial);

    }

    GHASH(aes, authIn, authInSz, out, sz, authTag, authTagSz);
    wc_AesEncrypt(aes, initialCounter, scratch);
    xorbuf(authTag, scratch, authTagSz);

    return 0;
}


#ifdef HAVE_AES_DECRYPT
int  wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* c = in;
    byte* p = out;
    byte counter[AES_BLOCK_SIZE];
    byte initialCounter[AES_BLOCK_SIZE];
    byte *ctr ;
    byte scratch[AES_BLOCK_SIZE];

    ctr = counter ;

    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    if (ivSz == NONCE_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(aes, NULL, 0, iv, ivSz, initialCounter, AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, AES_BLOCK_SIZE);

    /* Calculate the authTag again using the received auth data and the
     * cipher text. */
    {
        byte Tprime[AES_BLOCK_SIZE];
        byte EKY0[AES_BLOCK_SIZE];

        GHASH(aes, authIn, authInSz, in, sz, Tprime, sizeof(Tprime));
        wc_AesEncrypt(aes, ctr, EKY0);
        xorbuf(Tprime, EKY0, sizeof(Tprime));

        if (ConstantCompare(authTag, Tprime, authTagSz) != 0) {
            return AES_GCM_AUTH_E;
        }
    }

    /* do as many blocks as possible */
    if (blocks > 0) {
        /* pointer needed because it is incremented when read, causing
         * an issue with call to encrypt/decrypt leftovers */
        byte*  keyPt  = (byte*)aes->key;
        switch(aes->rounds) {
        case 10: /* AES 128 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64  \n"

            "#Create vector with the value 1   \n"
            "MOVI v14.16b, #1                  \n"
            "USHR v14.2d, v14.2d, #56          \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64  \n"
            "EOR v13.16b, v13.16b, v13.16b     \n"
            "EXT v14.16b, v14.16b, v13.16b, #8 \n"

            "LD1 {v9.2d-v11.2d}, [%[Key]], #48 \n"
            "LD1 {v12.2d}, [%[ctr]]            \n"
            "LD1 {v13.2d}, [%[input]], #16     \n"

            "AESGCM128BlockDec: \n"
            "REV64 v12.16b, v12.16b \n" /* network order */
            "EXT v12.16b, v12.16b, v12.16b, #8 \n"
            "ADD v12.2d, v12.2d, v14.2d \n" /* add 1 to counter */
            "EXT v12.16b, v12.16b, v12.16b, #8 \n"
            "REV64 v12.16b, v12.16b \n" /* revert from network order */
            "MOV v0.16b, v12.16b  \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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
            "EOR v0.16b, v0.16b, v11.16b \n"

            "EOR v0.16b, v0.16b, v13.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCMendDec \n"
            "LD1 {v13.2d}, [%[input]], #16 \n"
            "B AESGCM128BlockDec \n"

            "AESGCMendDec: \n"
            "#store current counter value at the end \n"
            "ST1 {v12.16b}, [%[ctrOut]] \n"

            :[out] "=r" (p), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (c)
            :"0" (p), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (c)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14"
            );
            break;

        case 12: /* AES 192 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64  \n"

            "#Create vector with the value 1   \n"
            "MOVI v16.16b, #1                  \n"
            "USHR v16.2d, v16.2d, #56          \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64  \n"
            "EOR v14.16b, v14.16b, v14.16b     \n"
            "EXT v16.16b, v16.16b, v14.16b, #8 \n"

            "LD1 {v9.2d-v12.2d}, [%[Key]], #64 \n"
            "LD1 {v13.2d}, [%[Key]], #16       \n"
            "LD1 {v14.2d}, [%[ctr]]            \n"
            "LD1 {v15.2d}, [%[input]], #16     \n"

            "AESGCM192BlockDec: \n"
            "REV64 v14.16b, v14.16b \n" /* network order */
            "EXT v14.16b, v14.16b, v14.16b, #8 \n"
            "ADD v14.2d, v14.2d, v16.2d \n" /* add 1 to counter */
            "EXT v14.16b, v14.16b, v14.16b, #8 \n"
            "REV64 v14.16b, v14.16b \n" /* revert from network order */
            "MOV v0.16b, v14.16b  \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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
            "EOR v0.16b, v0.16b, v13.16b \n"

            "EOR v0.16b, v0.16b, v15.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCM192endDec \n"
            "LD1 {v15.2d}, [%[input]], #16 \n"
            "B AESGCM192BlockDec \n"

            "AESGCM192endDec: \n"
            "#store current counter value at the end \n"
            "ST1 {v14.2d}, [%[ctrOut]]   \n"

            :[out] "=r" (p), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (c)
            :"0" (p), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (c)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16"
            );
            break;
        case 14: /* AES 256 BLOCK */
            __asm__ __volatile__ (
            "MOV w11, %w[blocks] \n"
            "LD1 {v1.2d-v4.2d}, [%[Key]], #64  \n"

            "#Create vector with the value 1   \n"
            "MOVI v18.16b, #1                  \n"
            "USHR v18.2d, v18.2d, #56          \n"
            "LD1 {v5.2d-v8.2d}, [%[Key]], #64  \n"
            "EOR v19.16b, v19.16b, v19.16b     \n"
            "EXT v18.16b, v18.16b, v19.16b, #8 \n"

            "LD1 {v9.2d-v12.2d},  [%[Key]], #64 \n"
            "LD1 {v13.2d-v15.2d}, [%[Key]], #48 \n"
            "LD1 {v17.2d}, [%[ctr]]             \n"
            "LD1 {v16.2d}, [%[input]], #16      \n"

            "AESGCM256BlockDec: \n"
            "REV64 v17.16b, v17.16b \n" /* network order */
            "EXT v17.16b, v17.16b, v17.16b, #8 \n"
            "ADD v17.2d, v17.2d, v18.2d \n" /* add 1 to counter */
            "EXT v17.16b, v17.16b, v17.16b, #8 \n"
            "REV64 v17.16b, v17.16b \n" /* revert from network order */
            "MOV v0.16b, v17.16b  \n"
            "AESE v0.16b, v1.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v2.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v3.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "AESE v0.16b, v4.16b  \n"
            "AESMC v0.16b, v0.16b \n"
            "SUB w11, w11, #1     \n"
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

            "EOR v0.16b, v0.16b, v16.16b \n"
            "ST1 {v0.2d}, [%[out]], #16  \n"

            "CBZ w11, AESGCM256endDec \n"
            "LD1 {v16.2d}, [%[input]], #16 \n"
            "B AESGCM256BlockDec \n"

            "AESGCM256endDec: \n"
            "#store current counter value at the end \n"
            "ST1 {v17.2d}, [%[ctrOut]] \n"

            :[out] "=r" (p), "=r" (keyPt), [ctrOut] "=r" (ctr), "=r" (c)
            :"0" (p), [Key] "1" (keyPt), [ctr] "2" (ctr), [blocks] "r" (blocks),
             [input] "3" (c)
            : "cc", "memory", "w11", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19"
            );
            break;

        default:
            WOLFSSL_MSG("Bad AES-GCM round value");
            return BAD_FUNC_ARG;
        }
    }
    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, c, partial);
        XMEMCPY(p, scratch, partial);
    }
    return 0;
}

#endif /* HAVE_AES_DECRYPT */

WOLFSSL_API int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len)
{
    return wc_AesGcmSetKey(&gmac->aes, key, len);
}


WOLFSSL_API int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                              const byte* authIn, word32 authInSz,
                              byte* authTag, word32 authTagSz)
{
    return wc_AesGcmEncrypt(&gmac->aes, NULL, NULL, 0, iv, ivSz,
                                         authTag, authTagSz, authIn, authInSz);
}

#endif /* HAVE_AESGCM */


#ifdef HAVE_AESCCM
/* Software version of AES-CCM from wolfcrypt/src/aes.c
 * Gets some speed up from hardware acceleration of wc_AesEncrypt */

void wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    byte nonce[AES_BLOCK_SIZE];

    if (!((keySz == 16) || (keySz == 24) || (keySz == 32)))
        return;

    XMEMSET(nonce, 0, sizeof(nonce));
    wc_AesSetKey(aes, key, keySz, nonce, AES_ENCRYPTION);
}


static void roll_x(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    /* process the bulk of the data */
    while (inSz >= AES_BLOCK_SIZE) {
        xorbuf(out, in, AES_BLOCK_SIZE);
        in += AES_BLOCK_SIZE;
        inSz -= AES_BLOCK_SIZE;

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
    remainder = AES_BLOCK_SIZE - authLenSz;
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


static INLINE void AesCcmCtrInc(byte* B, word32 lenSz)
{
    word32 i;

    for (i = 0; i < lenSz; i++) {
        if (++B[AES_BLOCK_SIZE - 1 - i] != 0) return;
    }
}


/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[AES_BLOCK_SIZE];
    byte B[AES_BLOCK_SIZE];
    byte lenSz;
    word32 i;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, in, inSz, A);
    XMEMCPY(authTag, A, authTagSz);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);
    xorbuf(authTag, A, authTagSz);

    B[15] = 1;
    while (inSz >= AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, AES_BLOCK_SIZE);
        XMEMCPY(out, A, AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        inSz -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, inSz);
        XMEMCPY(out, A, inSz);
    }

    ForceZero(A, AES_BLOCK_SIZE);
    ForceZero(B, AES_BLOCK_SIZE);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[AES_BLOCK_SIZE];
    byte B[AES_BLOCK_SIZE];
    byte* o;
    byte lenSz;
    word32 i, oSz;
    int result = 0;
    byte mask     = 0xFF;
    word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    o = out;
    oSz = inSz;
    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    B[15] = 1;

    while (oSz >= AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, AES_BLOCK_SIZE);
        XMEMCPY(o, A, AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        oSz -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        o += AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, oSz);
        XMEMCPY(o, A, oSz);
    }

    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);

    o = out;
    oSz = inSz;

    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, o, oSz, A);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, B);
    xorbuf(A, B, authTagSz);

    if (ConstantCompare(A, authTag, authTagSz) != 0) {
        /* If the authTag check fails, don't keep the decrypted data.
         * Unfortunately, you need the decrypted data to calculate the
         * check value. */
        XMEMSET(out, 0, inSz);
        result = AES_CCM_AUTH_E;
    }

    ForceZero(A, AES_BLOCK_SIZE);
    ForceZero(B, AES_BLOCK_SIZE);
    o = NULL;

    return result;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESCCM */


#ifdef WOLFSSL_ASYNC_CRYPT
    
/* Initialize Aes for use with Nitrox device */
int wc_AesAsyncInit(Aes* aes, int devId)
{
    WOLFSSL_STUB("wc_AesAsyncInit");
    (void)aes;
    (void)devId;
    return 0;
}


/* Free Aes from use with Nitrox device */
void wc_AesAsyncFree(Aes* aes)
{
    WOLFSSL_STUB("wc_AesAsyncFree");
    (void)aes;
}

#endif /* WOLFSSL_ASYNC_CRYPT */

#endif /* NO_AES */

