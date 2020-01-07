/* chacha.c
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



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif

#ifdef CHACHA_AEAD_TEST
#include <stdio.h>
#endif

#define CHACHA20_POLY1305_AEAD_INITIAL_COUNTER  0
#define CHACHA20_POLY1305_MAC_PADDING_ALIGNMENT 16


static void word32ToLittle64(const word32 inLittle32, byte outLittle64[8])
{
#ifndef WOLFSSL_X86_64_BUILD
    XMEMSET(outLittle64 + 4, 0, 4);

    outLittle64[0] = (byte)(inLittle32 & 0x000000FF);
    outLittle64[1] = (byte)((inLittle32 & 0x0000FF00) >> 8);
    outLittle64[2] = (byte)((inLittle32 & 0x00FF0000) >> 16);
    outLittle64[3] = (byte)((inLittle32 & 0xFF000000) >> 24);
#else
    *(word64*)outLittle64 = inLittle32;
#endif
}

int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inPlaintext, const word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret;
    ChaChaPoly_Aead aead;

    /* Validate function arguments */
    if (!inKey || !inIV ||
        !inPlaintext || !inPlaintextLen ||
        !outCiphertext ||
        !outAuthTag)
    {
        return BAD_FUNC_ARG;
    }

    ret = wc_ChaCha20Poly1305_Init(&aead, inKey, inIV,
        CHACHA20_POLY1305_AEAD_ENCRYPT);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_UpdateAad(&aead, inAAD, inAADLen);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_UpdateData(&aead, inPlaintext, outCiphertext,
            inPlaintextLen);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_Final(&aead, outAuthTag);
    return ret;
}


int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inCiphertext, const word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext)
{
    int ret;
    ChaChaPoly_Aead aead;
    byte calculatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Validate function arguments */
    if (!inKey || !inIV ||
        !inCiphertext || !inCiphertextLen ||
        !inAuthTag ||
        !outPlaintext)
    {
        return BAD_FUNC_ARG;
    }

    XMEMSET(calculatedAuthTag, 0, sizeof(calculatedAuthTag));

    ret = wc_ChaCha20Poly1305_Init(&aead, inKey, inIV,
        CHACHA20_POLY1305_AEAD_DECRYPT);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_UpdateAad(&aead, inAAD, inAADLen);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_UpdateData(&aead, inCiphertext, outPlaintext,
            inCiphertextLen);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_Final(&aead, calculatedAuthTag);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_CheckTag(inAuthTag, calculatedAuthTag);
    return ret;
}

int wc_ChaCha20Poly1305_CheckTag(
    const byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
    const byte authTagChk[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret = 0;
    if (authTag == NULL || authTagChk == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ConstantCompare(authTag, authTagChk,
            CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) != 0) {
        ret = MAC_CMP_FAILED_E;
    }
    return ret;
}

int wc_ChaCha20Poly1305_Init(ChaChaPoly_Aead* aead,
    const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
    const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
    int isEncrypt)
{
    int ret;
    byte authKey[CHACHA20_POLY1305_AEAD_KEYSIZE];

    /* check arguments */
    if (aead == NULL || inKey == NULL || inIV == NULL) {
        return BAD_FUNC_ARG;
    }

    /* setup aead context */
    XMEMSET(aead, 0, sizeof(ChaChaPoly_Aead));
    XMEMSET(authKey, 0, sizeof(authKey));
    aead->isEncrypt = isEncrypt;

    /* Initialize the ChaCha20 context (key and iv) */
    ret = wc_Chacha_SetKey(&aead->chacha, inKey,
        CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (ret == 0) {
        ret = wc_Chacha_SetIV(&aead->chacha, inIV,
            CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    }

    /* Create the Poly1305 key */
    if (ret == 0) {
        ret = wc_Chacha_Process(&aead->chacha, authKey, authKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
    }

    /* Initialize Poly1305 context */
    if (ret == 0) {
        ret = wc_Poly1305SetKey(&aead->poly, authKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
    }

    if (ret == 0) {
        aead->state = CHACHA20_POLY1305_STATE_READY;
    }

    return ret;
}

/* optional additional authentication data */
int wc_ChaCha20Poly1305_UpdateAad(ChaChaPoly_Aead* aead,
    const byte* inAAD, word32 inAADLen)
{
    int ret = 0;

    if (aead == NULL || inAAD == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_READY &&
        aead->state != CHACHA20_POLY1305_STATE_AAD) {
        return BAD_STATE_E;
    }

    if (inAADLen > 0) {
        ret = wc_Poly1305Update(&aead->poly, inAAD, inAADLen);
        if (ret == 0) {
            aead->aadLen += inAADLen;
            aead->state = CHACHA20_POLY1305_STATE_AAD;
        }
    }

    return ret;
}

static int wc_ChaCha20Poly1305_CalcAad(ChaChaPoly_Aead* aead)
{
    int ret = 0;
    word32 paddingLen;
    byte padding[CHACHA20_POLY1305_MAC_PADDING_ALIGNMENT - 1];

    XMEMSET(padding, 0, sizeof(padding));

    /* Pad the AAD to 16 bytes */
    paddingLen = -(int)aead->aadLen &
        (CHACHA20_POLY1305_MAC_PADDING_ALIGNMENT - 1);
    if (paddingLen > 0) {
        ret = wc_Poly1305Update(&aead->poly, padding, paddingLen);
    }
    return ret;
}

/* inData and outData can be same pointer (inline) */
int wc_ChaCha20Poly1305_UpdateData(ChaChaPoly_Aead* aead,
    const byte* inData, byte* outData, word32 dataLen)
{
    int ret = 0;

    if (aead == NULL || inData == NULL || outData == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_READY &&
        aead->state != CHACHA20_POLY1305_STATE_AAD &&
        aead->state != CHACHA20_POLY1305_STATE_DATA) {
        return BAD_STATE_E;
    }

    /* calculate AAD */
    if (aead->state == CHACHA20_POLY1305_STATE_AAD) {
        ret = wc_ChaCha20Poly1305_CalcAad(aead);
    }

    /* advance state */
    aead->state = CHACHA20_POLY1305_STATE_DATA;

    /* Perform ChaCha20 encrypt or decrypt inline and Poly1305 auth calc */
    if (ret == 0) {
        if (aead->isEncrypt) {
            ret = wc_Chacha_Process(&aead->chacha, outData, inData, dataLen);
            if (ret == 0)
                ret = wc_Poly1305Update(&aead->poly, outData, dataLen);
        }
        else {
            ret = wc_Poly1305Update(&aead->poly, inData, dataLen);
            if (ret == 0)
                ret = wc_Chacha_Process(&aead->chacha, outData, inData, dataLen);
        }
    }
    if (ret == 0) {
        aead->dataLen += dataLen;
    }
    return ret;
}

int wc_ChaCha20Poly1305_Final(ChaChaPoly_Aead* aead,
    byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret = 0;
    word32 paddingLen;
    byte padding[CHACHA20_POLY1305_MAC_PADDING_ALIGNMENT - 1];
    byte little64[16]; /* word64 * 2 */

    if (aead == NULL || outAuthTag == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_AAD &&
        aead->state != CHACHA20_POLY1305_STATE_DATA) {
        return BAD_STATE_E;
    }

    XMEMSET(padding, 0, sizeof(padding));
    XMEMSET(little64, 0, sizeof(little64));

    /* make sure AAD is calculated */
    if (aead->state == CHACHA20_POLY1305_STATE_AAD) {
        ret = wc_ChaCha20Poly1305_CalcAad(aead);
    }

    /* Pad the ciphertext to 16 bytes */
    if (ret == 0) {
        paddingLen = -(int)aead->dataLen &
            (CHACHA20_POLY1305_MAC_PADDING_ALIGNMENT - 1);
        if (paddingLen > 0) {
            ret = wc_Poly1305Update(&aead->poly, padding, paddingLen);
        }
    }

    /* Add the aad and ciphertext length */
    if (ret == 0) {
        /* AAD length as a 64-bit little endian integer */
        word32ToLittle64(aead->aadLen, little64);
        /* Ciphertext length as a 64-bit little endian integer */
        word32ToLittle64(aead->dataLen, little64 + 8);

        ret = wc_Poly1305Update(&aead->poly, little64, sizeof(little64));
    }

    /* Finalize the auth tag */
    if (ret == 0) {
        ret = wc_Poly1305Final(&aead->poly, outAuthTag);
    }

    /* reset and cleanup sensitive context */
    ForceZero(aead, sizeof(ChaChaPoly_Aead));

    return ret;
}


#endif /* HAVE_CHACHA && HAVE_POLY1305 */
