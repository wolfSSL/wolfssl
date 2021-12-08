/* wolfcaam_aes.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#if (WOLFSSL_CAAM) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam_aes.h>

/* return 0 on success */
static int wc_CAAM_AesAeadCommon(Aes* aes, const byte* in, byte* out, word32 sz,
        const byte* nonce, word32 nonceSz, byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz, int dir, int type)
{
    CAAM_BUFFER buf[7];
    int ret, idx = 0;
    word32 arg[4];
    word32 keySz;

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wc_AesGetKeySize(aes, &keySz) != 0 && aes->blackKey == 0) {
        return BAD_FUNC_ARG;
    }

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)aes->key;
    buf[idx].Length     = keySz;
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)nonce;
    buf[idx].Length     = nonceSz;
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)in;
    buf[idx].Length     = sz;
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)out;
    buf[idx].Length     = sz;
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)authTag;
    buf[idx].Length     = authTagSz;
    idx++;

    buf[idx].BufferType = DataBuffer | LastBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)authIn;
    buf[idx].Length     = authInSz;
    idx++;

    arg[0] = dir;
    arg[1] = keySz;
    arg[2] = sz;
    arg[3] = aes->blackKey;

    if ((ret = wc_caamAddAndWait(buf, idx, arg, type)) != 0) {
        WOLFSSL_MSG("Error with CAAM AES CCM operation");
        return ret;
    }

    return 0;
}


/* plaintext in ciphertext and mac out
 * return 0 on success
 */
int wc_CAAM_AesCcmEncrypt(Aes* aes, const byte* in, byte* out, word32 sz,
        const byte* nonce, word32 nonceSz, byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz)
{
    return wc_CAAM_AesAeadCommon(aes, in, out, sz, nonce, nonceSz, authTag,
                            authTagSz, authIn, authInSz, CAAM_ENC, CAAM_AESCCM);
}


/* ciphertext in plaintext out
 * return 0 on success
 */
int wc_CAAM_AesCcmDecrypt(Aes* aes, const byte* in, byte* out, word32 sz,
        const byte* nonce, word32 nonceSz, const byte* authTag,
        word32 authTagSz, const byte* authIn, word32 authInSz)
{
    return wc_CAAM_AesAeadCommon(aes, in, out, sz, nonce, nonceSz,
            (byte*)authTag, authTagSz, authIn, authInSz, CAAM_DEC, CAAM_AESCCM);
}


int wc_CAAM_AesGcmEncrypt(Aes* aes, const byte* in, byte* out, word32 sz,
        const byte* nonce, word32 nonceSz, byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz)
{
    return wc_CAAM_AesAeadCommon(aes, in, out, sz, nonce, nonceSz, authTag,
                            authTagSz, authIn, authInSz, CAAM_ENC, CAAM_AESGCM);
}


int wc_CAAM_AesGcmDecrypt(Aes* aes, const byte* in, byte* out, word32 sz,
        const byte* nonce, word32 nonceSz, const byte* authTag,
        word32 authTagSz, const byte* authIn, word32 authInSz)
{
    return wc_CAAM_AesAeadCommon(aes, in, out, sz, nonce, nonceSz,
            (byte*)authTag, authTagSz, authIn, authInSz, CAAM_DEC, CAAM_AESGCM);
}


static int wc_CAAM_AesCbcCommon(Aes* aes, byte* out, const byte* in, word32 sz,
    int dir)
{
    word32  blocks;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;

    if (blocks > 0) {
        CAAM_BUFFER buf[4];
        word32 arg[4];
        word32 keySz;
        int ret;

        if (wc_AesGetKeySize(aes, &keySz) != 0 && aes->blackKey == 0) {
            return BAD_FUNC_ARG;
        }

        /* Set buffers for key, cipher text, and plain text */
        buf[0].BufferType = DataBuffer;
        buf[0].TheAddress = (CAAM_ADDRESS)aes->key;
        buf[0].Length     = keySz;

        buf[1].BufferType = DataBuffer;
        buf[1].TheAddress = (CAAM_ADDRESS)aes->reg;
        buf[1].Length     = AES_BLOCK_SIZE;

        buf[2].BufferType = DataBuffer;
        buf[2].TheAddress = (CAAM_ADDRESS)in;
        buf[2].Length     = blocks * AES_BLOCK_SIZE;

        buf[3].BufferType = DataBuffer | LastBuffer;
        buf[3].TheAddress = (CAAM_ADDRESS)out;
        buf[3].Length     = blocks * AES_BLOCK_SIZE;

        arg[0] = dir;
        arg[1] = keySz;
        arg[2] = blocks * AES_BLOCK_SIZE;
        arg[3] = aes->blackKey;

        if ((ret = wc_caamAddAndWait(buf, 4, arg, CAAM_AESCBC)) != 0) {
            WOLFSSL_MSG("Error with CAAM AES CBC operation");
            return ret;
        }
    }

    return 0;
}

int wc_CAAM_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return wc_CAAM_AesCbcCommon(aes, out, in, sz, CAAM_ENC);
}


int wc_CAAM_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return wc_CAAM_AesCbcCommon(aes, out, in, sz, CAAM_DEC);
}

#if defined(HAVE_AES_ECB)
static int wc_CAAM_AesEcbCommon(Aes* aes, byte* out, const byte* in, word32 sz,
    int dir)
{
    word32 blocks;
    CAAM_BUFFER buf[4];
    word32 arg[4];
    word32 keySz = 0;
    int    ret;
    int    idx = 0;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    blocks = sz / AES_BLOCK_SIZE;

    if (wc_AesGetKeySize(aes, &keySz) != 0 && aes->blackKey == 0) {
        return BAD_FUNC_ARG;
    }

    /* Set buffers for key, cipher text, and plain text */
    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)aes->key;
    buf[idx].Length     = keySz;
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)aes->reg;
    buf[idx].Length     = 0; /* NO IV */
    idx++;

    buf[idx].BufferType = DataBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)in;
    buf[idx].Length     = blocks * AES_BLOCK_SIZE;
    idx++;

    buf[idx].BufferType = DataBuffer | LastBuffer;
    buf[idx].TheAddress = (CAAM_ADDRESS)out;
    buf[idx].Length     = blocks * AES_BLOCK_SIZE;
    idx++;

    arg[0] = dir;
    arg[1] = keySz;
    arg[2] = blocks * AES_BLOCK_SIZE;
    arg[3] = aes->blackKey;

    if ((ret = wc_caamAddAndWait(buf, idx, arg, CAAM_AESECB)) != 0) {
        WOLFSSL_MSG("Error with CAAM AES ECB encrypt");
        return ret;
    }

    return 0;
}


/* is assumed that input size is a multiple of AES_BLOCK_SIZE */
int wc_CAAM_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return wc_CAAM_AesEcbCommon(aes, out, in, sz, CAAM_ENC);
}


int wc_CAAM_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return wc_CAAM_AesEcbCommon(aes, out, in, sz, CAAM_DEC);
}
#endif /* HAVE_AES_ECB */
#endif /* WOLFSSL_CAAM && !NO_AES */
