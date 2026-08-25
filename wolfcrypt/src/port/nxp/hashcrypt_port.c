/* hashcrypt_port.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_NXP_HASHCRYPT

#if defined(WOLFSSL_CRYPT_HW_MUTEX) && WOLFSSL_CRYPT_HW_MUTEX > 0
    #error WOLFSSL_CRYPT_HW_MUTEX=1 not supported yet
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "fsl_hashcrypt.h"

#if (!defined(NO_SHA) || !defined(NO_SHA256)) && \
    defined(WOLFSSL_NXP_HASHCRYPT_SHA)
static hashcrypt_hash_ctx_t hash_ctx;
static int finish_called;
#endif

#if !defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES)
hashcrypt_handle_t aes_handle;
#endif

int wc_hashcrypt_init(void)
{
#if ((!defined(NO_SHA) || !defined(NO_SHA256)) && \
        defined(WOLFSSL_NXP_HASHCRYPT_SHA)) || \
    (!defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES))
    HASHCRYPT_Init(HASHCRYPT);
#endif
    return 0;
}

#if !defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    (void)heap;
    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256, 0, sizeof(wc_Sha256));
    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha256)
            != kStatus_Success)
        return WC_HW_E;

    finish_called = 0;

    return 0;
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    if (sha256 == NULL || (data == NULL && len != 0))
        return BAD_FUNC_ARG;

    if (finish_called)
    {
        HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha256);
        finish_called = 0;
    }
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len)
            != kStatus_Success)
        return WC_HW_E;

    return 0;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    static byte previous_sha256_hash[WC_SHA256_DIGEST_SIZE];

    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    if (finish_called)
    {
        memcpy(hash, previous_sha256_hash, WC_SHA256_DIGEST_SIZE);
        return 0;
    }

    if (
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen)
                != kStatus_Success
                || outlen != WC_SHA256_DIGEST_SIZE
    )
    {
        return WC_HW_E;
    }
    memcpy(previous_sha256_hash, hash, WC_SHA256_DIGEST_SIZE);
    finish_called = 1;

    return 0;
}
#endif /* !defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA) */


#if !defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)
int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    (void)heap;
    (void)devId;

    if (sha == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha, 0, sizeof(wc_Sha));
    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha1)
            != kStatus_Success)
        return WC_HW_E;

    finish_called = 0;

    return 0;
}

int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len)
{
    if (sha == NULL || (data == NULL && len != 0))
        return BAD_FUNC_ARG;

    if (finish_called)
    {
        HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha1);
        finish_called = 0;
    }
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len)
            != kStatus_Success)
        return WC_HW_E;

    return 0;
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    size_t outlen = WC_SHA_DIGEST_SIZE;
    static byte previous_sha_hash[WC_SHA_DIGEST_SIZE];

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    if (finish_called)
    {
        memcpy(hash, previous_sha_hash, WC_SHA_DIGEST_SIZE);
        return 0;
    }

    if (
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen)
                != kStatus_Success
                || outlen != WC_SHA_DIGEST_SIZE
    )
    {
        return WC_HW_E;
    }
    memcpy(previous_sha_hash, hash, WC_SHA_DIGEST_SIZE);
    finish_called = 1;

    return 0;
}
#endif /* !defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA) */


#if !defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES)
static int _hashcrypt_set_key(Aes* aes)
{
    aes_handle.keyType = kHASHCRYPT_UserKey;

    if (aes->keylen == 128/8)
        aes_handle.keySize = kHASHCRYPT_Aes128;
    else if (aes->keylen == 192/8)
        aes_handle.keySize = kHASHCRYPT_Aes192;
    else if (aes->keylen == 256/8)
        aes_handle.keySize = kHASHCRYPT_Aes256;
    else
        return BAD_FUNC_ARG;

    if (HASHCRYPT_AES_SetKey(
            HASHCRYPT, &aes_handle, (const uint8_t *)aes->devKey, aes->keylen
        ) != kStatus_Success
    )
         return WC_HW_E;

    return 0;
}

#ifdef HAVE_AES_ECB
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = _hashcrypt_set_key(aes);

    if (ret)
        return ret;

    if (HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &aes_handle, in, out, sz)
             != kStatus_Success)
         return WC_HW_E;

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = _hashcrypt_set_key(aes);

    if (ret)
        return ret;

    if (HASHCRYPT_AES_DecryptEcb(HASHCRYPT, &aes_handle, in, out, sz)
             != kStatus_Success)
         return WC_HW_E;

    return 0;
}
#endif
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = _hashcrypt_set_key(aes);

    if (ret)
        return ret;

    if (HASHCRYPT_AES_EncryptCbc(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
         return WC_HW_E;

    XMEMCPY(aes->reg, out + sz - 16, 16);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    byte tmp_iv[16];

    ret = _hashcrypt_set_key(aes);
    if (ret)
        return ret;

    XMEMCPY(tmp_iv, in + sz - 16, 16);

    if (HASHCRYPT_AES_DecryptCbc(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
         return WC_HW_E;

    XMEMCPY(aes->reg, tmp_iv, 16);

    return 0;
}
#endif
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_OFB
/* OFB is symmetric (encrypt and decrypt run the same keystream). Generate the
 * keystream one block at a time with the SDK's ECB primitive and keep the
 * feedback register plus any unused keystream bytes in the Aes context, so a
 * message split across calls continues the stream instead of restarting from
 * the original IV. */
static int _hashcrypt_aes_ofb(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    byte* tmp;

    if (aes == NULL || out == NULL || in == NULL)
        return BAD_FUNC_ARG;

    if (sz == 0)
        return 0;

    ret = _hashcrypt_set_key(aes);
    if (ret)
        return ret;

    while (sz > 0) {
        if (aes->left == 0) {
            /* keystream block O = E(reg); OFB feeds O back as the next reg */
            if (HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &aes_handle,
                    (const uint8_t *)aes->reg, (uint8_t *)aes->tmp,
                    WC_AES_BLOCK_SIZE) != kStatus_Success)
                return WC_HW_E;
            XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
            aes->left = WC_AES_BLOCK_SIZE;
        }
        tmp = (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left;
        while (aes->left > 0 && sz > 0) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
            sz--;
        }
    }

    return 0;
}

int wc_AesOfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return _hashcrypt_aes_ofb(aes, out, in, sz);
}

#ifdef HAVE_AES_DECRYPT
int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return _hashcrypt_aes_ofb(aes, out, in, sz);
}
#endif
#endif /* WOLFSSL_AES_OFB */

#ifdef WOLFSSL_AES_CFB
/* CFB-128, byte capable. The keystream block is E(reg); each ciphertext byte is
 * fed back into reg at the matching offset, so once a full block has passed reg
 * holds the next feedback block. State (reg, tmp keystream, left) persists in
 * the Aes context so one message may be processed across several calls. */
static int _hashcrypt_aes_cfb(Aes* aes, byte* out, const byte* in, word32 sz,
                              int decrypt)
{
    int ret;
    word32 idx;
    byte c;

    if (aes == NULL || out == NULL || in == NULL)
        return BAD_FUNC_ARG;

    if (sz == 0)
        return 0;

    ret = _hashcrypt_set_key(aes);
    if (ret)
        return ret;

    while (sz > 0) {
        if (aes->left == 0) {
            if (HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &aes_handle,
                    (const uint8_t *)aes->reg, (uint8_t *)aes->tmp,
                    WC_AES_BLOCK_SIZE) != kStatus_Success)
                return WC_HW_E;
            aes->left = WC_AES_BLOCK_SIZE;
        }
        idx = WC_AES_BLOCK_SIZE - aes->left;
        /* ciphertext = plaintext XOR keystream (and vice-versa for decrypt) */
        c = (byte)(*in ^ ((byte*)aes->tmp)[idx]);
        /* feedback register always takes the ciphertext byte */
        ((byte*)aes->reg)[idx] = decrypt ? *in : c;
        *out = c;
        in++;
        out++;
        sz--;
        aes->left--;
    }

    return 0;
}

int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return _hashcrypt_aes_cfb(aes, out, in, sz, 0);
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return _hashcrypt_aes_cfb(aes, out, in, sz, 1);
}
#endif
#endif /* WOLFSSL_AES_CFB */

#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    byte* tmp;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    /* consume any unused bytes left in aes->tmp */
    tmp = (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left;
    while (aes->left && sz) {
        *(out++) = *(in++) ^ *(tmp++);
        aes->left--;
        sz--;
    }

    if (sz) {
        ret = _hashcrypt_set_key(aes);
        if (ret)
            return ret;

        if (HASHCRYPT_AES_CryptCtr(
                HASHCRYPT, &aes_handle, in, out, sz, (byte *)aes->reg,
                (byte *)aes->tmp, (word32 *)&aes->left)
                    != kStatus_Success)
         return WC_HW_E;
    }

    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

#endif /* !defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES) */

#endif /* WOLFSSL_NXP_HASHCRYPT */
