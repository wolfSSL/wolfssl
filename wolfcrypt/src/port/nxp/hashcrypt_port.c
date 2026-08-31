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

/* AES and SHA are two views of the SAME HashCrypt engine, so both have to be
 * serialized by the same lock.  That is why this port takes the global crypto
 * hardware mutex rather than the per-algorithm aes_mutex/hash_mutex pair of
 * WOLFSSL_ALGO_HW_MUTEX, which would hand them two independent locks and leave
 * an AES request free to interrupt a hash. */

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "fsl_hashcrypt.h"

#if (!defined(NO_SHA) || !defined(NO_SHA256)) && \
    defined(WOLFSSL_NXP_HASHCRYPT_SHA)
/* The HashCrypt engine keeps the running digest itself, so one context is all
 * it can carry -- hence NO_WOLFSSL_SHA256_INTERLEAVE for this part.  Moving
 * this into wc_Sha256/wc_Sha buys nothing and breaks wc_Sha256GetHash(), whose
 * generic implementation finalizes a struct copy. */
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
    int ret;

    /* Redundant on the normal path -- wolfCrypt_Init() initializes the global
     * crypt HW mutex before it reaches here -- but it keeps a standalone
     * wc_hashcrypt_init() caller from having to rely on the lazy init inside
     * wolfSSL_CryptHwMutexLock().  No-op when WOLFSSL_CRYPT_HW_MUTEX is off. */
    if ((ret = wolfSSL_CryptHwMutexInit()) != 0)
        return ret;

    HASHCRYPT_Init(HASHCRYPT);
#endif
    return 0;
}

#if !defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret;

    (void)heap;
    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256, 0, sizeof(wc_Sha256));

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha256)
            != kStatus_Success)
        ret = WC_HW_E;
    else
        finish_called = 0;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret;

    if (sha256 == NULL || (data == NULL && len != 0))
        return BAD_FUNC_ARG;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    if (finish_called)
    {
        HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha256);
        finish_called = 0;
    }
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len)
            != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    static byte previous_sha256_hash[WC_SHA256_DIGEST_SIZE];
    int ret;

    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    /* wc_Sha256GetHash() finalizes a copy of the object, which on this engine
     * consumes the one running digest.  Replaying the cached result keeps a
     * later Final() consistent with the value GetHash() already returned. */
    if (finish_called)
    {
        memcpy(hash, previous_sha256_hash, WC_SHA256_DIGEST_SIZE);
        goto unlock;
    }

    if (
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen)
                != kStatus_Success
                || outlen != WC_SHA256_DIGEST_SIZE
    )
    {
        ret = WC_HW_E;
        goto unlock;
    }
    memcpy(previous_sha256_hash, hash, WC_SHA256_DIGEST_SIZE);
    finish_called = 1;

unlock:
    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif /* !defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA) */


#if !defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)
int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    int ret;

    (void)heap;
    (void)devId;

    if (sha == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha, 0, sizeof(wc_Sha));

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha1)
            != kStatus_Success)
        ret = WC_HW_E;
    else
        finish_called = 0;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len)
{
    int ret;

    if (sha == NULL || (data == NULL && len != 0))
        return BAD_FUNC_ARG;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    if (finish_called)
    {
        HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha1);
        finish_called = 0;
    }
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len)
            != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    size_t outlen = WC_SHA_DIGEST_SIZE;
    static byte previous_sha_hash[WC_SHA_DIGEST_SIZE];
    int ret;

    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    /* wc_Sha256GetHash() finalizes a copy of the object, which on this engine
     * consumes the one running digest.  Replaying the cached result keeps a
     * later Final() consistent with the value GetHash() already returned. */
    if (finish_called)
    {
        memcpy(hash, previous_sha_hash, WC_SHA_DIGEST_SIZE);
        goto unlock;
    }

    if (
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen)
                != kStatus_Success
                || outlen != WC_SHA_DIGEST_SIZE
    )
    {
        ret = WC_HW_E;
        goto unlock;
    }
    memcpy(previous_sha_hash, hash, WC_SHA_DIGEST_SIZE);
    finish_called = 1;

unlock:
    wolfSSL_CryptHwMutexUnLock();

    return ret;
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
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_EncryptEcb(HASHCRYPT, &aes_handle, in, out, sz)
             != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_DecryptEcb(HASHCRYPT, &aes_handle, in, out, sz)
             != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0) {
        if (HASHCRYPT_AES_EncryptCbc(
                HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                    != kStatus_Success)
            ret = WC_HW_E;
        else
            XMEMCPY(aes->reg, out + sz - 16, 16);
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    byte tmp_iv[16];

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0) {
        XMEMCPY(tmp_iv, in + sz - 16, 16);

        if (HASHCRYPT_AES_DecryptCbc(
                HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                    != kStatus_Success)
            ret = WC_HW_E;
        else
            XMEMCPY(aes->reg, tmp_iv, 16);
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_OFB
int wc_AesOfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_CryptOfb(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_CryptOfb(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif
#endif /* WOLFSSL_AES_OFB */

#ifdef WOLFSSL_AES_CFB
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_EncryptCfb(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;

    if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
        return ret;

    ret = _hashcrypt_set_key(aes);
    if (ret == 0 &&
        HASHCRYPT_AES_DecryptCfb(
            HASHCRYPT, &aes_handle, in, out, sz, (const uint8_t *)aes->reg)
                != kStatus_Success)
        ret = WC_HW_E;

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}
#endif
#endif /* WOLFSSL_AES_CFB */

#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;   /* sz may reach 0 in the drain below, skipping the lock */
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
        if ((ret = wolfSSL_CryptHwMutexLock()) != 0)
            return ret;

        ret = _hashcrypt_set_key(aes);
        if (ret == 0 &&
            HASHCRYPT_AES_CryptCtr(
                HASHCRYPT, &aes_handle, in, out, sz, (byte *)aes->reg,
                (byte *)aes->tmp, (word32 *)&aes->left)
                    != kStatus_Success)
            ret = WC_HW_E;

        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

#endif /* !defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES) */

#endif /* WOLFSSL_NXP_HASHCRYPT */
