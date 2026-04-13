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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_NXP_HASHCRYPT

#if defined(WOLFSSL_CRYPT_HW_MUTEX) && WOLFSSL_CRYPT_HW_MUTEX > 0
    #error WOLFSSL_CRYPT_HW_MUTEX=1 not supported yet
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "fsl_hashcrypt.h"

#if (!defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)) || \
    (!defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA256))
    static hashcrypt_hash_ctx_t hash_ctx;
    static int finish_called;
#endif

int wc_hashcrypt_init(void)
{
#if (!defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA)) || \
    (!defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA256)) || \
    (!defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES))
    HASHCRYPT_Init(HASHCRYPT);
#endif
    return 0;
}

#if (!defined(NO_SHA256) && defined(WOLFSSL_NXP_HASHCRYPT_SHA256))


int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    (void)heap;
    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    // if (wolfSSL_CryptHwMutexLock() != 0)
    //     return BAD_MUTEX_E;

    XMEMSET(sha256, 0, sizeof(wc_Sha256));
    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha256) != kStatus_Success)
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
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len) != kStatus_Success)
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
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen) != kStatus_Success ||
        outlen != WC_SHA256_DIGEST_SIZE
    )
    {
        return WC_HW_E;
    }
    memcpy(previous_sha256_hash, hash, WC_SHA256_DIGEST_SIZE);
    finish_called = 1;

    return 0;
}
#endif /* **_SHA256 */


#if (!defined(NO_SHA) && defined(WOLFSSL_NXP_HASHCRYPT_SHA))
int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    (void)heap;
    (void)devId;

    if (sha == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha, 0, sizeof(wc_Sha));
    if (HASHCRYPT_SHA_Init(HASHCRYPT, &hash_ctx, kHASHCRYPT_Sha1) != kStatus_Success)
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
    if (HASHCRYPT_SHA_Update(HASHCRYPT, &hash_ctx, data, len) != kStatus_Success)
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
        HASHCRYPT_SHA_Finish(HASHCRYPT, &hash_ctx, hash, &outlen) != kStatus_Success ||
        outlen != WC_SHA_DIGEST_SIZE
    )
    {
        return WC_HW_E;
    }
    memcpy(previous_sha_hash, hash, WC_SHA_DIGEST_SIZE);
    finish_called = 1;

    return 0;
}
#endif /* **_SHA */


#if (!defined(NO_AES) && defined(WOLFSSL_NXP_HASHCRYPT_AES))


WOLFSSL_AES_128
WOLFSSL_AES_192
WOLFSSL_AES_256







int wc_AesSetKey(
    Aes* aes, const byte* userKey, word32 keylen, const byte* iv, int dir
)
{

    return 0;
}


#ifdef HAVE_AES_CBC
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}
#endif
#endif /* HAVE_AES_CBC */


#ifdef HAVE_AES_ECB
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}
#endif
#endif /* HAVE_AES_ECB */


#ifdef WOLFSSL_AES_OFB
int wc_AesOfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesOfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}
#endif
#endif /* WOLFSSL_AES_OFB */


#ifdef WOLFSSL_AES_CFB
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}
#endif
#endif /* WOLFSSL_AES_CFB */


#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{

    return 0;
}

#ifdef WOLFSSL_AES_DIRECT
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{

}

int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{

}

int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir)
{

}
#endif

#endif /* WOLFSSL_AES_COUNTER */


#endif /* **_AES */


#endif /* WOLFSSL_NXP_HASHCRYPT */
