/* renesas_fspsm_sha.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(NO_SHA256)

#include <wolfssl/wolfcrypt/logging.h>

#if defined(WOLFSSL_RENESAS_FSPSM_TLS) || \
    defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>

/* Free up allocation for msg
 *
 * hash    The FSPSM Hash object.
 * no return value
 */
static void FSPSM_HashFree(wolfssl_FSPSM_Hash* hash)
{
    if (hash == NULL)
        return;

    if (hash->msg != NULL) {
        XFREE(hash->msg, hash->heap, DYNAMIC_TYPE_TMP_BUFFER);
        hash->msg = NULL;
    }
}
/* Initialize Hash object
 *
 * hash    The FSPSM Hash object.
 * heap    Buffer to hold heap if available
 * devId   device Id
 * return  0 on success, BAD_FUNC_ARG when has is NULL
 */
static int FSPSM_HashInit(wolfssl_FSPSM_Hash* hash, void* heap, int devId,
    word32 sha_type)
{
    if (hash == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)devId;
    XMEMSET(hash, 0, sizeof(wolfssl_FSPSM_Hash));

    hash->heap = heap;
    hash->len  = 0;
    hash->used = 0;
    hash->msg  = NULL;
    hash->sha_type = sha_type;

    return 0;
}

/* Add data to msg(work buffer) for final hash operation
 *
 * hash    The FSPSM Hash object.
 * data    Buffer to hold plain text for hash
 * sz      Length of data
 * return  0 on success, otherwise MEMORY_E or BAD_FUNC_ARG on failure
 */
static int FSPSM_HashUpdate(wolfssl_FSPSM_Hash* hash,
                                                const byte* data, word32 sz)
{
    if (hash == NULL || (sz > 0 && data == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (hash->len < hash->used + sz) {
        if (hash->msg == NULL) {
            hash->msg = (byte*)XMALLOC(hash->used + sz, hash->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
#ifdef FREERTOS
            byte* pt = (byte*)XMALLOC(hash->used + sz, hash->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (pt == NULL) {
                return MEMORY_E;
            }
            XMEMCPY(pt, hash->msg, hash->used);
            XFREE(hash->msg, hash->heap, DYNAMIC_TYPE_TMP_BUFFER);
            hash->msg = NULL;
            hash->msg = pt;
#else
            byte* pt = (byte*)XREALLOC(hash->msg, hash->used + sz, hash->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (pt == NULL) {
                return MEMORY_E;
            }
            hash->msg = pt;
#endif
        }
        if (hash->msg == NULL) {
            return MEMORY_E;
        }
        hash->len = hash->used + sz;
    }
    XMEMCPY(hash->msg + hash->used, data , sz);
    hash->used += sz;

    return 0;
}

/* Perform hash operation using accumulated msg
 *
 * hash    The FSPSM Hash object.
 * out     Buffer to hold hashed text
 * outSz   Length of out
 * return  FSP_SUCCESS(0) on success,
 *         otherwise BAD_FUNC_ARG or FSP Error code on failure
 */
static int FSPSM_HashFinal(wolfssl_FSPSM_Hash* hash, byte* out, word32 outSz)
{
    int ret;
    void* heap;
    FSPSM_SHA_HANDLE handle;
    uint32_t sz;

    fsp_err_t (*Init)(FSPSM_SHA_HANDLE*);
    fsp_err_t (*Update)(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t);
    fsp_err_t (*Final )(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t*);

    if (hash == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (hash->sha_type == FSPSM_SHA256) {
        Init = FSPSM_SHA256_Init;
        Update = FSPSM_SHA256_Up;
        Final = FSPSM_SHA256_Final;
    }
    else
        return BAD_FUNC_ARG;

    heap = hash->heap;

    wc_fspsm_hw_lock();

    if (Init(&handle) == FSP_SUCCESS) {
        ret = Update(&handle, (uint8_t*)hash->msg, hash->used);
        if (ret == FSP_SUCCESS) {
            ret = Final(&handle, out, (uint32_t*)&sz);
            if (ret != FSP_SUCCESS || sz != outSz) {
                return ret;
            }
        }
    }
    wc_fspsm_hw_unlock();

    FSPSM_HashFree(hash);
    return FSPSM_HashInit(hash, heap, 0, hash->sha_type);
}
/* Hash operation to message and return a result */
static int FSPSM_HashGet(wolfssl_FSPSM_Hash* hash, byte* out, word32 outSz)
{
    int ret;
    FSPSM_SHA_HANDLE handle;
    uint32_t sz;

    fsp_err_t (*Init)(FSPSM_SHA_HANDLE*);
    fsp_err_t (*Update)(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t);
    fsp_err_t (*Final )(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t*);

    if (hash == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (hash->sha_type == FSPSM_SHA256) {
        Init = FSPSM_SHA256_Init;
        Update = FSPSM_SHA256_Up;
        Final = FSPSM_SHA256_Final;
    }
    else
        return BAD_FUNC_ARG;

    wc_fspsm_hw_lock();

    if (Init(&handle) == FSP_SUCCESS) {
        ret = Update(&handle, (uint8_t*)hash->msg, hash->used);
        if (ret == FSP_SUCCESS) {
            ret = Final(&handle, out, &sz);
            if (ret != FSP_SUCCESS || sz != outSz) {
                return ret;
            }
        }
    }

    wc_fspsm_hw_unlock();

    return 0;
}
/* copy hash result from src to dst */
static int FSPSM_HashCopy(wolfssl_FSPSM_Hash* src, wolfssl_FSPSM_Hash* dst)
{
    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(dst, src, sizeof(wolfssl_FSPSM_Hash));

    if (src->len > 0 && src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }

    return 0;
}

#if !defined(NO_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

/*  wrapper for wc_InitSha256_ex */
int wc_InitSha256_ex(wc_Sha256* sha, void* heap, int devId)
{
    return FSPSM_HashInit(sha, heap, devId, FSPSM_SHA256);
}
/*  wrapper for wc_Sha256Update */
int wc_Sha256Update(wc_Sha256* sha, const byte* in, word32 sz)
{
    return FSPSM_HashUpdate(sha, in, sz);
}
/*  wrapper for wc_Sha256Final */
int wc_Sha256Final(wc_Sha256* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA256_DIGEST_SIZE);
}
/*  wrapper for wc_Sha256GetHash */
int wc_Sha256GetHash(wc_Sha256* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA256_DIGEST_SIZE);
}
/*  wrapper for wc_Sha256Copy */
int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* !NO_SHA256 */
#endif /* WOLFSSL_RENESAS_FSPSM_TLS */
#endif /* #if !defined(NO_SHA) || !defined(NO_SHA256) */
