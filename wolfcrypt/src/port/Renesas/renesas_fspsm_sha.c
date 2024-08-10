/* renesas_fspsm_sha.c
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
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(NO_SHA256)

#include <wolfssl/wolfcrypt/logging.h>

#if (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
     defined(WOLFSSL_RENESAS_RSIP)) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>

#if defined(WOLFSSL_RENESAS_RSIP)
extern FSPSM_INSTANCE   gFSPSM_ctrl;

/* wrapper for RSIP SHA1 Init */
static fsp_err_t _R_RSIP_SHA1_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA1 );
}
/* wrapper for RSIP SHA224 Init */
static fsp_err_t _R_RSIP_SHA224_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA224 );
}
/* wrapper for RSIP SHA256 Init */
static fsp_err_t _R_RSIP_SHA256_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA256 );
}
/* wrapper for RSIP SHA384 Init */
static fsp_err_t _R_RSIP_SHA384_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA384 );
}
/* wrapper for RSIP SHA512 Init */
static fsp_err_t _R_RSIP_SHA512_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA512 );
}
/* wrapper for RSIP SHA512_224 Init */
static fsp_err_t _R_RSIP_SHA512_224_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA512_224 );
}
/* wrapper for RSIP SHA512_256 Init */
static fsp_err_t _R_RSIP_SHA512_256_GenerateInit(FSPSM_SHA_HANDLE* h)
{
    return R_RSIP_SHA_GenerateInit(&gFSPSM_ctrl, h, RSIP_HASH_TYPE_SHA512_256 );
}
/* wrapper for RSIP SHA Update */
static fsp_err_t _R_RSIP_SHA_GenerateUpdate(FSPSM_SHA_HANDLE* h,
                                            uint8_t* m, uint32_t len)
{
    return R_RSIP_SHA_GenerateUpdate(&gFSPSM_ctrl, h, m, len );
}
/* wrapper for RSIP SHA Final */
static fsp_err_t _R_RSIP_SHA_GenerateFinal(FSPSM_SHA_HANDLE* h,
                                                uint8_t* d, uint32_t *sz)
{
    (void) sz;
    return R_RSIP_SHA_GenerateFinal(&gFSPSM_ctrl, h, d);
}
#endif /* WOLFSSL_RENESAS_RSIP */
/* Free up allocation for msg
 *
 * hash    The FSPSM Hash object.
 * no return value
 */
static void FSPSM_HashFree(wolfssl_FSPSM_Hash* hash)
{
    if (hash == NULL)
        return;

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    XFREE(hash->msg, hash->heap, DYNAMIC_TYPE_TMP_BUFFER);
    hash->msg = NULL;
#endif

}
/* copy hash result from src to dst */
static int FSPSM_HashCopy(wolfssl_FSPSM_Hash* src, wolfssl_FSPSM_Hash* dst)
{
    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(dst, src, sizeof(wolfssl_FSPSM_Hash));

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    if (src->len > 0 && src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif
    return 0;
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
#if defined(WOLFSSL_RENESAS_RSIP)
    int ret;
    fsp_err_t (*Init)(FSPSM_SHA_HANDLE*);
#endif
    if (hash == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)devId;
    XMEMSET(hash, 0, sizeof(wolfssl_FSPSM_Hash));
    hash->sha_type = sha_type;
    hash->heap = heap;

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    hash->len  = 0;
    hash->used = 0;
    hash->msg  = NULL;

#elif defined(WOLFSSL_RENESAS_RSIP)

    switch(hash->sha_type) {
    case FSPSM_SHA1:
        Init = FSPSM_SHA1_Init;
        break;
    case FSPSM_SHA256:
        Init = FSPSM_SHA256_Init;
        break;
    case FSPSM_SHA224:
        Init = FSPSM_SHA224_Init;
        break;
    case FSPSM_SHA384:
        Init = FSPSM_SHA384_Init;
        break;
    case FSPSM_SHA512:
        Init = FSPSM_SHA512_Init;
        break;
    case FSPSM_SHA512_224:
        Init = FSPSM_SHA512_224_Init;
        break;
    case FSPSM_SHA512_256:
        Init = FSPSM_SHA512_256_Init;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    wc_fspsm_hw_lock();
    ret = Init(&hash->handle);
    wc_fspsm_hw_unlock();
    return ret;
#endif

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
#if defined(WOLFSSL_RENESAS_RSIP)
    int ret;
    fsp_err_t (*Update)(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t);
#endif

    if (hash == NULL || (sz > 0 && data == NULL)) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
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
#elif defined(WOLFSSL_RENESAS_RSIP)

    switch(hash->sha_type) {
    case FSPSM_SHA1:
        Update = FSPSM_SHA1_Up;
        break;
    case FSPSM_SHA256:
        Update = FSPSM_SHA256_Up;
        break;
    case FSPSM_SHA224:
        Update = FSPSM_SHA224_Up;
        break;
    case FSPSM_SHA384:
        Update = FSPSM_SHA384_Up;
        break;
    case FSPSM_SHA512:
        Update = FSPSM_SHA512_Up;
        break;
    case FSPSM_SHA512_224:
        Update = FSPSM_SHA512_224_Up;
        break;
    case FSPSM_SHA512_256:
        Update = FSPSM_SHA512_256_Up;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    wc_fspsm_hw_lock();
    ret = Update(&hash->handle, (byte*)data, sz);
    wc_fspsm_hw_unlock();
    return ret;
#endif
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
    int ret = FSP_SUCCESS;
    fsp_err_t (*Final )(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t*);
    uint32_t sz;
    void* heap;
    (void) outSz;

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    FSPSM_SHA_HANDLE handle;
    fsp_err_t (*Init)(FSPSM_SHA_HANDLE*);
    fsp_err_t (*Update)(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t);

    if (hash == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (hash->sha_type == FSPSM_SHA256) {
        Init = FSPSM_SHA256_Init;
        Update = FSPSM_SHA256_Up;
        Final = FSPSM_SHA256_Final;
    } else
        return BAD_FUNC_ARG;

    wc_fspsm_hw_lock();

    if (Init(&handle) == FSP_SUCCESS) {
        ret = Update(&handle, (uint8_t*)hash->msg, hash->used);
        if (ret == FSP_SUCCESS) {
            ret = Final(&handle, out, (uint32_t*)&sz);
            if (ret != FSP_SUCCESS
            #if defined(WOLFSSL_RENESAS_SCEPROTECT)
             || sz != outSz
            #endif
            ) {
                WOLFSSL_MSG("Sha operation failed");
                WOLFSSL_ERROR(WC_HW_E);
                ret = WC_HW_E;
            }
        }
    }
    wc_fspsm_hw_unlock();

#elif defined(WOLFSSL_RENESAS_RSIP)
    switch(hash->sha_type) {
    case FSPSM_SHA1:
        Final = FSPSM_SHA1_Final;
        break;
    case FSPSM_SHA256:
        Final = FSPSM_SHA256_Final;
        break;
    case FSPSM_SHA224:
        Final = FSPSM_SHA224_Final;
        break;
    case FSPSM_SHA384:
        Final = FSPSM_SHA384_Final;
        break;
    case FSPSM_SHA512:
        Final = FSPSM_SHA512_Final;
        break;
    case FSPSM_SHA512_224:
        Final = FSPSM_SHA512_224_Final;
        break;
    case FSPSM_SHA512_256:
        Final = FSPSM_SHA512_256_Final;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    wc_fspsm_hw_lock();
    ret = Final(&hash->handle, out, (uint32_t*)&sz);
    if (ret != FSP_SUCCESS) {
        WOLFSSL_MSG("Sha operation failed");
        WOLFSSL_ERROR(WC_HW_E);
        ret = WC_HW_E;
    }
    wc_fspsm_hw_unlock();
#endif

    heap = hash->heap;

    FSPSM_HashFree(hash);
    FSPSM_HashInit(hash, heap, 0, hash->sha_type);

    return ret;
}
/* Hash operation to message and return a result */
static int FSPSM_HashGet(wolfssl_FSPSM_Hash* hash, byte* out, word32 outSz)
{
    int ret = FSP_SUCCESS;
    fsp_err_t (*Final )(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t*);
    uint32_t sz = 0;
    (void) outSz;

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    FSPSM_SHA_HANDLE handle;
    fsp_err_t (*Init)(FSPSM_SHA_HANDLE*);
    fsp_err_t (*Update)(FSPSM_SHA_HANDLE*, uint8_t*, uint32_t);
#elif defined(WOLFSSL_RENESAS_RSIP)
    wolfssl_FSPSM_Hash hashCopy;
#endif


    if (hash == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    if (hash->sha_type == FSPSM_SHA256) {
        Init = FSPSM_SHA256_Init;
        Update = FSPSM_SHA256_Up;
        Final = FSPSM_SHA256_Final;
    } else
        return BAD_FUNC_ARG;

    wc_fspsm_hw_lock();
    if (Init(&handle) == FSP_SUCCESS) {
        ret = Update(&handle, (uint8_t*)hash->msg, hash->used);
        if (ret == FSP_SUCCESS) {
            ret = Final(&handle, out, &sz);
            if (ret != FSP_SUCCESS
            #if defined(WOLFSSL_RENESAS_SCEPROTECT)
             || sz != outSz
            #endif
            ) {
                WOLFSSL_MSG("Sha operation failed");
                WOLFSSL_ERROR(WC_HW_E);
                ret = WC_HW_E;
            }
        }
    }
    wc_fspsm_hw_unlock();

#elif defined(WOLFSSL_RENESAS_RSIP)
    switch(hash->sha_type) {
    case FSPSM_SHA1:
        Final = FSPSM_SHA1_Final;
        break;
    case FSPSM_SHA256:
        Final = FSPSM_SHA256_Final;
        break;
    case FSPSM_SHA224:
        Final = FSPSM_SHA224_Final;
        break;
    case FSPSM_SHA384:
        Final = FSPSM_SHA384_Final;
        break;
    case FSPSM_SHA512:
        Final = FSPSM_SHA512_Final;
        break;
    case FSPSM_SHA512_224:
        Final = FSPSM_SHA512_224_Final;
        break;
    case FSPSM_SHA512_256:
        Final = FSPSM_SHA512_256_Final;
        break;
    default:
        return BAD_FUNC_ARG;
    }


    if(FSPSM_HashCopy(hash, &hashCopy) != 0) {
        WOLFSSL_MSG("ShaCopy operation failed");
        WOLFSSL_ERROR(WC_HW_E);
        ret = WC_HW_E;
    }
    wc_fspsm_hw_lock();
    ret = Final(&hashCopy.handle, out, (uint32_t*)&sz);
    if (ret != FSP_SUCCESS) {
        WOLFSSL_MSG("Sha operation failed");
        WOLFSSL_ERROR(WC_HW_E);
        ret = WC_HW_E;
    }
    wc_fspsm_hw_unlock();

#endif

    return ret;
}



#if !defined(NO_SHA) && defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
#include <wolfssl/wolfcrypt/sha.h>

int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    return FSPSM_HashInit(sha, heap, devId, FSPSM_SHA1);
}

int wc_ShaUpdate(wc_Sha* sha, const byte* in, word32 sz)
{
    return FSPSM_HashUpdate(sha, in, sz);
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA_DIGEST_SIZE);
}

int wc_ShaGetHash(wc_Sha* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA_DIGEST_SIZE);
}

int wc_ShaCopy(wc_Sha* src, wc_Sha* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* !NO_SHA && WOLFSSL_RENESAS_RSIP*/

#if defined(WOLFSSL_SHA224) && defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
#include <wolfssl/wolfcrypt/sha256.h>

/* WolfCrypt wrapper function for RX64 SHA224 Init */
int wc_InitSha224_ex(wc_Sha224* sha, void* heap, int devId)
{
    return FSPSM_HashInit(sha, heap, devId, FSPSM_SHA224);
}
/* WolfCrypt wrapper function for RX64 SHA224 Update */
int wc_Sha224Update(wc_Sha224* sha, const byte* in, word32 sz)
{
    return FSPSM_HashUpdate(sha, in, sz);
}
/* WolfCrypt wrapper function for RX64 SHA224 Final */
int wc_Sha224Final(wc_Sha224* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA224_DIGEST_SIZE);
}
/* WolfCrypt wrapper function for RX64 SHA224 Get */
int wc_Sha224GetHash(wc_Sha224* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA224_DIGEST_SIZE);
}
/* WolfCrypt wrapper function for RX64 SHA224 Copy */
int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* WOLFSSL_SHA224 */

#if !defined(NO_SHA256)
#if (defined(WOLFSSL_RENESAS_SCEPROTECT) || \
    defined(WOLFSSL_RENESAS_RSIP)) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
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
#endif /* WOLFSSL_RENESAS_SCEPROTECT) || \
        * WOLFSSL_RENESAS_RSIP */

#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
#include <wolfssl/wolfcrypt/sha512.h>
/*  wrapper for wc_InitSha384_ex */
int wc_InitSha384_ex(wc_Sha384* sha, void* heap, int devid)
{
    return FSPSM_HashInit(sha, heap, devid, FSPSM_SHA384);
}
/*  wrapper for wc_InitSha384_ex */
int wc_Sha384Update(wc_Sha384* sha, const byte* in, word32 sz)
{
    return FSPSM_HashUpdate(sha, in, sz);
}
/*  wrapper for wc_Sha384Final */
int wc_Sha384Final(wc_Sha384* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA384_DIGEST_SIZE);
}
/*  wrapper for wc_Sha384GetHash */
int wc_Sha384GetHash(wc_Sha384* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA384_DIGEST_SIZE);
}
/*  wrapper for wc_Sha384Copy */
int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH)
#include <wolfssl/wolfcrypt/sha512.h>

/*  wrapper for wc_InitSha512_ex */
int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devid)
{
    return FSPSM_HashInit(sha, heap, devid, FSPSM_SHA512);
}

/*  wrapper for wc_Sha512Update */
int wc_Sha512Update(wc_Sha512* sha, const byte* in, word32 sz)
{
    return FSPSM_HashUpdate(sha, in, sz);
}

/*  wrapper for wc_Sha512Final */
int wc_Sha512Final(wc_Sha512* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA512_DIGEST_SIZE);
}
/*  wrapper for wc_Sha512GetHash */
int wc_Sha512GetHash(wc_Sha512* sha, byte* hash)
{
   return FSPSM_HashGet(sha, hash, WC_SHA512_DIGEST_SIZE);
}
/*  wrapper for wc_Sha512Copy */
int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return FSPSM_HashCopy(src, dst);
}

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(WOLFSSL_NOSHA512_224) && \
    (defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH))

/* create KCAPI handle for SHA512 operation */
int wc_InitSha512_224_ex(wc_Sha512* sha, void* heap, int devid)
{
    return FSPSM_HashInit(sha, heap, devid, FSPSM_SHA512_224);
}

int wc_Sha512_224Final(wc_Sha512* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA512_224_DIGEST_SIZE);
}
int wc_Sha512_224GetHash(wc_Sha512* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA512_224_DIGEST_SIZE);
}

int wc_Sha512_224Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* !WOLFSSL_NOSHA512_224 */

#if !defined(WOLFSSL_NOSHA512_256) && \
    (defined(WOLFSSL_RENESAS_RSIP) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_HASH))

/* create KCAPI handle for SHA512 operation */
int wc_InitSha512_256_ex(wc_Sha512* sha, void* heap, int devid)
{
    return FSPSM_HashInit(sha, heap, devid, FSPSM_SHA512_256);
}

int wc_Sha512_256Final(wc_Sha512* sha, byte* hash)
{
    return FSPSM_HashFinal(sha, hash, WC_SHA512_256_DIGEST_SIZE);
}
int wc_Sha512_256GetHash(wc_Sha512* sha, byte* hash)
{
    return FSPSM_HashGet(sha, hash, WC_SHA512_224_DIGEST_SIZE);
}

int wc_Sha512_256Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return FSPSM_HashCopy(src, dst);
}
#endif /* !WOLFSSL_NOSHA512_256 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */

#endif /* WOLFSSL_SHA512 */


#endif /* WOLFSSL_RENESAS_FSPSM_TLS */
#endif /* #if !defined(NO_SHA) || !defined(NO_SHA256) */
