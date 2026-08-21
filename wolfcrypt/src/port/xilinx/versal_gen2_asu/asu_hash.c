/* asu_hash.c
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

/* Hashing on the ASU. The ASU cannot save a partial hash, so each context
 * saves its message in its own buffer and hashes it all at final(). */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_hash.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_sha2.h"
#include "xasu_sha3.h"
#include "xasu_shainfo.h"
#include "xstatus.h"

#ifndef WOLFSSL_HASH_KEEP
    #error "WOLFSSL_VERSAL_GEN2_ASU_HASH requires WOLFSSL_HASH_KEEP (_wc_Hash_Grow)"
#endif

#ifndef WOLFSSL_SHA512_HASHTYPE
    #error "WOLFSSL_VERSAL_GEN2_ASU_HASH requires WOLFSSL_SHA512_HASHTYPE to tell \
the SHA-512 family variants apart"
#endif

/* Per hash context message accumulation, held in the wolfSSL hash devCtx. */
typedef struct {
    byte*  msg;  /* accumulated message */
    word32 used; /* bytes accumulated */
    word32 len;  /* buffer capacity */
} AsuHashKeep;

/* One ASU hash request. */
typedef struct {
    XAsu_ShaOperationCmd cmd;
    int isSha3;
} AsuHashReq;

/* Free a saved message. It holds the data we hashed, so wipe it first. */
static void wc_AsuHashKeepFree(AsuHashKeep* keep)
{
    if (keep == NULL) {
        return;
    }
    if (keep->msg != NULL) {
        ForceZero(keep->msg, keep->len);
        XFREE(keep->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(keep, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Queue one ASU hash operation. The lock is held here, so only queue it. */
static int wc_AsuHashSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuHashReq* req = (AsuHashReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    if (req->isSha3 != 0) {
        return XAsu_Sha3Operation(params, &req->cmd);
    }
    else {
        return XAsu_Sha2Operation(params, &req->cmd);
    }
}

/* Size of the hash context for this type, or 0 if we do not support it. */
static word32 wc_AsuHashCtxSize(int hashType)
{
    switch (hashType) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            return (word32)sizeof(wc_Sha256);
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return (word32)sizeof(wc_Sha384);
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            return (word32)sizeof(wc_Sha512);
#endif
#ifdef WOLFSSL_SHA3
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512:
        case WC_HASH_TYPE_SHAKE256: /* wc_Shake is a wc_Sha3 */
            return (word32)sizeof(wc_Sha3);
#endif
        default:
            return 0;
    }
}

/* Address of the devCtx field for this hash type, or NULL if unsupported. */
static void** wc_AsuHashDevCtx(void* hashCtx, int hashType)
{
    if (hashCtx == NULL) {
        return NULL;
    }

    switch (hashType) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            return &((wc_Sha256*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return &((wc_Sha384*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            return &((wc_Sha512*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA3
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512:
        case WC_HASH_TYPE_SHAKE256: /* wc_Shake is a wc_Sha3 */
            return &((wc_Sha3*)hashCtx)->devCtx;
#endif
        default:
            return NULL;
    }
}

/* Work out the ASU type, mode, digest length and devCtx for this hash.
 * Returns 0 if we support it. */
static int wc_AsuHashResolve(wc_CryptoInfo* info, void*** devCtx, u8* shaType,
    u8* shaMode, word32* hashLen)
{
    if (info == NULL || devCtx == NULL || shaType == NULL ||
        shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->hash.type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha256, info->hash.type);
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hashLen = WC_SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha384, info->hash.type);
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hashLen = WC_SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            /* The ASU only does full SHA-512. The shorter versions start from
             * different values, so let software handle them. */
            if (info->hash.sha512 != NULL &&
                (info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_224 ||
                 info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_256)) {
                return CRYPTOCB_UNAVAILABLE;
            }
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha512, info->hash.type);
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_512;
            *hashLen = WC_SHA512_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA3
        case WC_HASH_TYPE_SHA3_256:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha3, info->hash.type);
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hashLen = WC_SHA3_256_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA3_384:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha3, info->hash.type);
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hashLen = WC_SHA3_384_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA3_512:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha3, info->hash.type);
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_512;
            *hashLen = WC_SHA3_512_DIGEST_SIZE;
            break;
#ifdef WOLFSSL_SHAKE256
        case WC_HASH_TYPE_SHAKE256:
            /* SHAKE lets the caller pick the output length, which arrives in
             * outSz. SHAKE128 has no ASU mode and runs in software. */
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha3, info->hash.type);
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_SHAKE256;
            *hashLen = info->hash.outSz;
            break;
#endif /* WOLFSSL_SHAKE256 */
#endif /* WOLFSSL_SHA3 */
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

#if defined(WOLFSSL_HASH_FLAGS) && defined(WOLFSSL_SHA3)
    /* The ASU only does standard SHA3 padding, so older Keccak runs in
     * software. */
    if (*shaType == XASU_SHA3_TYPE && info->hash.sha3 != NULL &&
        (info->hash.sha3->flags & WC_HASH_SHA3_KECCAK256) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    if (*devCtx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
}

/* Hash the whole message in one ASU operation. */
static int wc_AsuHashOneShot(u8 shaType, u8 shaMode, const byte* data,
    word32 dataLen, byte* digest, word32 hashLen)
{
    AsuHashReq req;
    word32 status;
    byte*  outAddr = digest;
    word32 outLen  = hashLen;
    byte   xofTmp[XASU_SHAKE_256_MAX_HASH_LEN];

    if (digest == NULL || (data == NULL && dataLen > 0)) {
        return BAD_FUNC_ARG;
    }

    /* The ASU reads the digest 4 bytes at a time, so round the length up into
     * a temporary buffer and copy back only what was asked for. */
    if ((shaMode == XASU_SHA_MODE_SHAKE256) && ((hashLen % 4u) != 0u) &&
        (hashLen <= XASU_SHAKE_256_MAX_HASH_LEN)) {
        outLen  = (hashLen + 3u) & ~3u;
        outAddr = xofTmp;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.cmd.DataAddr    = (u64)(UINTPTR)data;
    req.cmd.DataSize    = dataLen;
    req.cmd.HashAddr    = (u64)(UINTPTR)outAddr;
    req.cmd.HashBufSize = outLen;
    req.cmd.ShaMode     = shaMode;
    req.cmd.IsLast      = (u8)XASU_TRUE;
    if (dataLen > 0) {
        req.cmd.OperationFlags =
            (u8)(XASU_SHA_START | XASU_SHA_UPDATE | XASU_SHA_FINISH);
    }
    else {
        req.cmd.OperationFlags = (u8)(XASU_SHA_START | XASU_SHA_FINISH);
    }
    if (shaType == XASU_SHA3_TYPE) {
        req.isSha3 = 1;
    }
    else {
        req.isSha3 = 0;
    }

    WC_ASU_PRINTF("[ASU] hash type=%d mode=%d dataLen=%u hashLen=%u\r\n",
        (int)shaType, (int)shaMode, (unsigned int)dataLen, (unsigned int)hashLen);

    /* The ASU reads the message from memory, so push it out first. The digest
     * comes back another way and needs nothing here. */
    if (dataLen > 0) {
        wc_AsuCacheFlush(data, dataLen);
    }

    status = wc_AsuTransact(wc_AsuHashSubmit, &req, NULL);
    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }

    /* Copy back only the bytes asked for when a temp buffer was used. */
    if (outAddr != digest) {
        XMEMCPY(digest, xofTmp, hashLen);
    }

    return 0;
}

/* The ASU sends the hash back in a 64 byte slot. A SHAKE output that fits goes
 * to the ASU, and anything longer is done in software. */
#define WC_ASU_SHAKE_HW_MAX_BYTES 64

#ifdef WOLFSSL_SHAKE256
/* Do SHAKE256 in software for long outputs. The private context uses an
 * invalid device id so this does not come back through the callback. */
static int wc_AsuShakeSoftware(const byte* data, word32 dataLen, byte* digest,
    word32 hashLen)
{
    wc_Shake shake;
    int      ret;

    if (digest == NULL || (data == NULL && dataLen > 0)) {
        return BAD_FUNC_ARG;
    }

    ret = wc_InitShake256(&shake, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    if (dataLen > 0) {
        ret = wc_Shake256_Update(&shake, data, dataLen);
    }
    if (ret == 0) {
        ret = wc_Shake256_Final(&shake, digest, hashLen);
    }

    wc_Shake256_Free(&shake);
    return ret;
}
#endif /* WOLFSSL_SHAKE256 */

/* Handles update and final for a hash. */
static int wc_AsuHashCompute(wc_CryptoInfo* info)
{
    void**       devCtxPtr = NULL;
    u8           shaType = 0;
    u8           shaMode = 0;
    word32       hashLen = 0;
    AsuHashKeep* keep;
    int          ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuHashResolve(info, &devCtxPtr, &shaType, &shaMode, &hashLen);
    if (ret != 0) {
        return ret;
    }

    keep = (AsuHashKeep*)(*devCtxPtr);

    /* update: add this chunk to the saved message. */
    if (info->hash.in != NULL) {
        if (keep == NULL) {
            keep = (AsuHashKeep*)XMALLOC(sizeof(AsuHashKeep), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (keep == NULL) {
                return MEMORY_E;
            }
            XMEMSET(keep, 0, sizeof(*keep));
            *devCtxPtr = keep;
        }

        ret = _wc_Hash_Grow(&keep->msg, &keep->used, &keep->len,
            info->hash.in, (int)info->hash.inSz, NULL);
        if (ret != 0) {
            return ret;
        }
    }

    /* final: hash the saved message in one go, then free the buffer. */
    if (info->hash.digest != NULL) {
        const byte* data = NULL;
        word32      dataLen = 0;

        if (keep != NULL) {
            data = keep->msg;
            dataLen = keep->used;
        }

        /* A long SHAKE output is done in software from the same message.
         * Everything else is one ASU operation. */
#ifdef WOLFSSL_SHAKE256
        if ((shaMode == XASU_SHA_MODE_SHAKE256) &&
            (hashLen > WC_ASU_SHAKE_HW_MAX_BYTES)) {
            ret = wc_AsuShakeSoftware(data, dataLen, info->hash.digest, hashLen);
        }
        else
#endif /* WOLFSSL_SHAKE256 */
        {
            ret = wc_AsuHashOneShot(shaType, shaMode, data, dataLen,
                info->hash.digest, hashLen);
        }

        if (keep != NULL) {
            wc_AsuHashKeepFree(keep);
            *devCtxPtr = NULL;
        }

        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* Handles copying a hash context. */
static int wc_AsuHashCopy(wc_CryptoInfo* info)
{
    void**       srcDevCtx;
    void**       dstDevCtx;
    AsuHashKeep* srcKeep;
    AsuHashKeep* dstKeep;
    word32       ctxSize;
    int          ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->copy.algo != WC_ALGO_TYPE_HASH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    srcDevCtx = wc_AsuHashDevCtx(info->copy.src, info->copy.type);
    dstDevCtx = wc_AsuHashDevCtx(info->copy.dst, info->copy.type);
    ctxSize   = wc_AsuHashCtxSize(info->copy.type);
    if (srcDevCtx == NULL || dstDevCtx == NULL || ctxSize == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* wolfSSL skips its own copy when we succeed, so we do all of it. Free
     * anything the destination already holds or it would leak. */
    wc_AsuHashKeepFree((AsuHashKeep*)(*dstDevCtx));

    /* Copy the whole struct, then give the destination its own copy of the
     * saved message so the two do not share a buffer. */
    XMEMCPY(info->copy.dst, info->copy.src, ctxSize);

    srcKeep = (AsuHashKeep*)(*srcDevCtx);
    if (srcKeep == NULL) {
        *dstDevCtx = NULL;
        return 0;
    }

    dstKeep = (AsuHashKeep*)XMALLOC(sizeof(AsuHashKeep), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (dstKeep == NULL) {
        *dstDevCtx = NULL;
        return MEMORY_E;
    }
    XMEMSET(dstKeep, 0, sizeof(*dstKeep));

    if (srcKeep->used > 0) {
        ret = _wc_Hash_Grow(&dstKeep->msg, &dstKeep->used, &dstKeep->len,
            srcKeep->msg, (int)srcKeep->used, NULL);
        if (ret != 0) {
            wc_AsuHashKeepFree(dstKeep);
            *dstDevCtx = NULL;
            return ret;
        }
    }

    *dstDevCtx = dstKeep;
    return 0;
}

/* Handles freeing a hash context. */
static int wc_AsuHashFree(wc_CryptoInfo* info)
{
    void**       devCtx;
    AsuHashKeep* keep;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->free.algo != WC_ALGO_TYPE_HASH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    devCtx = wc_AsuHashDevCtx(info->free.obj, info->free.type);
    if (devCtx != NULL) {
        keep = (AsuHashKeep*)(*devCtx);
        if (keep != NULL) {
            wc_AsuHashKeepFree(keep);
            *devCtx = NULL;
        }
    }

    /* Return unavailable so wolfSSL still wipes the context. devCtx is NULL
     * now, so nothing gets freed twice. */
    return CRYPTOCB_UNAVAILABLE;
}

/* Entry point for hashing. Sorts out whether this is an update, a final, a
 * copy or a free. */
int wc_AsuHash(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_HASH:
            return wc_AsuHashCompute(info);
        case WC_ALGO_TYPE_COPY:
            return wc_AsuHashCopy(info);
        case WC_ALGO_TYPE_FREE:
            return wc_AsuHashFree(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HASH */
