/* asu_hmac.c
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

/* ASU HMAC for the wolfSSL crypto callback: HMAC over SHA2 256/384/512 and SHA3
 * 256/384/512.
 *
 * The approach mirrors the SHA hash port (asu_hash.c): wolfSSL drives HMAC as
 * update()...update()...final() and may have several contexts in flight, but the
 * ASU keeps the running state only inside the core and cannot save and restore
 * it. So each context's message is accumulated in its own buffer hung off the
 * wolfSSL Hmac devCtx (with the wolfSSL _wc_Hash_Grow helper) and the whole HMAC
 * is produced in one atomic ASU operation at final(). The raw key is taken from
 * the context: wolfSSL records keyRaw and keyLen on the Hmac whenever the crypto
 * callback is enabled, and the ASU HMAC engine performs the key reduction
 * internally, so the unmodified user key is passed straight through.
 *
 * Lifecycle: unlike the hash contexts, wc_HmacCopy does not run through the copy
 * crypto callback and wc_HmacFree does not run through the free callback, so no
 * copy/free handlers are wired for HMAC. This is safe because the buffer is freed
 * in final() (the common path), wc_HmacFree finalizes any context that still owns
 * a buffer through this same callback (so an abandoned context is cleaned up),
 * and wolfSSL only copies an HMAC context right after the key is set, before any
 * update, when devCtx is still NULL (so the shallow struct copy shares nothing).
 *
 * HMAC output is always the underlying digest size (<= 64 bytes), so unlike SHAKE
 * it always fits the ASU response mailbox and is always offloaded for the
 * supported MAC types. HMAC over SHA-1, SHA-224 and the truncated SHA-512
 * variants has no ASU mode and is declined to software.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_hmac.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_hmac.h"
#include "xasu_hmacinfo.h"
#include "xasu_shainfo.h"
#include "xstatus.h"

#ifndef WOLFSSL_HASH_KEEP
    #error "WOLFSSL_VERSAL_GEN2_ASU_HMAC requires WOLFSSL_HASH_KEEP (_wc_Hash_Grow)"
#endif

/* Per HMAC context message accumulation, held in the wolfSSL Hmac devCtx. */
typedef struct {
    byte*  msg;  /* accumulated message */
    word32 used; /* bytes accumulated */
    word32 len;  /* buffer capacity */
} AsuHmacKeep;

/* One ASU HMAC request. */
typedef struct {
    XAsu_HmacParams params;
} AsuHmacReq;

/* Release a kept message record. The message buffer holds plaintext that was
 * MAC'd, so it is zeroized before being returned to the allocator. */
static void wc_AsuHmacKeepFree(AsuHmacKeep* keep)
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

/* Submit thunk: queue one ASU HMAC operation. Called by wc_AsuTransact with the
 * submit lock held, so it only queues the request. */
static int wc_AsuHmacSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuHmacReq* req = (AsuHmacReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_HmacCompute(params, &req->params);
}

/* Resolve the wolfSSL MAC (hash) type to the ASU SHA type and mode and the HMAC
 * output length. Returns 0 if supported, otherwise CRYPTOCB_UNAVAILABLE. */
static int wc_AsuHmacResolve(int macType, u8* shaType, u8* shaMode,
    word32* hmacLen)
{
    if (shaType == NULL || shaMode == NULL || hmacLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (macType) {
        case WC_HASH_TYPE_SHA256:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hmacLen = WC_SHA256_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA384:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hmacLen = WC_SHA384_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA512:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_512;
            *hmacLen = WC_SHA512_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA3_256:
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hmacLen = WC_SHA3_256_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA3_384:
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hmacLen = WC_SHA3_384_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA3_512:
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_512;
            *hmacLen = WC_SHA3_512_DIGEST_SIZE;
            break;
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
}

/* Compute HMAC over the whole message in one atomic ASU operation. */
static int wc_AsuHmacOneShot(u8 shaType, u8 shaMode, const byte* key,
    word32 keyLen, const byte* msg, word32 msgLen, byte* mac, word32 macLen)
{
    AsuHmacReq req;
    word32 status;

    if (key == NULL || mac == NULL || (msg == NULL && msgLen > 0)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.params.ShaType        = shaType;
    req.params.ShaMode        = shaMode;
    req.params.IsLast         = (u8)XASU_TRUE;
    req.params.KeyLen         = keyLen;
    req.params.MsgLen         = msgLen;
    req.params.HmacLen        = macLen;
    req.params.KeyAddr        = (u64)(UINTPTR)key;
    req.params.MsgBufferAddr  = (u64)(UINTPTR)msg;
    req.params.HmacAddr       = (u64)(UINTPTR)mac;
    if (msgLen > 0) {
        req.params.OperationFlags =
            (u8)(XASU_HMAC_INIT | XASU_HMAC_UPDATE | XASU_HMAC_FINAL);
    }
    else {
        req.params.OperationFlags = (u8)(XASU_HMAC_INIT | XASU_HMAC_FINAL);
    }

    WC_ASU_PRINTF("[ASU] hmac type=%d mode=%d keyLen=%u msgLen=%u macLen=%u\r\n",
        (int)shaType, (int)shaMode, (unsigned int)keyLen, (unsigned int)msgLen,
        (unsigned int)macLen);

    /* The ASU DMAs the key and message from memory, so clean them out. The MAC
     * is delivered back through the response path, so it needs no cache
     * maintenance here. */
    wc_AsuCacheFlush(key, keyLen);
    if (msgLen > 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuHmacSubmit, &req, NULL);
    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }

    return 0;
}

/* update() and final() handling for WC_ALGO_TYPE_HMAC. Internal helper reached
 * through the wc_AsuHmac dispatcher. */
static int wc_AsuHmacCompute(wc_CryptoInfo* info)
{
    Hmac*        hmac;
    AsuHmacKeep* keep;
    u8           shaType = 0;
    u8           shaMode = 0;
    word32       hmacLen = 0;
    int          ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    hmac = info->hmac.hmac;
    if (hmac == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuHmacResolve(info->hmac.macType, &shaType, &shaMode, &hmacLen);
    if (ret != 0) {
        return ret;
    }

    /* The ASU HMAC engine needs a non empty raw key; if wolfSSL did not retain
     * one, let it compute the HMAC in software. keyRaw and keyLen are fixed by
     * the preceding SetKey, so this decision is the same on every update and
     * final for a given context. */
    if ((hmac->keyRaw == NULL) || (hmac->keyLen == 0)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    keep = (AsuHmacKeep*)hmac->devCtx;

    /* update(): accumulate the message with the wolfSSL grow helper. */
    if (info->hmac.in != NULL) {
        if (keep == NULL) {
            keep = (AsuHmacKeep*)XMALLOC(sizeof(AsuHmacKeep), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (keep == NULL) {
                return MEMORY_E;
            }
            XMEMSET(keep, 0, sizeof(*keep));
            hmac->devCtx = keep;
        }

        ret = _wc_Hash_Grow(&keep->msg, &keep->used, &keep->len,
            info->hmac.in, (int)info->hmac.inSz, NULL);
        if (ret != 0) {
            return ret;
        }
    }

    /* final(): HMAC the whole accumulated message in one ASU operation, then
     * release the buffer. */
    if (info->hmac.digest != NULL) {
        const byte* msg = NULL;
        word32      msgLen = 0;

        if (keep != NULL) {
            msg = keep->msg;
            msgLen = keep->used;
        }

        ret = wc_AsuHmacOneShot(shaType, shaMode, hmac->keyRaw,
            (word32)hmac->keyLen, msg, msgLen, info->hmac.digest, hmacLen);

        if (keep != NULL) {
            wc_AsuHmacKeepFree(keep);
            hmac->devCtx = NULL;
        }

        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* WC_ALGO_TYPE_COPY handling for an HMAC context. Unlike the hash copy callback,
 * wc_HmacCopy performs the struct copy itself (and deep copies the inner hash),
 * then calls this only to fix up the kept message: the shallow struct copy left
 * the destination sharing the source buffer pointer, so replace it with the
 * destination's own deep copy. Internal helper reached through wc_AsuHmac. */
static int wc_AsuHmacCopy(wc_CryptoInfo* info)
{
    Hmac*        src;
    Hmac*        dst;
    AsuHmacKeep* srcKeep;
    AsuHmacKeep* dstKeep;
    int          ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->copy.algo != WC_ALGO_TYPE_HMAC) {
        return CRYPTOCB_UNAVAILABLE;
    }

    src = (Hmac*)info->copy.src;
    dst = (Hmac*)info->copy.dst;
    if (src == NULL || dst == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    srcKeep = (AsuHmacKeep*)src->devCtx;
    if (srcKeep == NULL) {
        dst->devCtx = NULL;
        return 0;
    }

    dstKeep = (AsuHmacKeep*)XMALLOC(sizeof(AsuHmacKeep), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (dstKeep == NULL) {
        dst->devCtx = NULL;
        return MEMORY_E;
    }
    XMEMSET(dstKeep, 0, sizeof(*dstKeep));

    if (srcKeep->used > 0) {
        ret = _wc_Hash_Grow(&dstKeep->msg, &dstKeep->used, &dstKeep->len,
            srcKeep->msg, (int)srcKeep->used, NULL);
        if (ret != 0) {
            wc_AsuHmacKeepFree(dstKeep);
            dst->devCtx = NULL;
            return ret;
        }
    }

    dst->devCtx = dstKeep;
    return 0;
}

/* WC_ALGO_TYPE_FREE handling for an HMAC context: release the accumulated
 * message buffer so an abandoned context (updated but never finalized) is freed
 * without a stray ASU operation. Internal helper reached through wc_AsuHmac. */
static int wc_AsuHmacFree(wc_CryptoInfo* info)
{
    Hmac*        hmac;
    AsuHmacKeep* keep;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->free.algo != WC_ALGO_TYPE_HMAC) {
        return CRYPTOCB_UNAVAILABLE;
    }

    hmac = (Hmac*)info->free.obj;
    if (hmac != NULL) {
        keep = (AsuHmacKeep*)hmac->devCtx;
        if (keep != NULL) {
            wc_AsuHmacKeepFree(keep);
            hmac->devCtx = NULL;
        }
    }

    /* Return unavailable so wolfSSL still runs its own cleanup. devCtx is now
     * NULL, so there is no second free. */
    return CRYPTOCB_UNAVAILABLE;
}

/* Single entry point for the HMAC engine. The crypto callback dispatcher routes
 * every HMAC related operation here and this handler decides which it is: update
 * and final (WC_ALGO_TYPE_HMAC), context copy (WC_ALGO_TYPE_COPY) or context
 * free (WC_ALGO_TYPE_FREE). */
int wc_AsuHmac(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_HMAC:
            return wc_AsuHmacCompute(info);
        case WC_ALGO_TYPE_COPY:
            return wc_AsuHmacCopy(info);
        case WC_ALGO_TYPE_FREE:
            return wc_AsuHmacFree(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_HMAC */
