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

/* HMAC on the ASU. Same idea as asu_hash.c: the message is saved per context
 * and the whole HMAC is done in one operation at final(). */

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

/* Free a saved message. It holds the data we read, so wipe it first. */
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

/* Queue one ASU HMAC operation. The lock is held here, so only queue it. */
static int wc_AsuHmacSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuHmacReq* req = (AsuHmacReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_HmacCompute(params, &req->params);
}

/* Work out the ASU type, mode and output length for this MAC type.
 * Returns 0 if we support it. */
static int wc_AsuHmacResolve(int macType, u8* shaType, u8* shaMode,
    word32* hmacLen)
{
    if (shaType == NULL || shaMode == NULL || hmacLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (macType) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hmacLen = WC_SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hmacLen = WC_SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_512;
            *hmacLen = WC_SHA512_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA3
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
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    return 0;
}

/* Run the whole HMAC in one ASU operation. */
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
    req.params.MsgLen         = msgLen;
    req.params.HmacLen        = macLen;
    req.params.MsgBufferAddr  = (u64)(UINTPTR)msg;
    req.params.HmacAddr       = (u64)(UINTPTR)mac;
    wc_AsuHmacSetKey(&req.params, key, keyLen);
    if (msgLen > 0) {
        req.params.OperationFlags =
            (u8)(WC_ASU_HMAC_OP_INIT | WC_ASU_HMAC_OP_UPDATE |
                 WC_ASU_HMAC_OP_FINAL);
    }
    else {
        req.params.OperationFlags =
            (u8)(WC_ASU_HMAC_OP_INIT | WC_ASU_HMAC_OP_FINAL);
    }

    WC_ASU_PRINTF("[ASU] hmac type=%d mode=%d keyLen=%u msgLen=%u macLen=%u\r\n",
        (int)shaType, (int)shaMode, (unsigned int)keyLen, (unsigned int)msgLen,
        (unsigned int)macLen);

    /* The ASU reads the key and message from memory, so push them out first.
     * The MAC returns in the mailbox response, so it needs no cache work. */
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

/* Handles update and final for an HMAC. */
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
        WC_ASU_PRINTF("[ASU] hmac decline: macType=%d unsupported\r\n",
            (int)info->hmac.macType);
        return ret;
    }

    /* The ASU needs the raw key. If wolfSSL did not keep one, use software. */
    if ((hmac->keyRaw == NULL) || (hmac->keyLen == 0)) {
        WC_ASU_PRINTF("[ASU] hmac decline: no raw key "
            "(keyRaw=%p keyLen=%u)\r\n",
            (void*)hmac->keyRaw, (unsigned int)hmac->keyLen);
        return CRYPTOCB_UNAVAILABLE;
    }

    keep = (AsuHmacKeep*)hmac->devCtx;

    /* update: add this chunk to the saved message. */
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

    /* final: run the saved message in one go, then free the buffer. */
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

/* Handles copying an HMAC context. wolfSSL copies the struct itself, so this
 * only gives the destination its own copy of the saved message. */
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

/* Handles freeing an HMAC context, so a context that was never finished does
 * not leak its saved message. */
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

    /* Return unavailable so wolfSSL still cleans up. devCtx is NULL now, so
     * nothing gets freed twice. */
    return CRYPTOCB_UNAVAILABLE;
}

/* Entry point for HMAC. Sorts out whether this is an update, a final, a copy
 * or a free. */
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
