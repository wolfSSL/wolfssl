/* silabs_cb_hash.c
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

#if defined(WOLFSSL_SILABS_CRYPTOCB) && defined(WOLFSSL_SILABS_CRYPTOCB_HASH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

/* Resolve a hash request to the SE context embedded in the caller's wolfCrypt
 * hash object, and to the digest length. Returns CRYPTOCB_UNAVAILABLE for
 * anything the SE cannot do, so software runs.
 *
 * SHA-384/512 are always left to software. The SE supports them on Vault High,
 * but wc_ShaXXXGetHash() copies the context and finalizes the copy, which the
 * SE context does not survive (the SDK-v3 fixups in wc_Sha512Copy() are gated
 * on the direct port's macros). Offloading needs copy support first, and an
 * EFR32FG25B showed no gain over software. SHA-1/224/256 do offload. */
static int silabs_hash_resolve(wc_CryptoInfo* info, wc_silabs_sha_t** ctx,
    int* digestSz)
{
    void* obj = NULL;

    *ctx = NULL;
    *digestSz = 0;

    switch (info->hash.type) {
#ifndef NO_SHA
    case WC_HASH_TYPE_SHA:
        obj = (void*)info->hash.sha1;
        if (obj != NULL)
            *ctx = &((wc_Sha*)obj)->silabsCtx;
        *digestSz = WC_SHA_DIGEST_SIZE;
        break;
#endif
#ifdef WOLFSSL_SHA224
    case WC_HASH_TYPE_SHA224:
        obj = (void*)info->hash.sha224;
        if (obj != NULL)
            *ctx = &((wc_Sha224*)obj)->silabsCtx;
        *digestSz = WC_SHA224_DIGEST_SIZE;
        break;
#endif
#ifndef NO_SHA256
    case WC_HASH_TYPE_SHA256:
        obj = (void*)info->hash.sha256;
        if (obj != NULL)
            *ctx = &((wc_Sha256*)obj)->silabsCtx;
        *digestSz = WC_SHA256_DIGEST_SIZE;
        break;
#endif
    default:
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (*ctx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return 0;
}

/* Start the SE context on first use. wolfCrypt has no crypto callback hook on
 * wc_InitShaXXX, and that call zeroes the object, so "started" is clear on a
 * freshly initialized context. */
static int silabs_hash_start(wc_silabs_sha_t* ctx, int hashType)
{
    int ret = 0;

    if (!ctx->started) {
        ret = silabs_cb_status(
            wc_silabs_se_hash_init_status(ctx, (enum wc_HashType)hashType));
        if (ret == 0) {
            ctx->started = 1;
        }
    }

    return ret;
}

/* WC_ALGO_TYPE_HASH. digest == NULL means update, digest != NULL means final.
 * A single call may carry both. */
int wc_SilabsHash(wc_CryptoInfo* info)
{
    int ret;
    int digestSz = 0;
    wc_silabs_sha_t* ctx = NULL;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    /* A copy needs no SE work: the multipart context is embedded in the
     * wolfCrypt object and holds no pointers back into it, so the XMEMCPY that
     * runs on a decline suffices. (The SDK v3 context does hold self pointers,
     * which sha256.c and friends fix up after the copy.) */
    if (info->algo_type == WC_ALGO_TYPE_COPY) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (info->algo_type != WC_ALGO_TYPE_HASH) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = silabs_hash_resolve(info, &ctx, &digestSz);
    if (ret != 0) {
        return ret;
    }

    /* The SE Manager already serializes the mailbox: every sl_se_* command
     * goes through sli_se_execute_and_wait(), which takes its own lock. This
     * mutex guards something else - the start/update/final sequence below runs
     * several commands against one streaming context, and interleaving two of
     * those would corrupt it. The one-shot engines (cipher, pk, kdf, cmac)
     * issue a single command and so need no lock of their own. */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    /* Declining is only safe before the SE has taken any of the message: after
     * that the software context has not seen the consumed input, so a fallback
     * would hash the wrong data. Failures must then be terminal. */
    ret = silabs_hash_start(ctx, info->hash.type);

    if (ret == 0 && info->hash.in != NULL) {
        ret = silabs_cb_status(
            wc_silabs_se_hash_update_status(ctx, info->hash.in,
                info->hash.inSz));
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = WC_HW_E;
        }
    }

    if (ret == 0 && info->hash.digest != NULL) {
        ret = silabs_cb_status(
            wc_silabs_se_hash_final_status(ctx, info->hash.digest,
                (word32)digestSz));
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = WC_HW_E;
        }
        /* wolfCrypt leaves a finalized hash ready for reuse. The software
         * final re-inits; here clearing the flag restarts the SE context on
         * the next update. */
        ctx->started = 0;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_HASH */
