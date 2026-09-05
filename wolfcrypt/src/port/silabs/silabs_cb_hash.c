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

/* Resolve a crypto callback hash request to the SE context embedded in the
 * caller's wolfCrypt hash object, and to the digest length. Returns
 * CRYPTOCB_UNAVAILABLE for anything the SE cannot do, so software runs.
 *
 * SHA-384 and SHA-512 are always left to software. The SE supports them on
 * Secure Vault High, but driving them through this callback returns a wrong
 * digest for the wc_ShaXXXGetHash() path, which copies the context and
 * finalizes the copy: the SE context does not survive that copy, and the
 * SDK-v3 fixups in wc_Sha512Copy()/wc_Sha384Copy() are gated on the direct
 * port's own macros. Offloading them needs complete copy and finalization
 * support first, and measurement on an EFR32FG25B showed no throughput gain
 * over software for either, so there is nothing lost by waiting. SHA-1,
 * SHA-224 and SHA-256 are unaffected and do offload. */
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

    /* A context copy needs no SE work: the multipart context is embedded in
     * the wolfCrypt object and holds no pointers back into it, so wolfSSL's
     * own XMEMCPY (which runs when this returns unavailable) is sufficient.
     * The SDK v3 streaming context does hold self pointers, and sha256.c and
     * friends fix those up after the copy. */
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

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    /* Declining is only safe before the SE has taken any of the message. Once
     * a start or an update has succeeded, the software context has not seen
     * the input consumed so far, so falling back there would finalize a hash
     * over the wrong data. After that point a failure has to be terminal. */
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
