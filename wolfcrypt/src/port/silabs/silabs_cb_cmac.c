/* silabs_cb_cmac.c
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

#if defined(WOLFSSL_SILABS_CRYPTOCB) && \
    defined(WOLFSSL_SILABS_CRYPTOCB_CMAC) && defined(WOLFSSL_CMAC) && \
    !defined(NO_AES)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_aes.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Per-Cmac SE state, hung off Cmac.devCtx and released by the free callback.
 * The SE multipart context buffers a partial block itself, so wolfCrypt can
 * update with any length. */
typedef struct {
    sl_se_command_context_t        cmd_ctx;
    sl_se_cmac_multipart_context_t cmac_ctx;
    silabs_aes_t                   keyDesc;
    byte                           key[AES_MAX_KEY_SIZE / WOLFSSL_BIT_SIZE];
    word32                         keySz;
} silabs_cmac_ctx_t;

static silabs_cmac_ctx_t* silabs_cmac_ctx(Cmac* cmac)
{
    return (cmac == NULL) ? NULL : (silabs_cmac_ctx_t*)cmac->devCtx;
}

static void silabs_cmac_free(Cmac* cmac)
{
    silabs_cmac_ctx_t* c = silabs_cmac_ctx(cmac);

    if (c != NULL) {
        ForceZero(c, sizeof(*c));
        XFREE(c, cmac->aes.heap, DYNAMIC_TYPE_CMAC);
        cmac->devCtx = NULL;
    }
}

/* Take a copy of the key: the SE descriptor references the buffer for the
 * lifetime of the multipart operation, and the caller's key may not live
 * that long. */
static int silabs_cmac_start(Cmac* cmac, const byte* key, word32 keySz)
{
    silabs_cmac_ctx_t* c;
    sl_status_t status;
    int ret;

    if (cmac == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keySz != AES_128_KEY_SIZE && keySz != AES_192_KEY_SIZE &&
        keySz != AES_256_KEY_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    silabs_cmac_free(cmac);

    c = (silabs_cmac_ctx_t*)XMALLOC(sizeof(silabs_cmac_ctx_t), cmac->aes.heap,
        DYNAMIC_TYPE_CMAC);
    if (c == NULL) {
        return MEMORY_E;
    }
    XMEMSET(c, 0, sizeof(*c));
    XMEMCPY(c->key, key, keySz);
    c->keySz = keySz;

    /* Only keyDesc.key is consumed here. The helper is shared with the cipher
     * path and also seeds keyDesc.cmd_ctx, but the CMAC multipart calls all
     * take c->cmd_ctx, so that context is intentionally left unused. */
    ret = silabs_aes_init_key_desc(&(c->keyDesc), c->key, keySz);
    if (ret != 0) {
        ForceZero(c, sizeof(*c));
        XFREE(c, cmac->aes.heap, DYNAMIC_TYPE_CMAC);
        return ret;
    }

    status = sl_se_cmac_multipart_starts(&(c->cmac_ctx), &(c->cmd_ctx),
        &(c->keyDesc.key));
    ret = silabs_cb_status((int)status);
    if (ret != 0) {
        ForceZero(c, sizeof(*c));
        XFREE(c, cmac->aes.heap, DYNAMIC_TYPE_CMAC);
        return ret;
    }

    cmac->devCtx = c;

    return 0;
}

/* One-shot: key, message and output all in a single call.
 *
 * wc_AesCmacGenerate_ex() dispatches here BEFORE wc_InitCmac_ex() has run, so
 * cmac->devCtx and cmac->aes.heap are still whatever the caller's storage
 * happened to contain. Touching them would mean freeing a garbage pointer, so
 * this path keeps every bit of state on the stack and never reads or writes
 * the Cmac. Declining part-way is safe here because software redoes the whole
 * operation from the key and message; nothing has been consumed. */
static int silabs_cmac_oneshot(wc_CryptoInfo* info)
{
    silabs_cmac_ctx_t c;
    byte tag[WC_AES_BLOCK_SIZE];
    sl_status_t status;
    int ret;

    if (info->cmac.keySz != AES_128_KEY_SIZE &&
        info->cmac.keySz != AES_192_KEY_SIZE &&
        info->cmac.keySz != AES_256_KEY_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (*info->cmac.outSz < WC_CMAC_TAG_MIN_SZ ||
        *info->cmac.outSz > WC_CMAC_TAG_MAX_SZ) {
        return BUFFER_E;
    }

    XMEMSET(&c, 0, sizeof(c));
    XMEMCPY(c.key, info->cmac.key, info->cmac.keySz);
    c.keySz = info->cmac.keySz;

    ret = silabs_aes_init_key_desc(&(c.keyDesc), c.key, c.keySz);
    if (ret == 0) {
        status = sl_se_cmac_multipart_starts(&(c.cmac_ctx), &(c.cmd_ctx),
            &(c.keyDesc.key));
        ret = silabs_cb_status((int)status);
    }
    if (ret == 0 && info->cmac.in != NULL) {
        status = sl_se_cmac_multipart_update(&(c.cmac_ctx), &(c.cmd_ctx),
            &(c.keyDesc.key), info->cmac.in, info->cmac.inSz);
        ret = silabs_cb_status((int)status);
    }
    if (ret == 0) {
        status = sl_se_cmac_multipart_finish(&(c.cmac_ctx), &(c.cmd_ctx),
            &(c.keyDesc.key), tag);
        ret = silabs_cb_status((int)status);
    }
    if (ret == 0) {
        XMEMCPY(info->cmac.out, tag, *info->cmac.outSz);
    }

    ForceZero(tag, sizeof(tag));
    ForceZero(&c, sizeof(c));

    return ret;
}

/* WC_ALGO_TYPE_CMAC and the CMAC arm of WC_ALGO_TYPE_FREE. wolfCrypt drives
 * this with key set (start), in set (update), out set (final), or all three
 * for the one-shot. */
int wc_SilabsCmac(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    silabs_cmac_ctx_t* c;
    sl_status_t status;
    Cmac* cmac;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        silabs_cmac_free((Cmac*)info->free.obj);
        /* Return unavailable so wolfSSL still runs its own cleanup. */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (info->algo_type != WC_ALGO_TYPE_CMAC) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    cmac = info->cmac.cmac;
    if (cmac == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* The SE does AES-CMAC only. */
    if (info->cmac.type != WC_CMAC_AES) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* The one-shot entry points dispatch here before wc_AesCmacGenerate_ex()
     * runs its own pointer/length validation, so check the pairs now. Doing it
     * before any SE state is created also means a rejected call cannot leave
     * an allocated device context behind. A NULL buffer with a positive length
     * would otherwise be silently taken as an empty message, or return success
     * without ever producing a tag. */
    if (info->cmac.in == NULL && info->cmac.inSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (info->cmac.out == NULL && info->cmac.outSz != NULL &&
        *info->cmac.outSz > 0) {
        return BAD_FUNC_ARG;
    }

    /* A one-shot arrives with key and output together, before the Cmac has
     * been initialised. Handle it without touching the object at all. */
    if (info->cmac.key != NULL && info->cmac.out != NULL &&
        info->cmac.outSz != NULL) {
        return silabs_cmac_oneshot(info);
    }

    if (info->cmac.key != NULL) {
        ret = silabs_cmac_start(cmac, info->cmac.key, info->cmac.keySz);
        if (ret != 0) {
            return ret;
        }
    }

    c = silabs_cmac_ctx(cmac);
    if (c == NULL) {
        /* No SE state: the key was set before this device took over, so let
         * software finish the operation. */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* From here the SE holds the key and any message consumed so far, while
     * wc_InitCmac_ex() returned without setting up the software AES/CMAC
     * state. Declining now would make the core resume an operation that was
     * never started in software, so a later failure has to be terminal. */
    if (info->cmac.in != NULL) {
        status = sl_se_cmac_multipart_update(&(c->cmac_ctx), &(c->cmd_ctx),
            &(c->keyDesc.key), info->cmac.in, info->cmac.inSz);
        ret = silabs_cb_status((int)status);
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = WC_HW_E;
        }
        if (ret != 0) {
            return ret;
        }
    }

    if (info->cmac.out != NULL) {
        /* The SE always writes a full block, but wolfCrypt permits a truncated
         * tag anywhere in [WC_CMAC_TAG_MIN_SZ, WC_CMAC_TAG_MAX_SZ]. Finalize
         * into a local block and copy out only what the caller asked for,
         * rather than overrunning a short buffer or rejecting a valid size. */
        byte tag[WC_AES_BLOCK_SIZE];

        if (info->cmac.outSz == NULL ||
            *info->cmac.outSz < WC_CMAC_TAG_MIN_SZ ||
            *info->cmac.outSz > WC_CMAC_TAG_MAX_SZ) {
            return BUFFER_E;
        }
        status = sl_se_cmac_multipart_finish(&(c->cmac_ctx), &(c->cmd_ctx),
            &(c->keyDesc.key), tag);
        ret = silabs_cb_status((int)status);
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = WC_HW_E;   /* see the note above the update */
        }
        if (ret == 0) {
            XMEMCPY(info->cmac.out, tag, *info->cmac.outSz);
        }
        ForceZero(tag, sizeof(tag));
        silabs_cmac_free(cmac);
    }

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_CMAC &&
        * WOLFSSL_CMAC && !NO_AES */
