/* nuvoton_cb_hash.c
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

/* Hashing on the M2354 CRPT SHA engine.
 *
 * Streams. Each hash context owns a feedback buffer, and the engine swaps its
 * working state in and out of that buffer by DMA around every chunk - FBIN
 * before, FBOUT after, addressed by HMAC_FBADDR. Nothing of a message stays in
 * the engine between calls, so hashes may interleave freely: a TLS handshake
 * running the transcript hash against the record MAC, or wc_Sha256Copy forking
 * the transcript, are all safe by construction.
 *
 * The context therefore costs a fixed ~350 bytes - 216 bytes of feedback state
 * plus one block of buffering - rather than growing with the message.
 *
 * The engine takes whole blocks for every chunk but the last, so updates
 * buffer a partial block here and hand over as soon as a full one is
 * available. The buffer is deliberately allowed to fill completely before it
 * is flushed, so that a message whose length is an exact multiple of the block
 * size still has a final chunk to give the engine with DMALAST set.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_HASH) && \
    defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Per hash context streaming state, held in the wolfSSL hash devCtx.
 *
 * fdbck is what the engine reads and writes by DMA, so it leads the struct to
 * keep it word aligned; XMALLOC gives it an address the engine can reach. */
typedef struct {
    word32   fdbck[WC_NUVOTON_SHA_FDBCK_WORDS];
    byte     block[WC_NUVOTON_SHA_BLOCK_MAX]; /* partial block between updates */
    word32   used;      /* bytes currently in block */
    word32   blockSz;   /* 64 or 128, by algorithm */
    int      shaMode;
    int      started;   /* has a chunk gone to the engine for this message */
} NuvotonShaCtx;

/* Release a hash context's streaming state. It holds a slice of the message
 * and the engine's working state, so wipe it. */
static void wc_NuvotonShaCtxFree(NuvotonShaCtx* ctx)
{
    if (ctx == NULL) {
        return;
    }
    ForceZero(ctx, sizeof(*ctx));
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Hand one chunk to the engine, carrying this context's feedback state. */
static int wc_NuvotonShaChunk(NuvotonShaCtx* ctx, const byte* in, word32 inSz,
    byte* digest, word32 digestSz, int last)
{
    wc_NuvotonShaReq req;
    int              ret;

    XMEMSET(&req, 0, sizeof(req));
    req.fdbck    = ctx->fdbck;
    req.in       = in;
    req.inSz     = inSz;
    req.digest   = digest;
    req.digestSz = digestSz;
    req.shaMode  = ctx->shaMode;
    req.first    = (ctx->started == 0);
    req.last     = last;

    ret = wc_nuvoton_hw_sha(&req);
    if (ret == 0) {
        ctx->started = 1;
    }

    return ret;
}

/* Block size for this algorithm, or 0 if we do not support it. */
static word32 wc_NuvotonShaBlockSz(int hashType)
{
    switch (hashType) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            return WC_SHA_BLOCK_SIZE;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return WC_SHA224_BLOCK_SIZE;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            return WC_SHA256_BLOCK_SIZE;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return WC_SHA384_BLOCK_SIZE;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            return WC_SHA512_BLOCK_SIZE;
#endif
        default:
            return 0;
    }
}

/* Size of the hash context for this type, or 0 if we do not support it. */
static word32 wc_NuvotonHashCtxSize(int hashType)
{
    switch (hashType) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            return (word32)sizeof(wc_Sha);
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return (word32)sizeof(wc_Sha224);
#endif
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
        default:
            return 0;
    }
}

/* Address of the devCtx field for this hash type, or NULL if unsupported. */
static void** wc_NuvotonHashDevCtx(void* hashCtx, int hashType)
{
    if (hashCtx == NULL) {
        return NULL;
    }

    switch (hashType) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            return &((wc_Sha*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return &((wc_Sha224*)hashCtx)->devCtx;
#endif
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
        default:
            return NULL;
    }
}

/* Work out the engine mode, digest length and devCtx for this hash. Returns 0
 * if the CRPT SHA engine can do it. */
static int wc_NuvotonHashResolve(wc_CryptoInfo* info, void*** devCtx,
    int* shaMode, word32* hashLen)
{
    if (info == NULL || devCtx == NULL || shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->hash.type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha1, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_1;
            *hashLen = WC_SHA_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha224, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_224;
            *hashLen = WC_SHA224_DIGEST_SIZE;
            break;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha256, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_256;
            *hashLen = WC_SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha384, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_384;
            *hashLen = WC_SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
    #ifdef WOLFSSL_SHA512_HASHTYPE
            /* The engine only does full SHA-512. SHA-512/224 and SHA-512/256
             * start from different initial values, so they must go to
             * software. hashType is the only way to tell them apart and it
             * exists only with WOLFSSL_SHA512_HASHTYPE, which is why
             * nuvoton_settings.h turns that on and refuses a build without
             * it: those two variants are gated on the negative
             * WOLFSSL_NOSHA512_224 / _256, so they are on by DEFAULT, and
             * without the member this check silently disappears.
             *
             * Caught on hardware. The benchmark showed SHA-512/224 and
             * SHA-512/256 running at full SHA-512 speed on the accelerator,
             * which meant they were being answered with a full SHA-512 digest
             * and no error at all. Wrong results, silently, in the default
             * configuration. */
            if (info->hash.sha512 != NULL &&
                (info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_224 ||
                 info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_256)) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
    #endif
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha512, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_512;
            *hashLen = WC_SHA512_DIGEST_SIZE;
            break;
#endif
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (*devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return 0;
}

/* Handles update and final for a hash. */
static int wc_NuvotonHashCompute(wc_CryptoInfo* info)
{
    void**         devCtxPtr = NULL;
    int            shaMode = 0;
    word32         hashLen = 0;
    word32         blockSz;
    NuvotonShaCtx* ctx;
    int            ret;

    ret = wc_NuvotonHashResolve(info, &devCtxPtr, &shaMode, &hashLen);
    if (ret != 0) {
        return ret;
    }

    blockSz = wc_NuvotonShaBlockSz(info->hash.type);
    if (blockSz == 0 || blockSz > WC_NUVOTON_SHA_BLOCK_MAX) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ctx = (NuvotonShaCtx*)(*devCtxPtr);
    if (ctx == NULL) {
        ctx = (NuvotonShaCtx*)XMALLOC(sizeof(NuvotonShaCtx), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx == NULL) {
            return MEMORY_E;
        }
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->blockSz = blockSz;
        ctx->shaMode = shaMode;
        *devCtxPtr = ctx;
    }

    /* update: fill the block buffer and hand over whole blocks. The buffer is
     * allowed to fill completely before flushing, so a message that is an
     * exact multiple of the block size still leaves a block for the final
     * call to send with DMALAST. */
    if (info->hash.in != NULL) {
        const byte* in = info->hash.in;
        word32      sz = info->hash.inSz;

        while (sz > 0) {
            word32 take = ctx->blockSz - ctx->used;

            if (take > sz) {
                take = sz;
            }
            XMEMCPY(ctx->block + ctx->used, in, take);
            ctx->used += take;
            in        += take;
            sz        -= take;

            if (ctx->used == ctx->blockSz && sz > 0) {
                ret = wc_NuvotonShaChunk(ctx, ctx->block, ctx->used, NULL, 0,
                    0);
                if (ret != 0) {
                    break;
                }
                ctx->used = 0;
            }
        }

        if (ret != 0) {
            /* Nothing partial can be handed back to software - it has not seen
             * the earlier updates - so a failure here is a failure. An address
             * the engine cannot reach is the one exception, and that can only
             * happen on the very first chunk with our own buffer, which is
             * always reachable. */
            wc_NuvotonShaCtxFree(ctx);
            *devCtxPtr = NULL;
            return ret;
        }
    }

    /* final: send whatever is left with DMALAST and let the engine pad. */
    if (info->hash.digest != NULL) {
        if (ctx->started == 0 && ctx->used == 0) {
            /* The empty message. The result register is only written by a DMA
             * round and a zero-length round does not start one, so software
             * takes it. */
            wc_NuvotonShaCtxFree(ctx);
            *devCtxPtr = NULL;
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }

        ret = wc_NuvotonShaChunk(ctx, ctx->block, ctx->used,
            info->hash.digest, hashLen, 1);

        wc_NuvotonShaCtxFree(ctx);
        *devCtxPtr = NULL;

        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

int wc_NuvotonCb_Hash(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_NuvotonHashCompute(info);
}

#ifdef WOLF_CRYPTO_CB_COPY
int wc_NuvotonCb_HashCopy(wc_CryptoInfo* info)
{
    void**         srcDevCtx;
    void**         dstDevCtx;
    NuvotonShaCtx* srcCtx;
    NuvotonShaCtx* dstCtx;
    word32         ctxSize;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->copy.algo != WC_ALGO_TYPE_HASH) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    srcDevCtx = wc_NuvotonHashDevCtx(info->copy.src, info->copy.type);
    dstDevCtx = wc_NuvotonHashDevCtx(info->copy.dst, info->copy.type);
    ctxSize   = wc_NuvotonHashCtxSize(info->copy.type);
    if (srcDevCtx == NULL || dstDevCtx == NULL || ctxSize == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* wolfSSL skips its own copy when this succeeds, so do all of it. Free
     * anything the destination already holds or it would leak. */
    wc_NuvotonShaCtxFree((NuvotonShaCtx*)(*dstDevCtx));

    XMEMCPY(info->copy.dst, info->copy.src, ctxSize);

    srcCtx = (NuvotonShaCtx*)(*srcDevCtx);
    if (srcCtx == NULL) {
        *dstDevCtx = NULL;
        return 0;
    }

    /* Give the fork its own feedback buffer. Sharing one would have the two
     * hashes overwrite each other's state on the next chunk, which is the
     * whole thing this design exists to avoid. */
    dstCtx = (NuvotonShaCtx*)XMALLOC(sizeof(NuvotonShaCtx), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (dstCtx == NULL) {
        *dstDevCtx = NULL;
        return MEMORY_E;
    }
    XMEMCPY(dstCtx, srcCtx, sizeof(*dstCtx));

    *dstDevCtx = dstCtx;
    return 0;
}
#endif /* WOLF_CRYPTO_CB_COPY */

#ifdef WOLF_CRYPTO_CB_FREE
/* Release the saved message a hash context is holding. Called from
 * wc_NuvotonCb_Free() for WC_ALGO_TYPE_HASH objects. */
int wc_NuvotonHashFree(wc_CryptoInfo* info)
{
    void**         devCtx;
    NuvotonShaCtx* ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    devCtx = wc_NuvotonHashDevCtx(info->free.obj, info->free.type);
    if (devCtx != NULL) {
        ctx = (NuvotonShaCtx*)(*devCtx);
        if (ctx != NULL) {
            wc_NuvotonShaCtxFree(ctx);
            *devCtx = NULL;
        }
    }

    /* Decline so wolfSSL still wipes the context. devCtx is NULL now, so
     * nothing gets freed twice. */
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLF_CRYPTO_CB_FREE */

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_HASH && WOLF_CRYPTO_CB */
