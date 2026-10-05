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
    byte     block[WC_NUVOTON_SHA_BLOCK_MAX]; /* buffered partial block */
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

/* Per-algorithm constants, one source of truth for the lookups below. The
 * devCtx pointer still needs a per-type cast, so it stays a switch. */
typedef struct {
    int    hashType;
    int    shaMode;
    word32 blockSz;
    word32 hashLen;
    word32 ctxSize;
} NuvotonHashInfo;

static const NuvotonHashInfo nuvotonHashInfo[] = {
#ifndef NO_SHA
    { WC_HASH_TYPE_SHA,    WC_NUVOTON_SHA_1,   WC_SHA_BLOCK_SIZE,
      WC_SHA_DIGEST_SIZE,    (word32)sizeof(wc_Sha)    },
#endif
#ifdef WOLFSSL_SHA224
    { WC_HASH_TYPE_SHA224, WC_NUVOTON_SHA_224, WC_SHA224_BLOCK_SIZE,
      WC_SHA224_DIGEST_SIZE, (word32)sizeof(wc_Sha224) },
#endif
#ifndef NO_SHA256
    { WC_HASH_TYPE_SHA256, WC_NUVOTON_SHA_256, WC_SHA256_BLOCK_SIZE,
      WC_SHA256_DIGEST_SIZE, (word32)sizeof(wc_Sha256) },
#endif
#ifdef WOLFSSL_SHA384
    { WC_HASH_TYPE_SHA384, WC_NUVOTON_SHA_384, WC_SHA384_BLOCK_SIZE,
      WC_SHA384_DIGEST_SIZE, (word32)sizeof(wc_Sha384) },
#endif
#ifdef WOLFSSL_SHA512
    { WC_HASH_TYPE_SHA512, WC_NUVOTON_SHA_512, WC_SHA512_BLOCK_SIZE,
      WC_SHA512_DIGEST_SIZE, (word32)sizeof(wc_Sha512) },
#endif
};

static const NuvotonHashInfo* wc_NuvotonHashInfoFind(int hashType)
{
    word32 i;

    for (i = 0; i < sizeof(nuvotonHashInfo) / sizeof(nuvotonHashInfo[0]); i++) {
        if (nuvotonHashInfo[i].hashType == hashType) {
            return &nuvotonHashInfo[i];
        }
    }
    return NULL;
}

/* Block size for this algorithm, or 0 if we do not support it. */
static word32 wc_NuvotonShaBlockSz(int hashType)
{
    const NuvotonHashInfo* e = wc_NuvotonHashInfoFind(hashType);
    return (e != NULL) ? e->blockSz : 0;
}

/* Size of the hash context for this type, or 0 if we do not support it. */
static word32 wc_NuvotonHashCtxSize(int hashType)
{
    const NuvotonHashInfo* e = wc_NuvotonHashInfoFind(hashType);
    return (e != NULL) ? e->ctxSize : 0;
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
    const NuvotonHashInfo* e;

    if (info == NULL || devCtx == NULL || shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->hash.type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            *devCtx = wc_NuvotonHashDevCtx(info->hash.sha1, info->hash.type);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            *devCtx = wc_NuvotonHashDevCtx(info->hash.sha224, info->hash.type);
            break;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *devCtx = wc_NuvotonHashDevCtx(info->hash.sha256, info->hash.type);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *devCtx = wc_NuvotonHashDevCtx(info->hash.sha384, info->hash.type);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
    #ifdef WOLFSSL_SHA512_HASHTYPE
            /* The engine does full SHA-512 only and loads the standard IV,
             * ignoring the caller's. Decline anything whose hashType is not
             * plain SHA-512: 512/224 and 512/256 have different IVs, and
             * wc_CryptoCb_Sha384Hash() retries a declined SHA-384 as SHA-512
             * on the same struct, which would otherwise come back as a
             * truncated SHA-512 reported as SHA-384. hashType exists only with
             * WOLFSSL_SHA512_HASHTYPE, which nuvoton_settings.h requires. */
            if (info->hash.sha512 != NULL &&
                info->hash.sha512->hashType != WC_HASH_TYPE_SHA512) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
    #endif
            *devCtx = wc_NuvotonHashDevCtx(info->hash.sha512, info->hash.type);
            break;
#endif
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    e = wc_NuvotonHashInfoFind(info->hash.type);
    if (e == NULL || *devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    *shaMode = e->shaMode;
    *hashLen = e->hashLen;

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

    /* The empty message: no context yet, a final call, and no data to add.
     * The result register is only written by a DMA round and a zero-length
     * round does not start one, so let software take it without allocating a
     * context just to free it. */
    if (*devCtxPtr == NULL && info->hash.digest != NULL &&
        (info->hash.in == NULL || info->hash.inSz == 0)) {
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
/* Release everything the destination already owns. wolfCrypt's own free is
 * used rather than a hand written one, so the device context still goes out
 * through wc_NuvotonHashFree() and nothing new in the struct gets missed. */
static void nuvoton_hash_free_dst(int type, void* dst)
{
    switch (type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            wc_ShaFree((wc_Sha*)dst);
            break;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            wc_Sha224Free((wc_Sha224*)dst);
            break;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            wc_Sha256Free((wc_Sha256*)dst);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            wc_Sha384Free((wc_Sha384*)dst);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            wc_Sha512Free((wc_Sha512*)dst);
            break;
#endif
        default:
            break;
    }
}


/* The fixups wolfCrypt performs after its own XMEMCPY. Claiming the copy
 * means claiming these too: the struct owns pointers, and leaving them
 * aliased gives two hashes one buffer and a double free at teardown. */
#if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
    #define NUVOTON_HASH_OWNS_W
#endif

#if defined(NUVOTON_HASH_OWNS_W) || defined(WOLFSSL_HASH_KEEP) || \
    defined(WOLFSSL_HASH_FLAGS)
    #define NUVOTON_HASH_NEEDS_FIXUP
#endif

static int nuvoton_hash_dup_owned(int type, void* src, void* dst)
{
    int ret = 0;

#ifndef NUVOTON_HASH_NEEDS_FIXUP
    (void)type;
    (void)src;
    (void)dst;
#else
    switch (type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA: {
            wc_Sha* s = (wc_Sha*)src;
            wc_Sha* d = (wc_Sha*)dst;
            (void)s; (void)d;
    #ifdef WOLFSSL_HASH_FLAGS
            d->flags |= WC_HASH_FLAG_ISCOPY;
    #endif
    #ifdef WOLFSSL_HASH_KEEP
            if (s->msg != NULL) {
                d->msg = (byte*)XMALLOC(s->len, d->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (d->msg == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMCPY(d->msg, s->msg, s->used);
                }
            }
    #endif
            break;
        }
#endif
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA224)
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
    #endif
    #ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
    #endif
        {
            wc_Sha256* s = (wc_Sha256*)src;
            wc_Sha256* d = (wc_Sha256*)dst;
            (void)s; (void)d;
    #ifdef NUVOTON_HASH_OWNS_W
            d->W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE,
                d->heap, DYNAMIC_TYPE_DIGEST);
            if (d->W == NULL) {
                ret = MEMORY_E;
            }
    #endif
    #ifdef WOLFSSL_HASH_FLAGS
            if (ret == 0) {
                d->flags |= WC_HASH_FLAG_ISCOPY;
            }
    #endif
    #ifdef WOLFSSL_HASH_KEEP
            if (ret == 0 && s->msg != NULL) {
                d->msg = (byte*)XMALLOC(s->len, d->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (d->msg == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMCPY(d->msg, s->msg, s->len);
                }
            }
    #endif
            break;
        }
#endif
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
    #endif
    #ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
    #endif
        {
            wc_Sha512* s = (wc_Sha512*)src;
            wc_Sha512* d = (wc_Sha512*)dst;
            (void)s; (void)d;
    #ifdef NUVOTON_HASH_OWNS_W
            d->W = (word64*)XMALLOC((sizeof(word64) * 16) +
                WC_SHA512_BLOCK_SIZE, d->heap, DYNAMIC_TYPE_DIGEST);
            if (d->W == NULL) {
                ret = MEMORY_E;
            }
    #endif
    #ifdef WOLFSSL_HASH_FLAGS
            if (ret == 0) {
                d->flags |= WC_HASH_FLAG_ISCOPY;
            }
    #endif
    #ifdef WOLFSSL_HASH_KEEP
            if (ret == 0 && s->msg != NULL) {
                d->msg = (byte*)XMALLOC(s->len, d->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (d->msg == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    XMEMCPY(d->msg, s->msg, s->len);
                }
            }
    #endif
            break;
        }
#endif
        default:
            break;
    }
#endif /* NUVOTON_HASH_NEEDS_FIXUP */

    return ret;
}


int wc_NuvotonCb_HashCopy(wc_CryptoInfo* info)
{
    void**         srcDevCtx;
    void**         dstDevCtx;
    NuvotonShaCtx* srcCtx;
    NuvotonShaCtx* dstCtx;
    word32         ctxSize;
    int            ret;

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

    /* wolfSSL skips its own copy when this succeeds, so do all of it: release
     * what the destination holds - the device context and the buffers the
     * struct itself owns - copy, then rebuild both for the fork. */
    nuvoton_hash_free_dst(info->copy.type, info->copy.dst);

    XMEMCPY(info->copy.dst, info->copy.src, ctxSize);

    ret = nuvoton_hash_dup_owned(info->copy.type, info->copy.src,
        info->copy.dst);
    if (ret != 0) {
        /* Drop the pointers the XMEMCPY above aliased onto the source (devCtx,
         * W, msg), as wc_Sha512Copy() does when its own allocation fails.
         * Leaving them gives the two contexts one buffer each and a double
         * free at teardown. */
        XMEMSET(info->copy.dst, 0, ctxSize);
        return ret;
    }

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
