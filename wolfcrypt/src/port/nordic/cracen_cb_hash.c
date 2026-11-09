/* cracen_cb_hash.c
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

/* SHA-1/224/256/384/512 through the BA413 hash engine.
 *
 * The engine processes whole blocks and can export and reload its internal
 * state, so a multi-part hash runs as: buffer partial blocks in software,
 * push whole blocks with state export, and finish with the standard padding
 * computed here. No fields are added to the wolfCrypt hash objects: while
 * the port owns an object its software members are reused - digest[] holds
 * the exported hardware state, buffer[]/buffLen the pending partial block and
 * loLen/hiLen the byte count - and devCtx marks the ownership (NULL: not
 * owned, WC_CRACEN_MARK_FRESH: counters reset, WC_CRACEN_MARK_STATE: a
 * hardware state is held). Every wc_InitSha*_ex() sets devCtx to NULL.
 *
 * An object is taken over only when it is provably fresh: counters at zero
 * and digest[] still holding the algorithm's initial value. That keeps
 * software-owned objects out, including the SHA-512/224, SHA-512/256 and
 * SHA-384 streams that cryptocb.c re-sends as plain SHA-512 requests whose
 * only difference is the initial state. A final on an object the port never
 * started is declined for the same reason. After a final the object is put
 * back through its public init, so it is ready for software or hardware
 * reuse exactly as the software final leaves it.
 *
 * Once a block has gone to the hardware the request can no longer be declined
 * (software has not seen those bytes), so a failure after that point is a
 * terminal error, not a fall-back. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_HASH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define WC_CRACEN_HASH_MAX_BLOCK 128
#define WC_CRACEN_HASH_MAX_STATE 64

typedef struct CracenHashView {
    void*   obj;
    void**  devCtx;
    byte*   state;      /* exported hardware state (software digest words) */
    byte*   buf;        /* pending partial block (software block buffer)   */
    word32* bufLen;
    void*   lenLo;      /* byte count, word32 or word64 per object type    */
    void*   lenHi;
    int     len64;
    int     type;       /* enum wc_HashType                                */
    word32  blockSz;
    word32  digestSz;
    word32  stateSz;
    word32  lenFieldSz; /* 8 or 16 bytes of big-endian bit count           */
    word32  algo;       /* WC_CM_HASH_ALGO_*                               */
    word32  iv0;        /* first word of the initial state                 */
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    word64  iv0_64;
#endif
} CracenHashView;

static int cracen_hash_resolve(wc_CryptoInfo* info, CracenHashView* v)
{
    XMEMSET(v, 0, sizeof(*v));
    v->type = info->hash.type;

    switch (info->hash.type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
        {
            wc_Sha* sha = info->hash.sha1;
            if (sha == NULL)
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            v->obj    = sha;
            v->devCtx = &sha->devCtx;
            v->state  = (byte*)sha->digest;
            v->buf    = (byte*)sha->buffer;
            v->bufLen = &sha->buffLen;
            v->lenLo  = &sha->loLen;
            v->lenHi  = &sha->hiLen;
            v->blockSz    = WC_SHA_BLOCK_SIZE;
            v->digestSz   = WC_SHA_DIGEST_SIZE;
            v->stateSz    = WC_SHA_DIGEST_SIZE;
            v->lenFieldSz = 8;
            v->algo       = WC_CM_HASH_ALGO_SHA1;
            v->iv0        = 0x67452301UL;
            break;
        }
#endif
#ifndef NO_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
    #endif
        case WC_HASH_TYPE_SHA256:
        {
            wc_Sha256* sha;
    #ifdef WOLFSSL_SHA224
            if (info->hash.type == WC_HASH_TYPE_SHA224)
                sha = (wc_Sha256*)info->hash.sha224;
            else
    #endif
                sha = info->hash.sha256;
            if (sha == NULL)
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            v->obj    = sha;
            v->devCtx = &sha->devCtx;
            v->state  = (byte*)sha->digest;
            v->buf    = (byte*)sha->buffer;
            v->bufLen = &sha->buffLen;
            v->lenLo  = &sha->loLen;
            v->lenHi  = &sha->hiLen;
            v->blockSz    = WC_SHA256_BLOCK_SIZE;
            v->stateSz    = WC_SHA256_DIGEST_SIZE;
            v->lenFieldSz = 8;
    #ifdef WOLFSSL_SHA224
            if (info->hash.type == WC_HASH_TYPE_SHA224) {
                v->digestSz = WC_SHA224_DIGEST_SIZE;
                v->algo     = WC_CM_HASH_ALGO_SHA224;
                v->iv0      = 0xc1059ed8UL;
            }
            else
    #endif
            {
                v->digestSz = WC_SHA256_DIGEST_SIZE;
                v->algo     = WC_CM_HASH_ALGO_SHA256;
                v->iv0      = 0x6a09e667UL;
            }
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
            wc_Sha512* sha = NULL;
    #ifdef WOLFSSL_SHA384
            if (info->hash.type == WC_HASH_TYPE_SHA384)
                sha = (wc_Sha512*)info->hash.sha384;
    #endif
    #ifdef WOLFSSL_SHA512
            if (info->hash.type == WC_HASH_TYPE_SHA512)
                sha = info->hash.sha512;
    #endif
            if (sha == NULL)
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            v->obj    = sha;
            v->devCtx = &sha->devCtx;
            v->state  = (byte*)sha->digest;
            v->buf    = (byte*)sha->buffer;
            v->bufLen = &sha->buffLen;
            v->lenLo  = &sha->loLen;
            v->lenHi  = &sha->hiLen;
            v->len64  = 1;
            v->blockSz    = WC_SHA512_BLOCK_SIZE;
            v->stateSz    = WC_SHA512_DIGEST_SIZE;
            v->lenFieldSz = 16;
    #ifdef WOLFSSL_SHA384
            if (info->hash.type == WC_HASH_TYPE_SHA384) {
                v->digestSz = WC_SHA384_DIGEST_SIZE;
                v->algo     = WC_CM_HASH_ALGO_SHA384;
                v->iv0_64   = W64LIT(0xcbbb9d5dc1059ed8);
            }
            else
    #endif
            {
                v->digestSz = WC_SHA512_DIGEST_SIZE;
                v->algo     = WC_CM_HASH_ALGO_SHA512;
                v->iv0_64   = W64LIT(0x6a09e667f3bcc908);
            }
            break;
        }
#endif
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    return 0;
}

static WC_INLINE void cracen_put_be32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

static void cracen_hash_len_get(const CracenHashView* v, word32* lo,
    word32* hi)
{
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    if (v->len64) {
        *lo = (word32)*(word64*)v->lenLo;
        *hi = (word32)(*(word64*)v->lenLo >> 32);
        return;
    }
#endif
    *lo = *(word32*)v->lenLo;
    *hi = *(word32*)v->lenHi;
}

static void cracen_hash_len_set(const CracenHashView* v, word32 lo, word32 hi)
{
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    if (v->len64) {
        *(word64*)v->lenLo = ((word64)hi << 32) | lo;
        *(word64*)v->lenHi = 0;
        return;
    }
#endif
    *(word32*)v->lenLo = lo;
    *(word32*)v->lenHi = hi;
}

static void cracen_hash_len_add(const CracenHashView* v, word32 n)
{
    word32 lo;
    word32 hi;

    cracen_hash_len_get(v, &lo, &hi);
    lo += n;
    if (lo < n)
        hi++;
    cracen_hash_len_set(v, lo, hi);
}

/* An object nothing has touched since its init: counters zero and the
 * algorithm's initial value in the state words. */
static int cracen_hash_is_fresh(const CracenHashView* v)
{
    word32 lo;
    word32 hi;

    if (*v->bufLen != 0)
        return 0;
    cracen_hash_len_get(v, &lo, &hi);
    if (lo != 0 || hi != 0)
        return 0;
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    if (v->len64)
        return *(const word64*)v->state == v->iv0_64;
#endif
    return *(const word32*)v->state == v->iv0;
}

/* Leave the object as the software final does: re-initialised and ready. */
static int cracen_hash_reinit(const CracenHashView* v)
{
    switch (v->type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
        {
            wc_Sha* sha = (wc_Sha*)v->obj;
            return wc_InitSha_ex(sha, sha->heap, sha->devId);
        }
#endif
#ifndef NO_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
        {
            wc_Sha224* sha = (wc_Sha224*)v->obj;
            return wc_InitSha224_ex(sha, sha->heap, sha->devId);
        }
    #endif
        case WC_HASH_TYPE_SHA256:
        {
            wc_Sha256* sha = (wc_Sha256*)v->obj;
            return wc_InitSha256_ex(sha, sha->heap, sha->devId);
        }
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
        {
            wc_Sha384* sha = (wc_Sha384*)v->obj;
            return wc_InitSha384_ex(sha, sha->heap, sha->devId);
        }
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
        {
            wc_Sha512* sha = (wc_Sha512*)v->obj;
            return wc_InitSha512_ex(sha, sha->heap, sha->devId);
        }
#endif
        default:
            return BAD_FUNC_ARG;
    }
}

/* Push whole blocks; the exported state lands in the object. */
static int cracen_hash_blocks(const CracenHashView* v, const byte* data,
    word32 sz)
{
    byte  state[WC_CRACEN_HASH_MAX_STATE];
    const byte* statePtr = NULL;
    int   ret;

    if (*v->devCtx == WC_CRACEN_MARK_STATE) {
        XMEMCPY(state, v->state, v->stateSz);
        statePtr = state;
    }
    ret = wc_CracenHw_Hash(v->algo, statePtr, v->stateSz, data, sz,
        v->state, v->stateSz, 0);
    if (ret == 0) {
        *v->devCtx = WC_CRACEN_MARK_STATE;
    }
    else if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        ret = WC_HW_E;
    }
    ForceZero(state, sizeof(state));
    return ret;
}

static int cracen_hash_update(const CracenHashView* v, const byte* in,
    word32 inSz)
{
    int    ret = 0;
    word32 full;

    if (*v->devCtx == NULL) {
        if (!cracen_hash_is_fresh(v))
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        *v->devCtx = WC_CRACEN_MARK_FRESH;
    }
    if (inSz == 0)
        return 0;

    cracen_hash_len_add(v, inSz);

    if (*v->bufLen > 0) {
        word32 fill = v->blockSz - *v->bufLen;
        if (fill > inSz)
            fill = inSz;
        XMEMCPY(v->buf + *v->bufLen, in, fill);
        *v->bufLen += fill;
        in   += fill;
        inSz -= fill;
        if (*v->bufLen == v->blockSz) {
            ret = cracen_hash_blocks(v, v->buf, v->blockSz);
            *v->bufLen = 0;
        }
    }

    full = inSz & ~(v->blockSz - 1);
    if (ret == 0 && full > 0) {
        ret = cracen_hash_blocks(v, in, full);
        in   += full;
        inSz -= full;
    }
    if (ret == 0 && inSz > 0) {
        XMEMCPY(v->buf, in, inSz);
        *v->bufLen = inSz;
    }
    return ret;
}

static int cracen_hash_final(const CracenHashView* v, byte* digest)
{
    byte   last[2 * WC_CRACEN_HASH_MAX_BLOCK];
    byte   state[WC_CRACEN_HASH_MAX_STATE];
    const byte* statePtr = NULL;
    word32 bufLen;
    word32 lo;
    word32 hi;
    word32 total;
    word32 lenPos;
    int    ret;

    if (*v->devCtx == NULL)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    bufLen = *v->bufLen;
    cracen_hash_len_get(v, &lo, &hi);
    if (bufLen > v->blockSz)
        return BAD_STATE_E;

    /* message tail || 0x80 || zeros || bit length, to a block boundary */
    total = bufLen + 1 + v->lenFieldSz;
    total = (total + v->blockSz - 1) & ~(v->blockSz - 1);
    XMEMSET(last, 0, total);
    XMEMCPY(last, v->buf, bufLen);
    last[bufLen] = 0x80;
    lenPos = total - 8;
    cracen_put_be32(last + lenPos, (hi << 3) | (lo >> 29));
    cracen_put_be32(last + lenPos + 4, lo << 3);
    if (v->lenFieldSz == 16)
        cracen_put_be32(last + lenPos - 4, hi >> 29);

    if (*v->devCtx == WC_CRACEN_MARK_STATE) {
        XMEMCPY(state, v->state, v->stateSz);
        statePtr = state;
    }

    ret = wc_CracenHw_Hash(v->algo, statePtr, v->stateSz, last, total,
        digest, v->digestSz, 1);
    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
        ret = WC_HW_E;

    ForceZero(v->buf, v->blockSz);
    if (ret == 0)
        ret = cracen_hash_reinit(v);
    else
        (void)cracen_hash_reinit(v);
    ForceZero(last, sizeof(last));
    ForceZero(state, sizeof(state));
    return ret;
}

int wc_CracenHash(wc_CryptoInfo* info)
{
    CracenHashView v;
    wc_CracenHwInfo hw;
    int ret;

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (info->algo_type != WC_ALGO_TYPE_HASH)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    ret = cracen_hash_resolve(info, &v);
    if (ret != 0)
        return ret;

    /* Decline before touching the object when the engine or algorithm is not
     * there, except for an object already in flight. */
    if (*v.devCtx == NULL) {
        if (wc_CracenHw_GetInfo(&hw) != 0 ||
                (hw.engines & WC_CM_HW_BA413_HASH) == 0 ||
                (hw.hashCfg & v.algo) == 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    if (info->hash.in != NULL) {
        ret = cracen_hash_update(&v, info->hash.in, info->hash.inSz);
    }
    else if (info->hash.digest != NULL) {
        ret = cracen_hash_final(&v, info->hash.digest);
    }
    return ret;
}

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_HASH */
