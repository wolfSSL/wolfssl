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

/* ASU hashing for the wolfSSL crypto callback: SHA2 256/384/512, SHA3
 * 256/384/512 and SHAKE256.
 *
 * Why the message is buffered instead of streamed to the hardware:
 *   wolfSSL drives hashing as update()...update()...final(), and may have
 *   several hash contexts in flight at the same time (interleaved). The ASU SHA
 *   core supports START/UPDATE/FINISH streaming, but it keeps the running hash
 *   state only inside the core and exposes no way to save and restore it:
 *   XSha_Start always begins a fresh hash and the digest registers are read
 *   only (read out at FINISH). The client library therefore allows only one
 *   multi update stream in progress per priority channel. Because the hardware
 *   cannot hold more than one partial hash, interleaved hardware streaming is
 *   physically impossible.
 *
 *   To support arbitrary interleaving correctly, each hash context's message is
 *   accumulated in its own buffer hung off the wolfSSL hash devCtx (using the
 *   wolfSSL _wc_Hash_Grow helper), and the digest is produced with a single
 *   atomic ASU operation (START|UPDATE|FINISH) at final(). Several contexts can
 *   be mid stream at once, each in its own buffer; the ASU only ever performs
 *   one complete hash at a time (serialized by wc_AsuTransact).
 *
 * Because the state lives in devCtx, the copy and free crypto callbacks are
 * required: copy gives the destination context its own deep copy of the
 * buffer (a plain struct copy would share the pointer), and free releases the
 * buffer if a context is freed without being finalized.
 *
 * SHAKE256 is an extendable output function: the output length chosen at final()
 * is carried to this callback in the hash info outSz field (by wc_CryptoCb_Shake).
 * An output that fits the ASU response mailbox (WC_ASU_SHAKE_HW_MAX_BYTES) is
 * produced in one ASU SHAKE256 operation; a longer output cannot be returned by
 * the hardware (see that define) and is computed in software from the same
 * accumulated message. SHAKE128 has no ASU mode, so it is declined and runs in
 * software. Only the update()/final() hash style routes here; the
 * absorb()/squeezeBlocks() streaming XOF (used by ML-KEM and ML-DSA) is not on
 * the callback path and stays in software.
 */

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

/* Release a kept message record. The message buffer holds the plaintext that
 * was hashed, so it is zeroized before being returned to the allocator. */
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

/* Submit thunk: queue one ASU hash operation. Called by wc_AsuTransact with the
 * submit lock held, so it only queues the request. */
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

/* Return the size of the hash context struct for the given hash type, or 0 for
 * an unsupported type. The copy callback needs this to duplicate the whole
 * context (see wc_AsuHashCopy). */
static word32 wc_AsuHashCtxSize(int hashType)
{
    switch (hashType) {
        case WC_HASH_TYPE_SHA256:
            return (word32)sizeof(wc_Sha256);
        case WC_HASH_TYPE_SHA384:
            return (word32)sizeof(wc_Sha384);
        case WC_HASH_TYPE_SHA512:
            return (word32)sizeof(wc_Sha512);
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512:
        case WC_HASH_TYPE_SHAKE256: /* wc_Shake is a wc_Sha3 */
            return (word32)sizeof(wc_Sha3);
        default:
            return 0;
    }
}

/* Return the address of the devCtx field of the hash context for the given hash
 * type, or NULL for an unsupported type. */
static void** wc_AsuHashDevCtx(void* hashCtx, int hashType)
{
    if (hashCtx == NULL) {
        return NULL;
    }

    switch (hashType) {
        case WC_HASH_TYPE_SHA256:
            return &((wc_Sha256*)hashCtx)->devCtx;
        case WC_HASH_TYPE_SHA384:
            return &((wc_Sha384*)hashCtx)->devCtx;
        case WC_HASH_TYPE_SHA512:
            return &((wc_Sha512*)hashCtx)->devCtx;
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512:
        case WC_HASH_TYPE_SHAKE256: /* wc_Shake is a wc_Sha3 */
            return &((wc_Sha3*)hashCtx)->devCtx;
        default:
            return NULL;
    }
}

/* Resolve the hash info to the ASU type and mode, the digest length, and the
 * address of the context's devCtx field. Returns 0 if supported, otherwise
 * CRYPTOCB_UNAVAILABLE. */
static int wc_AsuHashResolve(wc_CryptoInfo* info, void*** devCtx, u8* shaType,
    u8* shaMode, word32* hashLen)
{
    if (info == NULL || devCtx == NULL || shaType == NULL ||
        shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->hash.type) {
        case WC_HASH_TYPE_SHA256:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha256, info->hash.type);
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_256;
            *hashLen = WC_SHA256_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA384:
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha384, info->hash.type);
            *shaType = XASU_SHA2_TYPE;
            *shaMode = XASU_SHA_MODE_384;
            *hashLen = WC_SHA384_DIGEST_SIZE;
            break;
        case WC_HASH_TYPE_SHA512:
            /* SHA-512/224 and SHA-512/256 share the wc_Sha512 context and reach
             * this callback as plain SHA-512 on update() (the variant is only
             * known at final()). The ASU does only full SHA-512, and the
             * truncated variants use different initial values, so decline them
             * here and let wolfSSL run them entirely in software. */
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
        case WC_HASH_TYPE_SHAKE256:
            /* SHAKE is an extendable output function: the digest length is the
             * caller's requested output, carried in outSz on the final call.
             * SHAKE128 is not a hardware mode, so it falls through to the
             * default and runs in software. */
            *devCtx  = wc_AsuHashDevCtx(info->hash.sha3, info->hash.type);
            *shaType = XASU_SHA3_TYPE;
            *shaMode = XASU_SHA_MODE_SHAKE256;
            *hashLen = info->hash.outSz;
            break;
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

#ifdef WOLFSSL_HASH_FLAGS
    /* Keccak-256 (legacy 0x01 padding) is selected with a hash flag on a SHA3
     * context. The ASU SHA3 core only does NIST SHA3 (0x06) padding, so decline
     * Keccak and let wolfSSL compute it in software. */
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

/* Hash dataLen bytes from data in one atomic ASU operation, writing hashLen
 * bytes of digest. */
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

    /* SHAKE256 is an extendable output function with a caller chosen length. The
     * ASU reads the result out of the digest registers a 32 bit word at a time,
     * so a length that is not a multiple of 4 would drop the final partial word.
     * Round the request up to a word boundary into a temporary buffer and copy
     * back exactly the bytes asked for. The ASU also caps a single SHAKE squeeze
     * at one rate block (XASU_SHAKE_256_MAX_HASH_LEN), which bounds the temp. */
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

    /* The ASU DMAs the input message from memory, so clean it out. The digest is
     * delivered back through the response path (a CPU copy), so it needs no
     * cache maintenance here. */
    if (dataLen > 0) {
        wc_AsuCacheFlush(data, dataLen);
    }

    status = wc_AsuTransact(wc_AsuHashSubmit, &req, NULL);
    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }

    /* Copy back the exact byte count when a temp buffer was used for the SHAKE
     * word-alignment round up. */
    if (outAddr != digest) {
        XMEMCPY(digest, xofTmp, hashLen);
    }

    return 0;
}

/* The ASU returns a hash through a fixed response mailbox slot of 16 words (64
 * bytes), sized for the largest fixed digest (SHA-512). SHAKE256 is an
 * extendable output function, so a requested output up to this size fits in one
 * ASU operation and is offloaded; a longer output is computed in software
 * instead (see wc_AsuShakeSoftware).
 *
 * The hardware could in principle emit more by continuing the squeeze a rate
 * block at a time, but that path is closed to us: the XAsu_ShaOperationCmd
 * "next xof" continue-squeeze flag (ShakeReserved) is documented "NA for client,
 * ASUFW internal use", and the ASU server resets the squeeze after every finish.
 * So a client cannot chain blocks, and anything past one mailbox stays software. */
#define WC_ASU_SHAKE_HW_MAX_BYTES 64

/* Compute SHAKE256 of the already accumulated message in software, for outputs
 * larger than the ASU can return. A private context with INVALID_DEVID keeps it
 * off the crypto callback (no recursion) so wolfSSL runs its own SHAKE. */
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

/* update() and final() handling for WC_ALGO_TYPE_HASH. Internal helper reached
 * through the wc_AsuHash dispatcher. */
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

    /* wolfSSL's SHA3/SHAKE copy() and free() callbacks dispatch on hashType,
     * which the software update sets but the offload bypasses; record it here. */
    if (shaType == XASU_SHA3_TYPE && info->hash.sha3 != NULL) {
        info->hash.sha3->hashType = info->hash.type;
    }

    keep = (AsuHashKeep*)(*devCtxPtr);

    /* update(): accumulate the message with the wolfSSL grow helper. */
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

    /* final(): hash the whole accumulated message in one ASU operation, then
     * release the buffer. */
    if (info->hash.digest != NULL) {
        const byte* data = NULL;
        word32      dataLen = 0;

        if (keep != NULL) {
            data = keep->msg;
            dataLen = keep->used;
        }

        /* SHAKE256 output longer than the ASU response mailbox can carry is
         * produced in software from the same accumulated message; everything
         * else (the fixed hashes and short SHAKE) is one ASU operation. */
        if ((shaMode == XASU_SHA_MODE_SHAKE256) &&
            (hashLen > WC_ASU_SHAKE_HW_MAX_BYTES)) {
            ret = wc_AsuShakeSoftware(data, dataLen, info->hash.digest, hashLen);
        }
        else {
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

/* WC_ALGO_TYPE_COPY handling for a hash context. Internal helper reached
 * through the wc_AsuHash dispatcher. */
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

    /* wolfSSL calls this callback before its own struct copy and skips both that
     * copy and its own free of the destination when we return success, so the
     * callback owns the entire copy. Free any buffer the destination already
     * holds first (it is about to be overwritten), or it would leak. */
    wc_AsuHashKeepFree((AsuHashKeep*)(*dstDevCtx));

    /* Duplicate the whole context struct, which carries devId (so the copy keeps
     * routing to this port) and the rest of the state. The struct copy leaves the
     * destination devCtx pointing at the source buffer, so then replace it with
     * the destination's own deep copy of the kept message. */
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

/* WC_ALGO_TYPE_FREE handling for a hash context. Internal helper reached
 * through the wc_AsuHash dispatcher. */
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

    /* Return unavailable so wolfSSL still runs its own ForceZero. devCtx is now
     * NULL, so there is no second free. */
    return CRYPTOCB_UNAVAILABLE;
}

/* Single entry point for the SHA2/SHA3 engine. The crypto callback dispatcher
 * routes every hash related operation here and this handler decides which one it
 * is: update/final (WC_ALGO_TYPE_HASH), context copy (WC_ALGO_TYPE_COPY), or
 * context free (WC_ALGO_TYPE_FREE). Keeping the whole lifecycle behind one entry
 * keeps it owned by this module. */
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
