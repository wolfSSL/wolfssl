/* altera_fcs_hash.c
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


/* SHA-256 digests on the Agilex 5 Secure Device Manager.
 *
 * Why the message is buffered rather than streamed: the device grants a single
 * crypto session, and wolfSSL may have several hash contexts open at once
 * (a TLS transcript hash alongside the DRBG, for example). Interleaving those
 * over one hardware stream is not possible, so each context accumulates its own
 * message in an anonymous memory file and the digest is produced by one
 * fcs_get_digest_streaming() at final(), which libfcs splits into 4 MiB device
 * transactions itself.
 *
 * Because that state lives in devCtx, the copy and free callbacks are
 * mandatory: wolfSSL's plain struct copy would leave two contexts sharing one
 * file, which corrupts the DRBG and shows up as DRBG_CONT_FIPS_E.
 *
 * The ordinary SHA-256 state is advanced in software alongside, because
 * callers such as the TLS CBC verifier read it through wc_Sha256FinalRaw().
 * That shadow also lets any device failure at final() decline to software.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WOLFSSL_ALTERA_FCS_HASH)

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <libfcs.h>
#include <unistd.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if !defined(WOLF_CRYPTO_CB_COPY) || !defined(WOLF_CRYPTO_CB_FREE)
    #error "WOLFSSL_ALTERA_FCS_HASH requires WOLF_CRYPTO_CB_COPY and _FREE"
#endif
#ifdef NO_SHA256
    #error "WOLFSSL_ALTERA_FCS_HASH requires SHA-256"
#endif

#define FCS_SHA_OP_MODE_SHA 1
#define FCS_SHA_SZ_256      0
/* Measured on hardware: the SDM refuses any message whose length is not a
 * multiple of 8 bytes (the one shot call fails, the streaming call returns
 * success with a wrong digest), so those finish on the software shadow. */
#define WC_ALTERA_FCS_HASH_ALIGN 8

/* Public SHA APIs may consult WOLF_CRYPTO_CB_FIND even with INVALID_DEVID.
 * Internal software-shadow work sets this thread-local guard so redispatch
 * declines instead of recursively entering this callback. */
#if !defined(SINGLE_THREADED) && \
    (!defined(HAVE_THREAD_LS) || defined(NO_THREAD_LS))
    #error "WOLFSSL_ALTERA_FCS_HASH requires thread-local storage"
#endif
static THREAD_LS_T int g_alteraHashSoftware = 0;

typedef struct {
    void*  heap;
    word32 used;
    int    fd;          /* memory file holding the message, or -1 */
    byte   active;
    /* Set once the message passes WOLFSSL_ALTERA_FCS_HASH_MAX or the file
     * cannot be grown; the shadow state then finishes in software. */
    byte   overflowed;
} AlteraHashKeep;

static void wc_AlteraFcs_KeepDrop(AlteraHashKeep* keep)
{
    if (keep->fd >= 0) {
        (void)close(keep->fd);
        keep->fd = -1;
    }
    keep->used = 0;
    keep->overflowed = 1;
}

static void wc_AlteraFcs_KeepFree(AlteraHashKeep* keep)
{
    if (keep == NULL) {
        return;
    }
    if (keep->fd >= 0) {
        (void)close(keep->fd);
    }
    if (keep->active) {
        wc_AlteraFcs_ResourceRemove();
    }
    XFREE(keep, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Append to the memory file. Running out of room or file space is not an
 * error for the caller: the software shadow still carries the message. */
static void wc_AlteraFcs_KeepAppend(AlteraHashKeep* keep, const byte* in,
                                    word32 inSz)
{
    if (keep->overflowed || inSz == 0) {
        return;
    }
    if (keep->used + inSz < keep->used ||
        keep->used + inSz > (word32)WOLFSSL_ALTERA_FCS_HASH_MAX) {
        WOLFSSL_MSG("Altera FCS hash message past WOLFSSL_ALTERA_FCS_HASH_MAX");
        wc_AlteraFcs_KeepDrop(keep);
        return;
    }
    if (keep->fd < 0) {
        keep->fd = wc_AlteraFcs_MemFd();
        if (keep->fd < 0) {
            wc_AlteraFcs_KeepDrop(keep);
            return;
        }
    }
    if (wc_AlteraFcs_MemFdWrite(keep->fd, in, inSz) != 0) {
        WOLFSSL_MSG("Altera FCS hash message file write failed");
        wc_AlteraFcs_KeepDrop(keep);
        return;
    }
    keep->used += inSz;
}

/* Duplicate the message file for a copied context. */
static int wc_AlteraFcs_KeepCopy(const AlteraHashKeep* src,
                                 AlteraHashKeep* dst)
{
    byte   buf[1024];
    word32 done = 0;
    int    ret = 0;

    if (src->overflowed) {
        dst->overflowed = 1;
        return 0;
    }
    if (src->used == 0) {
        return 0;
    }
    dst->fd = wc_AlteraFcs_MemFd();
    if (dst->fd < 0) {
        return MEMORY_E;
    }
    while (ret == 0 && done < src->used) {
        word32 chunk = src->used - done;

        if (chunk > (word32)sizeof(buf)) {
            chunk = (word32)sizeof(buf);
        }
        ret = wc_AlteraFcs_MemFdRead(src->fd, done, buf, chunk);
        if (ret != 0) {
            break;
        }
        ret = wc_AlteraFcs_MemFdWrite(dst->fd, buf, chunk);
        done += chunk;
    }
    if (ret == 0) {
        dst->used = src->used;
    }
    ForceZero(buf, sizeof(buf));
    return ret;
}

/* One digest over the whole message file. */
static int wc_AlteraFcs_Digest(const AlteraHashKeep* keep, byte* out)
{
    struct fcs_digest_req_streaming req;
    char         inPath[WC_ALTERA_FCS_FD_PATH_SZ];
    char         outPath[WC_ALTERA_FCS_FD_PATH_SZ];
    void*        session = NULL;
    word32       outSz   = 0;
    int          outFd;
    int          ret;

    outFd = wc_AlteraFcs_MemFd();
    if (outFd < 0) {
        return WC_HW_E;
    }

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret == 0) {
        wc_AlteraFcs_MemFdPath(keep->fd, inPath);
        wc_AlteraFcs_MemFdPath(outFd, outPath);
        XMEMSET(&req, 0, sizeof(req));
        req.sha_op_mode   = FCS_SHA_OP_MODE_SHA;
        req.sha_digest_sz = FCS_SHA_SZ_256;
        req.filename      = inPath;
        req.outfilename   = outPath;

        ret = fcs_get_digest_streaming((FCS_OSAL_UUID*)session, 0,
                                       WOLFSSL_ALTERA_FCS_CTX_ID, &req);
        wc_AlteraFcs_SessionRelease();
        if (ret != 0) {
            ret = wc_AlteraFcs_MapError(ret);
        }
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdSize(outFd, &outSz);
    }
    if (ret == 0 && outSz != WC_SHA256_DIGEST_SIZE) {
        /* An invalid session has been seen to report success while returning a
         * short or empty digest, so the length is checked rather than trusted. */
        WOLFSSL_MSG("Altera FCS digest length mismatch");
        ret = WC_HW_E;
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdRead(outFd, 0, out, WC_SHA256_DIGEST_SIZE);
    }
    (void)close(outFd);
    return ret;
}

/* Address of the devCtx field inside a hash context of the given type. The
 * SHA-512 family is deliberately not offloaded: this CPU has no ARMv8 SHA-512
 * extension and the SDM is far slower than software regardless. */
static void** wc_AlteraFcs_DevCtxOf(void* hashCtx, int type)
{
    void** devCtx = NULL;

    if (hashCtx != NULL && type == WC_HASH_TYPE_SHA256) {
        devCtx = &((wc_Sha256*)hashCtx)->devCtx;
    }
    return devCtx;
}

/* Finalize the shadow state into a discarded digest so the context resets the
 * way a software final would. */
static int wc_AlteraFcs_Sha256Reset(wc_Sha256* sha, byte* digest)
{
    int  devId;
    int  ret;

    devId = sha->devId;
    sha->devId = INVALID_DEVID;
    g_alteraHashSoftware++;
    ret = wc_Sha256Final(sha, digest);
    g_alteraHashSoftware--;
    sha->devId = devId;
    return ret;
}

static int wc_AlteraFcs_SoftSha256Update(wc_Sha256* sha, const byte* in,
                                         word32 inSz)
{
    int devId = sha->devId;
    int ret;

    sha->devId = INVALID_DEVID;
    g_alteraHashSoftware++;
    ret = wc_Sha256Update(sha, in, inSz);
    g_alteraHashSoftware--;
    sha->devId = devId;
    return ret;
}

/* wolfSSL skips its own copy path when this callback succeeds. Delegate the
 * ordinary context portion back to wc_Sha256Copy with the FCS state detached,
 * then independently duplicate the message file. This preserves every
 * backend-specific deep-copy hook compiled into the ordinary implementation. */
static int wc_AlteraFcs_HashCopy(wc_CryptoInfo* info)
{
    wc_Sha256*      srcSha;
    wc_Sha256*      dstSha;
    AlteraHashKeep* srcKeep;
    AlteraHashKeep* dstKeep = NULL;
    void*           srcDevCtx;
    int             srcDevId;
    int             ret = 0;

    if (info->copy.algo != WC_ALGO_TYPE_HASH ||
        info->copy.type != WC_HASH_TYPE_SHA256 ||
        info->copy.src == NULL || info->copy.dst == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    srcSha = (wc_Sha256*)info->copy.src;
    dstSha = (wc_Sha256*)info->copy.dst;
    if (srcSha == dstSha) {
        return BAD_FUNC_ARG;
    }
    srcKeep = (AlteraHashKeep*)srcSha->devCtx;
    if (srcKeep == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Free the destination while its current callback state is still visible.
     * The guarded recursive copy then sees an inert destination and cannot
     * redispatch into this handler. */
    wc_Sha256Free(dstSha);
    XMEMSET(dstSha, 0, sizeof(*dstSha));
    dstSha->devId = INVALID_DEVID;

    srcDevId = srcSha->devId;
    srcDevCtx = srcSha->devCtx;
    srcSha->devId = INVALID_DEVID;
    srcSha->devCtx = NULL;
    g_alteraHashSoftware++;
    ret = wc_Sha256Copy(srcSha, dstSha);
    g_alteraHashSoftware--;
    srcSha->devCtx = srcDevCtx;
    srcSha->devId = srcDevId;

    if (ret == 0) {
        dstKeep = (AlteraHashKeep*)XMALLOC(sizeof(AlteraHashKeep),
                                           dstSha->heap,
                                           DYNAMIC_TYPE_TMP_BUFFER);
        if (dstKeep == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMSET(dstKeep, 0, sizeof(*dstKeep));
        dstKeep->heap = dstSha->heap;
        dstKeep->fd = -1;
        ret = wc_AlteraFcs_KeepCopy(srcKeep, dstKeep);
    }
    if (ret == 0) {
        dstKeep->active = 1;
        wc_AlteraFcs_ResourceAdd();
        dstSha->devCtx = dstKeep;
        dstSha->devId = srcDevId;
    }
    else {
        wc_AlteraFcs_KeepFree(dstKeep);
        dstSha->devCtx = NULL;
        dstSha->devId = INVALID_DEVID;
        wc_Sha256Free(dstSha);
        XMEMSET(dstSha, 0, sizeof(*dstSha));
    }
    return ret;
}

/* Release the file when a context is freed without being finalized. */
static int wc_AlteraFcs_HashFreeCtx(wc_CryptoInfo* info)
{
    void** devCtx;

    if (info->free.algo != WC_ALGO_TYPE_HASH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    devCtx = wc_AlteraFcs_DevCtxOf(info->free.obj, info->free.type);
    if (devCtx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    wc_AlteraFcs_KeepFree((AlteraHashKeep*)(*devCtx));
    *devCtx = NULL;

    /* Decline so wolfSSL still performs its own teardown. */
    return CRYPTOCB_UNAVAILABLE;
}

static int wc_AlteraFcs_Sha256Started(const wc_Sha256* sha)
{
#if defined(FREESCALE_LTC_SHA) || \
    (defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)) || \
    defined(STM32_HASH_SHA2) || defined(WOLFSSL_SILABS_SE_ACCEL) || \
    defined(WOLFSSL_IMXRT_DCP) || defined(PSOC6_HASH_SHA2) || \
    (defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_HASH))
    /* An opaque software state cannot prove that no prefix was consumed. */
    (void)sha;
    return 1;
#else
    return sha->buffLen != 0 || sha->loLen != 0 || sha->hiLen != 0;
#endif
}

int wc_AlteraFcs_Hash(wc_CryptoInfo* info)
{
    AlteraHashKeep* keep;
    wc_Sha256*   sha;
    void**       devCtxPtr;
    byte         shadow[WC_SHA256_DIGEST_SIZE];
    int          ret = 0;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (g_alteraHashSoftware) {
        return CRYPTOCB_UNAVAILABLE;
    }

    if (info->algo_type == WC_ALGO_TYPE_COPY) {
        return wc_AlteraFcs_HashCopy(info);
    }
    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        return wc_AlteraFcs_HashFreeCtx(info);
    }

    if (info->hash.type != WC_HASH_TYPE_SHA256) {
        return CRYPTOCB_UNAVAILABLE;
    }
    sha = info->hash.sha256;
    devCtxPtr = wc_AlteraFcs_DevCtxOf(sha, info->hash.type);
    if (devCtxPtr == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    keep = (AlteraHashKeep*)(*devCtxPtr);

    /* update(): append to this context's own file and advance the shadow. */
    if (info->hash.in != NULL) {
        if (keep == NULL) {
            if (wc_AlteraFcs_UnregisterPending() ||
                wc_AlteraFcs_Sha256Started(sha)) {
                return CRYPTOCB_UNAVAILABLE;
            }
            keep = (AlteraHashKeep*)XMALLOC(sizeof(AlteraHashKeep), sha->heap,
                                            DYNAMIC_TYPE_TMP_BUFFER);
            if (keep == NULL) {
                return MEMORY_E;
            }
            XMEMSET(keep, 0, sizeof(*keep));
            keep->heap = sha->heap;
            keep->fd = -1;
            keep->active = 1;
            wc_AlteraFcs_ResourceAdd();
            *devCtxPtr = keep;
        }

        wc_AlteraFcs_KeepAppend(keep, info->hash.in, info->hash.inSz);
        ret = wc_AlteraFcs_SoftSha256Update(sha, info->hash.in,
                                            info->hash.inSz);
        if (ret != 0) {
            return ret;
        }
    }

    /* final(): one device digest over the file. Declining hands the shadow
     * state to wolfSSL's own final, which is exact, so every reason the
     * device cannot serve this message ends there: no callback-owned file
     * (earlier updates ran while unregistered), an empty or unaligned
     * message, an overflowed one, or a device failure. */
    if (ret == 0 && info->hash.digest != NULL) {
        if (keep == NULL) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if (keep->overflowed || keep->used == 0 ||
            (keep->used % WC_ALTERA_FCS_HASH_ALIGN) != 0) {
            ret = CRYPTOCB_UNAVAILABLE;
        }
        else {
            ret = wc_AlteraFcs_Digest(keep, info->hash.digest);
            if (ret != 0) {
                WOLFSSL_MSG("Altera FCS digest failed; software completes");
                ret = CRYPTOCB_UNAVAILABLE;
            }
        }
        if (ret == 0) {
            ret = wc_AlteraFcs_Sha256Reset(sha, shadow);
            /* The shadow saw the same message, so a disagreement can only be
             * a device fault and is reported rather than hidden. */
            if (ret == 0 && ConstantCompare(shadow, info->hash.digest,
                                            WC_SHA256_DIGEST_SIZE) != 0) {
                WOLFSSL_MSG("Altera FCS digest disagrees with software");
                ret = WC_HW_E;
            }
            ForceZero(shadow, sizeof(shadow));
            if (ret == 0) {
                wc_AlteraFcs_TestHwMark(WC_ALTERA_FCS_TEST_HW_HASH);
            }
        }
        wc_AlteraFcs_KeepFree(keep);
        *devCtxPtr = NULL;
    }

    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS && WOLFSSL_ALTERA_FCS_HASH */
