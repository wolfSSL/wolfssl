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

/* SHA-2 digests on the Agilex 5 Secure Device Manager.
 *
 * Why the message is buffered rather than streamed: the device grants a single
 * crypto session, and wolfSSL may have several hash contexts open at once
 * (a TLS transcript hash alongside the DRBG, for example). Interleaving those
 * over one hardware stream is not possible, so each context accumulates its own
 * message in the wolfSSL hash devCtx and the digest is produced by one atomic
 * fcs_get_digest() at final().
 *
 * Because that state lives in devCtx, the copy and free callbacks are
 * mandatory: wolfSSL's plain struct copy would leave two contexts sharing one
 * buffer, which corrupts the DRBG and shows up as DRBG_CONT_FIPS_E.
 *
 * A minimum size threshold keeps small hashes in software. An SDM digest costs
 * roughly 5 ms regardless of length, so routing short hashes here would slow
 * the library dramatically for no benefit.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WOLFSSL_ALTERA_FCS_HASH)

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include <libfcs.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if !defined(WOLF_CRYPTO_CB_COPY) || !defined(WOLF_CRYPTO_CB_FREE)
    #error "WOLFSSL_ALTERA_FCS_HASH requires WOLF_CRYPTO_CB_COPY and _FREE"
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_SHA512_HASHTYPE)
    /* Without this the truncated SHA-512/224 and /256 variants are
     * indistinguishable from full SHA-512 and would be given a 64 byte digest. */
    #error "WOLFSSL_ALTERA_FCS_HASH requires WOLFSSL_SHA512_HASHTYPE"
#endif

#define FCS_SHA_OP_MODE_SHA 1
#define FCS_SHA_SZ_256 0
#define FCS_SHA_SZ_384 1
#define FCS_SHA_SZ_512 2

/* Starting capacity for an accumulated message. */
#define WC_ALTERA_FCS_KEEP_MIN 256
#ifndef WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX
    #define WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX WC_ALTERA_FCS_MAX_XFER
#endif
#ifndef WOLFSSL_ALTERA_FCS_HASH_TOTAL_MAX
    #define WOLFSSL_ALTERA_FCS_HASH_TOTAL_MAX (4 * 1024 * 1024)
#endif
#if WOLFSSL_ALTERA_FCS_HASH_TOTAL_MAX > 0x7fffffff
    #error "WOLFSSL_ALTERA_FCS_HASH_TOTAL_MAX exceeds atomic counter range"
#endif

/* Internal result: retain no more input and continue in the software shadow. */
#define WC_ALTERA_FCS_KEEP_SOFTWARE 1
static wolfSSL_Atomic_Int g_alteraHashBuffered = 0;

/* Public SHA APIs may consult WOLF_CRYPTO_CB_FIND even with INVALID_DEVID.
 * Internal software-shadow work sets this thread-local guard so redispatch
 * declines instead of recursively entering this callback. */
#if !defined(SINGLE_THREADED) && \
    (!defined(HAVE_THREAD_LS) || defined(NO_THREAD_LS))
    #error "WOLFSSL_ALTERA_FCS_HASH requires thread-local storage"
#endif
static THREAD_LS_T int g_alteraHashSoftware = 0;

typedef struct {
    byte*      msg;
    word32     used;
    word32     len;
    void*      heap;
    /* Once the message passes what one SDM transaction can carry, the buffer
     * is folded into this software state and released: a multi gigabyte hash
     * must not be held in memory just to discover at final() that it has to
     * run in software anyway. */
#ifndef NO_SHA256
    wc_Sha256  soft;
#endif
    byte       softInit;
    byte       overflowed;
    byte       active;
} AlteraHashKeep;

static int wc_AlteraFcs_HashReserve(word32 sz)
{
    int used;

    do {
        used = wolfSSL_Atomic_Int_FetchAdd(&g_alteraHashBuffered, 0);
        if (used < 0 || sz > (word32)WOLFSSL_ALTERA_FCS_HASH_TOTAL_MAX -
                             (word32)used) {
            return 0;
        }
    } while (!wolfSSL_Atomic_Int_CompareExchange(&g_alteraHashBuffered,
                                                  &used,
                                                  used + (int)sz));
    return 1;
}

static void wc_AlteraFcs_HashRelease(word32 sz)
{
    if (sz > 0) {
        (void)wolfSSL_Atomic_Int_FetchSub(&g_alteraHashBuffered, (int)sz);
    }
}

/* Append with geometric growth. _wc_Hash_Grow sizes to exactly used + inSz, so
 * a message arriving in many small updates reallocates every time and copies
 * the whole prefix again. Reallocating by hand also lets the old buffer be
 * zeroized rather than left in the allocator. */
static int wc_AlteraFcs_KeepAppend(AlteraHashKeep* keep, const byte* in,
                                   word32 inSz)
{
    byte*  tmp;
    word32 need;
    word32 cap;

    if (inSz == 0) {
        return 0;
    }

    need = keep->used + inSz;
    if (need < keep->used) {
        return BUFFER_E;
    }

    if (need > (word32)WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX) {
        return WC_ALTERA_FCS_KEEP_SOFTWARE;
    }

    if (need > keep->len) {
        cap = (keep->len == 0) ? WC_ALTERA_FCS_KEEP_MIN : keep->len;
        while (cap < need) {
            word32 next = cap << 1;

            if (next < cap ||
                next > (word32)WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX) {
                next = (word32)WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX;
            }
            cap = next;
        }

        if (!wc_AlteraFcs_HashReserve(cap - keep->len)) {
            return WC_ALTERA_FCS_KEEP_SOFTWARE;
        }
        tmp = (byte*)XMALLOC(cap, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            wc_AlteraFcs_HashRelease(cap - keep->len);
            return MEMORY_E;
        }
        if (keep->used > 0) {
            XMEMCPY(tmp, keep->msg, keep->used);
        }
        if (keep->msg != NULL) {
            ForceZero(keep->msg, keep->len);
            XFREE(keep->msg, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        keep->msg = tmp;
        keep->len = cap;
    }

    XMEMCPY(keep->msg + keep->used, in, inSz);
    keep->used += inSz;
    return 0;
}

static void wc_AlteraFcs_KeepFree(AlteraHashKeep* keep)
{
    if (keep == NULL) {
        return;
    }
#ifndef NO_SHA256
    if (keep->softInit) {
        wc_Sha256Free(&keep->soft);
        keep->softInit = 0;
    }
#endif
    if (keep->msg != NULL) {
        ForceZero(keep->msg, keep->len);
        XFREE(keep->msg, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
        wc_AlteraFcs_HashRelease(keep->len);
    }
    if (keep->active) {
        wc_AlteraFcs_ResourceRemove();
    }
    XFREE(keep, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Address of the devCtx field inside a hash context of the given type. */
static void** wc_AlteraFcs_DevCtxOf(void* hashCtx, int type)
{
    void** devCtx = NULL;

    if (hashCtx == NULL) {
        return NULL;
    }

    switch (type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            devCtx = &((wc_Sha256*)hashCtx)->devCtx;
            break;
#endif
        /* The SHA-512 family is deliberately not offloaded. Its truncated
         * variants (SHA-512/224, /256) are indistinguishable from full SHA-512
         * at update() time - the digest size only appears at final() - so
         * buffering them here risks finalising with the wrong length. There is
         * nothing to gain either: this CPU has no ARMv8 SHA-512 extension, and
         * the SDM is far slower than software regardless. */
        default:
            break;
    }

    return devCtx;
}

static int wc_AlteraFcs_HashParams(int type, word32* digestSz,
                                   FCS_OSAL_U32* shaSel)
{
    int ret = 0;

    switch (type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *digestSz = WC_SHA256_DIGEST_SIZE;
            *shaSel   = FCS_SHA_SZ_256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *digestSz = WC_SHA384_DIGEST_SIZE;
            *shaSel   = FCS_SHA_SZ_384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            *digestSz = WC_SHA512_DIGEST_SIZE;
            *shaSel   = FCS_SHA_SZ_512;
            break;
#endif
        /* The SDM offers no truncated SHA-512 modes, so SHA-512/224 and
         * SHA-512/256 stay in software. */
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

/* Resolve the hash context pointer carried in info->hash for this type. */
static void* wc_AlteraFcs_HashObj(wc_CryptoInfo* info)
{
    void* obj = NULL;

    switch (info->hash.type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            obj = info->hash.sha256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            obj = info->hash.sha384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
        case WC_HASH_TYPE_SHA512_224:
        case WC_HASH_TYPE_SHA512_256:
            obj = info->hash.sha512;
            break;
#endif
        default:
            break;
    }

    return obj;
}

static int wc_AlteraFcs_Digest(const byte* in, word32 inSz, byte* out,
                               word32 digestSz, FCS_OSAL_U32 shaSel)
{
    struct fcs_digest_get_req req;
    void*        session = NULL;
    FCS_OSAL_U32 outLen  = digestSz;
    int          ret;

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.sha_op_mode   = FCS_SHA_OP_MODE_SHA;
    req.sha_digest_sz = shaSel;
    req.src           = (FCS_OSAL_CHAR*)in;
    req.src_len       = (FCS_OSAL_U32)inSz;
    req.digest        = (FCS_OSAL_CHAR*)out;
    req.digest_len    = &outLen;

    ret = fcs_get_digest((FCS_OSAL_UUID*)session, WOLFSSL_ALTERA_FCS_CTX_ID,
                         0, &req);
    if (ret != 0) {
        ret = wc_AlteraFcs_MapError(ret);
    }
    else if (outLen != digestSz) {
        /* An invalid session has been seen to report success while returning a
         * short or empty digest, so the length is checked rather than trusted. */
        WOLFSSL_MSG("Altera FCS digest length mismatch");
        ret = WC_HW_E;
    }
    else {
        wc_AlteraFcs_TestHwMark(WC_ALTERA_FCS_TEST_HW_HASH);
    }

    wc_AlteraFcs_SessionRelease();
    return ret;
}

/* Digest the accumulated message in software.
 *
 * Required, not an optimisation: once update() has returned success wolfSSL
 * stops maintaining its own hash state, so this callback owns the data. Bailing
 * out with CRYPTOCB_UNAVAILABLE at final() would make wolfSSL finalize an empty
 * context and silently produce the digest of nothing. Contexts are created with
 * INVALID_DEVID so they cannot recurse back into this callback. */
static int wc_AlteraFcs_SoftDigest(int type, const byte* in, word32 inSz,
                                   byte* out, void* heap)
{
    int ret;

    g_alteraHashSoftware++;
    switch (type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256: {
            wc_Sha256 s;

            ret = wc_InitSha256_ex(&s, heap, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_Sha256Update(&s, in, inSz);
                if (ret == 0) {
                    ret = wc_Sha256Final(&s, out);
                }
                wc_Sha256Free(&s);
            }
            break;
        }
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384: {
            wc_Sha384 s;

            ret = wc_InitSha384_ex(&s, heap, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_Sha384Update(&s, in, inSz);
                if (ret == 0) {
                    ret = wc_Sha384Final(&s, out);
                }
                wc_Sha384Free(&s);
            }
            break;
        }
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
    !defined(HAVE_SELFTEST)
        case WC_HASH_TYPE_SHA512_224: {
            wc_Sha512 s;

            ret = wc_InitSha512_224_ex(&s, heap, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_Sha512_224Update(&s, in, inSz);
                if (ret == 0) {
                    ret = wc_Sha512_224Final(&s, out);
                }
                wc_Sha512_224Free(&s);
            }
            break;
        }
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
    !defined(HAVE_SELFTEST)
        case WC_HASH_TYPE_SHA512_256: {
            wc_Sha512 s;

            ret = wc_InitSha512_256_ex(&s, heap, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_Sha512_256Update(&s, in, inSz);
                if (ret == 0) {
                    ret = wc_Sha512_256Final(&s, out);
                }
                wc_Sha512_256Free(&s);
            }
            break;
        }
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512: {
            wc_Sha512 s;

            ret = wc_InitSha512_ex(&s, heap, INVALID_DEVID);
            if (ret == 0) {
                ret = wc_Sha512Update(&s, in, inSz);
                if (ret == 0) {
                    ret = wc_Sha512Final(&s, out);
                }
                wc_Sha512Free(&s);
            }
            break;
        }
#endif
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    g_alteraHashSoftware--;
    return ret;
}

#ifndef NO_SHA256
static int wc_AlteraFcs_Sha256Reset(wc_Sha256* sha)
{
    byte digest[WC_SHA256_DIGEST_SIZE];
    int  devId;
    int  ret;

    devId = sha->devId;
    sha->devId = INVALID_DEVID;
    g_alteraHashSoftware++;
    ret = wc_Sha256Final(sha, digest);
    g_alteraHashSoftware--;
    sha->devId = devId;
    ForceZero(digest, sizeof(digest));
    return ret;
}

static int wc_AlteraFcs_SoftSha256Update(wc_Sha256* sha, const byte* in,
                                         word32 inSz)
{
    int ret;

    g_alteraHashSoftware++;
    ret = wc_Sha256Update(sha, in, inSz);
    g_alteraHashSoftware--;
    return ret;
}

static int wc_AlteraFcs_KeepToSoftware(AlteraHashKeep* keep)
{
    int ret;

    ret = wc_InitSha256_ex(&keep->soft, keep->heap, INVALID_DEVID);
    if (ret == 0) {
        keep->softInit = 1;
        if (keep->used > 0) {
            ret = wc_AlteraFcs_SoftSha256Update(&keep->soft, keep->msg,
                                                keep->used);
        }
    }
    if (ret != 0) {
        return ret;
    }
    if (keep->msg != NULL) {
        ForceZero(keep->msg, keep->len);
        XFREE(keep->msg, keep->heap, DYNAMIC_TYPE_TMP_BUFFER);
        wc_AlteraFcs_HashRelease(keep->len);
        keep->msg = NULL;
    }
    keep->used = 0;
    keep->len = 0;
    keep->overflowed = 1;
    return 0;
}
#endif

/* wolfSSL skips its own copy path when this callback succeeds. Delegate the
 * ordinary context portion back to wc_Sha256Copy with the FCS state detached,
 * then independently duplicate the buffered FCS state. This preserves every
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
    if (ret != 0) {
        goto exit;
    }

    dstKeep = (AlteraHashKeep*)XMALLOC(sizeof(AlteraHashKeep),
                                       dstSha->heap,
                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (dstKeep == NULL) {
        ret = MEMORY_E;
        goto exit;
    }
    XMEMSET(dstKeep, 0, sizeof(*dstKeep));
    dstKeep->heap = dstSha->heap;

#ifndef NO_SHA256
    if (srcKeep->overflowed) {
        /* The message is gone; the live software state has to be duplicated
         * so the two contexts stay independent. */
        dstKeep->softInit = 1;
        ret = wc_Sha256Copy(&srcKeep->soft, &dstKeep->soft);
        if (ret != 0) {
            goto exit;
        }
        dstKeep->overflowed = 1;
    }
    else
#endif
    if (srcKeep->used > 0) {
        ret = wc_AlteraFcs_KeepAppend(dstKeep, srcKeep->msg, srcKeep->used);
        if (ret == WC_ALTERA_FCS_KEEP_SOFTWARE) {
            ret = wc_AlteraFcs_KeepToSoftware(dstKeep);
            if (ret == 0) {
                ret = wc_AlteraFcs_SoftSha256Update(&dstKeep->soft,
                                                     srcKeep->msg,
                                                     srcKeep->used);
            }
        }
        if (ret != 0) {
            goto exit;
        }
    }

    dstKeep->active = 1;
    wc_AlteraFcs_ResourceAdd();
    dstSha->devCtx = dstKeep;
    dstSha->devId = srcDevId;
    return 0;

exit:
    wc_AlteraFcs_KeepFree(dstKeep);
    dstSha->devCtx = NULL;
    dstSha->devId = INVALID_DEVID;
    wc_Sha256Free(dstSha);
    XMEMSET(dstSha, 0, sizeof(*dstSha));
    return ret;
}

/* Release the buffer when a context is freed without being finalized. */
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

#ifndef NO_SHA256
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
#endif

int wc_AlteraFcs_Hash(wc_CryptoInfo* info)
{
    AlteraHashKeep* keep;
    void**       devCtxPtr;
    void*        hashObj;
    word32       digestSz = 0;
    FCS_OSAL_U32 shaSel   = 0;
    int          hwOk     = 0;
    int          ret      = 0;

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

    /* A failure here only means there is no hardware mode for this variant; the
     * message is still buffered and finished in software at final(). */
    hwOk = (wc_AlteraFcs_HashParams(info->hash.type, &digestSz, &shaSel) == 0);

    hashObj = wc_AlteraFcs_HashObj(info);
    devCtxPtr = wc_AlteraFcs_DevCtxOf(hashObj, info->hash.type);
    if (devCtxPtr == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    keep = (AlteraHashKeep*)(*devCtxPtr);

    /* update(): accumulate into this context's own buffer, unless the message
     * has outgrown what one device transaction can carry, in which case it is
     * streamed into a software state instead. */
    if (info->hash.in != NULL) {
        if (keep == NULL) {
            void* heap = ((wc_Sha256*)hashObj)->heap;

            if (wc_AlteraFcs_UnregisterPending()) {
                return CRYPTOCB_UNAVAILABLE;
            }
#ifndef NO_SHA256
            if (info->hash.type == WC_HASH_TYPE_SHA256 &&
                wc_AlteraFcs_Sha256Started((wc_Sha256*)hashObj)) {
                return CRYPTOCB_UNAVAILABLE;
            }
#endif
            keep = (AlteraHashKeep*)XMALLOC(sizeof(AlteraHashKeep), heap,
                                            DYNAMIC_TYPE_TMP_BUFFER);
            if (keep == NULL) {
                return MEMORY_E;
            }
            XMEMSET(keep, 0, sizeof(*keep));
            keep->heap = heap;
            keep->active = 1;
            wc_AlteraFcs_ResourceAdd();
            *devCtxPtr = keep;
        }

#ifndef NO_SHA256
        if (!keep->overflowed && info->hash.type == WC_HASH_TYPE_SHA256 &&
            ((word32)(keep->used + info->hash.inSz) < keep->used ||
             (word32)(keep->used + info->hash.inSz) >
                 (word32)WOLFSSL_ALTERA_FCS_HASH_BUFFER_MAX)) {
            ret = wc_AlteraFcs_KeepToSoftware(keep);
            if (ret != 0)
                return ret;
        }

        if (keep->overflowed) {
            ret = wc_AlteraFcs_SoftSha256Update(&keep->soft, info->hash.in,
                                                info->hash.inSz);
            if (ret != 0) {
                return ret;
            }
        }
        else
#endif
        {
            ret = wc_AlteraFcs_KeepAppend(keep, info->hash.in,
                                          info->hash.inSz);
            if (ret == WC_ALTERA_FCS_KEEP_SOFTWARE) {
#ifndef NO_SHA256
                if (info->hash.type == WC_HASH_TYPE_SHA256) {
                    ret = wc_AlteraFcs_KeepToSoftware(keep);
                    if (ret == 0) {
                        ret = wc_AlteraFcs_SoftSha256Update(
                            &keep->soft, info->hash.in, info->hash.inSz);
                    }
                }
                else
#endif
                {
                    ret = MEMORY_E;
                }
            }
            if (ret != 0) {
                return ret;
            }
        }

#ifndef NO_SHA256
        /* The callback owns update processing, but callers such as the TLS CBC
         * verifier also inspect the ordinary SHA state through FinalRaw().
         * Advance that state in software while retaining the buffered message
         * for the final atomic SDM operation. */
        if (info->hash.type == WC_HASH_TYPE_SHA256) {
            wc_Sha256* sha = (wc_Sha256*)hashObj;
            int devId = sha->devId;

            sha->devId = INVALID_DEVID;
            g_alteraHashSoftware++;
            ret = wc_Sha256Update(sha, info->hash.in, info->hash.inSz);
            g_alteraHashSoftware--;
            sha->devId = devId;
            if (ret != 0) {
                return ret;
            }
        }
#endif
    }

    /* final(): one atomic SDM digest over everything accumulated. Short
     * messages are hashed in software here rather than declined, because this
     * callback already consumed the updates. */
    if (ret == 0 && info->hash.digest != NULL) {
        const byte* msg    = (keep != NULL) ? keep->msg  : NULL;
        word32      msgLen = (keep != NULL) ? keep->used : 0;

        /* No callback-owned buffer means earlier updates ran in software while
         * this device was unregistered. Decline so that state is finalized. */
        if (keep == NULL) {
            return CRYPTOCB_UNAVAILABLE;
        }

#ifndef NO_SHA256
        if (keep->overflowed) {
            ret = wc_Sha256Final(&keep->soft, info->hash.digest);
            if (ret == 0) {
                ret = wc_AlteraFcs_Sha256Reset((wc_Sha256*)hashObj);
            }
            wc_AlteraFcs_KeepFree(keep);
            *devCtxPtr = NULL;
            return ret;
        }
#endif

        /* Oversized messages exceed a single SDM transaction, so they are
         * finished in software rather than rejected by the driver. */
        if (hwOk && msgLen >= WOLFSSL_ALTERA_FCS_HASH_MIN &&
            msgLen <= WC_ALTERA_FCS_MAX_XFER) {
            ret = wc_AlteraFcs_Digest(msg, msgLen, info->hash.digest,
                                      digestSz, shaSel);
            if (ret != 0) {
                /* The callback consumed every update, so the message is only
                 * available here. Any device failure, not just a busy one,
                 * must still produce the digest. */
                ret = wc_AlteraFcs_SoftDigest(info->hash.type, msg, msgLen,
                                              info->hash.digest, keep->heap);
            }
        }
        else {
            ret = wc_AlteraFcs_SoftDigest(info->hash.type, msg, msgLen,
                                          info->hash.digest, keep->heap);
        }

        if (ret == 0 && info->hash.type == WC_HASH_TYPE_SHA256) {
            ret = wc_AlteraFcs_Sha256Reset((wc_Sha256*)hashObj);
        }
        wc_AlteraFcs_KeepFree(keep);
        *devCtxPtr = NULL;
    }

    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS && WOLFSSL_ALTERA_FCS_HASH */
