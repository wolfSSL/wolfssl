/* altera_fcs_hmac.c
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

/* HMAC verification against a key held inside the Agilex 5 Secure Device
 * Manager.
 *
 * This is deliberately not a crypto callback. The device exposes only
 * verification: fcs_mac_verify() returns a four byte verdict and never a tag,
 * while wolfSSL's HMAC API is a generator that ends in wc_HmacFinal(). There is
 * no verify entry point to hook, so a callback could not be written without
 * silently changing what callers get.
 *
 * What it does provide is authentication under a key that HPS software cannot
 * read, which is the isolation property applied to MACs rather than signatures.
 * Tags produced by an ordinary software HMAC verify correctly here, so the
 * device implementation is interoperable.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WOLFSSL_ALTERA_FCS_HMAC)

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <libfcs.h>
#include <unistd.h>
#include <errno.h>

#define WC_ALTERA_FCS_HMAC_TRACK_MAX 32

static wolfSSL_Atomic_Uint g_hmacKeys[WC_ALTERA_FCS_HMAC_TRACK_MAX];

static int wc_AlteraFcs_HmacTrackAdd(word32 keyId)
{
    int i;

    for (i = 0; i < WC_ALTERA_FCS_HMAC_TRACK_MAX; i++) {
        WC_ATOMIC_UINT_ARG empty = 0;

        if (wolfSSL_Atomic_Uint_CompareExchange(&g_hmacKeys[i], &empty,
                                               (WC_ATOMIC_UINT_ARG)keyId)) {
            return 0;
        }
    }
    return MEMORY_E;
}

static int wc_AlteraFcs_HmacTrackTake(word32 keyId)
{
    int i;

    if (keyId == 0) {
        return 0;
    }

    for (i = 0; i < WC_ALTERA_FCS_HMAC_TRACK_MAX; i++) {
        WC_ATOMIC_UINT_ARG expected = (WC_ATOMIC_UINT_ARG)keyId;

        if (wolfSSL_Atomic_Uint_CompareExchange(&g_hmacKeys[i], &expected,
                                                0)) {
            return 1;
        }
    }
    return 0;
}

static int wc_AlteraFcs_HmacTrackHas(word32 keyId)
{
    int i;

    if (keyId == 0) {
        return 0;
    }
    for (i = 0; i < WC_ALTERA_FCS_HMAC_TRACK_MAX; i++) {
        if (wolfSSL_Atomic_Uint_FetchAdd(&g_hmacKeys[i], 0) ==
                (WC_ATOMIC_UINT_ARG)keyId) {
            return 1;
        }
    }
    return 0;
}

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* The device reports the outcome as a 32 bit word rather than a return code. */
#define FCS_MAC_RESULT_SZ  4
#define FCS_MAC_RESULT_OK  0x900DU

/* Map a wolfSSL hash type to the device digest selector and tag size. */
static int wc_AlteraFcs_HmacDigest(int hashType, FCS_OSAL_U32* digSel,
                                   word32* macSz)
{
    int ret = 0;

    switch (hashType) {
    #ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *digSel = 0;
            *macSz  = WC_SHA256_DIGEST_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *digSel = 1;
            *macSz  = WC_SHA384_DIGEST_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            *digSel = 2;
            *macSz  = WC_SHA512_DIGEST_SIZE;
            break;
    #endif
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

/* Shared by import and generate; key == NULL means the device generates it. */
static int wc_AlteraFcs_HmacKeyNew(const byte* key, int keyBits,
                                   word32* keyId)
{
    byte   obj[WC_ALTERA_FCS_KEY_OBJ_MAX_SZ];
    byte   status[WC_ALTERA_FCS_KEY_STATUS_SZ];
    FCS_OSAL_UINT statusLen = (FCS_OSAL_UINT)sizeof(status);
    void*  session = NULL;
    word32 objSz = 0;
    word32 newId = 0;
    int    createFailed = 0;
    int    keepResource = 0;
    int    ret;

    if (keyId == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyBits != 256 && keyBits != 384 && keyBits != 512) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AlteraFcs_ResourceAcquire();
    if (ret != 0) {
        return WC_HW_E;
    }

    ret = wc_AlteraFcs_KeyIdNew(&newId);
    if (ret == 0) {
        /* Sign and Verify only, the same exclusivity the ECC objects carry. */
        ret = wc_AlteraFcs_KeyObject(obj, newId, WC_ALTERA_FCS_KEY_TYPE_HMAC,
                                     WC_ALTERA_FCS_KEY_USAGE_SIGN_VERIFY,
                                     key, (word32)keyBits, &objSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_SessionAcquire(&session);
        if (ret != 0) {
            ret = WC_HW_E;
        }
    }
    if (ret == 0) {
        XMEMSET(status, 0, sizeof(status));
        if (key != NULL) {
            ret = fcs_import_service_key((FCS_OSAL_UUID*)session,
                                         (FCS_OSAL_CHAR*)obj,
                                         (FCS_OSAL_INT)objSz,
                                         (FCS_OSAL_CHAR*)status, &statusLen);
        }
        else {
            ret = fcs_create_service_key((FCS_OSAL_UUID*)session,
                                         (FCS_OSAL_CHAR*)obj,
                                         (FCS_OSAL_INT)objSz,
                                         (FCS_OSAL_CHAR*)status,
                                         (FCS_OSAL_UINT)sizeof(status));
        }
        if (ret != 0) {
            WOLFSSL_MSG("Altera FCS HMAC key creation failed");
            createFailed = 1;
            ret = WC_HW_E;
        }
        else {
            ret = wc_AlteraFcs_HmacTrackAdd(newId);
            if (ret == 0) {
                *keyId = newId;
                /* Transfer the provisional resource reference to the tracked
                 * device key. Removal releases it. */
                keepResource = 1;
            }
            else {
                if (fcs_remove_service_key((FCS_OSAL_UUID*)session,
                                           (FCS_OSAL_U32)newId) != 0) {
                    (void)wc_AlteraFcs_OrphanKey(newId);
                }
            }
        }
        wc_AlteraFcs_SessionRelease();
        if (createFailed) {
            wc_AlteraFcs_DiscardServiceKey(newId);
        }
    }

    if (!keepResource) {
        wc_AlteraFcs_ResourceRemove();
    }
    ForceZero(obj, sizeof(obj));
    return ret;
}

int wc_AlteraFcs_HmacImportKey(const byte* key, int keyBits, word32* keyId)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    return wc_AlteraFcs_HmacKeyNew(key, keyBits, keyId);
}

int wc_AlteraFcs_HmacMakeKey(int keyBits, word32* keyId)
{
    return wc_AlteraFcs_HmacKeyNew(NULL, keyBits, keyId);
}

int wc_AlteraFcs_HmacRemoveKey(word32 keyId)
{
    int ret;

    /* Claim the tracker entry before touching the device so two removers cannot
     * operate on the same key and release its resource twice. */
    if (!wc_AlteraFcs_HmacTrackTake(keyId)) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AlteraFcs_RemoveServiceKey(keyId);
    if (ret != 0) {
        /* The key is no longer caller reachable. Record it for best-effort
         * retry; closing the session ultimately reclaims it even if retry
         * keeps failing. */
        (void)wc_AlteraFcs_OrphanKey(keyId);
    }
    wc_AlteraFcs_ResourceRemove();
    return ret;
}

/* One transaction. The device wants the message and the tag contiguous, with
 * user_data_sz giving the length of the message part. A message only request
 * is refused with 0x4. */
static int wc_AlteraFcs_HmacVerifyOnce(word32 keyId, FCS_OSAL_U32 digSel,
                                       const byte* data, word32 dataSz,
                                       const byte* mac, word32 macSz,
                                       byte* result)
{
    struct fcs_mac_verify_req req;
    byte*        buf = NULL;
    void*        session = NULL;
    FCS_OSAL_U32 resultLen = FCS_MAC_RESULT_SZ;
    word32       totalSz = dataSz + macSz;
    int          ret;

    buf = (byte*)XMALLOC(totalSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MEMORY_E;
    }
    if (dataSz > 0) {
        XMEMCPY(buf, data, dataSz);
    }
    XMEMCPY(buf + dataSz, mac, macSz);

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret == 0) {
        XMEMSET(&req, 0, sizeof(req));
        req.op_mode      = 0;
        req.dig_sz       = digSel;
        req.src          = (FCS_OSAL_CHAR*)buf;
        req.src_sz       = (FCS_OSAL_U32)totalSz;
        req.dst          = (FCS_OSAL_CHAR*)result;
        req.dst_sz       = &resultLen;
        req.user_data_sz = (FCS_OSAL_U32)dataSz;

        ret = fcs_mac_verify((FCS_OSAL_UUID*)session,
                             WOLFSSL_ALTERA_FCS_CTX_ID, (FCS_OSAL_U32)keyId,
                             &req);
        wc_AlteraFcs_SessionRelease();
        if (ret != 0) {
            WOLFSSL_MSG("Altera FCS HMAC verify request failed");
            ret = WC_HW_E;
        }
        else if (resultLen != FCS_MAC_RESULT_SZ) {
            WOLFSSL_MSG("Altera FCS HMAC verify result length unexpected");
            ret = WC_HW_E;
        }
    }
    else {
        ret = WC_HW_E;
    }

    ForceZero(buf, totalSz);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Past one transaction the message and tag go through memory files and
 * libfcs feeds the device in 4 MiB pieces. */
static int wc_AlteraFcs_HmacVerifyStream(word32 keyId, FCS_OSAL_U32 digSel,
                                         const byte* data, word32 dataSz,
                                         const byte* mac, word32 macSz,
                                         byte* result)
{
    struct fcs_mac_verify_req_streaming req;
    char   dataPath[WC_ALTERA_FCS_FD_PATH_SZ];
    char   macPath[WC_ALTERA_FCS_FD_PATH_SZ];
    char   outPath[WC_ALTERA_FCS_FD_PATH_SZ];
    void*  session = NULL;
    word32 outSz = 0;
    int    dataFd;
    int    macFd = -1;
    int    outFd = -1;
    int    ret = 0;

    dataFd = wc_AlteraFcs_MemFd();
    if (dataFd < 0) {
        return WC_HW_E;
    }
    macFd = wc_AlteraFcs_MemFd();
    if (macFd >= 0) {
        outFd = wc_AlteraFcs_MemFd();
    }
    if (macFd < 0 || outFd < 0) {
        ret = WC_HW_E;
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdWrite(dataFd, data, dataSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdWrite(macFd, mac, macSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_SessionAcquire(&session);
        if (ret != 0) {
            ret = WC_HW_E;
        }
    }
    if (ret == 0) {
        wc_AlteraFcs_MemFdPath(dataFd, dataPath);
        wc_AlteraFcs_MemFdPath(macFd, macPath);
        wc_AlteraFcs_MemFdPath(outFd, outPath);
        XMEMSET(&req, 0, sizeof(req));
        req.op_mode     = 0;
        req.dig_sz      = digSel;
        req.filename1   = dataPath;
        req.filename2   = macPath;
        req.outfilename = outPath;

        ret = fcs_mac_verify_streaming((FCS_OSAL_UUID*)session,
                                       (FCS_OSAL_U32)keyId,
                                       WOLFSSL_ALTERA_FCS_CTX_ID, &req);
        wc_AlteraFcs_SessionRelease();
        /* Unlike the one shot call, the streaming call reports a mismatch as
         * -EIO while still writing the verdict word, so that case is read
         * from the result file below. */
        if (ret == -EIO) {
            ret = 0;
        }
        else if (ret != 0) {
            WOLFSSL_MSG("Altera FCS HMAC streamed verify request failed");
            ret = WC_HW_E;
        }
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdSize(outFd, &outSz);
    }
    /* libfcs writes a 16 byte result file; the verdict is its first word. */
    if (ret == 0 && outSz < FCS_MAC_RESULT_SZ) {
        WOLFSSL_MSG("Altera FCS HMAC verify result length unexpected");
        ret = WC_HW_E;
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_MemFdRead(outFd, 0, result, FCS_MAC_RESULT_SZ);
    }

    if (outFd >= 0) {
        (void)close(outFd);
    }
    if (macFd >= 0) {
        (void)close(macFd);
    }
    (void)close(dataFd);
    return ret;
}

int wc_AlteraFcs_HmacVerify(word32 keyId, int hashType, const byte* data,
                            word32 dataSz, const byte* mac, word32 macSz,
                            int* isValid)
{
    byte         result[FCS_MAC_RESULT_SZ];
    FCS_OSAL_U32 digSel = 0;
    word32       expectSz = 0;
    int          ret;

    if ((data == NULL && dataSz != 0) || mac == NULL || isValid == NULL) {
        return BAD_FUNC_ARG;
    }
    *isValid = 0;
    if (!wc_AlteraFcs_HmacTrackHas(keyId)) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AlteraFcs_HmacDigest(hashType, &digSel, &expectSz);
    if (ret != 0) {
        return ret;
    }
    if (macSz != expectSz) {
        return BAD_FUNC_ARG;
    }

    /* The device counts message and tag together in one 32 bit length. */
    if (dataSz > 0xFFFFFFFFU - macSz) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(result, 0, sizeof(result));
    if (dataSz <= WC_ALTERA_FCS_MAX_XFER - macSz) {
        ret = wc_AlteraFcs_HmacVerifyOnce(keyId, digSel, data, dataSz, mac,
                                          macSz, result);
    }
    else {
        ret = wc_AlteraFcs_HmacVerifyStream(keyId, digSel, data, dataSz, mac,
                                            macSz, result);
    }
    if (ret != 0) {
        return ret;
    }

    /* A mismatch is reported in the result word, not as a request failure, so
     * the verdict has to be read rather than inferred from ret. */
    *isValid = (wc_AlteraFcs_Get32(result) == FCS_MAC_RESULT_OK) ? 1 : 0;
    return 0;
}

#endif /* WOLFSSL_ALTERA_FCS && WOLFSSL_ALTERA_FCS_HMAC */
