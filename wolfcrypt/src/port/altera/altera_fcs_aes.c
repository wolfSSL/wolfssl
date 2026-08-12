/* altera_fcs_aes.c
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

/* AES-CBC and AES-CTR on the Agilex 5 Secure Device Manager.
 *
 * Unlike the hash path an AES request arrives whole, so this callback can
 * decline any operation it cannot serve exactly and let wolfSSL run it in
 * software. Nothing is consumed before the decision is made.
 *
 * Three device properties shape the code, all measured on hardware rather than
 * taken from the documentation:
 *
 * 1. Input length must be a multiple of 32 bytes. AES blocks are 16, so lengths
 *    such as 16 and 48 are refused by the driver and stay in software.
 * 2. The IV buffer is not updated by the device, so the chaining state in
 *    aes->reg is maintained here.
 * 3. Key slots are few, about 27, and a leaked slot lasts until the session
 *    closes. Keys are therefore imported lazily on first eligible use and
 *    removed when the context is freed.
 *
 * Importing a plaintext key gives SDM enforcement of the usage mask, not key
 * secrecy: the key was already in HPS memory when wc_AesSetKey stored it.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WOLFSSL_ALTERA_FCS_AES)

#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <libfcs.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLF_CRYPTO_CB_FREE
    #error "WOLFSSL_ALTERA_FCS_AES requires WOLF_CRYPTO_CB_FREE to release keys"
#endif
#ifndef WOLF_CRYPTO_CB_SETKEY
    #error "WOLFSSL_ALTERA_FCS_AES requires WOLF_CRYPTO_CB_SETKEY for re-keying"
#endif

/* The driver refuses any non-GCM length that is not a multiple of this. */
#define WC_ALTERA_FCS_AES_ALIGN 32

#define FCS_KEY_OBJ_MAGIC     0x43736B4FU
#define FCS_KEY_DATA_MAGIC    0x43736B64U
#define FCS_KEY_OBJ_VER       1
#define FCS_KEY_TYPE_AES      1
#define FCS_KEY_SIZE_128      1
#define FCS_KEY_SIZE_256      2
#define FCS_KEY_USAGE_ENC_DEC 0x3
#define FCS_KEY_MAC_SZ        48
#define FCS_KEY_DATA_OFFSET   56
#define FCS_KEY_STATUS_SZ     64

/* Distinguishes a device context from stale memory, and an imported key (a
 * plaintext key the HPS already held) from a resident one generated in the SDM. */
#define WC_ALTERA_FCS_AES_TAG      0x41414553U /* 'AAES' */
#define WC_ALTERA_FCS_AES_IMPORTED 0
#define WC_ALTERA_FCS_AES_RESIDENT 1

/* Header, one 32 byte aligned key, then the unused MAC field. */
#define WC_ALTERA_FCS_KEYOBJ_SZ \
    (FCS_KEY_DATA_OFFSET + WC_ALTERA_FCS_AES_ALIGN + FCS_KEY_MAC_SZ)

/* The imported key is cached against the material it was built from, because
 * wc_AesSetKey may re-key a context without clearing devCtx and a stale id
 * would silently encrypt under the previous key. */
typedef struct {
    void*  heap;
    word32 tag;                   /* WC_ALTERA_FCS_AES_TAG, else stale memory */
    word32 keyId;                 /* SDM service key slot id */
    int    keyLen;
    int    origin;                /* WC_ALTERA_FCS_AES_IMPORTED | _RESIDENT */
    byte   key[AES_256_KEY_SIZE]; /* imported origin only; zero for resident */
} AlteraAesKey;

/* Return the device context when this Aes holds a valid FCS key, else NULL. */
static AlteraAesKey* wc_AlteraFcs_AesCtx(const Aes* aes)
{
    AlteraAesKey* keyCtx;

    if (aes == NULL || aes->devId != WOLFSSL_ALTERA_FCS_DEVID ||
        aes->devCtx == NULL) {
        return NULL;
    }
    keyCtx = (AlteraAesKey*)aes->devCtx;
    if (keyCtx->tag != WC_ALTERA_FCS_AES_TAG) {
        return NULL;
    }
    return keyCtx;
}

static void wc_AlteraFcs_Put32(byte* out, word32 val)
{
    out[0] = (byte)( val        & 0xFF);
    out[1] = (byte)((val >>  8) & 0xFF);
    out[2] = (byte)((val >> 16) & 0xFF);
    out[3] = (byte)((val >> 24) & 0xFF);
}

/* Encode an unprotected AES key object, the binary layout that fcs_prepare
 * produces. A non-NULL key builds an import object; a NULL key leaves the data
 * region zeroed so fcs_create_service_key generates the key inside the SDM. */
static int wc_AlteraFcs_KeyObject(byte* out, word32 keyId, const byte* key,
                                  int keyLen, word32* outSz)
{
    word32 objSz;
    word32 padded;
    word32 sizeCode;

    if (keyLen == AES_128_KEY_SIZE) {
        sizeCode = FCS_KEY_SIZE_128;
    }
    else if (keyLen == AES_256_KEY_SIZE) {
        sizeCode = FCS_KEY_SIZE_256;
    }
    else {
        /* The key object has no code for 192 bit keys. */
        return CRYPTOCB_UNAVAILABLE;
    }

    padded = (word32)keyLen;
    if ((padded % WC_ALTERA_FCS_AES_ALIGN) != 0) {
        padded += WC_ALTERA_FCS_AES_ALIGN -
                  (padded % WC_ALTERA_FCS_AES_ALIGN);
    }

    XMEMSET(out, 0, WC_ALTERA_FCS_KEYOBJ_SZ);
    wc_AlteraFcs_Put32(out,      FCS_KEY_OBJ_MAGIC);
    wc_AlteraFcs_Put32(out + 8,  keyId);
    wc_AlteraFcs_Put32(out + 20, (sizeCode << 16) |
                                 ((word32)FCS_KEY_TYPE_AES << 24));
    wc_AlteraFcs_Put32(out + 24, FCS_KEY_USAGE_ENC_DEC);
    wc_AlteraFcs_Put32(out + 48, FCS_KEY_DATA_MAGIC);
    if (key != NULL) {
        XMEMCPY(out + FCS_KEY_DATA_OFFSET, key, (word32)keyLen);
    }

    /* The declared size covers the object but not the trailing MAC field. */
    objSz = FCS_KEY_DATA_OFFSET + padded;
    wc_AlteraFcs_Put32(out + 4, ((word32)FCS_KEY_OBJ_VER << 16) |
                                (objSz & 0xFFFF));

    *outSz = objSz + FCS_KEY_MAC_SZ;
    return 0;
}

static int wc_AlteraFcs_KeyRemove(word32 keyId)
{
    return wc_AlteraFcs_RemoveServiceKey(keyId);
}

/* Resolve the device key id for this context, importing on first use. */
static int wc_AlteraFcs_AesKeyId(Aes* aes, word32* keyId)
{
    AlteraAesKey* keyCtx;
    byte          keyObj[WC_ALTERA_FCS_KEYOBJ_SZ];
    byte          status[FCS_KEY_STATUS_SZ];
    FCS_OSAL_UINT statusLen = (FCS_OSAL_UINT)sizeof(status);
    void*         session   = NULL;
    word32        objSz     = 0;
    word32        newId     = 0;
    int           resourceReserved = 0;
    int           ret;

    /* A schedule-less context never completed wc_AesSetKey here, so devKey is
     * not caller key material; importing it would install an all-zero key. */
    if (aes->rounds == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    keyCtx = wc_AlteraFcs_AesCtx(aes);
    if (keyCtx == NULL && aes->devCtx != NULL) {
        /* Not a context this port created; leave it undisturbed. */
        return CRYPTOCB_UNAVAILABLE;
    }
    if (keyCtx != NULL) {
        void* heap = keyCtx->heap;

        if (keyCtx->keyLen == aes->keylen &&
            ConstantCompare(keyCtx->key, (const byte*)aes->devKey,
                            aes->keylen) == 0) {
            *keyId = keyCtx->keyId;
            return 0;
        }
        if (wc_AlteraFcs_UnregisterPending()) {
            return CRYPTOCB_UNAVAILABLE;
        }
        /* Keep one resource reserved across replacement. Otherwise a pending
         * unregister can remove the callback in the instant between dropping
         * the old key and installing the new one. */
        wc_AlteraFcs_ResourceAdd();
        resourceReserved = 1;
        ret = wc_AlteraFcs_KeyRemove(keyCtx->keyId);
        if (ret != 0) {
            wc_AlteraFcs_ResourceRemove();
            return ret;
        }
        wc_AlteraFcs_ResourceRemove();
        ForceZero(keyCtx, sizeof(*keyCtx));
        XFREE(keyCtx, heap, DYNAMIC_TYPE_TMP_BUFFER);
        aes->devCtx = NULL;
    }
    else if (wc_AlteraFcs_UnregisterPending()) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AlteraFcs_KeyIdNew(&newId);
    if (ret == 0) {
        ret = wc_AlteraFcs_KeyObject(keyObj, newId, (const byte*)aes->devKey,
                                     aes->keylen, &objSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_SessionAcquire(&session);
    }
    if (ret == 0) {
        XMEMSET(status, 0, sizeof(status));
        ret = fcs_import_service_key((FCS_OSAL_UUID*)session,
                                     (FCS_OSAL_CHAR*)keyObj,
                                     (FCS_OSAL_INT)objSz,
                                     (FCS_OSAL_CHAR*)status, &statusLen);
        wc_AlteraFcs_SessionRelease();
        if (ret != 0) {
            wc_AlteraFcs_DiscardServiceKey(newId);
            /* Slots are finite, so exhaustion has to mean software rather
             * than a hard failure. */
            WOLFSSL_MSG("Altera FCS AES key import failed");
            ret = CRYPTOCB_UNAVAILABLE;
        }
    }

    if (ret == 0) {
        keyCtx = (AlteraAesKey*)XMALLOC(sizeof(AlteraAesKey), aes->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (keyCtx == NULL) {
            wc_AlteraFcs_DiscardServiceKey(newId);
            ret = MEMORY_E;
        }
        else {
            XMEMSET(keyCtx, 0, sizeof(*keyCtx));
            keyCtx->tag    = WC_ALTERA_FCS_AES_TAG;
            keyCtx->keyId  = newId;
            keyCtx->keyLen = aes->keylen;
            keyCtx->origin = WC_ALTERA_FCS_AES_IMPORTED;
            keyCtx->heap   = aes->heap;
            XMEMCPY(keyCtx->key, aes->devKey, (size_t)aes->keylen);
            aes->devCtx = keyCtx;
            if (!resourceReserved) {
                wc_AlteraFcs_ResourceAdd();
            }
            *keyId = newId;
        }
    }

    if (aes->devCtx == NULL && resourceReserved) {
        wc_AlteraFcs_ResourceRemove();
    }

    ForceZero(keyObj, sizeof(keyObj));
    return ret;
}

/* A request is only offloaded when the device can serve it exactly. */
static int wc_AlteraFcs_AesEligible(const Aes* aes, word32 sz)
{
    if (aes->keylen != AES_128_KEY_SIZE &&
        aes->keylen != AES_256_KEY_SIZE) {
        return 0;
    }
    if (sz < WC_ALTERA_FCS_AES_ALIGN || sz > WC_ALTERA_FCS_MAX_XFER) {
        return 0;
    }
    if ((sz % WC_ALTERA_FCS_AES_ALIGN) != 0) {
        return 0;
    }
    if (sz < WOLFSSL_ALTERA_FCS_AES_MIN) {
        return 0;
    }
    return 1;
}

static int wc_AlteraFcs_AesOp(Aes* aes, byte* out, const byte* in, word32 sz,
                              FCS_OSAL_U32 blockMode, FCS_OSAL_U32 cryptMode)
{
    struct fcs_aes_req req;
    AlteraAesKey* keyCtx;
    byte         iv[WC_AES_BLOCK_SIZE];
    byte*        tmp = NULL;
    void*        session = NULL;
    FCS_OSAL_U32 outLen  = (FCS_OSAL_U32)sz;
    word32       keyId   = 0;
    int          resident;
    int          ret;

    /* A resident key exists only inside the SDM, so a failure cannot fall back
     * to software: there is no plaintext key, and CRYPTOCB_UNAVAILABLE would
     * make wolfSSL encrypt under an uninitialised software schedule. */
    keyCtx   = wc_AlteraFcs_AesCtx(aes);
    resident = (keyCtx != NULL && keyCtx->origin == WC_ALTERA_FCS_AES_RESIDENT);

    /* A software schedule on a resident context means some key setup bypassed
     * the callback. Refuse rather than guess which key the caller meant. */
    if (resident && aes->rounds != 0) {
        WOLFSSL_MSG("Altera FCS resident AES context was re-keyed unsafely");
        return WC_HW_E;
    }

    /* Keep caller input and output untouched until the device confirms a full
     * result. This makes in-place requests safe to retry in software after a
     * transport, session, or device failure. */
    tmp = (byte*)XMALLOC(sz, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return resident ? WC_HW_E : CRYPTOCB_UNAVAILABLE;
    }

    if (resident) {
        keyId = keyCtx->keyId;
    }
    else {
        ret = wc_AlteraFcs_AesKeyId(aes, &keyId);
        if (ret != 0) {
            ret = CRYPTOCB_UNAVAILABLE;
            goto exit;
        }
    }

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        ret = resident ? WC_HW_E : CRYPTOCB_UNAVAILABLE;
        goto exit;
    }

    XMEMCPY(iv, aes->reg, WC_AES_BLOCK_SIZE);

    XMEMSET(&req, 0, sizeof(req));
    req.crypt_mode = cryptMode;
    req.block_mode = blockMode;
    req.iv_source  = FCS_AES_IV_SOURCE_EXTERNAL;
    req.iv         = (FCS_OSAL_CHAR*)iv;
    req.iv_len     = WC_AES_BLOCK_SIZE;
    req.input      = (FCS_OSAL_CHAR*)in;
    req.ip_len     = (FCS_OSAL_U32)sz;
    req.output     = (FCS_OSAL_CHAR*)tmp;
    req.op_len     = &outLen;

    ret = fcs_aes_crypt((FCS_OSAL_UUID*)session, (FCS_OSAL_U32)keyId,
                        WOLFSSL_ALTERA_FCS_CTX_ID, &req);
    if (ret != 0) {
        (void)wc_AlteraFcs_MapError(ret);
        ret = resident ? WC_HW_E : CRYPTOCB_UNAVAILABLE;
    }
    else if (outLen != sz) {
        /* A stale session has been seen to report success with a short
         * result, so the length is checked rather than trusted. */
        WOLFSSL_MSG("Altera FCS AES length mismatch");
        ret = resident ? WC_HW_E : CRYPTOCB_UNAVAILABLE;
    }
    else {
        XMEMCPY(out, tmp, sz);
        wc_AlteraFcs_TestHwMark(resident ? WC_ALTERA_FCS_TEST_HW_AES_RESIDENT
                                         : WC_ALTERA_FCS_TEST_HW_AES);
    }

    wc_AlteraFcs_SessionRelease();
exit:
    ForceZero(tmp, sz);
    XFREE(tmp, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
    ForceZero(iv, sizeof(iv));
    return ret;
}

#ifdef HAVE_AES_CBC
static int wc_AlteraFcs_AesCbc(wc_CryptoInfo* info)
{
    Aes*        aes = info->cipher.aescbc.aes;
    byte*       out = info->cipher.aescbc.out;
    const byte* in  = info->cipher.aescbc.in;
    word32      sz  = info->cipher.aescbc.sz;
    byte        lastIn[WC_AES_BLOCK_SIZE];
    int         ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!wc_AlteraFcs_AesEligible(aes, sz)) {
        return wc_AlteraFcsAes_IsDeviceKey(aes) ? WC_HW_E
                                                : CRYPTOCB_UNAVAILABLE;
    }

    /* Decrypt chains on the last input block, which an in place request would
     * overwrite before it could be read back. */
    XMEMSET(lastIn, 0, sizeof(lastIn));
    if (info->cipher.enc == 0) {
        XMEMCPY(lastIn, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }

    ret = wc_AlteraFcs_AesOp(aes, out, in, sz, FCS_AES_BLOCK_MODE_CBC,
                             info->cipher.enc ? FCS_AES_ENCRYPT
                                              : FCS_AES_DECRYPT);
    if (ret == 0) {
        if (info->cipher.enc) {
            XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE,
                    WC_AES_BLOCK_SIZE);
        }
        else {
            XMEMCPY(aes->reg, lastIn, WC_AES_BLOCK_SIZE);
        }
    }

    ForceZero(lastIn, sizeof(lastIn));
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
/* Advance the big endian counter block by a block count in one bounded pass,
 * equivalent to that many single increments including wraparound. */
static void wc_AlteraFcs_AddCounter(byte* ctr, word32 blocks)
{
    word32 carry = blocks;
    int    i;

    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0 && carry != 0; i--) {
        carry += ctr[i];
        ctr[i] = (byte)(carry & 0xFF);
        carry >>= 8;
    }
}

static int wc_AlteraFcs_AesCtr(wc_CryptoInfo* info)
{
    Aes*        aes = info->cipher.aesctr.aes;
    byte*       out = info->cipher.aesctr.out;
    const byte* in  = info->cipher.aesctr.in;
    word32      sz  = info->cipher.aesctr.sz;
    int         ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Keystream left over from an earlier call cannot be expressed in a whole
     * operation request, so such calls stay in software. */
    if (aes->left != 0) {
        return wc_AlteraFcsAes_IsDeviceKey(aes) ? WC_HW_E
                                                : CRYPTOCB_UNAVAILABLE;
    }
    if (!wc_AlteraFcs_AesEligible(aes, sz)) {
        return wc_AlteraFcsAes_IsDeviceKey(aes) ? WC_HW_E
                                                : CRYPTOCB_UNAVAILABLE;
    }

    /* Counter mode is its own inverse, so the device always encrypts. */
    ret = wc_AlteraFcs_AesOp(aes, out, in, sz, FCS_AES_BLOCK_MODE_CTR,
                             FCS_AES_ENCRYPT);
    if (ret == 0) {
        wc_AlteraFcs_AddCounter((byte*)aes->reg, sz / WC_AES_BLOCK_SIZE);
    }

    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

static void wc_AlteraFcs_AesKeyFree(Aes* aes)
{
    AlteraAesKey* keyCtx;

    if (aes == NULL) {
        return;
    }

    keyCtx = wc_AlteraFcs_AesCtx(aes);
    if (keyCtx != NULL) {
        void* heap = keyCtx->heap;

        if (wc_AlteraFcs_KeyRemove(keyCtx->keyId) != 0) {
            (void)wc_AlteraFcs_OrphanKey(keyCtx->keyId);
        }
        wc_AlteraFcs_ResourceRemove();
        ForceZero(keyCtx, sizeof(*keyCtx));
        XFREE(keyCtx, heap, DYNAMIC_TYPE_TMP_BUFFER);
        aes->devCtx = NULL;
    }
}

/* Release the device key when a context is freed. */
static int wc_AlteraFcs_AesFreeCtx(wc_CryptoInfo* info)
{
    if (info->free.algo != WC_ALGO_TYPE_CIPHER ||
        info->free.type != WC_CIPHER_AES) {
        return CRYPTOCB_UNAVAILABLE;
    }

    wc_AlteraFcs_AesKeyFree((Aes*)info->free.obj);

    /* Decline so wolfSSL still performs its own teardown. */
    return CRYPTOCB_UNAVAILABLE;
}

/* Retire an imported key before the generic AES setup overwrites devKey. A
 * resident key is refused instead: importing a plaintext key over it would
 * silently downgrade the isolation. Free the context first to re-key. */
static int wc_AlteraFcs_AesSetKey(wc_CryptoInfo* info)
{
    Aes* aes;

    if (info->setkey.type != WC_SETKEY_AES) {
        return CRYPTOCB_UNAVAILABLE;
    }

    aes = (Aes*)info->setkey.obj;
    if (wc_AlteraFcsAes_IsDeviceKey(aes)) {
        WOLFSSL_MSG("Altera FCS resident AES key cannot be re-keyed");
        return WC_HW_E;
    }

    wc_AlteraFcs_AesKeyFree(aes);
    return CRYPTOCB_UNAVAILABLE;
}

/* Create a device resident AES key. The key is generated inside the SDM from a
 * zero data key object, so it never exists in HPS memory, and CBC/CTR are then
 * offloaded by handle with no software fallback. Requires
 * wc_AesInit(aes, heap, WOLFSSL_ALTERA_FCS_DEVID) first and an empty devCtx.
 * Do not call wc_AesSetKey on the resulting context. */
int wc_AlteraFcsAes_MakeKey(Aes* aes, int keyBits)
{
    AlteraAesKey* keyCtx = NULL;
    byte          obj[WC_ALTERA_FCS_KEYOBJ_SZ];
    byte          status[FCS_KEY_STATUS_SZ];
    void*         session = NULL;
    word32        objSz = 0;
    word32        newId = 0;
    int           keyLen;
    int           ret;

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyBits == 128) {
        keyLen = AES_128_KEY_SIZE;
    }
    else if (keyBits == 256) {
        keyLen = AES_256_KEY_SIZE;
    }
    else {
        /* The key object has no code for 192 bit keys. */
        return BAD_FUNC_ARG;
    }
    /* The key must route back to this callback or its device slot could never
     * be used or released. */
    if (aes->devId != WOLFSSL_ALTERA_FCS_DEVID) {
        WOLFSSL_MSG("Altera FCS AES key needs the FCS devId");
        return BAD_FUNC_ARG;
    }
    if (!wc_AlteraFcs_AlgoEnabled(WC_ALTERA_FCS_ALGO_AES)) {
        WOLFSSL_MSG("Altera FCS AES callback is not active");
        return WC_HW_E;
    }
    /* Overwriting devCtx would strand the previous slot until the session
     * closes, and there are only about 27 of them. */
    if (aes->devCtx != NULL) {
        WOLFSSL_MSG("Altera FCS AES key already has a device key");
        return BAD_FUNC_ARG;
    }
    /* A context that went through wc_AesSetKey holds a plaintext key and
     * software schedule in HPS memory. Accepting it would report device
     * isolation while the earlier key material is still present, and leave
     * software paths keyed differently than the device. */
    if (aes->keylen != 0 || aes->rounds != 0) {
        WOLFSSL_MSG("Altera FCS AES context already holds a key");
        return BAD_FUNC_ARG;
    }

    /* Past this point a failure is reported as a failure. Returning success
     * without a resident key would defeat the isolation the caller asked for. */
    ret = wc_AlteraFcs_ResourceAcquire();
    if (ret != 0) {
        return WC_HW_E;
    }
    ret = wc_AlteraFcs_KeyIdNew(&newId);
    if (ret == 0) {
        ret = wc_AlteraFcs_KeyObject(obj, newId, NULL, keyLen, &objSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_SessionAcquire(&session);
    }
    if (ret != 0) {
        wc_AlteraFcs_ResourceRemove();
        ForceZero(obj, sizeof(obj));
        return WC_HW_E;
    }

    XMEMSET(status, 0, sizeof(status));
    ret = fcs_create_service_key((FCS_OSAL_UUID*)session,
                                 (FCS_OSAL_CHAR*)obj, (FCS_OSAL_INT)objSz,
                                 (FCS_OSAL_CHAR*)status,
                                 (FCS_OSAL_UINT)sizeof(status));
    wc_AlteraFcs_SessionRelease();
    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS resident AES key creation failed");
        wc_AlteraFcs_DiscardServiceKey(newId);
        wc_AlteraFcs_ResourceRemove();
        ForceZero(obj, sizeof(obj));
        return WC_HW_E;
    }

    keyCtx = (AlteraAesKey*)XMALLOC(sizeof(AlteraAesKey), aes->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (keyCtx == NULL) {
        if (wc_AlteraFcs_KeyRemove(newId) != 0) {
            (void)wc_AlteraFcs_OrphanKey(newId);
        }
        wc_AlteraFcs_ResourceRemove();
        ForceZero(obj, sizeof(obj));
        return MEMORY_E;
    }

    XMEMSET(keyCtx, 0, sizeof(*keyCtx));
    keyCtx->tag    = WC_ALTERA_FCS_AES_TAG;
    keyCtx->keyId  = newId;
    keyCtx->keyLen = keyLen;
    keyCtx->origin = WC_ALTERA_FCS_AES_RESIDENT;
    keyCtx->heap   = aes->heap;
    aes->devCtx = keyCtx;
    /* No plaintext key or software schedule is kept: only the size is recorded
     * so the eligibility check can size device requests. */
    aes->keylen = keyLen;

    ForceZero(obj, sizeof(obj));
    return 0;
}

/* Non-zero when this Aes uses a key generated inside the SDM. */
int wc_AlteraFcsAes_IsDeviceKey(const Aes* aes)
{
    AlteraAesKey* keyCtx = wc_AlteraFcs_AesCtx(aes);

    return (keyCtx != NULL && keyCtx->origin == WC_ALTERA_FCS_AES_RESIDENT);
}

/* Resolve the Aes context of an AES cipher request, reading only union
 * members this build compiled in. Unknown or non-AES types return NULL. */
static Aes* wc_AlteraFcs_AesCipherCtx(const wc_CryptoInfo* info)
{
    Aes* aes = NULL;

    switch (info->cipher.type) {
    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            aes = info->cipher.enc ? info->cipher.aesgcm_enc.aes
                                   : info->cipher.aesgcm_dec.aes;
            break;
    #endif
    #ifdef HAVE_AESCCM
        case WC_CIPHER_AES_CCM:
            aes = info->cipher.enc ? info->cipher.aesccm_enc.aes
                                   : info->cipher.aesccm_dec.aes;
            break;
    #endif
    #if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
        defined(WOLF_CRYPTO_CB_ONLY_AES)
        case WC_CIPHER_AES_ECB:
            aes = info->cipher.aesecb.aes;
            break;
    #endif
    #ifdef WOLFSSL_AES_CFB
        case WC_CIPHER_AES_CFB:
            aes = info->cipher.aescfb.aes;
            break;
    #endif
    #ifdef WOLFSSL_AES_OFB
        case WC_CIPHER_AES_OFB:
            aes = info->cipher.aesofb.aes;
            break;
    #endif
        default:
            break;
    }

    return aes;
}

int wc_AlteraFcs_Aes(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        return wc_AlteraFcs_AesFreeCtx(info);
    }
    if (info->algo_type == WC_ALGO_TYPE_SETKEY) {
        return wc_AlteraFcs_AesSetKey(info);
    }

    switch (info->cipher.type) {
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = wc_AlteraFcs_AesCbc(info);
            break;
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            ret = wc_AlteraFcs_AesCtr(info);
            break;
    #endif
        case WC_CIPHER_AES:
    #ifdef WOLF_CRYPTO_CB_AES_SETKEY
            /* wc_CryptoCb_AesSetKey arrives as this cipher type. aes.c clears
             * devCtx on any error it returns, so the resident slot must be
             * released here rather than leaked; the context is then unusable
             * until a new device key is made. */
            if (wc_AlteraFcsAes_IsDeviceKey(info->cipher.aessetkey.aes)) {
                WOLFSSL_MSG("Altera FCS resident AES key cannot be re-keyed");
                wc_AlteraFcs_AesKeyFree(info->cipher.aessetkey.aes);
                ret = WC_HW_E;
            }
    #endif
            break;
        default:
            /* A resident key has no software schedule, so a mode the device
             * cannot serve must fail rather than fall back. */
            if (wc_AlteraFcsAes_IsDeviceKey(wc_AlteraFcs_AesCipherCtx(info))) {
                WOLFSSL_MSG("Altera FCS resident AES key: unsupported mode");
                ret = WC_HW_E;
            }
            break;
    }

    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS && WOLFSSL_ALTERA_FCS_AES */
