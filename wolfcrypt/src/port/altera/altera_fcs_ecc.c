/* altera_fcs_ecc.c
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

/* ECDSA on the Agilex 5 Secure Device Manager.
 *
 * This is the step where key isolation becomes real. A key made with
 * wc_AlteraFcsEcc_MakeSigningKey() or _MakeExchangeKey() is generated inside
 * the device; only its public point is returned, and the private scalar never
 * appears in HPS memory. Export is possible but yields a wrapped blob, not
 * plaintext. wc_ecc_make_key_ex() deliberately stays in software even on the
 * FCS devId, because an SDM key object must commit to signing or exchange
 * usage at creation and that API cannot express which is wanted.
 *
 * Only signing is offloaded. Verification uses nothing but the public key, so
 * it gains no security from the device and is much faster in software, and the
 * device verify command does not work on this firmware: it reports the same
 * failure for a valid signature as for a corrupt one.
 *
 * Sign has an asymmetry with the rest of the port that matters. Everywhere else
 * CRYPTOCB_UNAVAILABLE means fall back to software, which is safe. Here the
 * private key exists only inside the device, so a failure must be reported as a
 * failure. Declining would hand wolfSSL a key with no private scalar.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/port/altera/altera_fcs.h>

#if defined(WOLFSSL_ALTERA_FCS) && defined(WC_ALTERA_FCS_HAVE_ECC)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <libfcs.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLF_CRYPTO_CB_FREE
    #error "WOLFSSL_ALTERA_FCS_ECC requires WOLF_CRYPTO_CB_FREE to release keys"
#endif
#define FCS_KEY_OBJ_MAGIC     0x43736B4FU
#define FCS_KEY_DATA_MAGIC    0x43736B64U
#define FCS_KEY_OBJ_VER       1
#define FCS_KEY_TYPE_ECC_NIST 3
#define FCS_KEY_TYPE_ECC_BP   4
#define FCS_KEY_MAC_SZ        48
#define FCS_KEY_DATA_OFFSET   56
#define FCS_KEY_ALIGN         32
#define FCS_KEY_STATUS_SZ     64

/* Sign and Verify are exclusive with Exchange for an ECC key object, so an
 * ECDSA key cannot also serve ECDH. */
#define FCS_KEY_USAGE_SIGN_VERIFY 0xC
#define FCS_KEY_USAGE_EXCHANGE    0x10

/* Largest object: 56 byte header, 64 byte padded P-384 scalar, 48 byte MAC. */
#define WC_ALTERA_FCS_ECCOBJ_SZ (FCS_KEY_DATA_OFFSET + 64 + FCS_KEY_MAC_SZ)

#define WC_ALTERA_FCS_ECC_MAX_SZ 48

/* devCtx is a generic void* that any backend may use, so the context carries a
 * tag and the devId it was created for. Without them IsDeviceKey() would report
 * residency for a foreign backend's context, and a key made on an unregistered
 * devId would strand its device slot. */
#define WC_ALTERA_FCS_ECC_TAG 0x41454343U

typedef struct {
    word32 tag;
    word32 keyId;
    word32 usage;
    int    curveId;
    int    keySz;
    int    devId;
    void*  heap;
} AlteraEccKey;

/* The Agilex 5 kernel driver copies the entire ECDSA response into the address
 * supplied for dst_len instead of copying sizeof(FCS_OSAL_U32). Supply a
 * response-sized, aligned sink. The first word is the input capacity, but its
 * returned contents cannot be interpreted as a length with that driver. */
typedef union {
    FCS_OSAL_U32 capacity;
    byte         response[2 * WC_ALTERA_FCS_ECC_MAX_SZ];
} AlteraEccLengthSink;

static AlteraEccKey* wc_AlteraFcs_EccCtx(const ecc_key* key)
{
    AlteraEccKey* keyCtx;

    if (key == NULL || key->devId != WOLFSSL_ALTERA_FCS_DEVID ||
        key->devCtx == NULL) {
        return NULL;
    }
    keyCtx = (AlteraEccKey*)key->devCtx;
    if (keyCtx->tag != WC_ALTERA_FCS_ECC_TAG ||
        keyCtx->devId != key->devId) {
        return NULL;
    }
    return keyCtx;
}

#if (defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)) || \
    defined(HAVE_ECC_DHE)
static void wc_AlteraFcs_Put32(byte* out, word32 val)
{
    out[0] = (byte)( val        & 0xFF);
    out[1] = (byte)((val >>  8) & 0xFF);
    out[2] = (byte)((val >> 16) & 0xFF);
    out[3] = (byte)((val >> 24) & 0xFF);
}

/* Map a wolfSSL curve to the device curve code and scalar size. */
static int wc_AlteraFcs_EccCurve(int curveId, FCS_OSAL_U32* fcsCurve,
                                 int* keySz, word32* keyType)
{
    int ret = 0;

    switch (curveId) {
        case ECC_SECP256R1:
            *fcsCurve = FCS_ECC_CURVE_NIST_P256;
            *keySz    = 32;
            *keyType  = FCS_KEY_TYPE_ECC_NIST;
            break;
        case ECC_SECP384R1:
            *fcsCurve = FCS_ECC_CURVE_NIST_P384;
            *keySz    = 48;
            *keyType  = FCS_KEY_TYPE_ECC_NIST;
            break;
    #ifdef HAVE_ECC_BRAINPOOL
        case ECC_BRAINPOOLP256R1:
            *fcsCurve = FCS_ECC_CURVE_BRAINPOOL_P256;
            *keySz    = 32;
            *keyType  = FCS_KEY_TYPE_ECC_BP;
            break;
        case ECC_BRAINPOOLP384R1:
            *fcsCurve = FCS_ECC_CURVE_BRAINPOOL_P384;
            *keySz    = 48;
            *keyType  = FCS_KEY_TYPE_ECC_BP;
            break;
    #endif
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

/* Build the key object. The data region must be declared even when the device
 * generates the key: an object without it is refused with status 0x80. */
static int wc_AlteraFcs_EccKeyObject(byte* out, word32 keyId, word32 keyType,
                                     int keySz, word32 usage, word32* outSz)
{
    word32 padded;
    word32 objSz;
    word32 sizeCode;

    if (keySz == 32) {
        sizeCode = 2;
    }
    else if (keySz == 48) {
        sizeCode = 3;
    }
    else {
        return CRYPTOCB_UNAVAILABLE;
    }

    padded = (word32)keySz;
    if ((padded % FCS_KEY_ALIGN) != 0) {
        padded += FCS_KEY_ALIGN - (padded % FCS_KEY_ALIGN);
    }

    XMEMSET(out, 0, WC_ALTERA_FCS_ECCOBJ_SZ);
    wc_AlteraFcs_Put32(out,      FCS_KEY_OBJ_MAGIC);
    wc_AlteraFcs_Put32(out + 8,  keyId);
    wc_AlteraFcs_Put32(out + 20, (sizeCode << 16) | (keyType << 24));
    wc_AlteraFcs_Put32(out + 24, usage);
    wc_AlteraFcs_Put32(out + 48, FCS_KEY_DATA_MAGIC);

    objSz = FCS_KEY_DATA_OFFSET + padded;
    wc_AlteraFcs_Put32(out + 4, ((word32)FCS_KEY_OBJ_VER << 16) |
                                (objSz & 0xFFFF));

    *outSz = objSz + FCS_KEY_MAC_SZ;
    return 0;
}
#endif

static int wc_AlteraFcs_EccKeyRemove(word32 keyId)
{
    return wc_AlteraFcs_RemoveServiceKey(keyId);
}

static void wc_AlteraFcs_EccCtxFree(ecc_key* key)
{
    AlteraEccKey* keyCtx;
    void*         heap;

    if (key == NULL) {
        return;
    }
    keyCtx = wc_AlteraFcs_EccCtx(key);
    if (keyCtx == NULL) {
        return;
    }

    heap = keyCtx->heap;
    if (wc_AlteraFcs_EccKeyRemove(keyCtx->keyId) != 0) {
        (void)wc_AlteraFcs_OrphanKey(keyCtx->keyId);
    }
    wc_AlteraFcs_ResourceRemove();
    ForceZero(keyCtx, sizeof(*keyCtx));
    XFREE(keyCtx, heap, DYNAMIC_TYPE_TMP_BUFFER);
    key->devCtx = NULL;
}

/* Generate the key inside the device and keep only the public point here. */
#if (defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)) || \
    defined(HAVE_ECC_DHE)
static int wc_AlteraFcs_EccCreate(ecc_key* key, int curveId, int sizeHint,
                                  word32 usage)
{
    AlteraEccKey* keyCtx  = NULL;
    void*         session = NULL;
    byte          obj[WC_ALTERA_FCS_ECCOBJ_SZ];
    byte          status[FCS_KEY_STATUS_SZ];
    byte          pub[2 * WC_ALTERA_FCS_ECC_MAX_SZ];
    FCS_OSAL_U32  pubLen   = (FCS_OSAL_U32)sizeof(pub);
    FCS_OSAL_U32  fcsCurve = 0;
    word32        keyType  = 0;
    word32        objSz    = 0;
    word32        newId    = 0;
    int           keySz    = 0;
    int           devId;
    int           ret;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    /* The key must route back to this callback, otherwise sign and ECDH would
     * bypass the port and the allocated device slot could never be used or
     * released. */
    if (key->devId != WOLFSSL_ALTERA_FCS_DEVID) {
        WOLFSSL_MSG("Altera FCS ECC key needs the FCS devId");
        return BAD_FUNC_ARG;
    }
    if (!wc_AlteraFcs_AlgoEnabled(WC_ALTERA_FCS_ALGO_ECC)) {
        WOLFSSL_MSG("Altera FCS ECC callback is not active");
        return WC_HW_E;
    }
    /* Overwriting devCtx would strand the previous slot until the session
     * closes, and there are only about 27 of them. */
    if (key->devCtx != NULL) {
        WOLFSSL_MSG("Altera FCS ECC key already has a device key");
        return BAD_FUNC_ARG;
    }

    if (curveId == ECC_CURVE_DEF) {
        if (sizeHint == 32) {
            curveId = ECC_SECP256R1;
        }
        else if (sizeHint == 48) {
            curveId = ECC_SECP384R1;
        }
    }

    ret = wc_AlteraFcs_EccCurve(curveId, &fcsCurve, &keySz, &keyType);
    if (ret != 0) {
        return ret;
    }
    if (sizeHint != 0 && sizeHint != keySz) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Past this point a failure must be reported as a failure. Returning
     * CRYPTOCB_UNAVAILABLE would make wolfSSL quietly generate a software key
     * instead, so a caller that asked for a device resident key would receive
     * one whose private scalar sits in HPS memory, with nothing to indicate the
     * isolation it asked for was not delivered. Only an unsupported curve,
     * handled above, may decline. */
    ret = wc_AlteraFcs_ResourceAcquire();
    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS ECC keygen blocked by unregister");
        return WC_HW_E;
    }
    ret = wc_AlteraFcs_KeyIdNew(&newId);
    if (ret == 0) {
        ret = wc_AlteraFcs_EccKeyObject(obj, newId, keyType, keySz, usage,
                                        &objSz);
    }
    if (ret == 0) {
        ret = wc_AlteraFcs_SessionAcquire(&session);
    }
    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS ECC keygen cannot reach the device");
        wc_AlteraFcs_ResourceRemove();
        return WC_HW_E;
    }

    XMEMSET(status, 0, sizeof(status));
    ret = fcs_create_service_key((FCS_OSAL_UUID*)session,
                                 (FCS_OSAL_CHAR*)obj, (FCS_OSAL_INT)objSz,
                                 (FCS_OSAL_CHAR*)status,
                                 (FCS_OSAL_UINT)sizeof(status));
    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS ECC key creation failed");
        wc_AlteraFcs_SessionRelease();
        wc_AlteraFcs_DiscardServiceKey(newId);
        wc_AlteraFcs_ResourceRemove();
        return WC_HW_E;
    }

    ret = fcs_ecdsa_get_pub_key((FCS_OSAL_UUID*)session,
                                WOLFSSL_ALTERA_FCS_CTX_ID,
                                (FCS_OSAL_U32)newId, fcsCurve,
                                (FCS_OSAL_CHAR*)pub, &pubLen);
    wc_AlteraFcs_SessionRelease();

    if (ret != 0 || pubLen != (FCS_OSAL_U32)(2 * keySz)) {
        WOLFSSL_MSG("Altera FCS ECC public key retrieval failed");
        if (wc_AlteraFcs_EccKeyRemove(newId) != 0) {
            (void)wc_AlteraFcs_OrphanKey(newId);
        }
        wc_AlteraFcs_ResourceRemove();
        return WC_HW_E;
    }

    /* The device returns the point as raw X||Y with no leading 0x04. Importing
     * it resets the device fields, so they are restored afterwards. */
    devId = key->devId;
    ret = wc_ecc_import_unsigned(key, pub, pub + keySz, NULL, curveId);
    key->devId = devId;
    if (ret != 0) {
        if (wc_AlteraFcs_EccKeyRemove(newId) != 0) {
            (void)wc_AlteraFcs_OrphanKey(newId);
        }
        wc_AlteraFcs_ResourceRemove();
        return ret;
    }

    keyCtx = (AlteraEccKey*)XMALLOC(sizeof(AlteraEccKey), key->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (keyCtx == NULL) {
        if (wc_AlteraFcs_EccKeyRemove(newId) != 0) {
            (void)wc_AlteraFcs_OrphanKey(newId);
        }
        wc_AlteraFcs_ResourceRemove();
        return MEMORY_E;
    }

    keyCtx->tag     = WC_ALTERA_FCS_ECC_TAG;
    keyCtx->devId   = key->devId;
    keyCtx->keyId   = newId;
    keyCtx->usage   = usage;
    keyCtx->curveId = curveId;
    keyCtx->keySz   = keySz;
    keyCtx->heap    = key->heap;
    key->devCtx = keyCtx;

    return 0;
}
#endif

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
int wc_AlteraFcsEcc_MakeSigningKey(ecc_key* key, int curveId)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    return wc_AlteraFcs_EccCreate(key, curveId, 0,
                                  FCS_KEY_USAGE_SIGN_VERIFY);
}
#endif

#ifdef HAVE_ECC_DHE
int wc_AlteraFcsEcc_MakeExchangeKey(ecc_key* key, int curveId)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    return wc_AlteraFcs_EccCreate(key, curveId, 0, FCS_KEY_USAGE_EXCHANGE);
}
#endif

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
static int wc_AlteraFcs_EccCustomNonce(const ecc_key* key)
{
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic) {
        return 1;
    }
#endif
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
    #ifndef WOLFSSL_NO_MALLOC
    if (key->sign_k != NULL) {
        return 1;
    }
    #else
    if (key->sign_k_set) {
        return 1;
    }
    #endif
#endif
    (void)key;
    return 0;
}

static int wc_AlteraFcs_EccSign(wc_CryptoInfo* info)
{
    AlteraEccKey*      keyCtx;
    struct fcs_ecdsa_req req;
    ecc_key*     key     = info->pk.eccsign.key;
    void*        session = NULL;
    byte         sig[2 * WC_ALTERA_FCS_ECC_MAX_SZ];
    byte         digest[WC_ALTERA_FCS_ECC_MAX_SZ];
    AlteraEccLengthSink sigLen;
    FCS_OSAL_U32 fcsCurve = 0;
    word32       keyType  = 0;
    word32       outCapacity;
    int          keySz    = 0;
    int          verified = 0;
    int          ret;

    if (key == NULL || info->pk.eccsign.out == NULL ||
        info->pk.eccsign.outlen == NULL) {
        return BAD_FUNC_ARG;
    }
    outCapacity = *info->pk.eccsign.outlen;

    /* A key without our device state is an ordinary software key. */
    keyCtx = wc_AlteraFcs_EccCtx(key);
    if (keyCtx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* The SDM chooses its own nonce. A device key cannot fall back to software
     * to honor deterministic ECDSA or a caller-supplied k value. */
    if (wc_AlteraFcs_EccCustomNonce(key)) {
        WOLFSSL_MSG("Altera FCS ECDSA custom nonce unsupported");
        return WC_HW_E;
    }

    ret = wc_AlteraFcs_EccCurve(keyCtx->curveId, &fcsCurve, &keySz, &keyType);
    if (ret != 0) {
        return ret;
    }

    if (info->pk.eccsign.in == NULL || info->pk.eccsign.inlen == 0) {
        return BAD_FUNC_ARG;
    }

#ifndef WC_ALLOW_ECC_ZERO_HASH
    /* Returning from the callback skips the software body of
     * wc_ecc_sign_hash_ex(), so its all-zero digest rejection is repeated
     * here rather than silently signing what the API would refuse. */
    {
        word32 z;
        byte   acc = 0;

        for (z = 0; z < info->pk.eccsign.inlen; z++) {
            acc |= info->pk.eccsign.in[z];
        }
        if (acc == 0) {
            return ECC_BAD_ARG_E;
        }
    }
#endif

    /* The device signs the value handed to it and does not hash again, so the
     * digest is normalised to the curve size the way wc_ecc_sign_hash does:
     * longer digests keep their leftmost bytes, shorter ones are left padded. */
    XMEMSET(digest, 0, sizeof(digest));
    if (info->pk.eccsign.inlen >= (word32)keySz) {
        XMEMCPY(digest, info->pk.eccsign.in, (word32)keySz);
    }
    else {
        XMEMCPY(digest + ((word32)keySz - info->pk.eccsign.inlen),
                info->pk.eccsign.in, info->pk.eccsign.inlen);
    }

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        /* The private key exists only in the device, so this cannot be
         * softened into a fallback. */
        ForceZero(digest, sizeof(digest));
        return WC_HW_E;
    }

    XMEMSET(&req, 0, sizeof(req));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(&sigLen, 0, sizeof(sigLen));
    sigLen.capacity = (FCS_OSAL_U32)sizeof(sig);
    req.ecc_curve = fcsCurve;
    req.src       = (FCS_OSAL_CHAR*)digest;
    req.src_len   = (FCS_OSAL_U32)keySz;
    req.dst       = (FCS_OSAL_CHAR*)sig;
    req.dst_len   = &sigLen.capacity;

    ret = fcs_ecdsa_hash_sign((FCS_OSAL_UUID*)session,
                              WOLFSSL_ALTERA_FCS_CTX_ID,
                              (FCS_OSAL_U32)keyCtx->keyId, &req);
    wc_AlteraFcs_SessionRelease();

    ForceZero(digest, sizeof(digest));

    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS ECDSA sign failed");
        ForceZero(&sigLen, sizeof(sigLen));
        return WC_HW_E;
    }
    /* The device returns raw r||s; wolfSSL callers expect DER. */
    ret = wc_ecc_rs_raw_to_sig(sig, (word32)keySz, sig + keySz,
                               (word32)keySz, info->pk.eccsign.out,
                               info->pk.eccsign.outlen);
    if (ret == 0) {
        /* The Agilex 5 Linux driver does not return a trustworthy response
         * length. Verify against the device key's public point before any
         * possibly short response is exposed to the caller. ECDSA verify is
         * deliberately declined by this callback and completes in software. */
        ret = wc_ecc_verify_hash(info->pk.eccsign.out,
                                 *info->pk.eccsign.outlen,
                                 info->pk.eccsign.in,
                                 info->pk.eccsign.inlen, &verified, key);
        if (ret == 0 && verified != 1) {
            ret = WC_HW_E;
        }
    }
    if (ret != 0) {
        ForceZero(info->pk.eccsign.out, outCapacity);
        *info->pk.eccsign.outlen = 0;
    }
    ForceZero(sig, sizeof(sig));
    ForceZero(&sigLen, sizeof(sigLen));
    return ret;
}
#endif /* HAVE_ECC_SIGN && HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_DHE
/* Shared secret from a device resident private key and a peer public point. */
static int wc_AlteraFcs_Ecdh(wc_CryptoInfo* info)
{
    AlteraEccKey*       keyCtx;
    struct fcs_ecdh_req req;
    ecc_key*     priv    = info->pk.ecdh.private_key;
    ecc_key*     pub     = info->pk.ecdh.public_key;
    void*        session = NULL;
    byte         peer[2 * WC_ALTERA_FCS_ECC_MAX_SZ];
    byte         secret[2 * WC_ALTERA_FCS_ECC_MAX_SZ];
    word32       xLen, yLen;
    FCS_OSAL_U32 secretLen;
    FCS_OSAL_U32 fcsCurve = 0;
    word32       keyType  = 0;
    int          keySz    = 0;
    int          ret;

    if (priv == NULL || pub == NULL || info->pk.ecdh.out == NULL ||
        info->pk.ecdh.outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Not a device key, so software owns it. */
    keyCtx = wc_AlteraFcs_EccCtx(priv);
    if (keyCtx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* A signing key cannot perform key exchange: the two usages are exclusive
     * in the key object, and the private scalar is not available here to fall
     * back with, so this has to be reported rather than declined. */
    if (keyCtx->usage != FCS_KEY_USAGE_EXCHANGE) {
        WOLFSSL_MSG("Altera FCS ECDH needs a key made for exchange usage");
        return WC_HW_E;
    }

    ret = wc_AlteraFcs_EccCurve(keyCtx->curveId, &fcsCurve, &keySz, &keyType);
    if (ret != 0) {
        return WC_HW_E;
    }
    if (priv->dp == NULL || pub->dp == NULL ||
        priv->dp->id != keyCtx->curveId ||
        pub->dp->id != keyCtx->curveId) {
        return ECC_BAD_ARG_E;
    }
    ret = wc_ecc_check_key(pub);
    if (ret != 0) {
        return ret;
    }

    /* The device wants the peer point as raw X||Y with no leading 0x04. */
    xLen = (word32)keySz;
    yLen = (word32)keySz;
    ret = wc_ecc_export_public_raw(pub, peer, &xLen, peer + keySz, &yLen);
    if (ret != 0) {
        return ret;
    }
    if (xLen != (word32)keySz || yLen != (word32)keySz) {
        return WC_HW_E;
    }

    if (*info->pk.ecdh.outlen < (word32)keySz) {
        *info->pk.ecdh.outlen = (word32)keySz;
        return BUFFER_E;
    }

    /* The device returns the whole shared point, so it writes 2 * keySz even
     * though the secret is the X coordinate alone. Writing straight into the
     * caller buffer would overrun it, so the result lands here first. */
    XMEMSET(secret, 0, sizeof(secret));
    secretLen = (FCS_OSAL_U32)sizeof(secret);

    ret = wc_AlteraFcs_SessionAcquire(&session);
    if (ret != 0) {
        return WC_HW_E;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.ecc_curve        = fcsCurve;
    req.pubkey           = (FCS_OSAL_CHAR*)peer;
    req.pubkey_len       = (FCS_OSAL_U32)(2 * keySz);
    req.shared_secret    = (FCS_OSAL_CHAR*)secret;
    req.shared_secret_len = &secretLen;

    ret = fcs_ecdh_request((FCS_OSAL_UUID*)session,
                           (FCS_OSAL_U32)keyCtx->keyId,
                           WOLFSSL_ALTERA_FCS_CTX_ID, &req);
    wc_AlteraFcs_SessionRelease();

    if (ret != 0) {
        WOLFSSL_MSG("Altera FCS ECDH failed");
        ForceZero(peer, sizeof(peer));
        ForceZero(secret, sizeof(secret));
        return WC_HW_E;
    }
    if (secretLen != (FCS_OSAL_U32)(2 * keySz)) {
        WOLFSSL_MSG("Altera FCS ECDH secret length unexpected");
        ForceZero(peer, sizeof(peer));
        ForceZero(secret, sizeof(secret));
        return WC_HW_E;
    }

    XMEMCPY(info->pk.ecdh.out, secret, (word32)keySz);
    *info->pk.ecdh.outlen = (word32)keySz;
    ForceZero(peer, sizeof(peer));
    ForceZero(secret, sizeof(secret));
    return 0;
}
#endif /* HAVE_ECC_DHE */

/* Lets an application confirm that a key really is device resident rather than
 * trusting that it asked for the right devId. */
int wc_AlteraFcsEcc_IsDeviceKey(const ecc_key* key)
{
    return (wc_AlteraFcs_EccCtx(key) != NULL);
}

int wc_AlteraFcs_Ecc(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        /* The type must be checked, not just the algo: wc_FreeRsaKey also frees
         * under WC_ALGO_TYPE_PK and passes an RsaKey, so treating every PK free
         * as an ecc_key reads devCtx from the wrong offset and frees garbage. */
        if (info->free.algo == WC_ALGO_TYPE_PK &&
            info->free.type == WC_PK_TYPE_EC_KEYGEN &&
            info->free.obj != NULL) {
            wc_AlteraFcs_EccCtxFree((ecc_key*)info->free.obj);
        }
        /* Decline so wolfSSL still runs its own teardown. */
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.type) {
    #ifdef HAVE_ECC_DHE
        /* Key generation is deliberately NOT offloaded here. An SDM key object
         * must commit to Sign/Verify or Exchange usage at creation and the two
         * are mutually exclusive, but wc_ecc_make_key_ex cannot express which
         * is wanted, and callers routinely use one key for both ECDSA and ECDH.
         * Silently creating a signing key would break the later exchange. Key
         * slots are also scarce, so device residency is opt in through
         * wc_AlteraFcsEcc_MakeSigningKey and _MakeExchangeKey. */
        case WC_PK_TYPE_ECDH:
            ret = wc_AlteraFcs_Ecdh(info);
            break;
    #endif
    #if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
        case WC_PK_TYPE_ECDSA_SIGN:
            ret = wc_AlteraFcs_EccSign(info);
            break;
    #endif
        /* Verification needs only the public key, so it is left to software,
         * which is faster and avoids the single device session. The device
         * verify command is also unusable on this firmware: it reports the
         * same error for a valid signature as for a corrupt one. */
        default:
            break;
    }

    return ret;
}

#endif /* WOLFSSL_ALTERA_FCS && WC_ALTERA_FCS_HAVE_ECC */
