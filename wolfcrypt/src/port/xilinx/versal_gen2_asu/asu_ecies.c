/* asu_ecies.c
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

/* ECIES on the ASU. The ASU does the ECDH, the key derivation and the AES-GCM
 * in one command. Only the default GCM setup is offloaded. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
/* asu_ecies.h computes WC_ASU_ECIES_ENABLED from resolved feature macros. */
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecies.h>

#ifdef WC_ASU_ECIES_ENABLED

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/random.h>

/* The ASU takes raw x and y only, so a compressed key always runs in software.
 * Define WOLFSSL_VERSAL_GEN2_ASU_NO_COMP_KEY_WARN to silence this. */
#if defined(HAVE_COMP_KEY) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_COMP_KEY_WARN)
    #warning "ASU ECIES cannot offload compressed keys, software handles them"
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_ecies.h"
#include "xasu_eciesinfo.h"
#include "xasu_eccinfo.h"
#include "xasu_shainfo.h"
#include "xasu_aesinfo.h"
#include "xstatus.h"

/* Use the enum names so renumbering in ecc.h cannot pick the wrong scheme. */
#define WC_ASU_ECIES_AES128_GCM   ecAES_128_GCM
#define WC_ASU_ECIES_AES256_GCM   ecAES_256_GCM
#define WC_ASU_ECIES_HKDF_SHA256  ecHKDF_SHA256
#define WC_ASU_ECIES_NONCE_SZ     12
#define WC_ASU_ECIES_TAG_SZ       16

/* Biggest curve we support here, P-384 at 48 bytes. */
#define WC_ASU_ECIES_MAX_KEYLEN   XASU_ECC_P384_SIZE_IN_BYTES

/* One ASU ECIES request. The fixed size fields live on the heap so the ASU
 * can reach them. The message stays in the caller buffers. */
typedef struct {
    XAsu_EciesParams params;
    /* peer public point for encrypt, or our private key for decrypt */
    byte rxKey[2U * WC_ASU_ECIES_MAX_KEYLEN];
    /* Keep txKey on its own cache line and round the struct size up. */
    /* ephemeral pub (enc out/dec in) */
    WC_ASU_ALIGN64 byte txKey[2U * WC_ASU_ECIES_MAX_KEYLEN];
    byte iv[WC_ASU_ECIES_NONCE_SZ];            /* GCM nonce */
    byte tag[WC_ASU_ECIES_TAG_SZ];             /* GCM tag */
} AsuEciesReq;

/* Holds both pointers so they stay together. Use .req, free .raw. */
typedef struct {
    void*        raw;   /* what XMALLOC gave back, free this one */
    AsuEciesReq* req;   /* the aligned request the operation uses */
} AsuEciesMem;

/* Align the request to 64 bytes so txKey lands on a cache line.
 * Returns 0 or MEMORY_E. */
static int wc_AsuEciesReqNew(AsuEciesMem* mem)
{
    if (mem == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef WC_ASU_DISABLE_CACHE
    /* Cache is off, so a plain malloc is fine. */
    mem->raw = XMALLOC(sizeof(AsuEciesReq), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    mem->raw = XMALLOC(sizeof(AsuEciesReq) + 63U, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
#endif
    if (mem->raw == NULL) {
        mem->req = NULL;
        return MEMORY_E;
    }
#ifdef WC_ASU_DISABLE_CACHE
    mem->req = (AsuEciesReq*)mem->raw;
#else
    mem->req = (AsuEciesReq*)(void*)(((UINTPTR)mem->raw + 63U) & ~(UINTPTR)63U);
#endif
    return 0;
}

/* Wipe the request since it may hold the private key and message, then free
 * it. */
static void wc_AsuEciesReqFree(AsuEciesMem* mem)
{
    if (mem == NULL || mem->req == NULL) {
        return;
    }
    ForceZero(mem->req, sizeof(*mem->req));
    wc_AsuCacheFlush(mem->req, sizeof(*mem->req));
    XFREE(mem->raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Queue one ASU ECIES operation. IsEncrypt picks which one. */
typedef struct {
    AsuEciesReq* req;
    int          isEncrypt;
} AsuEciesSubmitCtx;

static int wc_AsuEciesSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuEciesSubmitCtx* sc = (AsuEciesSubmitCtx*)ctx;

    if (params == NULL || sc == NULL || sc->req == NULL) {
        return XST_FAILURE;
    }
    if (sc->isEncrypt != 0) {
        return XAsu_EciesEncrypt(params, &sc->req->params);
    }
    return XAsu_EciesDecrypt(params, &sc->req->params);
}

/* Turn the wolfSSL curve id into an ASU curve type and size. Curves we do not
 * support return an error so wolfSSL uses software. */
static int wc_AsuEciesCurve(ecc_key* key, u8* curveType, u8* keyLen)
{
    if (key == NULL || curveType == NULL || keyLen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (key->dp == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (key->dp->id) {
        case ECC_SECP256R1:
            *curveType = (u8)XASU_ECC_NIST_P256;
            *keyLen    = (u8)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_SECP384R1:
            *curveType = (u8)XASU_ECC_NIST_P384;
            *keyLen    = (u8)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#ifdef HAVE_ECC_BRAINPOOL
        case ECC_BRAINPOOLP256R1:
            *curveType = (u8)XASU_ECC_BRAINPOOL_P256;
            *keyLen    = (u8)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP384R1:
            *curveType = (u8)XASU_ECC_BRAINPOOL_P384;
            *keyLen    = (u8)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
    /* Reject a curve whose size does not match, so we never send the wrong
     * number of bytes. */
    if ((u32)key->dp->size != (u32)*keyLen) {
        return CRYPTOCB_UNAVAILABLE;
    }
    return 0;
}

/* Read the ECIES settings. Only AES-GCM with HKDF-SHA256 is offloaded. */
static int wc_AsuEciesScheme(ecEncCtx* ctx, u8* aesKeySize, u8* shaType,
    u8* shaMode)
{
    byte encAlgo = 0;
    byte kdfAlgo = 0;

    if (ctx == NULL || aesKeySize == NULL || shaType == NULL ||
        shaMode == NULL) {
        return BAD_FUNC_ARG;
    }
    if (wc_ecc_ctx_get_algo(ctx, &encAlgo, &kdfAlgo, NULL) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (kdfAlgo != WC_ASU_ECIES_HKDF_SHA256) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (encAlgo == WC_ASU_ECIES_AES128_GCM) {
        *aesKeySize = (u8)XASU_AES_KEY_SIZE_128_BITS;
    }
    else if (encAlgo == WC_ASU_ECIES_AES256_GCM) {
        *aesKeySize = (u8)XASU_AES_KEY_SIZE_256_BITS;
    }
    else {
        return CRYPTOCB_UNAVAILABLE;
    }
    *shaType = (u8)XASU_SHA2_TYPE;
    *shaMode = (u8)XASU_SHA_MODE_256;
    return 0;
}

/* Copy a public point out as Qx||Qy, fixed width, big end first. */
static int wc_AsuEciesExportPub(ecc_key* key, byte* out, u8 keyLen)
{
    if (mp_to_unsigned_bin_len(key->pubkey.x, out, (int)keyLen) < 0) {
        return WC_HW_E;
    }
    if (mp_to_unsigned_bin_len(key->pubkey.y, out + keyLen, (int)keyLen) < 0) {
        return WC_HW_E;
    }
    return 0;
}

/* Fill in the settings that encrypt and decrypt both need. */
static void wc_AsuEciesFillParams(XAsu_EciesParams* p, ecEncCtx* ctx,
    u8 curveType, u8 keyLen, u8 aesKeySize, u8 shaType, u8 shaMode,
    word32 dataLen)
{
    word32      saltLen = 0;
    word32      infoLen = 0;
    const byte* salt = NULL;
    const byte* info = NULL;

    (void)wc_ecc_ctx_get_kdf_salt(ctx, &salt, &saltLen);
    (void)wc_ecc_ctx_get_info(ctx, &info, &infoLen);

    p->EccCurveType = curveType;
    p->EccKeyLength = keyLen;
    p->ShaType      = shaType;
    p->ShaMode      = shaMode;
    p->AesKeySize   = aesKeySize;
    p->IvLength     = (u8)WC_ASU_ECIES_NONCE_SZ;
    p->MacLength    = (u8)WC_ASU_ECIES_TAG_SZ;
    p->DataLength   = dataLen;
    p->SaltAddr     = (u64)(UINTPTR)salt;
    p->SaltLen      = saltLen;
    p->ContextAddr  = (u64)(UINTPTR)info;
    p->ContextLen   = infoLen;
}

/* ECIES encrypt. The ASU makes its own throwaway key pair, derives the AES
 * key and encrypts. */
static int wc_AsuEciesEncrypt(wc_CryptoInfo* info)
{
    AsuEciesMem  mem;
    AsuEciesSubmitCtx sc;
    /* throwaway key, the private part is not used */
    ecc_key* privKey = info->pk.eciesencrypt.privKey;
    ecc_key* pubKey = info->pk.eciesencrypt.pubKey;
    const byte* msg = info->pk.eciesencrypt.msg;
    word32   msgSz  = info->pk.eciesencrypt.msgSz;
    byte*    out    = info->pk.eciesencrypt.out;
    ecEncCtx* ctx   = info->pk.eciesencrypt.ctx;
    u8       curveType = 0;
    u8       keyLen = 0;
    u8       aesKeySize = 0;
    u8       shaType = 0;
    u8       shaMode = 0;
    word32   pubKeySz;
    word32   need;
    word32   status;
    word32   addl = 0;
    int      ret;

    /* Return the decline code, not an error, so wolfSSL can use software. */
    if (pubKey == NULL || msg == NULL || out == NULL ||
        info->pk.eciesencrypt.outSz == NULL || ctx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* The ASU only writes uncompressed keys, so turn down compressed. */
    if (info->pk.eciesencrypt.compressed != 0) {
        WC_ASU_PRINTF("[ASU] ecies enc: compressed key asked for, "
            "software will do it\r\n");
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = wc_AsuEciesCurve(pubKey, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuEciesScheme(ctx, &aesKeySize, &shaType, &shaMode);
    if (ret != 0) {
        return ret;
    }
    /* Only GCM here. The ASU cannot take extra salt and needs a context, so
     * software handles those cases. */
    {
        const byte* macSalt = NULL;
        const byte* infoP   = NULL;
        word32 macSaltSz = 0;
        word32 infoSz    = 0;
        int    proto     = 0;
        (void)wc_ecc_ctx_get_mac_salt(ctx, &macSalt, &macSaltSz);
        (void)wc_ecc_ctx_get_info(ctx, &infoP, &infoSz);
        (void)wc_ecc_ctx_get_protocol(ctx, &proto);
        if (macSaltSz > 0U) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if (infoSz == 0U) {
            WC_ASU_PRINTF("[ASU] ecies: GCM needs a non-empty KDF context\r\n");
            return CRYPTOCB_UNAVAILABLE;
        }
        /* The ASU always uses the first half of the derived key, which is the
         * client half. A context is never built with protocol zero. */
        if (proto != REQ_RESP_CLIENT) {
            return CRYPTOCB_UNAVAILABLE;
        }
    }
    /* The caller passes a key here, but the ASU makes its own. */
    if (privKey == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Both keys have to be on the same curve. */
    if (privKey->dp == NULL || privKey->dp->id != pubKey->dp->id) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* A zero peer point goes to software, which answers with ECC_INF_E. The
     * ASU only reports a generic bad point, so the error would be worse. */
    if (mp_iszero(pubKey->pubkey.x) && mp_iszero(pubKey->pubkey.y)) {
        WC_ASU_PRINTF("[ASU] ecies: zero peer point, software will do it\r\n");
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The ASU client turns down a zero data length, so let software do it. */
    if (msgSz == 0U) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* uncompressed point: 0x04 then Qx and Qy */
    pubKeySz = 1U + (2U * (word32)keyLen);
    /* Check the length first so the size math below cannot overflow. */
    if (msgSz > 0xFFFFFFFFU - pubKeySz - (word32)WC_ASU_ECIES_NONCE_SZ -
            (word32)WC_ASU_ECIES_TAG_SZ) {
        return BAD_FUNC_ARG;
    }
    need = pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ + msgSz +
           (word32)WC_ASU_ECIES_TAG_SZ;
    if (*info->pk.eciesencrypt.outSz < need) {
        return BUFFER_E;
    }

    ret = wc_AsuEciesReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    ret = wc_AsuEciesExportPub(pubKey, mem.req->rxKey, keyLen);
    if (ret != 0) {
        wc_AsuEciesReqFree(&mem);
        return ret;
    }
    /* Make the GCM nonce with a local RNG on the ASU device id. */
    {
        WC_RNG rng;
        ret = wc_InitRng_ex(&rng, NULL, WOLFSSL_VERSAL_GEN2_ASU_DEVID);
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(&rng, mem.req->iv,
                WC_ASU_ECIES_NONCE_SZ);
            wc_FreeRng(&rng);
        }
    }
    if (ret != 0) {
        /* That RNG needs a seed source this build may not have, so decline
         * and let wolfSSL try again in software. */
        wc_AsuEciesReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }

    wc_AsuEciesFillParams(&mem.req->params, ctx, curveType, keyLen, aesKeySize,
        shaType, shaMode, msgSz);
    /* peer public key in */
    mem.req->params.RxKeyAddr  = (u64)(UINTPTR)mem.req->rxKey;
    /* ephemeral public key out */
    mem.req->params.TxKeyAddr  = (u64)(UINTPTR)mem.req->txKey;
    mem.req->params.IvAddr     = (u64)(UINTPTR)mem.req->iv;
    /* GCM tag out */
    mem.req->params.MacAddr    = (u64)(UINTPTR)mem.req->tag;
    /* plaintext in */
    mem.req->params.InDataAddr = (u64)(UINTPTR)msg;
    /* ciphertext out, in place */
    mem.req->params.OutDataAddr = (u64)(UINTPTR)(out + pubKeySz +
        (word32)WC_ASU_ECIES_NONCE_SZ);

    WC_ASU_PRINTF("[ASU] ecies enc curve=%u keyLen=%u aesKey=%u msgSz=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)aesKeySize,
        (unsigned int)msgSz);

    /* Push the inputs out to memory, then reload what the ASU writes. */
    wc_AsuCacheFlush(mem.req, sizeof(*mem.req));
    wc_AsuCacheFlush(msg, msgSz);
    if (mem.req->params.SaltLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)mem.req->params.SaltAddr,
            mem.req->params.SaltLen);
    }
    if (mem.req->params.ContextLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)mem.req->params.ContextAddr,
            mem.req->params.ContextLen);
    }
    wc_AsuCacheFlush(out, need);

    sc.req = mem.req;
    sc.isEncrypt = 1;
    status = wc_AsuTransact(wc_AsuEciesSubmit, &sc, &addl);

    wc_AsuCacheInvalidate(mem.req, sizeof(*mem.req));
    wc_AsuCacheInvalidate(out, need);

    WC_ASU_PRINTF("[ASU] ecies enc st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        wc_AsuEciesReqFree(&mem);
        return WC_HW_E;
    }

    /* Build the output wolfSSL expects. The ciphertext is already in place,
     * so only the key, nonce and tag are copied. */
    out[0] = (byte)ECC_POINT_UNCOMP;
    XMEMCPY(out + 1, mem.req->txKey, 2U * (word32)keyLen);
    XMEMCPY(out + pubKeySz, mem.req->iv, WC_ASU_ECIES_NONCE_SZ);
    XMEMCPY(out + pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ + msgSz,
        mem.req->tag, WC_ASU_ECIES_TAG_SZ);
    *info->pk.eciesencrypt.outSz = need;
    wc_AsuEciesReqFree(&mem);
    return 0;
}

/* ECIES decrypt. The ASU derives the AES key from our private key and the
 * sender throwaway key, then decrypts and checks the tag. */
static int wc_AsuEciesDecrypt(wc_CryptoInfo* info)
{
    AsuEciesMem  mem;
    AsuEciesSubmitCtx sc;
    ecc_key* privKey = info->pk.eciesdecrypt.privKey;
    const byte* msg  = info->pk.eciesdecrypt.msg;
    word32   msgSz   = info->pk.eciesdecrypt.msgSz;
    byte*    out     = info->pk.eciesdecrypt.out;
    ecEncCtx* ctx    = info->pk.eciesdecrypt.ctx;
    u8       curveType = 0;
    u8       keyLen = 0;
    u8       aesKeySize = 0;
    u8       shaType = 0;
    u8       shaMode = 0;
    word32   pubKeySz;
    word32   ctLen;
    word32   status;
    word32   addl = 0;
    int      ret;

    /* Return the decline code so wolfSSL can use software. */
    if (privKey == NULL || msg == NULL || out == NULL ||
        info->pk.eciesdecrypt.outSz == NULL || ctx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Software hands back the sender public point and the ASU cannot, so
     * decline when the caller asks for it. */
    if (info->pk.eciesdecrypt.pubKey != NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* wolfSSL checks this after the callback, so our side needs a private key
     * here or the ASU would be handed a zero scalar. */
    if (privKey->type != ECC_PRIVATEKEY &&
        privKey->type != ECC_PRIVATEKEY_ONLY) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Check the curve first, since reading the private key below needs it. */
    ret = wc_AsuEciesCurve(privKey, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuEciesScheme(ctx, &aesKeySize, &shaType, &shaMode);
    if (ret != 0) {
        return ret;
    }
    /* Only GCM here. The ASU cannot take extra salt and needs a context, so
     * software handles those cases. */
    {
        const byte* macSalt = NULL;
        const byte* infoP   = NULL;
        word32 macSaltSz = 0;
        word32 infoSz    = 0;
        int    proto     = 0;
        (void)wc_ecc_ctx_get_mac_salt(ctx, &macSalt, &macSaltSz);
        (void)wc_ecc_ctx_get_info(ctx, &infoP, &infoSz);
        (void)wc_ecc_ctx_get_protocol(ctx, &proto);
        if (macSaltSz > 0U) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if (infoSz == 0U) {
            WC_ASU_PRINTF("[ASU] ecies: GCM needs a non-empty KDF context\r\n");
            return CRYPTOCB_UNAVAILABLE;
        }
        /* The ASU always uses the first half of the derived key, which is the
         * server half here. A context is never built with protocol zero. */
        if (proto != REQ_RESP_SERVER) {
            return CRYPTOCB_UNAVAILABLE;
        }
    }

    /* The sender key must be uncompressed, so turn down compressed. */
    if (msgSz < 1U || msg[0] != (byte)ECC_POINT_UNCOMP) {
        WC_ASU_PRINTF("[ASU] ecies dec: sender key is not uncompressed, "
            "software will do it\r\n");
        return CRYPTOCB_UNAVAILABLE;
    }
    pubKeySz = 1U + (2U * (word32)keyLen);
    if (msgSz < pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ +
        (word32)WC_ASU_ECIES_TAG_SZ) {
        return BAD_FUNC_ARG;
    }
    ctLen = msgSz - pubKeySz - (word32)WC_ASU_ECIES_NONCE_SZ -
        (word32)WC_ASU_ECIES_TAG_SZ;
    /* Same as encrypt: a zero data length is turned down by the client. */
    if (ctLen == 0U) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (*info->pk.eciesdecrypt.outSz < ctLen) {
        return BUFFER_E;
    }

    ret = wc_AsuEciesReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    /* Our private key. The sender public key comes from the message. */
    if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(privKey), mem.req->rxKey,
            (int)keyLen) < 0) {
        /* If the key does not fit in keyLen bytes we fall back to software. */
        wc_AsuEciesReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
    XMEMCPY(mem.req->txKey, msg + 1, 2U * (word32)keyLen);
    XMEMCPY(mem.req->iv, msg + pubKeySz, WC_ASU_ECIES_NONCE_SZ);
    XMEMCPY(mem.req->tag, msg + msgSz - (word32)WC_ASU_ECIES_TAG_SZ,
        WC_ASU_ECIES_TAG_SZ);

    wc_AsuEciesFillParams(&mem.req->params, ctx, curveType, keyLen, aesKeySize,
        shaType, shaMode, ctLen);
    /* our private key in */
    mem.req->params.RxKeyAddr  = (u64)(UINTPTR)mem.req->rxKey;
    /* ephemeral public key in */
    mem.req->params.TxKeyAddr  = (u64)(UINTPTR)mem.req->txKey;
    mem.req->params.IvAddr     = (u64)(UINTPTR)mem.req->iv;
    /* GCM tag in */
    mem.req->params.MacAddr    = (u64)(UINTPTR)mem.req->tag;
    /* ciphertext in */
    mem.req->params.InDataAddr = (u64)(UINTPTR)(msg + pubKeySz +
        (word32)WC_ASU_ECIES_NONCE_SZ);
    /* plaintext out */
    mem.req->params.OutDataAddr = (u64)(UINTPTR)out;

    WC_ASU_PRINTF("[ASU] ecies dec curve=%u keyLen=%u aesKey=%u ctLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)aesKeySize,
        (unsigned int)ctLen);

    wc_AsuCacheFlush(mem.req, sizeof(*mem.req));
    wc_AsuCacheFlush(msg, msgSz);
    if (mem.req->params.SaltLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)mem.req->params.SaltAddr,
            mem.req->params.SaltLen);
    }
    if (mem.req->params.ContextLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)mem.req->params.ContextAddr,
            mem.req->params.ContextLen);
    }
    wc_AsuCacheFlush(out, ctLen);

    sc.req = mem.req;
    sc.isEncrypt = 0;
    status = wc_AsuTransact(wc_AsuEciesSubmit, &sc, &addl);

    wc_AsuCacheInvalidate(out, ctLen);

    WC_ASU_PRINTF("[ASU] ecies dec st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        /* Wipe the output whatever went wrong, so no unchecked plaintext is
         * ever handed back. */
        ForceZero(out, ctLen);
        /* Push the zeros out to memory, or only the cache copy is cleared. */
        wc_AsuCacheFlush(out, ctLen);
        *info->pk.eciesdecrypt.outSz = 0;
        wc_AsuEciesReqFree(&mem);
        return WC_HW_E;
    }
    *info->pk.eciesdecrypt.outSz = ctLen;
    wc_AsuEciesReqFree(&mem);
    return 0;
}

/* Entry point for ECIES, called from the PK dispatcher. */
int wc_AsuEcies(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->pk.type == WC_PK_TYPE_ECIES_ENCRYPT) {
        return wc_AsuEciesEncrypt(info);
    }
    if (info->pk.type == WC_PK_TYPE_ECIES_DECRYPT) {
        return wc_AsuEciesDecrypt(info);
    }
    return CRYPTOCB_UNAVAILABLE;
}

#endif /* WC_ASU_ECIES_ENABLED */
