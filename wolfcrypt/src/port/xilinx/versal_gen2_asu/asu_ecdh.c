/* asu_ecdh.c
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

/* ECDH on the ASU. It multiplies our private key by the peer public key and
 * returns the X coordinate, which is the shared secret. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
/* asu_ecdh.h works out WC_ASU_ECDH_ENABLED from the ECC macros. */
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecdh.h>

#ifdef WC_ASU_ECDH_ENABLED

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_ecc.h"
#include "xasu_eccinfo.h"
#include "xasu_status.h"
#include "xstatus.h"

/* X25519 and X448 ride the same ECDH command with a Montgomery curve id. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_X25519) && defined(HAVE_CURVE25519)
    #include <wolfssl/wolfcrypt/curve25519.h>
    #define WC_ASU_X25519_ENABLED
    /* The scalar and peer point are read out of the key, so declining the
     * export API and asking for the offload is a contradiction, not a
     * choice. */
    #ifdef NO_CURVE25519_KEY_EXPORT
        #error "ASU X25519 needs the curve25519 key export API: drop \
NO_CURVE25519_KEY_EXPORT or name WOLFSSL_VERSAL_GEN2_ASU_NO_X25519"
    #endif
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_X448) && defined(HAVE_CURVE448)
    #include <wolfssl/wolfcrypt/curve448.h>
    #define WC_ASU_X448_ENABLED
    #ifdef NO_CURVE448_KEY_EXPORT
        #error "ASU X448 needs the curve448 key export API: drop \
NO_CURVE448_KEY_EXPORT or name WOLFSSL_VERSAL_GEN2_ASU_NO_X448"
    #endif
#endif

/* Biggest curve we support, P-521 at 66 bytes. */
#define WC_ASU_ECDH_MAX_KEYLEN  WC_ASU_ECC_P521_LEN

/* One ASU ECDH request. The buffers live on the heap so the ASU can reach
 * them. */
typedef struct {
    XAsu_EcdhParams params;
    byte privKey[WC_ASU_ECDH_MAX_KEYLEN];      /* our private key */
    byte pubKey[2U * WC_ASU_ECDH_MAX_KEYLEN];  /* peer public point */
    /* Keep the shared secret on its own cache line, away from the key above. */
    /* shared secret (DMA result) */
    WC_ASU_ALIGN64 byte secret[WC_ASU_ECDH_MAX_KEYLEN];
} AsuEcdhReq;

/* Holds both pointers so they stay together. Use .req, free .raw. */
typedef struct {
    void*       raw;   /* what XMALLOC gave back, free this one */
    AsuEcdhReq* req;   /* the aligned request the operation uses */
} AsuEcdhMem;

/* Align the request to 64 bytes so the secret gets its own cache line.
 * Returns 0 or MEMORY_E. */
static int wc_AsuEcdhReqNew(AsuEcdhMem* mem)
{
    if (mem == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef WC_ASU_DISABLE_CACHE
    /* Cache is off, so a plain malloc is fine. */
    mem->raw = XMALLOC(sizeof(AsuEcdhReq), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    mem->raw = XMALLOC(sizeof(AsuEcdhReq) + 63U, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    if (mem->raw == NULL) {
        mem->req = NULL;
        return MEMORY_E;
    }
#ifdef WC_ASU_DISABLE_CACHE
    mem->req = (AsuEcdhReq*)mem->raw;
#else
    mem->req = (AsuEcdhReq*)(void*)(((UINTPTR)mem->raw + 63U) & ~(UINTPTR)63U);
#endif
    return 0;
}

/* Wipe the request since it held the private key and secret, then free it. */
static void wc_AsuEcdhReqFree(AsuEcdhMem* mem)
{
    if (mem == NULL || mem->req == NULL) {
        return;
    }
    ForceZero(mem->req, sizeof(*mem->req));
    wc_AsuCacheFlush(mem->req, sizeof(*mem->req));
    XFREE(mem->raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Queue one ASU ECDH operation. */
static int wc_AsuEcdhSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuEcdhReq* req = (AsuEcdhReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }
    return XAsu_EcdhGenSharedSecret(params, &req->params);
}

/* Turn the wolfSSL curve id into an ASU curve type and size. Curves we do not
 * support return an error so wolfSSL uses software. */
static int wc_AsuEcdhCurve(ecc_key* key, u32* curveType, u32* keyLen)
{
    u32 type;
    u32 len;

    if (key == NULL || curveType == NULL || keyLen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (key->dp == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (key->dp->id) {
        case ECC_SECP192R1:
            type = (u32)XASU_ECC_NIST_P192;
            len  = (u32)WC_ASU_ECC_P192_LEN;
            break;
        case ECC_SECP256R1:
            type = (u32)XASU_ECC_NIST_P256;
            len  = (u32)WC_ASU_ECC_P256_LEN;
            break;
        case ECC_SECP384R1:
            type = (u32)XASU_ECC_NIST_P384;
            len  = (u32)WC_ASU_ECC_P384_LEN;
            break;
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC_P521
        /* Uses the same P-521 switch as ECDSA, on from Vitis 2026.1. */
        case ECC_SECP521R1:
            type = (u32)XASU_ECC_NIST_P521;
            len  = (u32)WC_ASU_ECC_P521_LEN;
            break;
#endif
#ifdef HAVE_ECC_BRAINPOOL
        case ECC_BRAINPOOLP256R1:
            type = (u32)XASU_ECC_BRAINPOOL_P256;
            len  = (u32)WC_ASU_ECC_P256_LEN;
            break;
        case ECC_BRAINPOOLP320R1:
            type = (u32)XASU_ECC_BRAINPOOL_P320;
            len  = (u32)WC_ASU_ECC_P320_LEN;
            break;
        case ECC_BRAINPOOLP384R1:
            type = (u32)XASU_ECC_BRAINPOOL_P384;
            len  = (u32)WC_ASU_ECC_P384_LEN;
            break;
        case ECC_BRAINPOOLP512R1:
            type = (u32)XASU_ECC_BRAINPOOL_P512;
            len  = (u32)WC_ASU_ECC_P512_LEN;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
    if ((u32)key->dp->size != len) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *curveType = type;
    *keyLen    = len;
    return 0;
}

/* ECDH shared secret. Both keys must be on the same supported curve. */
#ifdef WC_ASU_X25519_ENABLED
static int wc_AsuX25519(wc_CryptoInfo* info);
#endif
#ifdef WC_ASU_X448_ENABLED
static int wc_AsuX448(wc_CryptoInfo* info);
#endif

int wc_AsuEcdh(wc_CryptoInfo* info)
{
    AsuEcdhMem  mem;
    ecc_key* priv;
    ecc_key* pub;
    u32     curveType = 0;
    u32     keyLen = 0;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }
#ifdef WC_ASU_X25519_ENABLED
    if (info->pk.type == WC_PK_TYPE_CURVE25519) {
        return wc_AsuX25519(info);
    }
#endif
#ifdef WC_ASU_X448_ENABLED
    if (info->pk.type == WC_PK_TYPE_CURVE448) {
        return wc_AsuX448(info);
    }
#endif
    if (info->pk.type != WC_PK_TYPE_ECDH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    priv = info->pk.ecdh.private_key;
    pub  = info->pk.ecdh.public_key;

    if (priv == NULL || pub == NULL || info->pk.ecdh.out == NULL ||
        info->pk.ecdh.outlen == NULL) {
        return BAD_FUNC_ARG;
    }
    /* wolfSSL checks this after the callback, so our side needs a private key
     * here or the ASU would be handed a zero scalar. */
    if (priv->type != ECC_PRIVATEKEY && priv->type != ECC_PRIVATEKEY_ONLY) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuEcdhCurve(priv, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Both keys must be on the same supported curve. */
    if (pub->dp == NULL || pub->dp->id != priv->dp->id) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* A zero peer point goes to software, which answers with ECC_INF_E. The
     * ASU only reports a generic bad point, so the error would be worse. */
    if (mp_iszero(pub->pubkey.x) && mp_iszero(pub->pubkey.y)) {
        WC_ASU_PRINTF("[ASU] ecdh: zero peer point, software will do it\r\n");
        return CRYPTOCB_UNAVAILABLE;
    }
    /* This call hands back the plain private key. */
    if (*info->pk.ecdh.outlen < keyLen) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuEcdhReqNew(&mem);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(mem.req, 0, sizeof(*mem.req));
    /* A key too big for keyLen bytes is not something the ASU can take, so
     * fall back to software rather than report a hardware error. */
    if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(priv), mem.req->privKey,
            (int)keyLen) < 0) {
        wc_AsuEcdhReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
    /* The peer point is public data, so a failure here is a real error. */
    if (mp_to_unsigned_bin_len(pub->pubkey.x, mem.req->pubKey,
            (int)keyLen) < 0 ||
        mp_to_unsigned_bin_len(pub->pubkey.y, mem.req->pubKey + keyLen,
            (int)keyLen) < 0) {
        wc_AsuEcdhReqFree(&mem);
        return WC_HW_E;
    }

    mem.req->params.CurveType             = curveType;
    wc_AsuEcdhSetKeys(&mem.req->params, mem.req->privKey, mem.req->pubKey,
        keyLen);
    mem.req->params.SharedSecretAddr      = (u64)(UINTPTR)mem.req->secret;
    mem.req->params.SharedSecretObjIdAddr = 0;

    WC_ASU_PRINTF("[ASU] ecdh curve=%u keyLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen);

    wc_AsuCacheFlush(mem.req->privKey, keyLen);
    wc_AsuCacheFlush(mem.req->pubKey, 2U * keyLen);
    /* Flush the output first, or old cache lines could overwrite the secret
     * the ASU writes and we would read zeros. */
    wc_AsuCacheFlush(mem.req->secret, keyLen);

    status = wc_AsuTransact(wc_AsuEcdhSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->secret, keyLen);

    WC_ASU_PRINTF("[ASU] ecdh st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        /* Inputs were already checked, so this is a real hardware error. */
        wc_AsuEcdhReqFree(&mem);
        return WC_HW_E;
    }
    XMEMCPY(info->pk.ecdh.out, mem.req->secret, keyLen);
    *info->pk.ecdh.outlen = keyLen;
    wc_AsuEcdhReqFree(&mem);
    return 0;
}

#if defined(WC_ASU_X25519_ENABLED) || defined(WC_ASU_X448_ENABLED)
/* One X25519 or X448 agreement. Both are a scalar, a u coordinate and a shared
 * secret of one curve width, so only the curve id and the length differ. */
static int wc_AsuMontgomeryEcdh(u32 curveType, u32 keyLen, const byte* pvt,
    const byte* peer, byte* out, word32* outLen, int bigEndian)
{
    AsuEcdhMem mem;
    word32 status;
    word32 addl = 0;
    int    ret;

    ret = wc_AsuEcdhReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));
    XMEMCPY(mem.req->privKey, pvt, keyLen);
    XMEMCPY(mem.req->pubKey, peer, keyLen);

    mem.req->params.CurveType             = curveType;
    wc_AsuEcdhSetKeys(&mem.req->params, mem.req->privKey, mem.req->pubKey,
        keyLen);
    mem.req->params.SharedSecretAddr      = (u64)(UINTPTR)mem.req->secret;
    mem.req->params.SharedSecretObjIdAddr = 0;

    WC_ASU_PRINTF("[ASU] ecdh curve=%u keyLen=%u montgomery\r\n",
        (unsigned int)curveType, (unsigned int)keyLen);

    wc_AsuCacheFlush(mem.req->privKey, keyLen);
    /* A Montgomery public key is only the u coordinate, so one key length
     * here, not the two a Weierstrass x||y point needs. */
    wc_AsuCacheFlush(mem.req->pubKey, keyLen);
    /* Flush the output first, or old cache lines could overwrite the secret
     * the ASU writes and we would read zeros. */
    wc_AsuCacheFlush(mem.req->secret, keyLen);

    status = wc_AsuTransact(wc_AsuEcdhSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->secret, keyLen);

    WC_ASU_PRINTF("[ASU] ecdh st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        wc_AsuEcdhReqFree(&mem);
        return WC_HW_E;
    }
    /* No zero shared secret test needed: the ASU refuses a low order point
     * itself (measured, XASUFW_ECDH_GEN_SECRET_OPERATION_FAIL). */
    /* The curve works little endian and so does the ASU; a caller that asked
     * for big endian gets the same reversal software would have done. */
    if (bigEndian) {
        u32 i;
        for (i = 0; i < keyLen; i++) {
            out[i] = mem.req->secret[keyLen - i - 1U];
        }
    }
    else {
        XMEMCPY(out, mem.req->secret, keyLen);
    }
    *outLen = keyLen;
    wc_AsuEcdhReqFree(&mem);
    return 0;
}
#endif /* WC_ASU_X25519_ENABLED || WC_ASU_X448_ENABLED */

#ifdef WC_ASU_X25519_ENABLED
/* X25519 shared secret on the ASU. */
static int wc_AsuX25519(wc_CryptoInfo* info)
{
    byte   pvt[CURVE25519_KEYSIZE];
    byte   peer[CURVE25519_KEYSIZE];
    word32 pvtLen  = (word32)sizeof(pvt);
    word32 peerLen = (word32)sizeof(peer);
    int    ret;

    if (info->pk.curve25519.private_key == NULL ||
        info->pk.curve25519.public_key == NULL ||
        info->pk.curve25519.out == NULL ||
        info->pk.curve25519.outlen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (*info->pk.curve25519.outlen < (word32)CURVE25519_KEYSIZE) {
        return BUFFER_E;
    }

    ret = wc_curve25519_export_private_raw_ex(info->pk.curve25519.private_key,
        pvt, &pvtLen, EC25519_LITTLE_ENDIAN);
    if (ret == 0) {
        /* Exported as stored, not masked: the ASU clears the RFC 7748 reserved
         * high bit itself, measured to match what software returns. */
        ret = wc_curve25519_export_public_ex(info->pk.curve25519.public_key,
            peer, &peerLen, EC25519_LITTLE_ENDIAN);
    }
    /* No usable key material is a reason to use software, not an error. */
    if (ret != 0 || pvtLen != (word32)CURVE25519_KEYSIZE ||
        peerLen != (word32)CURVE25519_KEYSIZE) {
        ForceZero(pvt, sizeof(pvt));
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuMontgomeryEcdh((u32)XASU_ECC_CURVE25519,
        (u32)CURVE25519_KEYSIZE, pvt, peer, info->pk.curve25519.out,
        info->pk.curve25519.outlen,
        info->pk.curve25519.endian == EC25519_BIG_ENDIAN);

    ForceZero(pvt, sizeof(pvt));
    return ret;
}
#endif /* WC_ASU_X25519_ENABLED */

#ifdef WC_ASU_X448_ENABLED
/* X448 shared secret on the ASU. */
static int wc_AsuX448(wc_CryptoInfo* info)
{
    byte   pvt[CURVE448_KEY_SIZE];
    byte   peer[CURVE448_KEY_SIZE];
    word32 pvtLen  = (word32)sizeof(pvt);
    word32 peerLen = (word32)sizeof(peer);
    int    ret;

    if (info->pk.curve448.private_key == NULL ||
        info->pk.curve448.public_key == NULL ||
        info->pk.curve448.out == NULL ||
        info->pk.curve448.outlen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (*info->pk.curve448.outlen < (word32)CURVE448_KEY_SIZE) {
        return BUFFER_E;
    }

    ret = wc_curve448_export_private_raw_ex(info->pk.curve448.private_key,
        pvt, &pvtLen, EC448_LITTLE_ENDIAN);
    if (ret == 0) {
        ret = wc_curve448_export_public_ex(info->pk.curve448.public_key,
            peer, &peerLen, EC448_LITTLE_ENDIAN);
    }
    if (ret != 0 || pvtLen != (word32)CURVE448_KEY_SIZE ||
        peerLen != (word32)CURVE448_KEY_SIZE) {
        ForceZero(pvt, sizeof(pvt));
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuMontgomeryEcdh((u32)XASU_ECC_CURVE448,
        (u32)CURVE448_KEY_SIZE, pvt, peer, info->pk.curve448.out,
        info->pk.curve448.outlen,
        info->pk.curve448.endian == EC448_BIG_ENDIAN);

    ForceZero(pvt, sizeof(pvt));
    return ret;
}
#endif /* WC_ASU_X448_ENABLED */

#endif /* WC_ASU_ECDH_ENABLED */
