/* asu_ecc.c
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

/* ECDSA and EdDSA on the ASU. wolfSSL uses DER signatures and the ASU uses
 * raw r||s, so this file converts between the two. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* A build can still turn ECC off, so check both macros here. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_ECC) && defined(HAVE_ECC) && \
    !defined(NO_ECC)

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecc.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_ecc.h"
#include "xasu_eccinfo.h"
#include "xasu_shainfo.h"
#include "xasu_status.h"
#include "xstatus.h"

/* Which ASU call the thunk should make. */
#define WC_ASU_ECC_OP_SIGN    0   /* XAsu_EccGenSign */
#define WC_ASU_ECC_OP_VERIFY  1   /* XAsu_EccVerifySign */

/* Biggest curve we support, P-521 at 66 bytes. */
#define WC_ASU_ECC_MAX_KEYLEN  XASU_ECC_P521_SIZE_IN_BYTES

/* One ASU ECC request. The buffers live on the heap so the ASU can reach them. */
typedef struct {
    XAsu_EccParams params;
    /* private key for sign, or public point for verify */
    byte key[2U * WC_ASU_ECC_MAX_KEYLEN];
    byte digest[XASU_SHA_512_HASH_LEN];     /* message digest, <= 64 bytes */
    /* Keep the result on its own cache line, away from the key above. */
    WC_ASU_ALIGN64 byte sign[2U * WC_ASU_ECC_MAX_KEYLEN]; /* r||s, DMA out */
    int  op;
} AsuEccReq;

/* Holds both pointers so they stay together. Use .req, free .raw. */
typedef struct {
    void*      raw;   /* what XMALLOC gave back, free this one */
    AsuEccReq* req;   /* the aligned request the operation uses */
} AsuEccMem;


/* ECDSA and EdDSA both use the request helpers below, so build them when
 * either one is on. Without this they compile with no callers. */
#if ((defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)) && !defined(NO_ASN)) \
    || (defined(HAVE_ED25519) && \
        !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED25519)) \
    || (defined(HAVE_ED448) && !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED448))
    #define WC_ASU_ECC_REQ_USED
#endif

#ifdef WC_ASU_ECC_REQ_USED
/* Align the request to 64 bytes so the sign buffer gets its own cache line.
 * Returns 0 or MEMORY_E. */
static int wc_AsuEccReqNew(AsuEccMem* mem)
{
    if (mem == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef WC_ASU_DISABLE_CACHE
    /* Cache is off, so a plain malloc is fine. */
    mem->raw = XMALLOC(sizeof(AsuEccReq), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    mem->raw = XMALLOC(sizeof(AsuEccReq) + 63U, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    if (mem->raw == NULL) {
        mem->req = NULL;
        return MEMORY_E;
    }
#ifdef WC_ASU_DISABLE_CACHE
    mem->req = (AsuEccReq*)mem->raw;
#else
    mem->req = (AsuEccReq*)(void*)(((UINTPTR)mem->raw + 63U) & ~(UINTPTR)63U);
#endif
    return 0;
}

/* Wipe the request since it may hold the private key, then free it. */
static void wc_AsuEccReqFree(AsuEccMem* mem)
{
    if (mem == NULL || mem->req == NULL) {
        return;
    }
    ForceZero(mem->req, sizeof(*mem->req));
    wc_AsuCacheFlush(mem->req, sizeof(*mem->req));
    XFREE(mem->raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Queue one ASU ECC operation. */
static int wc_AsuEccSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuEccReq* req = (AsuEccReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }
    switch (req->op) {
        case WC_ASU_ECC_OP_SIGN:
            return XAsu_EccGenSign(params, &req->params);
        case WC_ASU_ECC_OP_VERIFY:
            return XAsu_EccVerifySign(params, &req->params);
        default:
            return XST_FAILURE;
    }
}
#endif /* WC_ASU_ECC_REQ_USED */

/* The DER helpers are gone under NO_ASN, so ECDSA runs in software there.
 * EdDSA uses raw signatures and still works. */
#if (defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)) && !defined(NO_ASN)
/* Turn the wolfSSL curve id into an ASU curve type and size. Curves we do not
 * support return an error so wolfSSL uses software. */
static int wc_AsuEccCurve(ecc_key* key, u32* curveType, u32* keyLen)
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
            len  = (u32)XASU_ECC_P192_SIZE_IN_BYTES;
            break;
        case ECC_SECP256R1:
            type = (u32)XASU_ECC_NIST_P256;
            len  = (u32)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_SECP384R1:
            type = (u32)XASU_ECC_NIST_P384;
            len  = (u32)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC_P521
        /* Off by default. Stock firmware pads the digest wrong and caps it at
         * 64 bytes, which is too small for P-521. */
        case ECC_SECP521R1:
            type = (u32)XASU_ECC_NIST_P521;
            len  = (u32)XASU_ECC_P521_SIZE_IN_BYTES;
            break;
#endif
#ifdef HAVE_ECC_BRAINPOOL
        /* Brainpool curves work like the NIST ones and all fit in 64 bytes. */
        case ECC_BRAINPOOLP256R1:
            type = (u32)XASU_ECC_BRAINPOOL_P256;
            len  = (u32)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP320R1:
            type = (u32)XASU_ECC_BRAINPOOL_P320;
            len  = (u32)XASU_ECC_P320_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP384R1:
            type = (u32)XASU_ECC_BRAINPOOL_P384;
            len  = (u32)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP512R1:
            type = (u32)XASU_ECC_BRAINPOOL_P512;
            len  = (u32)XASU_ECC_P512_SIZE_IN_BYTES;
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

/* The ASU will sign an all zero digest but then fail to verify it, so send
 * those to software, which turns them down. */
static int wc_AsuEccDigestIsZero(const byte* hash, word32 hashLen)
{
    word32 i;
    byte   acc = 0;

    for (i = 0; i < hashLen; i++) {
        acc |= hash[i];
    }

    return acc == 0;
}

/* Pad a short digest on the left to the curve size so the ASU reads the same
 * number as software. A longer digest keeps its leading bytes. */
static void wc_AsuEccDigest(const byte* hash, word32 hashLen, byte* out,
                            u32 width)
{
    XMEMSET(out, 0, width);
    if (hashLen >= width) {
        XMEMCPY(out, hash, width);
    }
    else {
        XMEMCPY(out + (width - hashLen), hash, hashLen);
    }
}
#endif /* (HAVE_ECC_SIGN || HAVE_ECC_VERIFY) && !NO_ASN */

#if defined(HAVE_ECC_SIGN) && !defined(NO_ASN)
/* ECDSA sign. The ASU returns raw r||s, which we then encode as DER. */
static int wc_AsuEccSign(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ecc_key* key = info->pk.eccsign.key;
    u32     curveType = 0;
    u32     keyLen = 0;
    u32     digLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || info->pk.eccsign.in == NULL ||
        info->pk.eccsign.out == NULL || info->pk.eccsign.outlen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.eccsign.inlen == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* wolfSSL checks this after the callback, so signing needs a private key
     * here or the ASU would be handed a zero scalar. */
    if (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (wc_AsuEccDigestIsZero(info->pk.eccsign.in, info->pk.eccsign.inlen)) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* The ASU picks its own random k, so a deterministic or caller set k has
     * to run in software. */
#if defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
    if (key->deterministic) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif
#if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K) || \
    defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
#ifdef WOLFSSL_NO_MALLOC
    if (key->sign_k_set) {
        return CRYPTOCB_UNAVAILABLE;
    }
#else
    if (key->sign_k != NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif
#endif

    ret = wc_AsuEccCurve(key, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Read the private key and check it using the exported bytes, which keeps
     * the timing steady. */
    /* Digest size for the ASU: the curve size, capped at the ASU limit. */
    digLen = keyLen;
    if (digLen > (u32)XASU_SHA_512_HASH_LEN) {
        digLen = (u32)XASU_SHA_512_HASH_LEN;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(mem.req, 0, sizeof(*mem.req));
    /* If the key does not fit in keyLen bytes we fall back to software. */
    if (mp_to_unsigned_bin_len(wc_ecc_key_get_priv(key), mem.req->key,
            (int)keyLen) < 0) {
        wc_AsuEccReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
    wc_AsuEccDigest(info->pk.eccsign.in, info->pk.eccsign.inlen,
        mem.req->digest, digLen);

    mem.req->op                 = WC_ASU_ECC_OP_SIGN;
    mem.req->params.CurveType   = curveType;
    mem.req->params.KeyLen      = keyLen;
    mem.req->params.DigestLen   = digLen;
    mem.req->params.KeyAddr     = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr  = (u64)(UINTPTR)mem.req->digest;
    mem.req->params.SignAddr    = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ecc sign curve=%u keyLen=%u digestLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)digLen);

    wc_AsuCacheFlush(mem.req->key, keyLen);
    wc_AsuCacheFlush(mem.req->digest, digLen);
    wc_AsuCacheFlush(mem.req->sign, 2U * keyLen);

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->sign, 2U * keyLen);

    WC_ASU_PRINTF("[ASU] ecc sign st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        /* Inputs were already checked, so this is a real hardware error. */
        wc_AsuEccReqFree(&mem);
        return WC_HW_E;
    }
    /* Encode the raw r||s from the ASU as a DER signature. */
    ret = wc_ecc_rs_raw_to_sig(mem.req->sign, keyLen, mem.req->sign + keyLen,
        keyLen, info->pk.eccsign.out, info->pk.eccsign.outlen);

    wc_AsuEccReqFree(&mem);
    return ret;
}
#endif /* HAVE_ECC_SIGN && !NO_ASN */

#if defined(HAVE_ECC_VERIFY) && !defined(NO_ASN)
/* ECDSA verify. The DER signature is turned into raw r||s for the ASU, and
 * res is set to 1 only when the ASU says the signature is good. */
static int wc_AsuEccVerify(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ecc_key* key = info->pk.eccverify.key;
    u32     curveType = 0;
    u32     keyLen = 0;
    u32     digLen;
    word32  rLen;
    word32  sLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info->pk.eccverify.res == NULL) {
        return BAD_FUNC_ARG;
    }
    *info->pk.eccverify.res = 0;

    if (key == NULL || info->pk.eccverify.sig == NULL ||
        info->pk.eccverify.hash == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.eccverify.hashlen == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (wc_AsuEccDigestIsZero(info->pk.eccverify.hash,
                              info->pk.eccverify.hashlen)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuEccCurve(key, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Digest size for the ASU: the curve size, capped at the ASU limit. */
    digLen = keyLen;
    if (digLen > (u32)XASU_SHA_512_HASH_LEN) {
        digLen = (u32)XASU_SHA_512_HASH_LEN;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(mem.req, 0, sizeof(*mem.req));
    /* Verify needs the public key. Without it the buffer would be all zeros,
     * so let software handle it. */
    if (mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y)) {
        wc_AsuEccReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Public key Qx||Qy, each padded with zeros on the left. */
    if (mp_to_unsigned_bin_len(key->pubkey.x, mem.req->key, (int)keyLen) < 0 ||
        mp_to_unsigned_bin_len(key->pubkey.y, mem.req->key + keyLen,
            (int)keyLen) < 0) {
        wc_AsuEccReqFree(&mem);
        return WC_HW_E;
    }

    /* Turn the DER signature into raw r and s, each keyLen bytes long. */
    rLen = keyLen;
    sLen = keyLen;
    ret = wc_ecc_sig_to_rs(info->pk.eccverify.sig, info->pk.eccverify.siglen,
        mem.req->sign, &rLen, mem.req->sign + keyLen, &sLen);
    if (ret != 0 || rLen > keyLen || sLen > keyLen) {
        wc_AsuEccReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
    if (rLen < keyLen) {
        XMEMMOVE(mem.req->sign + (keyLen - rLen), mem.req->sign, rLen);
        XMEMSET(mem.req->sign, 0, keyLen - rLen);
    }
    if (sLen < keyLen) {
        XMEMMOVE(mem.req->sign + keyLen + (keyLen - sLen),
            mem.req->sign + keyLen, sLen);
        XMEMSET(mem.req->sign + keyLen, 0, keyLen - sLen);
    }

    wc_AsuEccDigest(info->pk.eccverify.hash, info->pk.eccverify.hashlen,
        mem.req->digest, digLen);

    mem.req->op                 = WC_ASU_ECC_OP_VERIFY;
    mem.req->params.CurveType   = curveType;
    mem.req->params.KeyLen      = keyLen;
    mem.req->params.DigestLen   = digLen;
    mem.req->params.KeyAddr     = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr  = (u64)(UINTPTR)mem.req->digest;
    mem.req->params.SignAddr    = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ecc verify curve=%u keyLen=%u digestLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)digLen);

    wc_AsuCacheFlush(mem.req->key, 2U * keyLen);
    wc_AsuCacheFlush(mem.req->digest, digLen);
    wc_AsuCacheFlush(mem.req->sign, 2U * keyLen);

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);

    WC_ASU_PRINTF("[ASU] ecc verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    /* Only VERIFIED sets res to 1. A finished check that says no is just a
     * bad signature. An addl of 0 means the request never ran. */
    if (status == XST_SUCCESS && addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.eccverify.res = 1;
        ret = 0;
    }
    else if (addl == 0) {
        ret = WC_HW_E;
    }
    else {
        ret = 0;
    }

    wc_AsuEccReqFree(&mem);
    return ret;
}
#endif /* HAVE_ECC_VERIFY && !NO_ASN */

#if defined(HAVE_ED25519) && !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED25519)

/* Ed25519 sign. The ASU hashes the message itself, so the message goes in the
 * digest field and the 32 byte seed goes in the key field. */
static int wc_AsuEd25519Sign(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ed25519_key* key = info->pk.ed25519sign.key;
    byte*   msg = NULL;
    word32  msgLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || info->pk.ed25519sign.out == NULL ||
        info->pk.ed25519sign.outLen == NULL) {
        return BAD_FUNC_ARG;
    }
    /* The ASU only does plain Ed25519. Context and prehash go to software. */
    if (info->pk.ed25519sign.type != (byte)Ed25519 ||
        info->pk.ed25519sign.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Signing needs both the seed and the public key, same as software. */
    if (key->privKeySet == 0 || key->pubKeySet == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (*info->pk.ed25519sign.outLen < ED25519_SIG_SIZE) {
        return CRYPTOCB_UNAVAILABLE;
    }
    msgLen = info->pk.ed25519sign.inLen;
    if (msgLen != 0 && info->pk.ed25519sign.in == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    /* Copy the message where the ASU can read it. An empty message still needs
     * a valid pointer, so the zeroed digest field is used. */
    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            wc_AsuEccReqFree(&mem);
            return MEMORY_E;
        }
        XMEMCPY(msg, info->pk.ed25519sign.in, msgLen);
    }
    else {
        msg = mem.req->digest;
    }

    XMEMCPY(mem.req->key, key->k, ED25519_KEY_SIZE);

    mem.req->op                = WC_ASU_ECC_OP_SIGN;
    mem.req->params.CurveType  = (u32)XASU_ECC_NIST_ED25519;
    mem.req->params.KeyLen     = (u32)ED25519_KEY_SIZE;
    mem.req->params.DigestLen  = msgLen;
    mem.req->params.KeyAddr    = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr = (u64)(UINTPTR)msg;
    mem.req->params.SignAddr   = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ed25519 sign msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(mem.req->key, ED25519_KEY_SIZE);
    wc_AsuCacheFlush(mem.req->sign, ED25519_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->sign, ED25519_SIG_SIZE);
    /* The ASU only read msg, so free it now. */
    if (msgLen != 0) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    WC_ASU_PRINTF("[ASU] ed25519 sign st=%u\r\n", (unsigned int)status);

    if (status != XST_SUCCESS) {
        /* Inputs were already checked, so this is a real hardware error. */
        wc_AsuEccReqFree(&mem);
        return WC_HW_E;
    }
    XMEMCPY(info->pk.ed25519sign.out, mem.req->sign, ED25519_SIG_SIZE);
    *info->pk.ed25519sign.outLen = ED25519_SIG_SIZE;
    wc_AsuEccReqFree(&mem);
    return 0;
}

/* The ed25519 group order, low byte first. S must stay below it. */
static const byte wc_AsuEd25519Order[ED25519_KEY_SIZE] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Return 1 when S is too big, which wolfSSL treats as a bad argument. */
static int wc_AsuEd25519NonCanonicalS(const byte* sig)
{
    int i;
    for (i = (int)ED25519_KEY_SIZE - 1; i >= 0; i--) {
        if (sig[ED25519_SIG_SIZE / 2 + i] > wc_AsuEd25519Order[i]) {
            return 1;
        }
        if (sig[ED25519_SIG_SIZE / 2 + i] < wc_AsuEd25519Order[i]) {
            return 0;
        }
    }
    return 1; /* every byte matched, so S equals the order and is too big */
}

/* Ed25519 verify. The key buffer holds 32 zero bytes then the public key. */
static int wc_AsuEd25519Verify(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ed25519_key* key = info->pk.ed25519verify.key;
    byte*   msg = NULL;
    word32  msgLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info->pk.ed25519verify.res == NULL) {
        return BAD_FUNC_ARG;
    }
    *info->pk.ed25519verify.res = 0;

    if (key == NULL || info->pk.ed25519verify.sig == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.ed25519verify.type != (byte)Ed25519 ||
        info->pk.ed25519verify.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (key->pubKeySet == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->pk.ed25519verify.sigLen != ED25519_SIG_SIZE) {
        return CRYPTOCB_UNAVAILABLE;
    }
    msgLen = info->pk.ed25519verify.msgLen;
    if (msgLen != 0 && info->pk.ed25519verify.msg == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            wc_AsuEccReqFree(&mem);
            return MEMORY_E;
        }
        XMEMCPY(msg, info->pk.ed25519verify.msg, msgLen);
    }
    else {
        msg = mem.req->digest;
    }

    /* Zeros in the first half, the public key in the second. */
    XMEMCPY(mem.req->key + ED25519_PUB_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);
    XMEMCPY(mem.req->sign, info->pk.ed25519verify.sig, ED25519_SIG_SIZE);

    mem.req->op                = WC_ASU_ECC_OP_VERIFY;
    mem.req->params.CurveType  = (u32)XASU_ECC_NIST_ED25519;
    mem.req->params.KeyLen     = (u32)ED25519_KEY_SIZE;
    mem.req->params.DigestLen  = msgLen;
    mem.req->params.KeyAddr    = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr = (u64)(UINTPTR)msg;
    mem.req->params.SignAddr   = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ed25519 verify msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(mem.req->key, 2U * ED25519_KEY_SIZE);
    wc_AsuCacheFlush(mem.req->sign, ED25519_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);
    /* The ASU only read msg, so free it now. */
    if (msgLen != 0) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    WC_ASU_PRINTF("[ASU] ed25519 verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    /* Only VERIFIED passes. An S that is too big is a bad argument, and
     * anything else is just a bad signature. */
    if (status == XST_SUCCESS && addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.ed25519verify.res = 1;
        ret = 0;
    }
    else if (addl == 0) {
        ret = WC_HW_E;
    }
    else if (wc_AsuEd25519NonCanonicalS(info->pk.ed25519verify.sig)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = SIG_VERIFY_E;
    }

    wc_AsuEccReqFree(&mem);
    return ret;
}

#endif /* HAVE_ED25519 && !NO_ED25519 */

#if defined(HAVE_ED448) && !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED448)

/* Ed448 sign. Same idea as Ed25519, with a 57 byte seed. */
static int wc_AsuEd448Sign(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ed448_key* key = info->pk.ed448sign.key;
    byte*   msg = NULL;
    word32  msgLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || info->pk.ed448sign.out == NULL ||
        info->pk.ed448sign.outLen == NULL) {
        return BAD_FUNC_ARG;
    }
    /* The ASU only does plain Ed448. Context and prehash go to software. */
    if (info->pk.ed448sign.type != (byte)Ed448 ||
        info->pk.ed448sign.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Signing needs both the seed and the public key, same as software. */
    if (key->privKeySet == 0 || key->pubKeySet == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (*info->pk.ed448sign.outLen < ED448_SIG_SIZE) {
        return CRYPTOCB_UNAVAILABLE;
    }
    msgLen = info->pk.ed448sign.inLen;
    if (msgLen != 0 && info->pk.ed448sign.in == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            wc_AsuEccReqFree(&mem);
            return MEMORY_E;
        }
        XMEMCPY(msg, info->pk.ed448sign.in, msgLen);
    }
    else {
        msg = mem.req->digest;
    }

    XMEMCPY(mem.req->key, key->k, ED448_KEY_SIZE);

    mem.req->op                = WC_ASU_ECC_OP_SIGN;
    mem.req->params.CurveType  = (u32)XASU_ECC_NIST_ED448;
    mem.req->params.KeyLen     = (u32)ED448_KEY_SIZE;
    mem.req->params.DigestLen  = msgLen;
    mem.req->params.KeyAddr    = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr = (u64)(UINTPTR)msg;
    mem.req->params.SignAddr   = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ed448 sign msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(mem.req->key, ED448_KEY_SIZE);
    wc_AsuCacheFlush(mem.req->sign, ED448_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->sign, ED448_SIG_SIZE);
    /* The ASU only read msg, so free it now. */
    if (msgLen != 0) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    WC_ASU_PRINTF("[ASU] ed448 sign st=%u\r\n", (unsigned int)status);

    if (status != XST_SUCCESS) {
        /* Inputs were already checked, so this is a real hardware error. */
        wc_AsuEccReqFree(&mem);
        return WC_HW_E;
    }
    XMEMCPY(info->pk.ed448sign.out, mem.req->sign, ED448_SIG_SIZE);
    *info->pk.ed448sign.outLen = ED448_SIG_SIZE;
    wc_AsuEccReqFree(&mem);
    return 0;
}

/* The ed448 group order, low byte first. S must stay below it. */
static const byte wc_AsuEd448Order[ED448_KEY_SIZE] = {
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
    0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
    0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0x00
};

/* Return 1 when S is too big, which wolfSSL treats as a bad argument. */
static int wc_AsuEd448NonCanonicalS(const byte* sig)
{
    int i;
    for (i = (int)ED448_KEY_SIZE - 1; i >= 0; i--) {
        if (sig[ED448_SIG_SIZE / 2 + i] > wc_AsuEd448Order[i]) {
            return 1;
        }
        if (sig[ED448_SIG_SIZE / 2 + i] < wc_AsuEd448Order[i]) {
            return 0;
        }
    }
    return 1; /* every byte matched, so S equals the order and is too big */
}

/* Ed448 verify. The key buffer holds 57 zero bytes then the public key. */
static int wc_AsuEd448Verify(wc_CryptoInfo* info)
{
    AsuEccMem  mem;
    ed448_key* key = info->pk.ed448verify.key;
    byte*   msg = NULL;
    word32  msgLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info->pk.ed448verify.res == NULL) {
        return BAD_FUNC_ARG;
    }
    *info->pk.ed448verify.res = 0;

    if (key == NULL || info->pk.ed448verify.sig == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.ed448verify.type != (byte)Ed448 ||
        info->pk.ed448verify.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (key->pubKeySet == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->pk.ed448verify.sigLen != ED448_SIG_SIZE) {
        return CRYPTOCB_UNAVAILABLE;
    }
    msgLen = info->pk.ed448verify.msgLen;
    if (msgLen != 0 && info->pk.ed448verify.msg == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuEccReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            wc_AsuEccReqFree(&mem);
            return MEMORY_E;
        }
        XMEMCPY(msg, info->pk.ed448verify.msg, msgLen);
    }
    else {
        msg = mem.req->digest;
    }

    /* Zeros in the first half, the public key in the second. */
    XMEMCPY(mem.req->key + ED448_PUB_KEY_SIZE, key->p, ED448_PUB_KEY_SIZE);
    XMEMCPY(mem.req->sign, info->pk.ed448verify.sig, ED448_SIG_SIZE);

    mem.req->op                = WC_ASU_ECC_OP_VERIFY;
    mem.req->params.CurveType  = (u32)XASU_ECC_NIST_ED448;
    mem.req->params.KeyLen     = (u32)ED448_KEY_SIZE;
    mem.req->params.DigestLen  = msgLen;
    mem.req->params.KeyAddr    = (u64)(UINTPTR)mem.req->key;
    mem.req->params.DigestAddr = (u64)(UINTPTR)msg;
    mem.req->params.SignAddr   = (u64)(UINTPTR)mem.req->sign;

    WC_ASU_PRINTF("[ASU] ed448 verify msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(mem.req->key, 2U * ED448_KEY_SIZE);
    wc_AsuCacheFlush(mem.req->sign, ED448_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, mem.req, &addl);
    /* The ASU only read msg, so free it now. */
    if (msgLen != 0) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    WC_ASU_PRINTF("[ASU] ed448 verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    /* Same rules as Ed25519 above. */
    if (status == XST_SUCCESS && addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.ed448verify.res = 1;
        ret = 0;
    }
    else if (addl == 0) {
        ret = WC_HW_E;
    }
    else if (wc_AsuEd448NonCanonicalS(info->pk.ed448verify.sig)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = SIG_VERIFY_E;
    }

    wc_AsuEccReqFree(&mem);
    return ret;
}

#endif /* HAVE_ED448 && !NO_ED448 */

/* Entry point for ECC. Sends sign and verify to the ASU and lets software
 * handle everything else. */
int wc_AsuEcc(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.type) {
#if defined(HAVE_ECC_SIGN) && !defined(NO_ASN)
        case WC_PK_TYPE_ECDSA_SIGN:
            return wc_AsuEccSign(info);
#endif
#if defined(HAVE_ECC_VERIFY) && !defined(NO_ASN)
        case WC_PK_TYPE_ECDSA_VERIFY:
            return wc_AsuEccVerify(info);
#endif
#if defined(HAVE_ED25519) && !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED25519)
        case WC_PK_TYPE_ED25519_SIGN:
            return wc_AsuEd25519Sign(info);
        case WC_PK_TYPE_ED25519_VERIFY:
            return wc_AsuEd25519Verify(info);
#endif
#if defined(HAVE_ED448) && !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_ED448)
        case WC_PK_TYPE_ED448:
            return wc_AsuEd448Sign(info);
        case WC_PK_TYPE_ED448_VERIFY:
            return wc_AsuEd448Verify(info);
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC && HAVE_ECC && !NO_ECC */
