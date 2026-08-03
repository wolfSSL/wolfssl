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

/* ASU ECDSA offload for the wolfSSL crypto callback.
 *
 * wolfSSL delivers the message digest to the sign/verify callbacks; the ASU does
 * the curve operation. The ASU works in raw fixed-width r||s and raw keys, while
 * wolfSSL passes a DER signature, so sign converts the ASU's raw r||s to DER with
 * wc_ecc_rs_raw_to_sig and verify converts the DER signature to raw with
 * wc_ecc_sig_to_rs (right-aligned to the curve width). Keys are marshalled
 * big-endian, fixed-width with mp_to_unsigned_bin_len. Verify returns its verdict
 * in the ASU additional status (fail-closed). NIST P-192/256/384/521 and
 * Brainpool P-256/320/384/512 prime curves.
 *
 * Ed25519 sign/verify also route here: the ASU hashes the raw message internally,
 * so wolfSSL's message is passed through the digest parameter, the private seed and
 * compressed public key through the key parameter, and the standard 64-byte
 * signature through the sign parameter. Only plain Ed25519 (no context, no prehash)
 * maps to the ASU; ctx/ph variants decline to software.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC

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

#include "xasu_ecc.h"
#include "xasu_eccinfo.h"
#include "xasu_shainfo.h"
#include "xasu_status.h"
#include "xstatus.h"

#if defined(NO_ECC) || !defined(HAVE_ECC)
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECC requires ECC"
#endif

/* Submit-thunk op selector. */
#define WC_ASU_ECC_OP_SIGN    0   /* XAsu_EccGenSign */
#define WC_ASU_ECC_OP_VERIFY  1   /* XAsu_EccVerifySign */

/* Largest supported curve width (NIST P-521, 66 bytes). */
#define WC_ASU_ECC_MAX_KEYLEN  XASU_ECC_P521_SIZE_IN_BYTES

/* One ASU ECC request. The buffers are heap-resident so the ASU DMA can reach
 * them; the caller's digest/signature may live in non-DMA memory. */
typedef struct {
    XAsu_EccParams params;
    byte key[2U * WC_ASU_ECC_MAX_KEYLEN];   /* priv d (sign) or Qx||Qy (verify) */
    byte digest[XASU_SHA_512_HASH_LEN];     /* message digest, <= 64 bytes */
    byte sign[2U * WC_ASU_ECC_MAX_KEYLEN];  /* raw r||s */
    int  op;
} AsuEccReq;

/* Submit thunk: queue one ASU ECC operation. */
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

/* Map the wolfSSL curve id to an ASU CurveType and byte length, declining any
 * curve that is not a supported NIST or Brainpool prime curve so wolfSSL falls
 * back to software. The key's domain size must match the mapped length. */
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
        /* P-521 offload is gated off by default: the stock firmware left-pads a
         * short digest, and the client caps DigestLen at 64 < the 66-byte curve
         * width, so HW P-521 signatures are non-standard. The front-pad firmware
         * fix was verified on hardware (see ECC_P521_DIGEST_ISSUE.md); enable this
         * macro only when running firmware that carries that fix. */
        case ECC_SECP521R1:
            type = (u32)XASU_ECC_NIST_P521;
            len  = (u32)XASU_ECC_P521_SIZE_IN_BYTES;
            break;
#endif
#ifdef HAVE_ECC_BRAINPOOL
        /* Brainpool prime curves: standard ECDSA, same digest handling as the NIST
         * curves (every width <= the 64-byte ASU digest cap, so no P-521 issue). */
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

/* Normalize the caller's digest into a fixed-width big-endian value matching the
 * standard ECDSA hash-to-integer, so the ASU computes the same e as software. The
 * ASU firmware reads the digest as a curve-width integer and zero-pads a short
 * digest in the LOW bytes (left-aligning the hash), so a digest narrower than the
 * width must be right-aligned here instead; a digest at least the width keeps its
 * leftmost width bytes (the supported curves have byte-aligned order lengths).
 * The width is the curve length, capped at the ASU's 64-byte digest maximum. */
static void wc_AsuEccDigest(const byte* hash, word32 hashLen, byte* out, u32 width)
{
    XMEMSET(out, 0, width);
    if (hashLen >= width) {
        XMEMCPY(out, hash, width);
    }
    else {
        XMEMCPY(out + (width - hashLen), hash, hashLen);
    }
}

/* True if the digest is entirely zero. An all-zero digest (z = 0) is a degenerate
 * ECDSA input the ASU does not sign/verify correctly, so it is deferred to
 * software (wolfcrypt_test's ecc_test_curve_size exercises this case). */
static int wc_AsuEccZeroDigest(const byte* d, word32 len)
{
    word32 i;

    for (i = 0; i < len; i++) {
        if (d[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Full-hardware ECDSA sign. wolfSSL passes the digest in info->pk.eccsign.in; the
 * ASU signs it with the private key and returns raw r||s, which is encoded to a
 * DER signature in info->pk.eccsign.out. */
static int wc_AsuEccSign(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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
    if (wc_AsuEccZeroDigest(info->pk.eccsign.in, info->pk.eccsign.inlen)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuEccCurve(key, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Private key is required to sign. */
    if (mp_iszero(key->k) || mp_unsigned_bin_size(key->k) > (int)keyLen) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Digest width fed to the ASU: the curve length, capped at the ASU maximum. */
    digLen = keyLen;
    if (digLen > (u32)XASU_SHA_512_HASH_LEN) {
        digLen = (u32)XASU_SHA_512_HASH_LEN;
    }

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    if (mp_to_unsigned_bin_len(key->k, req->key, (int)keyLen) < 0) {
        ret = WC_HW_E;
        goto out;
    }
    wc_AsuEccDigest(info->pk.eccsign.in, info->pk.eccsign.inlen, req->digest,
        digLen);

    req->op                 = WC_ASU_ECC_OP_SIGN;
    req->params.CurveType   = curveType;
    req->params.KeyLen      = keyLen;
    req->params.DigestLen   = digLen;
    req->params.KeyAddr     = (u64)(UINTPTR)req->key;
    req->params.DigestAddr  = (u64)(UINTPTR)req->digest;
    req->params.SignAddr    = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ecc sign curve=%u keyLen=%u digestLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)digLen);

    wc_AsuCacheFlush(req->key, keyLen);
    wc_AsuCacheFlush(req->digest, digLen);

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->sign, 2U * keyLen);

    WC_ASU_PRINTF("[ASU] ecc sign st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        /* Defer to software on any ASU failure rather than hard-failing the
         * sign; software is authoritative and handles edge-case inputs. */
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
    /* Encode the ASU's raw r||s (each keyLen, big-endian) as a DER signature. */
    ret = wc_ecc_rs_raw_to_sig(req->sign, keyLen, req->sign + keyLen, keyLen,
        info->pk.eccsign.out, info->pk.eccsign.outlen);

out:
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Full-hardware ECDSA verify. wolfSSL passes the DER signature and the digest;
 * the signature is converted to raw r||s and the ASU does the public-key verify,
 * returning its verdict in the additional status. *res is set to 1 only on a
 * verified result (fail-closed otherwise). */
static int wc_AsuEccVerify(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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
    if (wc_AsuEccZeroDigest(info->pk.eccverify.hash, info->pk.eccverify.hashlen)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuEccCurve(key, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Digest width fed to the ASU: the curve length, capped at the ASU maximum. */
    digLen = keyLen;
    if (digLen > (u32)XASU_SHA_512_HASH_LEN) {
        digLen = (u32)XASU_SHA_512_HASH_LEN;
    }

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    /* Public key Qx||Qy, each left-zero-padded to the curve width. */
    if (mp_to_unsigned_bin_len(key->pubkey.x, req->key, (int)keyLen) < 0 ||
        mp_to_unsigned_bin_len(key->pubkey.y, req->key + keyLen,
            (int)keyLen) < 0) {
        ret = WC_HW_E;
        goto out;
    }

    /* DER signature -> raw r,s (natural length), right-aligned to keyLen each. */
    rLen = keyLen;
    sLen = keyLen;
    ret = wc_ecc_sig_to_rs(info->pk.eccverify.sig, info->pk.eccverify.siglen,
        req->sign, &rLen, req->sign + keyLen, &sLen);
    if (ret != 0 || rLen > keyLen || sLen > keyLen) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
    if (rLen < keyLen) {
        XMEMMOVE(req->sign + (keyLen - rLen), req->sign, rLen);
        XMEMSET(req->sign, 0, keyLen - rLen);
    }
    if (sLen < keyLen) {
        XMEMMOVE(req->sign + keyLen + (keyLen - sLen), req->sign + keyLen, sLen);
        XMEMSET(req->sign + keyLen, 0, keyLen - sLen);
    }

    wc_AsuEccDigest(info->pk.eccverify.hash, info->pk.eccverify.hashlen,
        req->digest, digLen);

    req->op                 = WC_ASU_ECC_OP_VERIFY;
    req->params.CurveType   = curveType;
    req->params.KeyLen      = keyLen;
    req->params.DigestLen   = digLen;
    req->params.KeyAddr     = (u64)(UINTPTR)req->key;
    req->params.DigestAddr  = (u64)(UINTPTR)req->digest;
    req->params.SignAddr    = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ecc verify curve=%u keyLen=%u digestLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)digLen);

    wc_AsuCacheFlush(req->key, 2U * keyLen);
    wc_AsuCacheFlush(req->digest, digLen);
    wc_AsuCacheFlush(req->sign, 2U * keyLen);

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    WC_ASU_PRINTF("[ASU] ecc verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    /* A clean VERIFIED status confirms the signature. Anything else (mismatch or
     * an input the ASU rejected) defers to software, which is authoritative: it
     * confirms a valid signature the ASU could not process and rejects a truly
     * bad one, so the result is always correct and never a false rejection. */
    if (status == XST_SUCCESS &&
        addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.eccverify.res = 1;
        ret = 0;
    }
    else {
        ret = CRYPTOCB_UNAVAILABLE;
    }

out:
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#ifdef HAVE_ED25519

/* Full-hardware Ed25519 sign. The ASU hashes the raw message internally (SHA-512),
 * so wolfSSL's message goes through the digest parameter and the 32-byte private
 * seed (the first half of key->k) through the key parameter; the ASU returns the
 * standard 64-byte R||S signature. Only plain Ed25519 (no context, no prehash) maps
 * to the ASU; anything else declines to software. */
static int wc_AsuEd25519Sign(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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
    /* The ASU implements only plain Ed25519; ctx/prehash or a context string defer
     * to software. Ed25519 is -1, stored in the byte type field. */
    if (info->pk.ed25519sign.type != (byte)Ed25519 ||
        info->pk.ed25519sign.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Match software's precondition: signing needs both the private seed and the
     * public key set. wolfSSL rejects a private-only key with BAD_FUNC_ARG, so
     * decline rather than sign it on hardware (the ASU would derive the public key
     * and succeed, diverging from software). */
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

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    /* DMA-resident copy of the message; the (zeroed) digest field is the non-NULL
     * stand-in the client requires for a zero-length message. */
    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            ret = MEMORY_E;
            goto out;
        }
        XMEMCPY(msg, info->pk.ed25519sign.in, msgLen);
    }
    else {
        msg = req->digest;
    }

    XMEMCPY(req->key, key->k, ED25519_KEY_SIZE);

    req->op                = WC_ASU_ECC_OP_SIGN;
    req->params.CurveType  = (u32)XASU_ECC_NIST_ED25519;
    req->params.KeyLen     = (u32)ED25519_KEY_SIZE;
    req->params.DigestLen  = msgLen;
    req->params.KeyAddr    = (u64)(UINTPTR)req->key;
    req->params.DigestAddr = (u64)(UINTPTR)msg;
    req->params.SignAddr   = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ed25519 sign msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(req->key, ED25519_KEY_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->sign, ED25519_SIG_SIZE);

    WC_ASU_PRINTF("[ASU] ed25519 sign st=%u\r\n", (unsigned int)status);

    if (status != XST_SUCCESS) {
        /* Defer to software on any ASU failure; software is authoritative. */
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
    XMEMCPY(info->pk.ed25519sign.out, req->sign, ED25519_SIG_SIZE);
    *info->pk.ed25519sign.outLen = ED25519_SIG_SIZE;
    ret = 0;

out:
    if (msgLen != 0 && msg != NULL) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Full-hardware Ed25519 verify. wolfSSL passes the 64-byte signature, the message,
 * and the 32-byte compressed public key (key->p). The ASU public-key buffer is the
 * curve point as 32 zero bytes (unused Qx) followed by the compressed key (Qy); the
 * ASU hashes the message internally and returns its verdict in the additional
 * status. *res is set to 1 only on a verified result (fail-closed otherwise). */
static int wc_AsuEd25519Verify(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            ret = MEMORY_E;
            goto out;
        }
        XMEMCPY(msg, info->pk.ed25519verify.msg, msgLen);
    }
    else {
        msg = req->digest;
    }

    /* Public-key buffer: leading zero Qx then the compressed key in the Qy half. */
    XMEMCPY(req->key + ED25519_PUB_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);
    XMEMCPY(req->sign, info->pk.ed25519verify.sig, ED25519_SIG_SIZE);

    req->op                = WC_ASU_ECC_OP_VERIFY;
    req->params.CurveType  = (u32)XASU_ECC_NIST_ED25519;
    req->params.KeyLen     = (u32)ED25519_KEY_SIZE;
    req->params.DigestLen  = msgLen;
    req->params.KeyAddr    = (u64)(UINTPTR)req->key;
    req->params.DigestAddr = (u64)(UINTPTR)msg;
    req->params.SignAddr   = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ed25519 verify msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(req->key, 2U * ED25519_KEY_SIZE);
    wc_AsuCacheFlush(req->sign, ED25519_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    WC_ASU_PRINTF("[ASU] ed25519 verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    /* Confirm only on a clean VERIFIED status; otherwise defer to software, which is
     * authoritative and never produces a false rejection (see wc_AsuEccVerify). */
    if (status == XST_SUCCESS &&
        addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.ed25519verify.res = 1;
        ret = 0;
    }
    else {
        ret = CRYPTOCB_UNAVAILABLE;
    }

out:
    if (msgLen != 0 && msg != NULL) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* HAVE_ED25519 */

#ifdef HAVE_ED448

/* Full-hardware Ed448 sign. Mirrors the Ed25519 handler: the ASU hashes the raw
 * message internally (SHAKE256), so wolfSSL's message goes through the digest
 * parameter and the 57-byte private seed (the first half of key->k) through the key
 * parameter; the ASU returns the standard 114-byte signature. Only plain Ed448 (no
 * context, no prehash) maps to the ASU; anything else declines to software. */
static int wc_AsuEd448Sign(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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
    /* The ASU implements only plain Ed448; ctx/prehash or a context string defer to
     * software. Ed448 is 0, stored in the byte type field. */
    if (info->pk.ed448sign.type != (byte)Ed448 ||
        info->pk.ed448sign.contextLen != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Match software's precondition: signing needs both the private seed and the
     * public key set. wolfSSL rejects a private-only key with BAD_FUNC_ARG, so
     * decline rather than sign it on hardware. */
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

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            ret = MEMORY_E;
            goto out;
        }
        XMEMCPY(msg, info->pk.ed448sign.in, msgLen);
    }
    else {
        msg = req->digest;
    }

    XMEMCPY(req->key, key->k, ED448_KEY_SIZE);

    req->op                = WC_ASU_ECC_OP_SIGN;
    req->params.CurveType  = (u32)XASU_ECC_NIST_ED448;
    req->params.KeyLen     = (u32)ED448_KEY_SIZE;
    req->params.DigestLen  = msgLen;
    req->params.KeyAddr    = (u64)(UINTPTR)req->key;
    req->params.DigestAddr = (u64)(UINTPTR)msg;
    req->params.SignAddr   = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ed448 sign msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(req->key, ED448_KEY_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->sign, ED448_SIG_SIZE);

    WC_ASU_PRINTF("[ASU] ed448 sign st=%u\r\n", (unsigned int)status);

    if (status != XST_SUCCESS) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
    XMEMCPY(info->pk.ed448sign.out, req->sign, ED448_SIG_SIZE);
    *info->pk.ed448sign.outLen = ED448_SIG_SIZE;
    ret = 0;

out:
    if (msgLen != 0 && msg != NULL) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Full-hardware Ed448 verify. wolfSSL passes the 114-byte signature, the message,
 * and the 57-byte compressed public key (key->p). The ASU public-key buffer is the
 * curve point as 57 zero bytes (unused Qx) followed by the compressed key (Qy); the
 * ASU hashes the message internally and returns its verdict in the additional
 * status. *res is set to 1 only on a verified result (fail-closed otherwise). */
static int wc_AsuEd448Verify(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEccReq, 1, NULL);
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

    WC_ALLOC_VAR_EX(req, AsuEccReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    if (msgLen != 0) {
        msg = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            ret = MEMORY_E;
            goto out;
        }
        XMEMCPY(msg, info->pk.ed448verify.msg, msgLen);
    }
    else {
        msg = req->digest;
    }

    /* Public-key buffer: leading zero Qx then the compressed key in the Qy half. */
    XMEMCPY(req->key + ED448_PUB_KEY_SIZE, key->p, ED448_PUB_KEY_SIZE);
    XMEMCPY(req->sign, info->pk.ed448verify.sig, ED448_SIG_SIZE);

    req->op                = WC_ASU_ECC_OP_VERIFY;
    req->params.CurveType  = (u32)XASU_ECC_NIST_ED448;
    req->params.KeyLen     = (u32)ED448_KEY_SIZE;
    req->params.DigestLen  = msgLen;
    req->params.KeyAddr    = (u64)(UINTPTR)req->key;
    req->params.DigestAddr = (u64)(UINTPTR)msg;
    req->params.SignAddr   = (u64)(UINTPTR)req->sign;

    WC_ASU_PRINTF("[ASU] ed448 verify msgLen=%u\r\n", (unsigned int)msgLen);

    wc_AsuCacheFlush(req->key, 2U * ED448_KEY_SIZE);
    wc_AsuCacheFlush(req->sign, ED448_SIG_SIZE);
    if (msgLen != 0) {
        wc_AsuCacheFlush(msg, msgLen);
    }

    status = wc_AsuTransact(wc_AsuEccSubmit, req, &addl);

    WC_ASU_PRINTF("[ASU] ed448 verify st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status == XST_SUCCESS &&
        addl == (word32)XASU_ECC_SIGNATURE_VERIFIED) {
        *info->pk.ed448verify.res = 1;
        ret = 0;
    }
    else {
        ret = CRYPTOCB_UNAVAILABLE;
    }

out:
    if (msgLen != 0 && msg != NULL) {
        XFREE(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* HAVE_ED448 */

/* WC_ALGO_TYPE_PK entry point for ECC: dispatch ECDSA sign and verify. Other ECC
 * operations and unsupported curves decline to software. */
int wc_AsuEcc(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.type) {
        case WC_PK_TYPE_ECDSA_SIGN:
            return wc_AsuEccSign(info);
        case WC_PK_TYPE_ECDSA_VERIFY:
            return wc_AsuEccVerify(info);
#ifdef HAVE_ED25519
        case WC_PK_TYPE_ED25519_SIGN:
            return wc_AsuEd25519Sign(info);
        case WC_PK_TYPE_ED25519_VERIFY:
            return wc_AsuEd25519Verify(info);
#endif
#ifdef HAVE_ED448
        case WC_PK_TYPE_ED448:
            return wc_AsuEd448Sign(info);
        case WC_PK_TYPE_ED448_VERIFY:
            return wc_AsuEd448Verify(info);
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECC */
