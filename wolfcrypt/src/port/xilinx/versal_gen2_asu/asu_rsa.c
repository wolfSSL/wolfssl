/* asu_rsa.c
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

/* ASU RSA offload for the wolfSSL crypto callback.
 *
 * Handles the raw RSA operation (public m^e / private c^d) and full-hardware
 * RSA-PSS sign and verify. wolfSSL's WOLF_CRYPTO_CB_RSA_PAD path delivers PSS
 * sign here with the message digest, which maps to the ASU "hashed input" mode;
 * PSS verify arrives through the dedicated wc_CryptoCb_RsaPssVerify hook with the
 * signature AND the digest so the ASU does the whole verify and returns pass or
 * fail. Each RSA key number is written into a fixed-size byte array, padded
 * with zeros on the left (mp_to_unsigned_bin_len), which is the layout the ASU
 * key structs expect (checked against the xilasu RSA known-answer example).
 *
 * OAEP encrypt is full hardware (ASU does the SHA/MGF encode and the RSA math).
 * OAEP decrypt is NOT offloaded here: the ASU OAEP-decode command returns no
 * recovered-message length, which wolfSSL requires, so it declines to software
 * (the private RSA math is still offloaded through the raw WC_PK_TYPE_RSA path).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RSA

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_rsa.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_rsa.h"
#include "xasu_rsainfo.h"
#include "xasu_shainfo.h"
#include "xasu_status.h"
#include "xstatus.h"

#ifdef NO_RSA
    #error "WOLFSSL_VERSAL_GEN2_ASU_RSA requires RSA (NO_RSA is defined)"
#endif

/* Submit-thunk op selector. */
#define WC_ASU_RSA_OP_PUB        0   /* XAsu_RsaEnc:       public  m^e mod n */
#define WC_ASU_RSA_OP_PVT        1   /* XAsu_RsaDec:       private c^d mod n */
#define WC_ASU_RSA_OP_PSS_SIGN   2   /* XAsu_RsaPssSignGen */
#define WC_ASU_RSA_OP_PSS_VERIFY 3   /* XAsu_RsaPssSignVer */
#define WC_ASU_RSA_OP_OAEP_ENC   4   /* XAsu_RsaOaepEnc */

/* One ASU RSA request: the padding params (whose embedded XAsu_RsaOpComp serves
 * the raw operations) and the private-key components it points at (the public
 * components alone, at the start, serve a public operation). */
typedef struct {
    XAsu_RsaPaddingParams     pad;
    XAsu_RsaOaepPaddingParams oaep;                    /* OAEP encrypt params */
    XAsu_RsaPvtKeyComp        key;
    byte                  out[XRSA_4096_KEY_SIZE];     /* DMA result, copied out */
    byte                  scratch[XRSA_4096_KEY_SIZE]; /* PSS sign OutputDataAddr */
    int                   op;
} AsuRsaReq;

/* Submit thunk: queue one ASU RSA operation. */
static int wc_AsuRsaSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuRsaReq* req = (AsuRsaReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }
    switch (req->op) {
        case WC_ASU_RSA_OP_PUB:
            return XAsu_RsaEnc(params, &req->pad.XAsu_RsaOpComp);
        case WC_ASU_RSA_OP_PVT:
            return XAsu_RsaDec(params, &req->pad.XAsu_RsaOpComp);
        case WC_ASU_RSA_OP_PSS_SIGN:
            return XAsu_RsaPssSignGen(params, &req->pad);
        case WC_ASU_RSA_OP_PSS_VERIFY:
            return XAsu_RsaPssSignVer(params, &req->pad);
        case WC_ASU_RSA_OP_OAEP_ENC:
            return XAsu_RsaOaepEnc(params, &req->oaep);
        default:
            return XST_FAILURE;
    }
}

/* Map the modulus byte length to an ASU KeySize, declining anything that is not
 * 2048, 3072 or 4096 bit so wolfSSL falls back to software. */
static int wc_AsuRsaKeySize(RsaKey* key, u32* keySize)
{
    int n;

    if (key == NULL || keySize == NULL) {
        return BAD_FUNC_ARG;
    }
    n = mp_unsigned_bin_size(&key->n);
    if (n == (int)XRSA_2048_KEY_SIZE || n == (int)XRSA_3072_KEY_SIZE ||
        n == (int)XRSA_4096_KEY_SIZE) {
        *keySize = (u32)n;
        return 0;
    }
    return CRYPTOCB_UNAVAILABLE;
}

/* Copy the public key numbers (modulus, exponent) into the ASU struct as
 * fixed-size byte arrays (mp_to_unsigned_bin_len); the public exponent must fit
 * the 32-bit PubExp field. */
static int wc_AsuRsaPubComp(RsaKey* key, u32 keySize, XAsu_RsaPubKeyComp* pub)
{
    if (key == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (mp_unsigned_bin_size(&key->e) > (int)sizeof(pub->PubExp)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    XMEMSET(pub, 0, sizeof(*pub));
    pub->Keysize = keySize;
    if (mp_to_unsigned_bin_len(&key->e, (byte*)&pub->PubExp,
            (int)sizeof(pub->PubExp)) < 0) {
        return WC_HW_E;
    }
    if (mp_to_unsigned_bin_len(&key->n, (byte*)pub->Modulus,
            (int)keySize) < 0) {
        return WC_HW_E;
    }
    return 0;
}

/* Map a wolfSSL hash type to the ASU SHA type/mode and digest length. The ASU
 * uses one hash for the message hash and the MGF, so decline a mismatched MGF.
 * Returns 0 or CRYPTOCB_UNAVAILABLE. */
static int wc_AsuRsaShaMap(enum wc_HashType hash, int mgf, u8* shaType,
    u8* shaMode, word32* hashLen)
{
    if (shaType == NULL || shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }
    switch (hash) {
        case WC_HASH_TYPE_SHA256:
            *shaType = (u8)XASU_SHA2_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_256;
            *hashLen = XASU_SHA_256_HASH_LEN;
            if (mgf != WC_MGF1SHA256) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        case WC_HASH_TYPE_SHA384:
            *shaType = (u8)XASU_SHA2_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_384;
            *hashLen = XASU_SHA_384_HASH_LEN;
            if (mgf != WC_MGF1SHA384) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        case WC_HASH_TYPE_SHA512:
            *shaType = (u8)XASU_SHA2_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_512;
            *hashLen = XASU_SHA_512_HASH_LEN;
            if (mgf != WC_MGF1SHA512) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        case WC_HASH_TYPE_SHA3_256:
            *shaType = (u8)XASU_SHA3_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_256;
            *hashLen = XASU_SHA_256_HASH_LEN;
            if (mgf != WC_MGF1SHA3_256) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        case WC_HASH_TYPE_SHA3_384:
            *shaType = (u8)XASU_SHA3_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_384;
            *hashLen = XASU_SHA_384_HASH_LEN;
            if (mgf != WC_MGF1SHA3_384) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        case WC_HASH_TYPE_SHA3_512:
            *shaType = (u8)XASU_SHA3_TYPE;
            *shaMode = (u8)XASU_SHA_MODE_512;
            *hashLen = XASU_SHA_512_HASH_LEN;
            if (mgf != WC_MGF1SHA3_512) {
                return CRYPTOCB_UNAVAILABLE;
            }
            break;
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
    return 0;
}

/* Raw RSA math: public (m^e) or private (c^d) in one ASU operation. The input
 * is one full modulus-width block and the result is keySize bytes. */
static int wc_AsuRsaRaw(wc_CryptoInfo* info, RsaKey* key, u32 keySize, int op)
{
    WC_DECLARE_VAR(req, AsuRsaReq, 1, NULL);
    word32 addl = 0;
    word32 status;
    int    ret = 0;

    WC_ALLOC_VAR_EX(req, AsuRsaReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }
    if (op == WC_ASU_RSA_OP_PVT) {
        req->key.PrimeCompOrTotientPrsnt = 0U;
        if (mp_to_unsigned_bin_len(&key->d, (byte*)req->key.PvtExp,
                (int)keySize) < 0) {
            ret = WC_HW_E;
            goto out;
        }
    }

    req->op                            = op;
    req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* The ASU DMA writes the result into the request buffer; the caller's output
     * may be in a region the DMA cannot reach, so copy it out afterwards. */
    req->pad.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)req->out;
    req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&req->key;
    req->pad.XAsu_RsaOpComp.ExpoCompAddr   = 0U;
    req->pad.XAsu_RsaOpComp.Len            = keySize;
    req->pad.XAsu_RsaOpComp.KeySize        = keySize;

    WC_ASU_PRINTF("[ASU] rsa raw op=%d keySize=%u\r\n",
        op, (unsigned int)keySize);

    wc_AsuCacheFlush(info->pk.rsa.in, keySize);
    wc_AsuCacheFlush(&req->key, sizeof(req->key));
    wc_AsuCacheFlush(req->out, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->out, keySize);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }
    /* Private decrypt reports its own additional success status. */
    if (op == WC_ASU_RSA_OP_PVT &&
        addl != (word32)XASU_RSA_DECRYPTION_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(info->pk.rsa.out, req->out, keySize);
    if (info->pk.rsa.outLen != NULL) {
        *info->pk.rsa.outLen = keySize;
    }
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Pick the public or private RSA math for the WC_PK_TYPE_RSA direction. */
static int wc_AsuRsaRawDispatch(wc_CryptoInfo* info)
{
    RsaKey* key = info->pk.rsa.key;
    u32     keySize = 0;
    int     op;
    int     ret;

    if (key == NULL || info->pk.rsa.in == NULL || info->pk.rsa.out == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }

    if (info->pk.rsa.type == RSA_PUBLIC_ENCRYPT ||
        info->pk.rsa.type == RSA_PUBLIC_DECRYPT) {
        op = WC_ASU_RSA_OP_PUB;
    }
    else if (info->pk.rsa.type == RSA_PRIVATE_ENCRYPT ||
             info->pk.rsa.type == RSA_PRIVATE_DECRYPT) {
        op = WC_ASU_RSA_OP_PVT;
        /* Private op needs the private exponent. */
        if (mp_unsigned_bin_size(&key->d) == 0) {
            return CRYPTOCB_UNAVAILABLE;
        }
    }
    else {
        return CRYPTOCB_UNAVAILABLE;
    }

    return wc_AsuRsaRaw(info, key, keySize, op);
}

/* Full-hardware RSA-PSS sign. wolfSSL passes the message digest in info->pk.rsa.in
 * (hashed-input mode); the ASU does the PSS encode and private RSA math, writing
 * the signature to info->pk.rsa.out. */
static int wc_AsuRsaPssSign(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuRsaReq, 1, NULL);
    RsaKey* key = info->pk.rsa.key;
    RsaPadding* padding = info->pk.rsa.padding;
    u32     keySize = 0;
    u8      shaType = 0;
    u8      shaMode = 0;
    word32  hashLen = 0;
    int     saltLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || padding == NULL || info->pk.rsa.in == NULL ||
        info->pk.rsa.out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.rsa.type != RSA_PRIVATE_ENCRYPT) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (mp_unsigned_bin_size(&key->d) == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuRsaShaMap(padding->hash, padding->mgf, &shaType, &shaMode,
        &hashLen);
    if (ret != 0) {
        return ret;
    }
    /* wolfSSL hands us the digest; it must match the hash length. */
    if (info->pk.rsa.inLen != hashLen) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Only DEFAULT (use the hash length) can offload. DISCOVER and any other
     * out-of-range salt go to software, which handles or rejects them. */
    saltLen = padding->saltLen;
    if (saltLen == RSA_PSS_SALT_LEN_DEFAULT) {
        saltLen = (int)hashLen;
    }
    if ((saltLen < 0) || ((word32)saltLen > hashLen)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    WC_ALLOC_VAR_EX(req, AsuRsaReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }
    req->key.PrimeCompOrTotientPrsnt = 0U;
    if (mp_to_unsigned_bin_len(&key->d, (byte*)req->key.PvtExp,
            (int)keySize) < 0) {
        ret = WC_HW_E;
        goto out;
    }

    req->op                                = WC_ASU_RSA_OP_PSS_SIGN;
    req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* For sign the signature is written to OutputDataAddr (not SignatureDataAddr,
     * which is the verify input); DMA it into req->out and copy out after. */
    req->pad.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)req->out;
    req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&req->key;
    req->pad.XAsu_RsaOpComp.Len            = hashLen;
    req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    req->pad.SignatureDataAddr             = (u64)(UINTPTR)req->scratch;
    req->pad.SignatureLen                  = keySize;
    req->pad.SaltLen                       = (u32)saltLen;
    req->pad.ShaType                       = shaType;
    req->pad.ShaMode                       = shaMode;
    req->pad.InputDataType                 = (u8)XASU_RSA_HASHED_INPUT_DATA;

    WC_ASU_PRINTF("[ASU] rsa pss-sign keySize=%u shaMode=%u saltLen=%d\r\n",
        (unsigned int)keySize, (unsigned int)shaMode, saltLen);

    wc_AsuCacheFlush(info->pk.rsa.in, hashLen);
    wc_AsuCacheFlush(&req->key, sizeof(req->key));
    wc_AsuCacheFlush(req->out, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->out, keySize);

    WC_ASU_PRINTF("[ASU] pss-sign st=%u out %02x%02x%02x%02x..%02x%02x%02x%02x\r\n",
        (unsigned int)status, req->out[0], req->out[1], req->out[2], req->out[3],
        req->out[keySize - 4], req->out[keySize - 3], req->out[keySize - 2],
        req->out[keySize - 1]);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }
    XMEMCPY(info->pk.rsa.out, req->out, keySize);
    if (info->pk.rsa.outLen != NULL) {
        *info->pk.rsa.outLen = keySize;
    }
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Full-hardware RSA-PSS verify, reached through the wc_CryptoCb_RsaPssVerify hook
 * with both the signature and the message digest. The ASU does the public RSA
 * math and PSS check and returns pass or fail; *res is set to 1 only when the
 * signature is good (fail-closed otherwise). */
static int wc_AsuRsaPssVerify(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuRsaReq, 1, NULL);
    RsaKey* key = info->pk.rsa_pss_verify.key;
    u32     keySize = 0;
    u8      shaType = 0;
    u8      shaMode = 0;
    word32  hashLen = 0;
    int     saltLen;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info->pk.rsa_pss_verify.res == NULL) {
        return BAD_FUNC_ARG;
    }
    *info->pk.rsa_pss_verify.res = 0;

    if (key == NULL || info->pk.rsa_pss_verify.sig == NULL ||
        info->pk.rsa_pss_verify.digest == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }
    if (info->pk.rsa_pss_verify.sigSz != keySize) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = wc_AsuRsaShaMap(info->pk.rsa_pss_verify.hash,
        info->pk.rsa_pss_verify.mgf, &shaType, &shaMode, &hashLen);
    if (ret != 0) {
        return ret;
    }
    if (info->pk.rsa_pss_verify.digestSz != hashLen) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* DEFAULT maps to the hash length; DISCOVER needs the salt read back from
     * the signature, which the hardware cannot do, so hand that to software. */
    saltLen = info->pk.rsa_pss_verify.saltLen;
    if (saltLen == RSA_PSS_SALT_LEN_DEFAULT) {
        saltLen = (int)hashLen;
    }
    if ((saltLen < 0) || ((word32)saltLen > hashLen)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    WC_ALLOC_VAR_EX(req, AsuRsaReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    /* Verify is a public operation; only the public components are needed. */
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }

    req->op                                = WC_ASU_RSA_OP_PSS_VERIFY;
    req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa_pss_verify.digest;
    req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&req->key;
    req->pad.XAsu_RsaOpComp.Len            = hashLen;
    req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    req->pad.SignatureDataAddr             = (u64)(UINTPTR)info->pk.rsa_pss_verify.sig;
    req->pad.SignatureLen                  = keySize;
    req->pad.SaltLen                       = (u32)saltLen;
    req->pad.ShaType                       = shaType;
    req->pad.ShaMode                       = shaMode;
    req->pad.InputDataType                 = (u8)XASU_RSA_HASHED_INPUT_DATA;

    wc_AsuCacheFlush(info->pk.rsa_pss_verify.digest, hashLen);
    wc_AsuCacheFlush(info->pk.rsa_pss_verify.sig, keySize);
    wc_AsuCacheFlush(&req->key, sizeof(req->key));

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    WC_ASU_PRINTF("[ASU] rsa pss-verify keySize=%u status=%u addl=0x%x\r\n",
        (unsigned int)keySize, (unsigned int)status, (unsigned int)addl);

    /* Fail-closed: only a clean VERIFIED status counts as verified. */
    if (status == XST_SUCCESS &&
        addl == (word32)XASU_RSA_PSS_SIGNATURE_VERIFIED) {
        *info->pk.rsa_pss_verify.res = 1;
    }
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Full-hardware RSA-OAEP encrypt. wolfSSL hands us the raw message in
 * info->pk.rsa.in with the OAEP hash/MGF/label in info->pk.rsa.padding; the ASU
 * does the OAEP encode and public RSA math, writing keySize bytes to the output.
 * Only encrypt is offloaded: OAEP decrypt declines (see file header). */
static int wc_AsuRsaOaepEnc(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuRsaReq, 1, NULL);
    RsaKey* key = info->pk.rsa.key;
    RsaPadding* padding = info->pk.rsa.padding;
    u32     keySize = 0;
    u8      shaType = 0;
    u8      shaMode = 0;
    word32  hashLen = 0;
    const byte* label;
    word32  labelSz;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || padding == NULL || info->pk.rsa.in == NULL ||
        info->pk.rsa.out == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Only encrypt is offloaded; the ASU OAEP-decode returns no message length. */
    if (info->pk.rsa.type != RSA_PUBLIC_ENCRYPT) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuRsaShaMap(padding->hash, padding->mgf, &shaType, &shaMode,
        &hashLen);
    if (ret != 0) {
        return ret;
    }

    WC_ALLOC_VAR_EX(req, AsuRsaReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }

    /* The ASU requires a non-zero label address; an empty label (wolfSSL's
     * default) passes a valid address with size 0, hashing the empty string. */
    label = padding->label;
    labelSz = padding->labelSz;
    if (label == NULL) {
        label = req->scratch;
        labelSz = 0;
    }

    req->op                                 = WC_ASU_RSA_OP_OAEP_ENC;
    req->oaep.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* DMA the ciphertext into req->out, then copy to the (maybe non-DMA) caller. */
    req->oaep.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)req->out;
    req->oaep.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&req->key;
    req->oaep.XAsu_RsaOpComp.Len            = info->pk.rsa.inLen;
    req->oaep.XAsu_RsaOpComp.KeySize        = keySize;
    req->oaep.OptionalLabelAddr             = (u64)(UINTPTR)label;
    req->oaep.OptionalLabelSize             = labelSz;
    req->oaep.ShaType                       = shaType;
    req->oaep.ShaMode                       = shaMode;

    WC_ASU_PRINTF("[ASU] rsa oaep-enc keySize=%u shaMode=%u labelSz=%u\r\n",
        (unsigned int)keySize, (unsigned int)shaMode, (unsigned int)labelSz);

    wc_AsuCacheFlush(info->pk.rsa.in, info->pk.rsa.inLen);
    if (labelSz > 0) {
        wc_AsuCacheFlush(label, labelSz);
    }
    wc_AsuCacheFlush(&req->key, sizeof(req->key));
    wc_AsuCacheFlush(req->out, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->out, keySize);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }
    XMEMCPY(info->pk.rsa.out, req->out, keySize);
    if (info->pk.rsa.outLen != NULL) {
        *info->pk.rsa.outLen = keySize;
    }
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* WC_ALGO_TYPE_PK entry point: dispatch on the RSA pk sub-type. Raw, PSS sign,
 * PSS verify and OAEP encrypt are offloaded; OAEP decrypt and PKCS decline to
 * software (the raw RSA math is still offloaded through WC_PK_TYPE_RSA). */
int wc_AsuRsa(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.type) {
        case WC_PK_TYPE_RSA:
            return wc_AsuRsaRawDispatch(info);
        case WC_PK_TYPE_RSA_PSS:
            return wc_AsuRsaPssSign(info);
        case WC_PK_TYPE_RSA_PSS_VERIFY:
            return wc_AsuRsaPssVerify(info);
        case WC_PK_TYPE_RSA_OAEP:
            return wc_AsuRsaOaepEnc(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA */
