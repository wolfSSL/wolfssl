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
 * PSS verify arrives through the dedicated wc_CryptoCb_RsaPssVerify hook with
 * the signature AND the digest so the ASU does the whole verify and returns
 * pass or fail. Each RSA key number is written into a fixed-size byte array,
 * padded with zeros on the left (mp_to_unsigned_bin_len), which is the layout
 * the ASU key structs expect (checked against the xilasu RSA known-answer
 * example).
 *
 * OAEP encrypt is full hardware (ASU does the SHA/MGF encode and the RSA math).
 * OAEP decrypt is NOT offloaded here: the ASU OAEP-decode command returns no
 * recovered-message length, which wolfSSL requires, so it declines to software
 * (the private RSA math is still offloaded through the raw WC_PK_TYPE_RSA
 * path).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* Also require RSA itself: a size profile can define NO_RSA in settings.h after
 * asu_settings.h auto-enabled this engine; gate on both, not an #error. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && !defined(NO_RSA)

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

/* Submit-thunk op selector. */
#define WC_ASU_RSA_OP_PUB        0   /* XAsu_RsaEnc:       public  m^e mod n */
#define WC_ASU_RSA_OP_PVT        1   /* XAsu_RsaDec:       private c^d mod n */
#define WC_ASU_RSA_OP_PSS_SIGN   2   /* XAsu_RsaPssSignGen */
#define WC_ASU_RSA_OP_PSS_VERIFY 3   /* XAsu_RsaPssSignVer */
#define WC_ASU_RSA_OP_OAEP_ENC   4   /* XAsu_RsaOaepEnc */

/* Everything one RSA request needs: the operation/padding info plus the key.
 * Public-key operations (encrypt, verify) use only the public part. */
/* It is large (about 2.5 KB), so wc_AsuRsaReqNew allocates it on the heap, not
 * on the stack. */
typedef struct {
    XAsu_RsaPaddingParams     pad;
    XAsu_RsaOaepPaddingParams oaep;                    /* OAEP encrypt params */
    XAsu_RsaPvtKeyComp        key;
    /* ALIGN64 so an invalidate range never shares a cache line with CPU-owned
     * data and stamps stale bytes over the DMA result (see asu_cmac.c). */
    ALIGN64 byte          out[XRSA_4096_KEY_SIZE];  /* DMA result, copied out */
    ALIGN64 byte          scratch[XRSA_4096_KEY_SIZE]; /* PSS sig/OAEP label */
    int                   op;
} AsuRsaReq;

/* Line the request up on a 64-byte boundary so the hardware output buffer does
 * not share space with the key. *raw returns the pointer to free later. */
static AsuRsaReq* wc_AsuRsaReqNew(void** raw)
{
#ifdef WC_ASU_DISABLE_CACHE
    /* Cache off: nothing to align for, so allocate plainly. */
    AsuRsaReq* p = (AsuRsaReq*)XMALLOC(sizeof(AsuRsaReq), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    *raw = p;
    return p;
#else
    byte* p = (byte*)XMALLOC(sizeof(AsuRsaReq) + 63U, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    *raw = p;
    if (p == NULL) {
        return NULL;
    }
    return (AsuRsaReq*)(void*)(((UINTPTR)p + 63U) & ~(UINTPTR)63U);
#endif
}

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
    if (n != (int)XRSA_2048_KEY_SIZE && n != (int)XRSA_3072_KEY_SIZE &&
        n != (int)XRSA_4096_KEY_SIZE) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Byte length alone accepts a short (leading-zero-bit) modulus; require the
     * exact bit width so raw, PSS and OAEP all decline it to software. */
    if (mp_count_bits(&key->n) != n * 8) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *keySize = (u32)n;
    return 0;
}

/* Copy the public key numbers (modulus, exponent) into the ASU struct as
 * fixed-size byte arrays; the public exponent must fit the 32-bit PubExp. */
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

#ifdef WOLF_CRYPTO_CB_RSA_PAD
/* Map a wolfSSL hash type to the ASU SHA type/mode and digest length; the ASU
 * uses one hash for message and MGF, so a mismatched MGF declines (else 0). */
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
#endif /* WOLF_CRYPTO_CB_RSA_PAD */

/* Raw RSA math: public (m^e) or private (c^d) in one ASU operation. The input
 * is one full modulus-width block and the result is keySize bytes. */
static int wc_AsuRsaRaw(wc_CryptoInfo* info, RsaKey* key, u32 keySize, int op)
{
    AsuRsaReq* req;
    void*      reqRaw = NULL;
    word32 addl = 0;
    word32 status;
    int    ret = 0;

    req = wc_AsuRsaReqNew(&reqRaw);
    if (req == NULL) {
        return MEMORY_E;
    }

    XMEMSET(req, 0, sizeof(*req));
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }
    /* Reject in >= n (SW: RSA_OUT_OF_RANGE_E); the ASU reduces mod n, so in and
     * in+n verify alike. The 0/1/n-1 small-input hardening is left to HW. */
    if (XMEMCMP(info->pk.rsa.in, req->key.PubKeyComp.Modulus, keySize) >= 0) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    if (op == WC_ASU_RSA_OP_PVT) {
        req->key.PrimeCompOrTotientPrsnt = 0U;
        if (mp_to_unsigned_bin_len_ct(&key->d, (byte*)req->key.PvtExp,
                (int)keySize) < 0) {
            ret = WC_HW_E;
            goto out;
        }
    }
#endif

    req->op                            = op;
    req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* The ASU DMA writes the result into the request buffer; the caller's
     * output may be in a region the DMA cannot reach, so copy it out after. */
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
    /* A private decrypt reports its own success in addl; the public path
     * trusts the SUCCESS status (the firmware writes the result on success). */
    if (op == WC_ASU_RSA_OP_PVT &&
        addl != (word32)XASU_RSA_DECRYPTION_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(info->pk.rsa.out, req->out, keySize);
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    /* The request held the private exponent / plaintext, which was DMA-flushed
     * to DRAM; flush the zeros too or the cleared bytes live only in cache. */
    wc_AsuCacheFlush(req, sizeof(*req));
    XFREE(reqRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    /* wc_CryptoCb_RsaPad maps an unknown pad_type here, so only a raw (no-pad)
     * request may run; decline real padding so SW does it, not a raw op. */
#ifdef WOLF_CRYPTO_CB_RSA_PAD
    if (info->pk.rsa.padding != NULL &&
        info->pk.rsa.padding->pad_type != WC_RSA_NO_PAD) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }

    /* The ASU DMAs a keySize-wide block from in; short input over-reads. */
    if (info->pk.rsa.inLen != keySize) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The ASU writes keySize bytes into out; reject a missing/short buffer. */
    if (info->pk.rsa.outLen == NULL || *info->pk.rsa.outLen < keySize) {
        return RSA_BUFFER_E;
    }

    if (info->pk.rsa.type == RSA_PUBLIC_ENCRYPT ||
        info->pk.rsa.type == RSA_PUBLIC_DECRYPT) {
        op = WC_ASU_RSA_OP_PUB;
    }
    else if (info->pk.rsa.type == RSA_PRIVATE_ENCRYPT ||
             info->pk.rsa.type == RSA_PRIVATE_DECRYPT) {
    #ifdef WOLFSSL_RSA_PUBLIC_ONLY
        return CRYPTOCB_UNAVAILABLE;
    #else
        op = WC_ASU_RSA_OP_PVT;
        /* Private op needs the private exponent. */
        if (mp_unsigned_bin_size(&key->d) == 0) {
            return CRYPTOCB_UNAVAILABLE;
        }
    #endif
    }
    else {
        return CRYPTOCB_UNAVAILABLE;
    }

    return wc_AsuRsaRaw(info, key, keySize, op);
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && defined(WOLF_CRYPTO_CB_RSA_PAD)
/* Full-hardware RSA-PSS sign: wolfSSL passes the digest in info->pk.rsa.in
 * (hashed-input mode); ASU does the PSS encode and private RSA math to out. */
static int wc_AsuRsaPssSign(wc_CryptoInfo* info)
{
    AsuRsaReq* req;
    void*      reqRaw = NULL;
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
    /* The ASU writes keySize signature bytes into out; reject short buffer. */
    if (info->pk.rsa.outLen == NULL || *info->pk.rsa.outLen < keySize) {
        return RSA_BUFFER_E;
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

    req = wc_AsuRsaReqNew(&reqRaw);
    if (req == NULL) {
        return MEMORY_E;
    }

    XMEMSET(req, 0, sizeof(*req));
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }
    req->key.PrimeCompOrTotientPrsnt = 0U;
    if (mp_to_unsigned_bin_len_ct(&key->d, (byte*)req->key.PvtExp,
            (int)keySize) < 0) {
        ret = WC_HW_E;
        goto out;
    }

    req->op                                = WC_ASU_RSA_OP_PSS_SIGN;
    req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* For sign the signature goes to OutputDataAddr (not SignatureDataAddr,
     * the verify input); DMA it into req->out and copy out after. */
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
    /* req->scratch is published as SignatureDataAddr; flush the XMEMSET-dirtied
     * lines to DRAM and invalidate after, like req->out and the verify path. */
    wc_AsuCacheFlush(req->scratch, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->out, keySize);
    wc_AsuCacheInvalidate(req->scratch, keySize);

    WC_ASU_PRINTF(
        "[ASU] pss-sign st=%u out %02x%02x%02x%02x..%02x%02x%02x%02x\r\n",
        (unsigned int)status,
        req->out[0], req->out[1], req->out[2], req->out[3],
        req->out[keySize - 4], req->out[keySize - 3], req->out[keySize - 2],
        req->out[keySize - 1]);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }
    XMEMCPY(info->pk.rsa.out, req->out, keySize);
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    /* The request held the private exponent / plaintext, which was DMA-flushed
     * to DRAM; flush the zeros too or the cleared bytes live only in cache. */
    wc_AsuCacheFlush(req, sizeof(*req));
    XFREE(reqRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY && WOLF_CRYPTO_CB_RSA_PAD */

#ifdef WOLF_CRYPTO_CB_RSA_PAD
/* Firmware packs its error into an ASU status: bits 0-9 and 10-19 each hold a
 * code; bad-sig PSS verify reports 0xC4..0xCA (decode/compare); match both. */
static int wc_AsuRsaPssIsReject(word32 status)
{
    word32 first  = status & 0x3FFU;
    word32 second = (status >> 10) & 0x3FFU;
    return ((first  >= 0xC4U && first  <= 0xCAU) ||
            (second >= 0xC4U && second <= 0xCAU));
}

/* Decode an ASU RSA verify into a verdict: *res = 1 verified / 0 rejected,
 * return 0 when the ASU gave a verdict, WC_HW_E only on transport fault. */
static int wc_AsuRsaVerifyResult(word32 status, word32 addl,
    word32 verifiedAddl, int* res)
{
    if (res == NULL) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    if (status == (word32)XST_SUCCESS) {
        if (addl == verifiedAddl) {
            *res = 1;
        }
        return 0;
    }
    if (wc_AsuRsaPssIsReject(status)) {
        return 0;
    }
    return WC_HW_E;
}

/* Full-hardware RSA-PSS verify via the wc_CryptoCb_RsaPssVerify hook with the
 * signature and digest; ASU does the RSA math + PSS check, *res=1 iff good. */
static int wc_AsuRsaPssVerify(wc_CryptoInfo* info)
{
    AsuRsaReq* req;
    void*      reqRaw = NULL;
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

    req = wc_AsuRsaReqNew(&reqRaw);
    if (req == NULL) {
        return MEMORY_E;
    }

    XMEMSET(req, 0, sizeof(*req));
    /* Verify is a public operation; only the public components are needed. */
    ret = wc_AsuRsaPubComp(key, keySize, &req->key.PubKeyComp);
    if (ret != 0) {
        goto out;
    }

    req->op                                = WC_ASU_RSA_OP_PSS_VERIFY;
    req->pad.XAsu_RsaOpComp.InputDataAddr  =
        (u64)(UINTPTR)info->pk.rsa_pss_verify.digest;
    req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&req->key;
    req->pad.XAsu_RsaOpComp.Len            = hashLen;
    req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    req->pad.SignatureDataAddr             =
        (u64)(UINTPTR)info->pk.rsa_pss_verify.sig;
    req->pad.SignatureLen                  = keySize;
    req->pad.SaltLen                       = (u32)saltLen;
    req->pad.ShaType                       = shaType;
    req->pad.ShaMode                       = shaMode;
    req->pad.InputDataType                 = (u8)XASU_RSA_HASHED_INPUT_DATA;

    /* Clear the verdict only now that every CRYPTOCB_UNAVAILABLE feasibility
     * exit has passed, so a decline never mutates the caller's result. */
    *info->pk.rsa_pss_verify.res = 0;

    wc_AsuCacheFlush(info->pk.rsa_pss_verify.digest, hashLen);
    wc_AsuCacheFlush(info->pk.rsa_pss_verify.sig, keySize);
    wc_AsuCacheFlush(&req->key, sizeof(req->key));

    status = wc_AsuTransact(wc_AsuRsaSubmit, req, &addl);

    WC_ASU_PRINTF("[ASU] rsa pss-verify keySize=%u status=%u addl=0x%x\r\n",
        (unsigned int)keySize, (unsigned int)status, (unsigned int)addl);

    /* VERIFIED -> res=1; a PSS decode/compare failure -> res=0 (bad signature);
     * any other non-success status -> WC_HW_E (a real fault). */
    ret = wc_AsuRsaVerifyResult(status, addl,
        (word32)XASU_RSA_PSS_SIGNATURE_VERIFIED, info->pk.rsa_pss_verify.res);

out:
    ForceZero(req, sizeof(*req));
    /* Verify is public-key only, so the request holds no secret; the scrub and
     * flush are just parity with the private paths. */
    wc_AsuCacheFlush(req, sizeof(*req));
    XFREE(reqRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* WOLF_CRYPTO_CB_RSA_PAD (PSS verify) */

#ifdef WOLF_CRYPTO_CB_RSA_PAD
/* Full-hardware RSA-OAEP encrypt (only); message in info->pk.rsa.in, OAEP
 * hash/MGF/label in .padding; ASU does the OAEP encode + public RSA math. */
static int wc_AsuRsaOaepEnc(wc_CryptoInfo* info)
{
    AsuRsaReq* req;
    void*      reqRaw = NULL;
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
    /* Only encrypt is offloaded; ASU OAEP-decode returns no message length. */
    if (info->pk.rsa.type != RSA_PUBLIC_ENCRYPT) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }
    /* The ASU writes keySize ciphertext bytes into out; reject short buffer. */
    if (info->pk.rsa.outLen == NULL || *info->pk.rsa.outLen < keySize) {
        return RSA_BUFFER_E;
    }
    ret = wc_AsuRsaShaMap(padding->hash, padding->mgf, &shaType, &shaMode,
        &hashLen);
    if (ret != 0) {
        return ret;
    }
    /* OAEP encodes at most keySize - 2*hashLen - 2 message bytes; wolfSSL only
     * enforces the generic minimum, so decline an oversized message to SW. */
    if ((2U * hashLen + 2U > keySize) ||
        (info->pk.rsa.inLen > keySize - 2U * hashLen - 2U)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    req = wc_AsuRsaReqNew(&reqRaw);
    if (req == NULL) {
        return MEMORY_E;
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
    /* A NULL label with a non-zero size is contradictory; wc_RsaPad_ex rejects
     * it with BUFFER_E, so do the same, not silently bind an empty label. */
    if (label == NULL && labelSz > 0) {
        ret = BUFFER_E;
        goto out;
    }
    if (label == NULL) {
        label = req->scratch;
        labelSz = 0;
    }

    req->op                                 = WC_ASU_RSA_OP_OAEP_ENC;
    req->oaep.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* DMA ciphertext to req->out, then copy to the (maybe non-DMA) caller. */
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
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    ret = 0;

out:
    ForceZero(req, sizeof(*req));
    /* The request held the plaintext message, DMA-flushed to DRAM; flush the
     * zeros too or the cleared bytes live only in cache (public-key op). */
    wc_AsuCacheFlush(req, sizeof(*req));
    XFREE(reqRaw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* WOLF_CRYPTO_CB_RSA_PAD (OAEP encrypt) */

/* WC_ALGO_TYPE_PK entry: dispatch on RSA pk sub-type. Raw always offloaded;
 * PSS and OAEP encrypt need WOLF_CRYPTO_CB_RSA_PAD; decrypt/PKCS to SW. */
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
    #ifdef WOLF_CRYPTO_CB_RSA_PAD
        #ifndef WOLFSSL_RSA_PUBLIC_ONLY
        case WC_PK_TYPE_RSA_PSS:
            return wc_AsuRsaPssSign(info);
        #endif
        case WC_PK_TYPE_RSA_PSS_VERIFY:
            return wc_AsuRsaPssVerify(info);
        case WC_PK_TYPE_RSA_OAEP:
            return wc_AsuRsaOaepEnc(info);
    #endif /* WOLF_CRYPTO_CB_RSA_PAD */
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA && !NO_RSA */
