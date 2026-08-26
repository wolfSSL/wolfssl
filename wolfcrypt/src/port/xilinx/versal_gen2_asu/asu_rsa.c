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
 * OAEP decrypt is full hardware from Vitis 2026.1, which returns the recovered
 * message length the decode needs; before that the length was lost, so it
 * declined to software with only the private RSA math offloaded through the raw
 * WC_PK_TYPE_RSA path, and it still does on 2025.2.
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

/* Effective PSS/OAEP offload switch. WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD forces
 * padding to software even if WOLF_CRYPTO_CB_RSA_PAD is set from elsewhere. */
#if defined(WOLF_CRYPTO_CB_RSA_PAD) && \
    !defined(WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD)
    #define WC_ASU_RSA_PAD
#endif

/* OAEP decrypt needs the recovered-message length back, which only the 2026.1
 * client returns (through OutputLenAddr). Before that the decode ran on the
 * ASU but the length was lost, so wolfSSL could not use the result. */
/* It also needs the private exponent, which RsaKey does not carry under
 * WOLFSSL_RSA_PUBLIC_ONLY, so the offload stays out of that build. */
#if defined(WC_ASU_RSA_PAD) && \
    defined(WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    #define WC_ASU_RSA_OAEP_DEC
#endif

/* Submit-thunk op selector. */
#define WC_ASU_RSA_OP_PUB        0   /* XAsu_RsaEnc:       public  m^e mod n */
#define WC_ASU_RSA_OP_PVT        1   /* XAsu_RsaDec:       private c^d mod n */
#define WC_ASU_RSA_OP_PSS_SIGN   2   /* XAsu_RsaPssSignGen */
#define WC_ASU_RSA_OP_PSS_VERIFY 3   /* XAsu_RsaPssSignVer */
#define WC_ASU_RSA_OP_OAEP_ENC   4   /* XAsu_RsaOaepEnc */
#define WC_ASU_RSA_OP_OAEP_DEC   5   /* XAsu_RsaOaepDec */

/* Everything one RSA request needs: the operation/padding info plus the key.
 * Public-key operations (encrypt, verify) use only the public part. */
/* It is large (about 2.5 KB), so wc_AsuRsaReqNew allocates it on the heap, not
 * on the stack. */
typedef struct {
    XAsu_RsaPaddingParams     pad;
    XAsu_RsaOaepPaddingParams oaep;                    /* OAEP encrypt params */
    XAsu_RsaPvtKeyComp        key;
    /* 64-byte aligned so an invalidate range never shares a cache line with
     * CPU-owned data and stamps stale bytes over the DMA result. */
    WC_ASU_ALIGN64 byte   out[XRSA_4096_KEY_SIZE];  /* DMA result, copied out */
    WC_ASU_ALIGN64 byte   scratch[XRSA_4096_KEY_SIZE]; /* PSS sig/OAEP label */
    /* 2026.1 returns the produced length here through the mailbox, and the
     * client refuses a request that does not offer somewhere to put it. */
    u32                   outLen;
    int                   op;
} AsuRsaReq;

/* Carries the request's original allocation and its aligned view together, so
 * they never get separated: use .req for the op, and Free frees .raw. */
typedef struct {
    void*      raw;   /* the pointer XMALLOC returned, the one to free */
    AsuRsaReq* req;   /* the 64-byte aligned request the operation uses */
} AsuRsaMem;

/* Allocate a request lined up on a 64-byte boundary (cache on) so the hardware
 * output buffer owns its cache line. Fills mem, returns 0 or MEMORY_E. */
static int wc_AsuRsaReqNew(AsuRsaMem* mem)
{
    if (mem == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef WC_ASU_DISABLE_CACHE
    /* Cache off: nothing to align for, so allocate plainly. */
    mem->raw = XMALLOC(sizeof(AsuRsaReq), NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    mem->raw = XMALLOC(sizeof(AsuRsaReq) + 63U, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    if (mem->raw == NULL) {
        mem->req = NULL;
        return MEMORY_E;
    }
#ifdef WC_ASU_DISABLE_CACHE
    mem->req = (AsuRsaReq*)mem->raw;
#else
    mem->req = (AsuRsaReq*)(void*)(((UINTPTR)mem->raw + 63U) & ~(UINTPTR)63U);
#endif
    return 0;
}

/* Scrub the request (it may hold the private exponent or plaintext), flush the
 * zeros to DRAM (the struct was DMA-flushed), then free the base. */
static void wc_AsuRsaReqFree(AsuRsaMem* mem)
{
    if (mem == NULL || mem->req == NULL) {
        return;
    }
    ForceZero(mem->req, sizeof(*mem->req));
    wc_AsuCacheFlush(mem->req, sizeof(*mem->req));
    XFREE(mem->raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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
    #ifdef WC_ASU_RSA_OAEP_DEC
        case WC_ASU_RSA_OP_OAEP_DEC:
            return XAsu_RsaOaepDec(params, &req->oaep);
    #endif
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

#ifdef WC_ASU_RSA_PAD
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
            *hashLen = WC_ASU_SHA_256_HASH_LEN;
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
            *hashLen = WC_ASU_SHA_256_HASH_LEN;
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
#endif /* WC_ASU_RSA_PAD */

/* Raw RSA math: public (m^e) or private (c^d) in one ASU operation. The input
 * is one full modulus-width block and the result is keySize bytes. */
static int wc_AsuRsaRaw(wc_CryptoInfo* info, RsaKey* key, u32 keySize, int op)
{
    AsuRsaMem mem;
    word32 addl = 0;
    word32 status;
    int    ret;

    ret = wc_AsuRsaReqNew(&mem);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(mem.req, 0, sizeof(*mem.req));
    ret = wc_AsuRsaPubComp(key, keySize, &mem.req->key.PubKeyComp);
    if (ret != 0) {
        wc_AsuRsaReqFree(&mem);
        return ret;
    }
    /* Reject in >= n (SW: RSA_OUT_OF_RANGE_E); the ASU reduces mod n, so in and
     * in+n verify alike. The 0/1/n-1 small-input hardening is left to HW. */
    if (XMEMCMP(info->pk.rsa.in, mem.req->key.PubKeyComp.Modulus,
                keySize) >= 0) {
        wc_AsuRsaReqFree(&mem);
        return CRYPTOCB_UNAVAILABLE;
    }
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    if (op == WC_ASU_RSA_OP_PVT) {
        mem.req->key.PrimeCompOrTotientPrsnt = 0U;
        if (mp_to_unsigned_bin_len_ct(&key->d, (byte*)mem.req->key.PvtExp,
                (int)keySize) < 0) {
            wc_AsuRsaReqFree(&mem);
            return WC_HW_E;
        }
    }
#endif

    mem.req->op                            = op;
    mem.req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* The ASU DMA writes the result into the request buffer; the caller's
     * output may be in a region the DMA cannot reach, so copy it out after. */
    mem.req->pad.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)mem.req->out;
    mem.req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&mem.req->key;
    mem.req->pad.XAsu_RsaOpComp.ExpoCompAddr   = 0U;
    mem.req->pad.XAsu_RsaOpComp.Len            = keySize;
    mem.req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    wc_AsuRsaSetOutLen(&mem.req->pad.XAsu_RsaOpComp, keySize,
        &mem.req->outLen);

    WC_ASU_PRINTF("[ASU] rsa raw op=%d keySize=%u\r\n",
        op, (unsigned int)keySize);

    wc_AsuCacheFlush(info->pk.rsa.in, keySize);
    wc_AsuCacheFlush(&mem.req->key, sizeof(mem.req->key));
    wc_AsuCacheFlush(mem.req->out, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->out, keySize);

    if (status != XST_SUCCESS) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }
    /* A private decrypt reports its own success in addl; the public path
     * trusts the SUCCESS status (the firmware writes the result on success). */
    if (op == WC_ASU_RSA_OP_PVT &&
        addl != (word32)XASU_RSA_DECRYPTION_SUCCESS) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }

    XMEMCPY(info->pk.rsa.out, mem.req->out, keySize);
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    wc_AsuRsaReqFree(&mem);
    return 0;
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

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && defined(WC_ASU_RSA_PAD)
/* Full-hardware RSA-PSS sign: wolfSSL passes the digest in info->pk.rsa.in
 * (hashed-input mode); ASU does the PSS encode and private RSA math to out. */
static int wc_AsuRsaPssSign(wc_CryptoInfo* info)
{
    AsuRsaMem mem;
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

    ret = wc_AsuRsaReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));
    ret = wc_AsuRsaPubComp(key, keySize, &mem.req->key.PubKeyComp);
    if (ret != 0) {
        wc_AsuRsaReqFree(&mem);
        return ret;
    }
    mem.req->key.PrimeCompOrTotientPrsnt = 0U;
    if (mp_to_unsigned_bin_len_ct(&key->d, (byte*)mem.req->key.PvtExp,
            (int)keySize) < 0) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }

    mem.req->op                                = WC_ASU_RSA_OP_PSS_SIGN;
    mem.req->pad.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* For sign the signature goes to OutputDataAddr (not SignatureDataAddr,
     * the verify input); DMA it into mem.req->out and copy out after. */
    mem.req->pad.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)mem.req->out;
    mem.req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&mem.req->key;
    mem.req->pad.XAsu_RsaOpComp.Len            = hashLen;
    mem.req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    wc_AsuRsaSetOutLen(&mem.req->pad.XAsu_RsaOpComp, keySize,
        &mem.req->outLen);
    mem.req->pad.SignatureDataAddr             = (u64)(UINTPTR)mem.req->scratch;
    mem.req->pad.SignatureLen                  = keySize;
    mem.req->pad.SaltLen                       = (u32)saltLen;
    mem.req->pad.ShaType                       = shaType;
    mem.req->pad.ShaMode                       = shaMode;
    mem.req->pad.InputDataType                 = (u8)XASU_RSA_HASHED_INPUT_DATA;

    WC_ASU_PRINTF("[ASU] rsa pss-sign keySize=%u shaMode=%u saltLen=%d\r\n",
        (unsigned int)keySize, (unsigned int)shaMode, saltLen);

    wc_AsuCacheFlush(info->pk.rsa.in, hashLen);
    wc_AsuCacheFlush(&mem.req->key, sizeof(mem.req->key));
    wc_AsuCacheFlush(mem.req->out, keySize);
    /* mem.req->scratch is published as SignatureDataAddr; flush the dirtied
     * lines to DRAM and invalidate after, like mem.req->out and the verify. */
    wc_AsuCacheFlush(mem.req->scratch, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->out, keySize);
    wc_AsuCacheInvalidate(mem.req->scratch, keySize);

    WC_ASU_PRINTF(
        "[ASU] pss-sign st=%u out %02x%02x%02x%02x..%02x%02x%02x%02x\r\n",
        (unsigned int)status,
        mem.req->out[0], mem.req->out[1], mem.req->out[2], mem.req->out[3],
        mem.req->out[keySize - 4], mem.req->out[keySize - 3],
        mem.req->out[keySize - 2], mem.req->out[keySize - 1]);

    if (status != XST_SUCCESS) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }
    XMEMCPY(info->pk.rsa.out, mem.req->out, keySize);
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    wc_AsuRsaReqFree(&mem);
    return 0;
}
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY && WC_ASU_RSA_PAD */

#ifdef WC_ASU_RSA_PAD
/* Firmware packs its error into an ASU status: bits 0-9 and 10-19 each hold a
 * code; bad-sig PSS verify reports 0xC4..0xCA (decode/compare); match both. */
static int wc_AsuRsaPssIsReject(word32 status)
{
    word32 first  = status & 0x3FFU;
    word32 second = (status >> 10) & 0x3FFU;
    return ((first  >= 0xC4U && first  <= 0xCAU) ||
            (second >= 0xC4U && second <= 0xCAU));
}

#ifdef WC_ASU_RSA_OAEP_DEC
/* Same packing. Measured 0x4002F0BC, 0xBC OAEP_DECODE_ERROR, on a tampered
 * ciphertext; 0xBD is its hash compare. Anything else is a fault, not a
 * verdict. */
static int wc_AsuRsaOaepStatusIsPadding(word32 status)
{
    word32 first  = status & 0x3FFU;
    word32 second = (status >> 10) & 0x3FFU;

    if (first == 0xBCU || first == 0xBDU) {
        return 1;
    }
    if (second == 0xBCU || second == 0xBDU) {
        return 1;
    }
    return 0;
}
#endif /* WC_ASU_RSA_OAEP_DEC */

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
    AsuRsaMem mem;
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

    ret = wc_AsuRsaReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));
    /* Verify is a public operation; only the public components are needed. */
    ret = wc_AsuRsaPubComp(key, keySize, &mem.req->key.PubKeyComp);
    if (ret != 0) {
        wc_AsuRsaReqFree(&mem);
        return ret;
    }

    mem.req->op                                = WC_ASU_RSA_OP_PSS_VERIFY;
    mem.req->pad.XAsu_RsaOpComp.InputDataAddr  =
        (u64)(UINTPTR)info->pk.rsa_pss_verify.digest;
    mem.req->pad.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&mem.req->key;
    mem.req->pad.XAsu_RsaOpComp.Len            = hashLen;
    mem.req->pad.XAsu_RsaOpComp.KeySize        = keySize;
    wc_AsuRsaSetOutLen(&mem.req->pad.XAsu_RsaOpComp, keySize,
        &mem.req->outLen);
    mem.req->pad.SignatureDataAddr             =
        (u64)(UINTPTR)info->pk.rsa_pss_verify.sig;
    mem.req->pad.SignatureLen                  = keySize;
    mem.req->pad.SaltLen                       = (u32)saltLen;
    mem.req->pad.ShaType                       = shaType;
    mem.req->pad.ShaMode                       = shaMode;
    mem.req->pad.InputDataType                 = (u8)XASU_RSA_HASHED_INPUT_DATA;

    /* Clear the verdict only now that every CRYPTOCB_UNAVAILABLE feasibility
     * exit has passed, so a decline never mutates the caller's result. */
    *info->pk.rsa_pss_verify.res = 0;

    wc_AsuCacheFlush(info->pk.rsa_pss_verify.digest, hashLen);
    wc_AsuCacheFlush(info->pk.rsa_pss_verify.sig, keySize);
    wc_AsuCacheFlush(&mem.req->key, sizeof(mem.req->key));

    status = wc_AsuTransact(wc_AsuRsaSubmit, mem.req, &addl);

    WC_ASU_PRINTF("[ASU] rsa pss-verify keySize=%u status=%u addl=0x%x\r\n",
        (unsigned int)keySize, (unsigned int)status, (unsigned int)addl);

    /* VERIFIED -> res=1; a PSS decode/compare failure -> res=0 (bad signature);
     * any other non-success status -> WC_HW_E (a real fault). */
    ret = wc_AsuRsaVerifyResult(status, addl,
        (word32)XASU_RSA_PSS_SIGNATURE_VERIFIED, info->pk.rsa_pss_verify.res);

    wc_AsuRsaReqFree(&mem);
    return ret;
}
#endif /* WC_ASU_RSA_PAD (PSS verify) */

#ifdef WC_ASU_RSA_PAD
/* Full-hardware RSA-OAEP encrypt (only); message in info->pk.rsa.in, OAEP
 * hash/MGF/label in .padding; ASU does the OAEP encode + public RSA math. */
static int wc_AsuRsaOaepEnc(wc_CryptoInfo* info)
{
    AsuRsaMem mem;
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

    ret = wc_AsuRsaReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));
    ret = wc_AsuRsaPubComp(key, keySize, &mem.req->key.PubKeyComp);
    if (ret != 0) {
        wc_AsuRsaReqFree(&mem);
        return ret;
    }

    /* The ASU requires a non-zero label address; an empty label (wolfSSL's
     * default) passes a valid address with size 0, hashing the empty string. */
    label = padding->label;
    labelSz = padding->labelSz;
    /* A NULL label with a non-zero size is contradictory; wc_RsaPad_ex rejects
     * it with BUFFER_E, so do the same, not silently bind an empty label. */
    if (label == NULL && labelSz > 0) {
        wc_AsuRsaReqFree(&mem);
        return BUFFER_E;
    }
    if (label == NULL) {
        label = mem.req->scratch;
        labelSz = 0;
    }

    mem.req->op                                 = WC_ASU_RSA_OP_OAEP_ENC;
    mem.req->oaep.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* DMA ciphertext to mem.req->out, then copy to the caller (which may be
     * in a region the DMA cannot reach). */
    mem.req->oaep.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)mem.req->out;
    mem.req->oaep.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&mem.req->key;
    mem.req->oaep.XAsu_RsaOpComp.Len            = info->pk.rsa.inLen;
    mem.req->oaep.XAsu_RsaOpComp.KeySize        = keySize;
    wc_AsuRsaSetOutLen(&mem.req->oaep.XAsu_RsaOpComp, keySize,
        &mem.req->outLen);
    mem.req->oaep.OptionalLabelAddr             = (u64)(UINTPTR)label;
    mem.req->oaep.OptionalLabelSize             = labelSz;
    mem.req->oaep.ShaType                       = shaType;
    mem.req->oaep.ShaMode                       = shaMode;

    WC_ASU_PRINTF("[ASU] rsa oaep-enc keySize=%u shaMode=%u labelSz=%u\r\n",
        (unsigned int)keySize, (unsigned int)shaMode, (unsigned int)labelSz);

    wc_AsuCacheFlush(info->pk.rsa.in, info->pk.rsa.inLen);
    if (labelSz > 0) {
        wc_AsuCacheFlush(label, labelSz);
    }
    wc_AsuCacheFlush(&mem.req->key, sizeof(mem.req->key));
    wc_AsuCacheFlush(mem.req->out, keySize);

    status = wc_AsuTransact(wc_AsuRsaSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->out, keySize);

    if (status != XST_SUCCESS) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }
    XMEMCPY(info->pk.rsa.out, mem.req->out, keySize);
    /* outLen is non-NULL here: dispatch/pre-check already rejected NULL. */
    *info->pk.rsa.outLen = keySize;
    wc_AsuRsaReqFree(&mem);
    return 0;
}
#ifdef WC_ASU_RSA_OAEP_DEC
/* OAEP decrypt: the ASU does the private math and the OAEP decode, and reports
 * how many message bytes it recovered. */
static int wc_AsuRsaOaepDec(wc_CryptoInfo* info)
{
    AsuRsaMem mem;
    RsaKey* key = info->pk.rsa.key;
    RsaPadding* padding = info->pk.rsa.padding;
    u32     keySize = 0;
    u8      shaType = 0;
    u8      shaMode = 0;
    word32  hashLen = 0;
    word32  recovered;
    const byte* label;
    word32  labelSz;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (key == NULL || padding == NULL || info->pk.rsa.in == NULL ||
        info->pk.rsa.out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.rsa.type != RSA_PRIVATE_DECRYPT) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Private op needs the private exponent, same as the raw and PSS paths. */
    if (mp_unsigned_bin_size(&key->d) == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuRsaKeySize(key, &keySize);
    if (ret != 0) {
        return ret;
    }
    /* The ciphertext is one modulus wide; anything else is not ours. */
    if (info->pk.rsa.inLen != keySize) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->pk.rsa.outLen == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wc_AsuRsaShaMap(padding->hash, padding->mgf, &shaType, &shaMode,
        &hashLen);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AsuRsaReqNew(&mem);
    if (ret != 0) {
        return ret;
    }
    XMEMSET(mem.req, 0, sizeof(*mem.req));
    ret = wc_AsuRsaPubComp(key, keySize, &mem.req->key.PubKeyComp);
    if (ret != 0) {
        wc_AsuRsaReqFree(&mem);
        return ret;
    }
    mem.req->key.PrimeCompOrTotientPrsnt = 0U;
    if (mp_to_unsigned_bin_len_ct(&key->d, (byte*)mem.req->key.PvtExp,
            (int)keySize) < 0) {
        wc_AsuRsaReqFree(&mem);
        return WC_HW_E;
    }

    /* Same empty-label rule as encrypt: a valid address with size 0. */
    label = padding->label;
    labelSz = padding->labelSz;
    if (label == NULL && labelSz > 0) {
        wc_AsuRsaReqFree(&mem);
        return BUFFER_E;
    }
    if (label == NULL) {
        label = mem.req->scratch;
        labelSz = 0;
    }

    mem.req->op                                 = WC_ASU_RSA_OP_OAEP_DEC;
    mem.req->oaep.XAsu_RsaOpComp.InputDataAddr  = (u64)(UINTPTR)info->pk.rsa.in;
    /* Recover into our own buffer: the message is shorter than the modulus and
     * the caller's buffer may be smaller than what the ASU is told it has. */
    mem.req->oaep.XAsu_RsaOpComp.OutputDataAddr = (u64)(UINTPTR)mem.req->out;
    mem.req->oaep.XAsu_RsaOpComp.KeyCompAddr    = (u64)(UINTPTR)&mem.req->key;
    mem.req->oaep.XAsu_RsaOpComp.Len            = info->pk.rsa.inLen;
    mem.req->oaep.XAsu_RsaOpComp.KeySize        = keySize;
    wc_AsuRsaSetOutLen(&mem.req->oaep.XAsu_RsaOpComp,
        (u32)sizeof(mem.req->out), &mem.req->outLen);
    mem.req->oaep.OptionalLabelAddr             = (u64)(UINTPTR)label;
    mem.req->oaep.OptionalLabelSize             = labelSz;
    mem.req->oaep.ShaType                       = shaType;
    mem.req->oaep.ShaMode                       = shaMode;

    WC_ASU_PRINTF("[ASU] rsa oaep-dec keySize=%u shaMode=%u labelSz=%u\r\n",
        (unsigned int)keySize, (unsigned int)shaMode, (unsigned int)labelSz);

    wc_AsuCacheFlush(info->pk.rsa.in, info->pk.rsa.inLen);
    if (labelSz > 0) {
        wc_AsuCacheFlush(label, labelSz);
    }
    wc_AsuCacheFlush(&mem.req->key, sizeof(mem.req->key));
    /* out is a DMA target so it is flushed and invalidated; outLen is not one,
     * it arrives in the mailbox response - see wc_AsuRsaSetOutLen. */
    wc_AsuCacheFlush(mem.req->out, sizeof(mem.req->out));

    status = wc_AsuTransact(wc_AsuRsaSubmit, mem.req, &addl);

    wc_AsuCacheInvalidate(mem.req->out, sizeof(mem.req->out));

    /* A decode failure is an answer, the padding is valid for this key or it
     * is not. A transport or argument fault is not, so keep the two apart. */
    if (status != XST_SUCCESS) {
        int isPadding = wc_AsuRsaOaepStatusIsPadding((word32)status);

        wc_AsuRsaReqFree(&mem);
        if (isPadding) {
            return RSA_PAD_E;
        }
        return WC_HW_E;
    }

    /* Trust the reported length only as far as both buffers allow. */
    recovered = mem.req->outLen;
    if (recovered > sizeof(mem.req->out) || recovered > *info->pk.rsa.outLen) {
        wc_AsuRsaReqFree(&mem);
        return RSA_BUFFER_E;
    }
    XMEMCPY(info->pk.rsa.out, mem.req->out, recovered);
    *info->pk.rsa.outLen = recovered;
    wc_AsuRsaReqFree(&mem);
    return 0;
}
#endif /* WC_ASU_RSA_OAEP_DEC */

#endif /* WC_ASU_RSA_PAD (OAEP encrypt) */

/* WC_ALGO_TYPE_PK entry: dispatch on RSA pk sub-type. Raw always offloaded;
 * PSS/OAEP encrypt need WC_ASU_RSA_PAD (off under opt-out); PKCS to SW. */
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
    #ifdef WC_ASU_RSA_PAD
        #ifndef WOLFSSL_RSA_PUBLIC_ONLY
        case WC_PK_TYPE_RSA_PSS:
            return wc_AsuRsaPssSign(info);
        #endif
        case WC_PK_TYPE_RSA_PSS_VERIFY:
            return wc_AsuRsaPssVerify(info);
        case WC_PK_TYPE_RSA_OAEP:
        #ifdef WC_ASU_RSA_OAEP_DEC
            if (info->pk.rsa.type == RSA_PRIVATE_DECRYPT) {
                return wc_AsuRsaOaepDec(info);
            }
        #endif
            return wc_AsuRsaOaepEnc(info);
    #endif /* WC_ASU_RSA_PAD */
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RSA && !NO_RSA */
