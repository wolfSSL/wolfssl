/* asu_cipher.c
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

/* ASU AES engine (CBC/ECB/CTR/CFB/OFB/GCM/CCM). Each call runs as one complete
 * ASU operation; AES-192 and partial blocks fall back to software. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_CIPHER

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cipher.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_aes.h"
#include "xasu_aesinfo.h"
#include "xasu_def.h"
#include "xasu_status.h"
#include "xstatus.h"

/* One ASU AES request: the params block and the key object it points at. */
typedef struct {
    XAsu_AesParams    params;
    XAsu_AesKeyObject keyObj;
} AsuCipherReq;

/* Hands one AES request to the ASU queue. wc_AsuTransact calls this while it
 * holds the submit lock, so this must only queue the request and return. */
static int wc_AsuCipherSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuCipherReq* req = (AsuCipherReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_AesOperation(params, &req->params);
}

/* Map a wolfSSL key length to the ASU key size. Returns CRYPTOCB_UNAVAILABLE for
 * AES-192 and any other unsupported length so wolfSSL falls back to software. */
static int wc_AsuCipherKeySize(word32 keyLen, u32* keySize)
{
    if (keySize == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyLen == XASU_AES_KEY_SIZE_128BIT_IN_BYTES) {
        *keySize = XASU_AES_KEY_SIZE_128_BITS;
        return 0;
    }
    if (keyLen == XASU_AES_KEY_SIZE_256BIT_IN_BYTES) {
        *keySize = XASU_AES_KEY_SIZE_256_BITS;
        return 0;
    }

    return CRYPTOCB_UNAVAILABLE;
}

/* Run one AES operation on the ASU. iv is NULL for ECB. Empty input, sizes that
 * are not whole blocks, and unsupported keys fall back to software. */
static int wc_AsuCipherOneShot(Aes* aes, byte* out, const byte* in, word32 sz,
    int enc, u8 engineMode, const byte* iv)
{
    AsuCipherReq req;
    u32          keySize = 0;
    word32       status;
    int          ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* The ASU only takes whole 16-byte blocks up to the DMA limit; any other
     * length runs in software. */
    if (sz == 0 || (sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        sz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuCipherKeySize(aes->keylen, &keySize);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)aes->devKey;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    req.params.InputDataAddr  = (u64)(UINTPTR)in;
    req.params.OutputDataAddr = (u64)(UINTPTR)out;
    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.DataLen        = sz;
    req.params.EngineMode     = engineMode;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    if (enc) {
        req.params.OperationType = (u8)XASU_AES_ENCRYPT_OPERATION;
    }
    else {
        req.params.OperationType = (u8)XASU_AES_DECRYPT_OPERATION;
    }
    if (iv != NULL) {
        req.params.IvAddr = (u64)(UINTPTR)iv;
        req.params.IvLen  = XASU_AES_IV_SIZE_128BIT_IN_BYTES;
    }

    WC_ASU_PRINTF("[ASU] cipher mode=%d enc=%d keyLen=%u sz=%u\r\n",
        (int)engineMode, enc, (unsigned int)aes->keylen, (unsigned int)sz);

    /* The ASU reads the key object, key, IV and input straight from RAM, so
     * flush our cached copies out first; drop the cached output after the op. */
    wc_AsuCacheFlush(aes->devKey, aes->keylen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    if (iv != NULL) {
        wc_AsuCacheFlush(iv, XASU_AES_IV_SIZE_128BIT_IN_BYTES);
    }
    wc_AsuCacheFlush(in, sz);
    wc_AsuCacheFlush(out, sz);

    status = wc_AsuTransact(wc_AsuCipherSubmit, &req, NULL);
    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }

    wc_AsuCacheInvalidate(out, sz);

    return 0;
}

/* AES-CBC. The IV comes from aes->reg and, on success, is updated to the last
 * ciphertext block so a chained call continues correctly. */
static int wc_AsuCipherCbc(wc_CryptoInfo* info)
{
    byte* ctr;
    int   ret;
    byte  lastBlock[WC_AES_BLOCK_SIZE];

    /* Reference info->cipher.aescbc fields directly; no aliasing locals. */
    if (info == NULL || info->cipher.aescbc.aes == NULL ||
        info->cipher.aescbc.out == NULL || info->cipher.aescbc.in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->cipher.aescbc.sz == 0 ||
        (info->cipher.aescbc.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The CBC chaining IV lives in aes->reg. For decrypt the next IV is the last
     * input block; save it now because out may be the same buffer as in. */
    ctr = (byte*)info->cipher.aescbc.aes->reg;
    if (!info->cipher.enc) {
        XMEMCPY(lastBlock, info->cipher.aescbc.in +
            (info->cipher.aescbc.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }

    ret = wc_AsuCipherOneShot(info->cipher.aescbc.aes, info->cipher.aescbc.out,
        info->cipher.aescbc.in, info->cipher.aescbc.sz, info->cipher.enc,
        (u8)XASU_AES_CBC_MODE, ctr);
    if (ret != 0) {
        return ret;
    }

    /* Update aes->reg to the last ciphertext block for a chained call. */
    if (info->cipher.enc) {
        XMEMCPY(ctr, info->cipher.aescbc.out +
            (info->cipher.aescbc.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY(ctr, lastBlock, WC_AES_BLOCK_SIZE);
    }

    return 0;
}

/* AES-ECB. No IV and no chaining state. */
static int wc_AsuCipherEcb(wc_CryptoInfo* info)
{
    if (info == NULL || info->cipher.aesecb.aes == NULL ||
        info->cipher.aesecb.out == NULL || info->cipher.aesecb.in == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_AsuCipherOneShot(info->cipher.aesecb.aes, info->cipher.aesecb.out,
        info->cipher.aesecb.in, info->cipher.aesecb.sz, info->cipher.enc,
        (u8)XASU_AES_ECB_MODE, NULL);
}

#ifdef WOLFSSL_AES_COUNTER
/* AES-CTR (counter in aes->reg). The ASU counts differently than wolfSSL once
 * the low 32 counter bits wrap around, so that case runs in software. */
static int wc_AsuCipherCtr(wc_CryptoInfo* info)
{
    byte*  ctr;
    word32 blocks;
    word32 carry;
    int    ret;
    int    i;

    if (info == NULL || info->cipher.aesctr.aes == NULL ||
        info->cipher.aesctr.out == NULL || info->cipher.aesctr.in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Partly-used keystream from an earlier call lives in the Aes context and
     * the ASU always starts fresh, so those calls run in software. */
    if (info->cipher.aesctr.aes->left != 0 || info->cipher.aesctr.sz == 0 ||
        (info->cipher.aesctr.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The ASU counts only the low 32 bits of the counter and wraps them to zero,
     * while wolfSSL software carries across the full 128 bits. */
    ctr = (byte*)info->cipher.aesctr.aes->reg;
    blocks = info->cipher.aesctr.sz / WC_AES_BLOCK_SIZE;

    /* CTR encrypt and decrypt are the same operation, so always run encrypt. */
    ret = wc_AsuCipherOneShot(info->cipher.aesctr.aes, info->cipher.aesctr.out,
        info->cipher.aesctr.in, info->cipher.aesctr.sz, 1,
        (u8)XASU_AES_CTR_MODE, ctr);
    if (ret != 0) {
        return ret;
    }

    /* Add the block count to the counter for the next call: start at the last
     * byte (ctr[15]) and carry toward the first, matching wolfSSL software. */
    carry = blocks;
    for (i = WC_AES_BLOCK_SIZE - 1; (i >= 0) && (carry != 0); i--) {
        carry += (word32)ctr[i];
        ctr[i] = (byte)carry;
        carry >>= 8;
    }

    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef WOLFSSL_AES_CFB
/* AES-CFB: the feedback register is the last ciphertext block, so the aes->reg
 * update matches CBC. Decline leftover keystream and non block-aligned sizes. */
static int wc_AsuCipherCfb(wc_CryptoInfo* info)
{
    byte* ctr;
    int   ret;
    byte  lastBlock[WC_AES_BLOCK_SIZE];

    if (info == NULL || info->cipher.aescfb.aes == NULL ||
        info->cipher.aescfb.out == NULL || info->cipher.aescfb.in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Partly-used keystream from an earlier call lives in the Aes context and
     * the ASU always starts fresh, so those calls run in software. */
    if (info->cipher.aescfb.aes->left != 0 || info->cipher.aescfb.sz == 0 ||
        (info->cipher.aescfb.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The feedback IV lives in aes->reg. For decrypt the next IV is the last
     * input block; save it now because out may be the same buffer as in. */
    ctr = (byte*)info->cipher.aescfb.aes->reg;
    if (!info->cipher.enc) {
        XMEMCPY(lastBlock, info->cipher.aescfb.in +
            (info->cipher.aescfb.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }

    ret = wc_AsuCipherOneShot(info->cipher.aescfb.aes, info->cipher.aescfb.out,
        info->cipher.aescfb.in, info->cipher.aescfb.sz, info->cipher.enc,
        (u8)XASU_AES_CFB_MODE, ctr);
    if (ret != 0) {
        return ret;
    }

    /* Update aes->reg to the last ciphertext block for a chained call. */
    if (info->cipher.enc) {
        XMEMCPY(ctr, info->cipher.aescfb.out +
            (info->cipher.aescfb.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY(ctr, lastBlock, WC_AES_BLOCK_SIZE);
    }

    return 0;
}
#endif /* WOLFSSL_AES_CFB */

#ifdef WOLFSSL_AES_OFB
/* AES-OFB: the feedback register is the keystream block, recovered after the op
 * as out XOR in. Symmetric, so always driven as encrypt; stream limits as CTR. */
static int wc_AsuCipherOfb(wc_CryptoInfo* info)
{
    byte*  ctr;
    byte*  lastOut;
    int    ret;
    word32 i;
    byte   lastIn[WC_AES_BLOCK_SIZE];

    if (info == NULL || info->cipher.aesofb.aes == NULL ||
        info->cipher.aesofb.out == NULL || info->cipher.aesofb.in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Partly-used keystream from an earlier call lives in the Aes context and
     * the ASU always starts fresh, so those calls run in software. */
    if (info->cipher.aesofb.aes->left != 0 || info->cipher.aesofb.sz == 0 ||
        (info->cipher.aesofb.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The keystream is out XOR in; save the last input block now because out may
     * be the same buffer as in, then recover the keystream after the op. */
    ctr = (byte*)info->cipher.aesofb.aes->reg;
    XMEMCPY(lastIn, info->cipher.aesofb.in +
        (info->cipher.aesofb.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);

    ret = wc_AsuCipherOneShot(info->cipher.aesofb.aes, info->cipher.aesofb.out,
        info->cipher.aesofb.in, info->cipher.aesofb.sz, 1,
        (u8)XASU_AES_OFB_MODE, ctr);
    if (ret != 0) {
        /* lastIn holds a plaintext block on encrypt; scrub before returning. */
        ForceZero(lastIn, sizeof(lastIn));
        return ret;
    }

    /* Update aes->reg to the last keystream block (out XOR in) for a chained call. */
    lastOut = info->cipher.aesofb.out + (info->cipher.aesofb.sz - WC_AES_BLOCK_SIZE);
    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        ctr[i] = (byte)(lastOut[i] ^ lastIn[i]);
    }
    ForceZero(lastIn, sizeof(lastIn));

    return 0;
}
#endif /* WOLFSSL_AES_OFB */

#ifdef HAVE_AESGCM
/* AES-GCM in a single call (key, IV, AAD and tag together). Encrypt and decrypt
 * share one struct layout, so aesgcm_enc reads either direction's fields. */
static int wc_AsuCipherGcm(wc_CryptoInfo* info)
{
    AsuCipherReq req;
    u32          keySize = 0;
    word32       addl = 0;
    word32       status;
    int          ret;

    if (info == NULL || info->cipher.aesgcm_enc.aes == NULL ||
        info->cipher.aesgcm_enc.iv == NULL ||
        info->cipher.aesgcm_enc.ivSz == 0 ||
        info->cipher.aesgcm_enc.authTag == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Data/AAD buffers must be valid when their length is non-zero. */
    if ((info->cipher.aesgcm_enc.sz != 0) &&
        ((info->cipher.aesgcm_enc.in == NULL) ||
         (info->cipher.aesgcm_enc.out == NULL))) {
        return BAD_FUNC_ARG;
    }
    if ((info->cipher.aesgcm_enc.authInSz != 0) &&
        (info->cipher.aesgcm_enc.authIn == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* The ASU GCM engine needs at least one byte of data or AAD; the empty
     * message with empty AAD (tag-only) case runs in software. */
    if (info->cipher.aesgcm_enc.sz == 0 && info->cipher.aesgcm_enc.authInSz == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The ASU client takes whole 16-byte plaintext and AAD within the DMA limit
     * and a 8..16 byte tag; anything else runs in software. */
    if ((info->cipher.aesgcm_enc.sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        (info->cipher.aesgcm_enc.authInSz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        info->cipher.aesgcm_enc.sz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH ||
        info->cipher.aesgcm_enc.authInSz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH ||
        info->cipher.aesgcm_enc.authTagSz < XASU_AES_RECOMMENDED_TAG_LENGTH_IN_BYTES ||
        info->cipher.aesgcm_enc.authTagSz > XASU_AES_MAX_TAG_LENGTH_IN_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = wc_AsuCipherKeySize(info->cipher.aesgcm_enc.aes->keylen, &keySize);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)info->cipher.aesgcm_enc.aes->devKey;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    /* The ASU client rejects a non-zero buffer address paired with a zero
     * length, so leave these at the memset-zero default when the length is 0. */
    if (info->cipher.aesgcm_enc.sz != 0) {
        req.params.InputDataAddr  = (u64)(UINTPTR)info->cipher.aesgcm_enc.in;
        req.params.OutputDataAddr = (u64)(UINTPTR)info->cipher.aesgcm_enc.out;
    }
    if (info->cipher.aesgcm_enc.authInSz != 0) {
        req.params.AadAddr        = (u64)(UINTPTR)info->cipher.aesgcm_enc.authIn;
    }
    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.IvAddr         = (u64)(UINTPTR)info->cipher.aesgcm_enc.iv;
    req.params.TagAddr        = (u64)(UINTPTR)info->cipher.aesgcm_enc.authTag;
    req.params.DataLen        = info->cipher.aesgcm_enc.sz;
    req.params.AadLen         = info->cipher.aesgcm_enc.authInSz;
    req.params.IvLen          = info->cipher.aesgcm_enc.ivSz;
    req.params.TagLen         = info->cipher.aesgcm_enc.authTagSz;
    req.params.EngineMode     = (u8)XASU_AES_GCM_MODE;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    if (info->cipher.enc) {
        req.params.OperationType = (u8)XASU_AES_ENCRYPT_OPERATION;
    }
    else {
        req.params.OperationType = (u8)XASU_AES_DECRYPT_OPERATION;
    }

    WC_ASU_PRINTF("[ASU] cipher mode=%d enc=%d keyLen=%u sz=%u aad=%u tag=%u\r\n",
        (int)XASU_AES_GCM_MODE, info->cipher.enc,
        (unsigned int)info->cipher.aesgcm_enc.aes->keylen,
        (unsigned int)info->cipher.aesgcm_enc.sz,
        (unsigned int)info->cipher.aesgcm_enc.authInSz,
        (unsigned int)info->cipher.aesgcm_enc.authTagSz);

    /* The ASU DMAs key, IV, AAD, input (and the tag on decrypt) from memory. */
    wc_AsuCacheFlush(info->cipher.aesgcm_enc.aes->devKey,
        info->cipher.aesgcm_enc.aes->keylen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    wc_AsuCacheFlush(info->cipher.aesgcm_enc.iv, info->cipher.aesgcm_enc.ivSz);
    if (info->cipher.aesgcm_enc.authInSz != 0) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.authIn,
            info->cipher.aesgcm_enc.authInSz);
    }
    if (info->cipher.aesgcm_enc.sz != 0) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.in, info->cipher.aesgcm_enc.sz);
    }
    if (!info->cipher.enc) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz);
    }
    if (info->cipher.aesgcm_enc.sz != 0) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.out, info->cipher.aesgcm_enc.sz);
    }
    if (info->cipher.enc) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz);
    }

    status = wc_AsuTransact(wc_AsuCipherSubmit, &req, &addl);

    /* Invalidate the CPU's view of the ASU-written output (and the tag on encrypt). */
    if (info->cipher.aesgcm_enc.sz != 0) {
        wc_AsuCacheInvalidate(info->cipher.aesgcm_enc.out,
            info->cipher.aesgcm_enc.sz);
    }
    if (info->cipher.enc) {
        wc_AsuCacheInvalidate(info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz);
    }

    /* Decrypt success is confirmed by TAG_MATCHED; on a mismatch zero the
     * unauthenticated plaintext the ASU already wrote to out. */
    if (!info->cipher.enc) {
        if ((status == XST_SUCCESS) &&
            (addl == (word32)XASU_AES_TAG_MATCHED)) {
            return 0;
        }
        if (info->cipher.aesgcm_enc.sz != 0) {
            ForceZero(info->cipher.aesgcm_enc.out, info->cipher.aesgcm_enc.sz);
        }
        return AES_GCM_AUTH_E;
    }
    /* Encrypt success is confirmed by TAG_READ. */
    if ((status != XST_SUCCESS) || (addl != (word32)XASU_AES_TAG_READ)) {
        return WC_HW_E;
    }

    return 0;
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
/* AES-CCM: the ASU takes the raw 7..13 byte nonce and even 4..16 byte tag and
 * formats the B0/counter blocks itself; enc/dec share the aesccm_enc layout. */
static int wc_AsuCipherCcm(wc_CryptoInfo* info)
{
    AsuCipherReq req;
    u32          keySize = 0;
    word32       addl = 0;
    word32       status;
    int          ret;

    if (info == NULL || info->cipher.aesccm_enc.aes == NULL ||
        info->cipher.aesccm_enc.nonce == NULL ||
        info->cipher.aesccm_enc.authTag == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Data/AAD buffers must be valid when their length is non-zero. */
    if ((info->cipher.aesccm_enc.sz != 0) &&
        ((info->cipher.aesccm_enc.in == NULL) ||
         (info->cipher.aesccm_enc.out == NULL))) {
        return BAD_FUNC_ARG;
    }
    if ((info->cipher.aesccm_enc.authInSz != 0) &&
        (info->cipher.aesccm_enc.authIn == NULL)) {
        return BAD_FUNC_ARG;
    }
    /* CCM requires a 7..13 byte nonce and an even 4..16 byte tag; outside this
     * the call is malformed and software rejects it identically. */
    if (info->cipher.aesccm_enc.nonceSz < XASU_AES_CCM_MIN_NONCE_LEN ||
        info->cipher.aesccm_enc.nonceSz > XASU_AES_CCM_MAX_NONCE_LEN ||
        (info->cipher.aesccm_enc.authTagSz % XASU_AES_EVEN_MODULUS) != 0 ||
        info->cipher.aesccm_enc.authTagSz < XASU_AES_MIN_TAG_LENGTH_IN_BYTES ||
        info->cipher.aesccm_enc.authTagSz > XASU_AES_MAX_TAG_LENGTH_IN_BYTES) {
        return BAD_FUNC_ARG;
    }

    /* Tag-only (no data, no AAD) is not something the engine accepts; software. */
    if (info->cipher.aesccm_enc.sz == 0 && info->cipher.aesccm_enc.authInSz == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Oversized transfers exceed the ASU DMA limit; software handles them. */
    if (info->cipher.aesccm_enc.sz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH ||
        info->cipher.aesccm_enc.authInSz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Optional: when this macro is defined, data or AAD that is not a multiple
     * of 16 bytes runs in software instead of going to the ASU. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_CCM_ALIGN_DECLINE
    if ((info->cipher.aesccm_enc.sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        (info->cipher.aesccm_enc.authInSz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    ret = wc_AsuCipherKeySize(info->cipher.aesccm_enc.aes->keylen, &keySize);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)info->cipher.aesccm_enc.aes->devKey;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    /* The ASU client rejects a non-zero buffer address paired with a zero
     * length, so leave these at the memset-zero default when the length is 0. */
    if (info->cipher.aesccm_enc.sz != 0) {
        req.params.InputDataAddr  = (u64)(UINTPTR)info->cipher.aesccm_enc.in;
        req.params.OutputDataAddr = (u64)(UINTPTR)info->cipher.aesccm_enc.out;
    }
    if (info->cipher.aesccm_enc.authInSz != 0) {
        req.params.AadAddr        = (u64)(UINTPTR)info->cipher.aesccm_enc.authIn;
    }
    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.IvAddr         = (u64)(UINTPTR)info->cipher.aesccm_enc.nonce;
    req.params.TagAddr        = (u64)(UINTPTR)info->cipher.aesccm_enc.authTag;
    req.params.DataLen        = info->cipher.aesccm_enc.sz;
    req.params.AadLen         = info->cipher.aesccm_enc.authInSz;
    req.params.IvLen          = info->cipher.aesccm_enc.nonceSz;
    req.params.TagLen         = info->cipher.aesccm_enc.authTagSz;
    req.params.EngineMode     = (u8)XASU_AES_CCM_MODE;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    if (info->cipher.enc) {
        req.params.OperationType = (u8)XASU_AES_ENCRYPT_OPERATION;
    }
    else {
        req.params.OperationType = (u8)XASU_AES_DECRYPT_OPERATION;
    }

    WC_ASU_PRINTF("[ASU] cipher mode=%d enc=%d keyLen=%u sz=%u aad=%u tag=%u\r\n",
        (int)XASU_AES_CCM_MODE, info->cipher.enc,
        (unsigned int)info->cipher.aesccm_enc.aes->keylen,
        (unsigned int)info->cipher.aesccm_enc.sz,
        (unsigned int)info->cipher.aesccm_enc.authInSz,
        (unsigned int)info->cipher.aesccm_enc.authTagSz);

    /* The ASU DMAs key, nonce, AAD, input (and the tag on decrypt) from memory. */
    wc_AsuCacheFlush(info->cipher.aesccm_enc.aes->devKey,
        info->cipher.aesccm_enc.aes->keylen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    wc_AsuCacheFlush(info->cipher.aesccm_enc.nonce, info->cipher.aesccm_enc.nonceSz);
    if (info->cipher.aesccm_enc.authInSz != 0) {
        wc_AsuCacheFlush(info->cipher.aesccm_enc.authIn,
            info->cipher.aesccm_enc.authInSz);
    }
    if (info->cipher.aesccm_enc.sz != 0) {
        wc_AsuCacheFlush(info->cipher.aesccm_enc.in, info->cipher.aesccm_enc.sz);
    }
    if (!info->cipher.enc) {
        wc_AsuCacheFlush(info->cipher.aesccm_enc.authTag,
            info->cipher.aesccm_enc.authTagSz);
    }
    if (info->cipher.aesccm_enc.sz != 0) {
        wc_AsuCacheFlush(info->cipher.aesccm_enc.out, info->cipher.aesccm_enc.sz);
    }
    if (info->cipher.enc) {
        wc_AsuCacheFlush(info->cipher.aesccm_enc.authTag,
            info->cipher.aesccm_enc.authTagSz);
    }

    status = wc_AsuTransact(wc_AsuCipherSubmit, &req, &addl);

    /* Invalidate the CPU's view of the ASU-written output (and the tag on encrypt). */
    if (info->cipher.aesccm_enc.sz != 0) {
        wc_AsuCacheInvalidate(info->cipher.aesccm_enc.out,
            info->cipher.aesccm_enc.sz);
    }
    if (info->cipher.enc) {
        wc_AsuCacheInvalidate(info->cipher.aesccm_enc.authTag,
            info->cipher.aesccm_enc.authTagSz);
    }

    /* Decrypt success is confirmed by TAG_MATCHED; on a mismatch zero the
     * unauthenticated plaintext the ASU already wrote to out. */
    if (!info->cipher.enc) {
        if ((status == XST_SUCCESS) &&
            (addl == (word32)XASU_AES_TAG_MATCHED)) {
            return 0;
        }
        if (info->cipher.aesccm_enc.sz != 0) {
            ForceZero(info->cipher.aesccm_enc.out, info->cipher.aesccm_enc.sz);
        }
        return AES_CCM_AUTH_E;
    }
    /* Encrypt success is confirmed by TAG_READ. */
    if ((status != XST_SUCCESS) || (addl != (word32)XASU_AES_TAG_READ)) {
        return WC_HW_E;
    }

    return 0;
}
#endif /* HAVE_AESCCM */

/* Single entry point for the cipher engine, reached through the crypto callback
 * dispatcher. */
int wc_AsuCipher(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_CIPHER) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->cipher.type) {
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            return wc_AsuCipherCbc(info);
    #endif
    #ifdef HAVE_AES_ECB
        case WC_CIPHER_AES_ECB:
            return wc_AsuCipherEcb(info);
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            return wc_AsuCipherCtr(info);
    #endif
    #ifdef WOLFSSL_AES_CFB
        case WC_CIPHER_AES_CFB:
            return wc_AsuCipherCfb(info);
    #endif
    #ifdef WOLFSSL_AES_OFB
        case WC_CIPHER_AES_OFB:
            return wc_AsuCipherOfb(info);
    #endif
    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            return wc_AsuCipherGcm(info);
    #endif
    #ifdef HAVE_AESCCM
        case WC_CIPHER_AES_CCM:
            return wc_AsuCipherCcm(info);
    #endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CIPHER */
