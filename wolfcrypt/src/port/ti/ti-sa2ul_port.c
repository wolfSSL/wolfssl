/* ti-sa2ul_port.c
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


#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_TI_AM64X)

#ifndef WOLF_CRYPTO_CB
    #error WOLFSSL_TI_SA2UL support requires ./configure --enable-cryptocb or WOLF_CRYPTO_CB to be defined
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-sa2ul_port.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* from ti mcu plus sdk... */
#include "kernel/dpl/CacheP.h"
#include "security/security_common/drivers/crypto/crypto.h"
#include "security/security_common/drivers/crypto/rng/rng.h"
#include "security/security_common/drivers/crypto/sa2ul/sa2ul.h"
#include "drivers/sciclient.h"
#include "drivers/sciclient/include/tisci/security/tisci_soc_uid.h"

static Crypto_Handle handle;
static Crypto_Context cryptoCtx XALIGNED(SA2UL_CACHELINE_ALIGNMENT);
static uint32_t socUid[UID_LEN_WORDS];
static int socUidAvail = 0;

static int _getSocUid(void)
{
    if (socUidAvail == 0)
    {
        struct tisci_msg_get_soc_uid_req req = {0};
        const Sciclient_ReqPrm_t reqPrm =
        {
            TISCI_MSG_GET_SOC_UID,
            TISCI_MSG_FLAG_AOP,
            (const uint8_t *)&req,
            sizeof(req),
            SystemP_WAIT_FOREVER
        };
        struct tisci_msg_get_soc_uid_resp resp;
        Sciclient_RespPrm_t respPrm =
        {
            0,
            (uint8_t *) &resp,
            sizeof(resp)
        };

        if (Sciclient_service(&reqPrm, &respPrm) != SystemP_SUCCESS ||
            respPrm.flags != TISCI_MSG_FLAG_ACK)
        {
            return -1;
        }
        XMEMCPY(socUid, resp.soc_uid, sizeof(socUid));
        socUidAvail = 1;
    }
    return 0;
}

#ifndef WC_NO_RNG
#define RNG_NUM_DWORDS (4u)
static RNG_Handle rngHandle = NULL;

static void ti_sa2ul_trng_init_common(void)
{
    RNG_Handle handle = NULL;
    if (gRngConfig[0].attrs->isOpen == 0) {
        SA2UL_engineEnable(CSL_CP_ACE_CMD_STATUS_TRNG_EN_MASK);
        handle = RNG_open(0);
        if (handle != NULL) {
            if (RNG_setup(handle) == RNG_RETURN_SUCCESS) {
                rngHandle = handle;
            }
            else {
                RNG_close(handle);
            }
        }
    }
    else {
        /* already opened -- use existing handle */
        rngHandle = (RNG_Handle)&gRngConfig[0];
    }
}

#ifdef WOLFSSL_TI_AM64X_RNG_CTR_DRBG
static void ti_sa2ul_trng_init_drbg(void)
{
    if (_getSocUid() == 0) {
        uint32_t initialSeed[RNG_DRBG_SEED_MAX_ARRY_SIZE_IN_DWORD];
        /* seed is 384 bits, uid is 256 bits, so copy uid 1.5x */
        XMEMCPY(initialSeed, socUid, sizeof(socUid));
        XMEMCPY(&initialSeed[8], socUid, sizeof(initialSeed) - sizeof(socUid));
        gRngConfig[0].attrs->mode = RNG_DRBG_MODE;
        gRngConfig[0].attrs->seedValue = initialSeed;
        gRngConfig[0].attrs->seedSizeInDwords =
            RNG_DRBG_SEED_MAX_ARRY_SIZE_IN_DWORD;
        ti_sa2ul_trng_init_common();
    }
}

static int ti_sa2ul_trng_get_drbg(byte* output, word32 sz)
{
    CSL_Cp_aceTrngRegs *pTrngRegs = (CSL_Cp_aceTrngRegs *)gRngConfig[0].attrs->rngBaseAddr;

    if (output == NULL && sz != 0)
        return -1;

    while (sz) {
        uint32_t val;
        uint32_t random[RNG_NUM_DWORDS];
        uint8_t *ptr = (uint8_t *)random;
        int copy_len;

        /* wait for READY==1 (random data ready) */
        do {
            val = CSL_REG_RD(&pTrngRegs->TRNG_STATUS);
        } while ((val & CSL_CP_ACE_TRNG_STATUS_READY_MASK) !=
                 CSL_CP_ACE_TRNG_STATUS_READY_MASK);

        random[0] = CSL_REG_RD(&pTrngRegs->TRNG_INPUT_0);
        random[1] = CSL_REG_RD(&pTrngRegs->TRNG_INPUT_1);
        random[2] = CSL_REG_RD(&pTrngRegs->TRNG_INPUT_2);
        random[3] = CSL_REG_RD(&pTrngRegs->TRNG_INPUT_3);
        /* ack the data read */
        CSL_REG_WR(&pTrngRegs->TRNG_STATUS, CSL_CP_ACE_TRNG_INTACK_READY_ACK_MASK);

        /* kick off next generate request */
        val = CSL_REG_RD(&pTrngRegs->TRNG_CONTROL);
        val |= CSL_CP_ACE_TRNG_CONTROL_DATA_BLOCKS_MASK;
        val |= CSL_CP_ACE_TRNG_CONTROL_REQUEST_DATA_MASK;
        CSL_REG_WR(&pTrngRegs->TRNG_CONTROL, val);

        copy_len = RNG_NUM_DWORDS * 4;
        if (sz < copy_len)
            copy_len = sz;
        XMEMCPY(output, ptr, copy_len);
        output += copy_len;
        sz -= copy_len;
    }

    return 0;
}
#else
static void ti_sa2ul_trng_init_nrbg(void)
{
    gRngConfig[0].attrs->mode = RNG_DRBG_DISABLE_MODE;
    ti_sa2ul_trng_init_common();
}

static int ti_sa2ul_trng_get_nrbg(byte* output, word32 sz)
{
    if (output == NULL && sz != 0)
        return -1;

    while (sz) {
        uint32_t random[RNG_NUM_DWORDS];
        uint8_t *ptr = (uint8_t *)random;
        int copy_len;
        if (RNG_read(rngHandle, random) != RNG_RETURN_SUCCESS)
            return -1;
        copy_len = RNG_NUM_DWORDS * 4;
        if (sz < copy_len)
            copy_len = sz;
        XMEMCPY(output, ptr, copy_len);
        output += copy_len;
        sz -= copy_len;
    }

    return 0;
}
#endif /* WOLFSSL_TI_AM64X_RNG_CTR_DRBG */

static void ti_sa2ul_trng_init(void)
{
#ifdef WOLFSSL_TI_AM64X_RNG_CTR_DRBG
    return ti_sa2ul_trng_init_drbg();
#else
    return ti_sa2ul_trng_init_nrbg();
#endif
}

static int ti_sa2ul_trng_get(byte* output, word32 sz)
{
#ifdef WOLFSSL_TI_AM64X_RNG_CTR_DRBG
    return ti_sa2ul_trng_get_drbg(output, sz);
#else
    return ti_sa2ul_trng_get_nrbg(output, sz);
#endif
}
#endif /* WC_NO_RNG */

static void _u8LeToU32(uint32_t *dest, uint8_t *src, uint32_t len)
{
    uint32_t i, t = 0;

    for (i=0; i<len; i++) {
        t = (t << 8) | src[i];
        if ((i & 3) == 3) {
            *dest++ = t;
            t = 0;
        }
    }
    if ((i & 3) != 0) {
        *dest = t << ((4-(i&3)) << 3);
    }
}

static void _64byteReverseWords(uint32_t *dest, uint32_t *src, uint32_t len)
{
    uint32_t tmp[4], *t;
    uint32_t i, j;

    t = &tmp[0];
    for (i=0; i<len; i+=16) {
        for (j=0; j<4; j++) *t++ = *src++;
        for (j=0; j<4; j++) *dest++ = *--t;
    }
}

#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_NO_AES)
static int check_aes_keylength(word32 keylen)
{
    /* mcuplussdk sa2ul driver only supports key lengths of 128 and 256 */
    if (keylen != AES_128_KEY_SIZE && keylen != AES_256_KEY_SIZE)
        return BAD_FUNC_ARG;

#if !defined(WOLFSSL_AES_128)
    if (keylen == AES_128_KEY_SIZE)
        return BAD_FUNC_ARG;
#endif

#if !defined(WOLFSSL_AES_256)
    if (keylen == AES_256_KEY_SIZE)
        return BAD_FUNC_ARG;
#endif

    return 0;
}

#ifdef HAVE_AES_CBC
static int ti_sa2ul_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_CBC;
    scParams.encDirection = SA2UL_ENC_DIR_ENCRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(&scParams.key[0], aes->devKey, aes->keylen);
    XMEMCPY(&scParams.iv[0], aes->reg, AES_IV_SIZE);
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    XMEMCPY(aes->reg, out + sz - 16, 16);

    return ret;
}

#ifdef HAVE_AES_DECRYPT
static int ti_sa2ul_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;
    byte tmp_iv[16];

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_CBC;
    scParams.encDirection = SA2UL_ENC_DIR_DECRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(&scParams.key[0], aes->devKey, aes->keylen);
    XMEMCPY(&scParams.iv[0], aes->reg, AES_IV_SIZE);
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    XMEMCPY(tmp_iv, in + sz - 16, 16);

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    XMEMCPY(aes->reg, tmp_iv, 16);

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AES_ECB
static int ti_sa2ul_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_ECB;
    scParams.encDirection = SA2UL_ENC_DIR_ENCRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(&scParams.key[0], aes->devKey, aes->keylen);
    XMEMCPY(&scParams.iv[0], aes->reg, AES_IV_SIZE);
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    return ret;
}

#ifdef HAVE_AES_DECRYPT
static int ti_sa2ul_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_ECB;
    scParams.encDirection = SA2UL_ENC_DIR_DECRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(&scParams.key[0], aes->devKey, aes->keylen);
    XMEMCPY(&scParams.iv[0], aes->reg, AES_IV_SIZE);
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
static void _override_iv_with_ghash(Aes* aes, const byte* iv, word32 ivSz)
{
    SA2UL_SecCtx sc;
    byte ivtmp[WC_AES_BLOCK_SIZE];

    GHASH(&aes->gcm, NULL, 0, iv, ivSz, ivtmp, WC_AES_BLOCK_SIZE);
    XMEMCPY(aes->scObj.ctxPrms.iv, ivtmp, WC_AES_BLOCK_SIZE);
    _64byteReverseWords((uint32_t*)&sc, (uint32_t*)&aes->scObj.secCtx, sizeof(sc));
    _u8LeToU32(sc.u.enc.encAux3, ivtmp, WC_AES_BLOCK_SIZE);
    _64byteReverseWords((uint32_t*)&aes->scObj.secCtx, (uint32_t*)&sc, sizeof(sc));
    CacheP_wbInv(&aes->scObj.secCtx, sizeof(sc), CacheP_TYPE_ALLD);
}

static int ti_sa2ul_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_GCM;
    scParams.encDirection = SA2UL_ENC_DIR_ENCRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(scParams.key, aes->devKey, aes->keylen);
    XMEMCPY(scParams.iv, iv, ivSz);
    XMEMCPY(scParams.ghash, aes->gcm.H, WC_AES_BLOCK_SIZE);
    if (authInSz <= sizeof(scParams.aad)) {
        XMEMCPY(scParams.aad, authIn, authInSz);
        scParams.aadLen = authInSz;
    }
    else {
        scParams.aadLen = 0;
    }
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    if (ivSz != GCM_NONCE_MID_SZ) {
        _override_iv_with_ghash(aes, iv, ivSz);
    }

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    if (authTag) {
        if (authInSz <= sizeof(scParams.aad)) {
            XMEMCPY(authTag, aes->scObj.computedHash, authTagSz);
        }
        else {
            ALIGN16 byte initialCounter[WC_AES_BLOCK_SIZE];
            ALIGN16 byte scratch[WC_AES_BLOCK_SIZE];
            GHASH(&aes->gcm, authIn, authInSz, out, sz, authTag, authTagSz);
            if (ivSz == GCM_NONCE_MID_SZ) {
                XMEMCPY(initialCounter, iv, ivSz);
                initialCounter[WC_AES_BLOCK_SIZE-4] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-3] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-2] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-1] = 1;
            }
            else {
                XMEMCPY(initialCounter, aes->scObj.ctxPrms.iv, WC_AES_BLOCK_SIZE);
            }
            ret = wc_AesEncryptDirect(aes, scratch, initialCounter);
            xorbuf(authTag, scratch, authTagSz);
        }
    }

    return ret;
}

#ifdef HAVE_AES_DECRYPT
static int ti_sa2ul_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz)
{
    int ret = 0;
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType       = SA2UL_OP_ENC;
    scParams.encAlg       = SA2UL_ENC_ALG_AES;
    scParams.encMode      = SA2UL_ENC_MODE_GCM;
    scParams.encDirection = SA2UL_ENC_DIR_DECRYPT;
    if (aes->keylen == AES_128_KEY_SIZE) {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_128;
    }
    else {
        scParams.encKeySize = SA2UL_ENC_KEYSIZE_256;
    }
    XMEMCPY(scParams.key, aes->devKey, aes->keylen);
    XMEMCPY(scParams.iv, iv, ivSz);
    XMEMCPY(scParams.ghash, aes->gcm.H, WC_AES_BLOCK_SIZE);
    XMEMCPY(scParams.aad, authIn, authInSz);
    scParams.aadLen = authInSz;
    scParams.inputLen = sz;
    aes->scObj.totalLengthInBytes = sz;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &aes->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    if (ivSz != GCM_NONCE_MID_SZ) {
        _override_iv_with_ghash(aes, iv, ivSz);
    }

    CacheP_wbInv((void *)in, sz, CacheP_TYPE_ALLD);

    if (SA2UL_contextProcess(&aes->scObj, in, sz, out) != SystemP_SUCCESS)
        ret = WC_HW_E;

    (void)SA2UL_contextFree(&aes->scObj);

    if (authTag) {
        if (authInSz <= sizeof(scParams.aad)) {
            if (XMEMCMP(authTag, aes->scObj.computedHash, authTagSz) != 0)
                ret = WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
        }
        else {
            ALIGN16 byte initialCounter[WC_AES_BLOCK_SIZE];
            ALIGN16 byte scratch[WC_AES_BLOCK_SIZE];
            ALIGN16 byte Tprime[WC_AES_BLOCK_SIZE];
            GHASH(&aes->gcm, authIn, authInSz, in, sz, Tprime, sizeof(Tprime));
            if (ivSz == GCM_NONCE_MID_SZ) {
                XMEMCPY(initialCounter, iv, ivSz);
                initialCounter[WC_AES_BLOCK_SIZE-4] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-3] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-2] = 0;
                initialCounter[WC_AES_BLOCK_SIZE-1] = 1;
            }
            else {
                XMEMCPY(initialCounter, aes->scObj.ctxPrms.iv, WC_AES_BLOCK_SIZE);
            }
            ret = wc_AesEncryptDirect(aes, scratch, initialCounter);
            xorbuf(Tprime, scratch, sizeof(Tprime));
            if (XMEMCMP(authTag, Tprime, authTagSz) != 0)
                ret = WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
        }
    }

    return ret;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_NO_AES */


#if !defined(WOLFSSL_TI_AM64X_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
/* The ti mcu plus sdk sa2ul driver requires an output buffer of at least
 * the size of the input buffer, and it will write data to it, though we don't
 * use the data.  So, we consider this a scratch buffer, but it also limits
 * the amount of data we can hash at one time. */
#define HASH_SCRATCH_SIZE 0x2000u
static byte hash_scratch[HASH_SCRATCH_SIZE] XALIGNED(SA2UL_CACHELINE_ALIGNMENT);
static volatile int sa2ul_hash_in_use = 0;

#ifndef NO_SHA256
static int ti_sa2ul_InitSha256_ctx(wc_Sha256* sha256)
{
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType   = SA2UL_OP_AUTH;
    scParams.hashAlg  = SA2UL_HASH_ALG_SHA2_256;
    /* default length to all ff's, final will override when known */
    scParams.inputLen = 0xffffffffUL;
    sha256->scObj.totalLengthInBytes = 0xffffffffUL;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &sha256->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }

    sa2ul_hash_in_use = 1;

    return 0;
}

static int ti_sa2ul_Sha256Free_ctx(wc_Sha256* sha256)
{
    (void)SA2UL_contextFree(&sha256->scObj);
    XMEMSET(&sha256->scObj, 0, sizeof(sha256->scObj));

    sa2ul_hash_in_use = 0;

    return 0;
}

static int ti_sa2ul_Sha256Hash(wc_Sha256* sha256, const byte* in,
                               word32 inSz, byte* digest)
{
    int ret = 0;
    byte* buffer = (byte*)sha256->buffer;
    word32 blocksLen;
    word32 partialLen;

    if (in == NULL && digest == NULL)
        return WC_HW_E;

    if (sha256->scObj.txBytesCnt == 0 && sa2ul_hash_in_use == 1) {
        sha256->flags |= WC_HASH_FLAG_ISCOPY;
        return CRYPTOCB_UNAVAILABLE;
    }

    if (in != NULL) {
        /* update... */
        sha256->loLen += inSz;

        /* handle leftovers first */
        if (sha256->buffLen > 0) {
            partialLen = min(inSz, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
            XMEMCPY(&buffer[sha256->buffLen], in, partialLen);
            sha256->buffLen += partialLen;
            in += partialLen;
            inSz -= partialLen;
            if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                CacheP_wbInv((void *)buffer, WC_SHA256_BLOCK_SIZE,
                             CacheP_TYPE_ALLD);
                if (sha256->scObj.txBytesCnt == 0) {
                    if (ti_sa2ul_InitSha256_ctx(sha256) != 0)
                        return WC_HW_E;
                }
                if (SA2UL_contextProcess(&sha256->scObj, buffer,
                        WC_SHA256_BLOCK_SIZE, hash_scratch) != SystemP_SUCCESS)
                {
                    return WC_HW_E;
                }
                XMEMCPY(sha256->digest, &sha256->scObj.computedHash,
                        WC_SHA256_DIGEST_SIZE);
                /* final will fall back to sw, and sw needs bytes reversed */
                ByteReverseWords(sha256->digest, sha256->digest,
                                 WC_SHA256_DIGEST_SIZE);
                sha256->buffLen = 0;
            }
        }
        /* chunks of full blocks */
        while (inSz >= WC_SHA256_BLOCK_SIZE) {
            blocksLen = min(sizeof(hash_scratch),
                            inSz & ~((word32)WC_SHA256_BLOCK_SIZE-1));
            CacheP_wbInv((void *)in, blocksLen, CacheP_TYPE_ALLD);
            if (sha256->scObj.txBytesCnt == 0) {
                if (ti_sa2ul_InitSha256_ctx(sha256) != 0)
                    return WC_HW_E;
            }
            if (SA2UL_contextProcess(&sha256->scObj, in, blocksLen,
                                     hash_scratch) != SystemP_SUCCESS) {
                return WC_HW_E;
            }
            XMEMCPY(sha256->digest, &sha256->scObj.computedHash,
                    WC_SHA256_DIGEST_SIZE);
            ByteReverseWords(sha256->digest, sha256->digest,
                             WC_SHA256_DIGEST_SIZE);
            in += blocksLen;
            inSz -= blocksLen;
        }
        /* save leftovers */
        if (inSz > 0) {
            XMEMCPY(&buffer[0], in, inSz);
            sha256->buffLen = inSz;
        }
    }
    else if (digest != NULL) {
        /* final... */
        /* hash will be finalized in sw via fallback, but we need the driver
         * to tear down the context in hw.  To do that, we update the context
         * length and push some final arbitrary data.  It will not affect
         * the hash */
        if (sha256->scObj.txBytesCnt != 0) {
            sha256->scObj.ctxPrms.inputLen = sha256->scObj.txBytesCnt +
                                             WC_SHA256_DIGEST_SIZE;
            sha256->scObj.totalLengthInBytes = sha256->scObj.txBytesCnt +
                                               WC_SHA256_DIGEST_SIZE;
            CacheP_wbInv((void *)buffer, WC_SHA256_DIGEST_SIZE, CacheP_TYPE_ALLD);
            if (SA2UL_contextProcess(&sha256->scObj, buffer,
                    WC_SHA256_DIGEST_SIZE, hash_scratch) != SystemP_SUCCESS)
            {
                ret = WC_HW_E;
            }
            (void)ti_sa2ul_Sha256Free_ctx(sha256);
        }
        ret = CRYPTOCB_UNAVAILABLE; /* fall back to sw */
    }

    return ret;
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
static int ti_sa2ul_InitSha512_ctx(wc_Sha512* sha512)
{
    SA2UL_ContextParams scParams;

    SA2UL_ContextParams_init(&scParams);

    scParams.opType   = SA2UL_OP_AUTH;
    scParams.hashAlg  = SA2UL_HASH_ALG_SHA2_512;
    /* default length to all ff's, final will override when known */
    scParams.inputLen = 0xffffffffUL;
    sha512->scObj.totalLengthInBytes = 0xffffffffUL;

    if (SA2UL_contextAlloc(cryptoCtx.drvHandle,
                           &sha512->scObj, &scParams) != SystemP_SUCCESS)
    {
        return WC_HW_E;
    }
    return 0;
}

static int ti_sa2ul_Sha512Free_ctx(wc_Sha512* sha512)
{
    (void)SA2UL_contextFree(&sha512->scObj);
    XMEMSET(&sha512->scObj, 0, sizeof(sha512->scObj));

    return 0;
}

static int ti_sa2ul_Sha512Hash(wc_Sha512* sha512, const byte* in,
                               word32 inSz, byte* digest)
{
    int ret = 0;
    byte* buffer = (byte*)sha512->buffer;
    word32 blocksLen;
    word32 partialLen;

    if (in == NULL && digest == NULL)
        return WC_HW_E;

    if (sha512->scObj.txBytesCnt == 0 && sa2ul_hash_in_use == 1) {
        sha512->flags |= WC_HASH_FLAG_ISCOPY;
        return CRYPTOCB_UNAVAILABLE;
    }

    if (in != NULL) {
        /* update... */
        sha512->loLen += inSz;

        /* handle leftovers first */
        if (sha512->buffLen > 0) {
            partialLen = min(inSz, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
            XMEMCPY(&buffer[sha512->buffLen], in, partialLen);
            sha512->buffLen += partialLen;
            in += partialLen;
            inSz -= partialLen;
            if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
                CacheP_wbInv((void *)buffer, WC_SHA512_BLOCK_SIZE, CacheP_TYPE_ALLD);
                if (sha512->scObj.txBytesCnt == 0) {
                    if (ti_sa2ul_InitSha512_ctx(sha512) != 0)
                        return WC_HW_E;
                }
                if (SA2UL_contextProcess(&sha512->scObj, buffer,
                      WC_SHA512_BLOCK_SIZE, hash_scratch) != SystemP_SUCCESS)
                {
                    return WC_HW_E;
                }
                XMEMCPY(sha512->digest, &sha512->scObj.computedHash,
                        WC_SHA512_DIGEST_SIZE);
                /* final will fall back to sw, and sw needs bytes reversed */
                ByteReverseWords64(sha512->digest, sha512->digest,
                                   WC_SHA512_DIGEST_SIZE);
                sha512->buffLen = 0;
            }
        }
        /* chunks of full blocks */
        while (inSz >= WC_SHA512_BLOCK_SIZE) {
            blocksLen = min(sizeof(hash_scratch),
                            inSz & ~((word32)WC_SHA512_BLOCK_SIZE-1));
            CacheP_wbInv((void *)in, blocksLen, CacheP_TYPE_ALLD);
            if (sha512->scObj.txBytesCnt == 0) {
                if (ti_sa2ul_InitSha512_ctx(sha512) != 0)
                    return WC_HW_E;
            }
            if (SA2UL_contextProcess(&sha512->scObj, in, blocksLen,
                                     hash_scratch) != SystemP_SUCCESS) {
                return WC_HW_E;
            }
            XMEMCPY(sha512->digest, &sha512->scObj.computedHash,
                    WC_SHA512_DIGEST_SIZE);
            ByteReverseWords64(sha512->digest, sha512->digest,
                               WC_SHA512_DIGEST_SIZE);
            in += blocksLen;
            inSz -= blocksLen;
        }
        /* save leftovers */
        if (inSz > 0) {
            XMEMCPY(&buffer[0], in, inSz);
            sha512->buffLen = inSz;
        }
    }
    else if (digest != NULL) {
        /* final... */
        /* hash will be finalized in sw via fallback, but we need the driver
         * to tear down the context in hw.  To do that, we update the context
         * length and push some final arbitrary data.  It will not affect
         * the hash */
        if (sha512->scObj.txBytesCnt != 0) {
            sha512->scObj.ctxPrms.inputLen = sha512->scObj.txBytesCnt +
                                             WC_SHA512_DIGEST_SIZE;
            sha512->scObj.totalLengthInBytes = sha512->scObj.txBytesCnt +
                                               WC_SHA512_DIGEST_SIZE;
            CacheP_wbInv((void *)buffer, WC_SHA512_DIGEST_SIZE, CacheP_TYPE_ALLD);
            if (SA2UL_contextProcess(&sha512->scObj, buffer,
                    WC_SHA512_DIGEST_SIZE, hash_scratch) != SystemP_SUCCESS) {
                ret = WC_HW_E;
            }
            (void)ti_sa2ul_Sha512Free_ctx(sha512);
        }
        ret = CRYPTOCB_UNAVAILABLE; /* fall back to sw */
    }

    return ret;
}
#endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_TI_AM64X_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */

static int ti_sa2ul_CryptoDevCb(int devId, wc_CryptoInfo* info, void* devCtx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    WOLFSSL_ENTER("ti_sa2ul_CryptoDevCb");

    (void)devCtx;

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (devId == INVALID_DEVID)
        return CRYPTOCB_UNAVAILABLE;

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    if (info->algo_type == WC_ALGO_TYPE_CIPHER)
    {
#if !defined(NO_AES) && !defined(WOLFSSL_TI_AM64X_NO_AES)
        if (0) {
            /* nothing */
        }
# if defined(HAVE_AES_CBC)
        else if (info->cipher.type == WC_CIPHER_AES_CBC) {
            Aes* aes = info->cipher.aescbc.aes;
            if (aes == NULL)
                return BAD_FUNC_ARG;
            if (check_aes_keylength(aes->keylen) != 0)
                return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
            if (info->cipher.enc) {
                ret = ti_sa2ul_AesCbcEncrypt(info->cipher.aescbc.aes,
                                             info->cipher.aescbc.out,
                                             info->cipher.aescbc.in,
                                             info->cipher.aescbc.sz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                ret = ti_sa2ul_AesCbcDecrypt(info->cipher.aescbc.aes,
                                             info->cipher.aescbc.out,
                                             info->cipher.aescbc.in,
                                             info->cipher.aescbc.sz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AES_CBC */
# if defined(HAVE_AES_ECB)
        else if (info->cipher.type == WC_CIPHER_AES_ECB) {
            Aes* aes = info->cipher.aesecb.aes;
            if (aes == NULL)
                return BAD_FUNC_ARG;
            if (check_aes_keylength(aes->keylen) != 0)
                return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
            if (info->cipher.enc) {
                ret = ti_sa2ul_AesEcbEncrypt(info->cipher.aesecb.aes,
                                             info->cipher.aesecb.out,
                                             info->cipher.aesecb.in,
                                             info->cipher.aesecb.sz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                ret = ti_sa2ul_AesEcbDecrypt(info->cipher.aesecb.aes,
                                             info->cipher.aesecb.out,
                                             info->cipher.aesecb.in,
                                             info->cipher.aesecb.sz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AES_ECB */
# if defined(HAVE_AESGCM)
        else if (info->cipher.type == WC_CIPHER_AES_GCM) {
            if (info->cipher.enc) {
                Aes* aes = info->cipher.aesgcm_enc.aes;
                if (aes == NULL)
                    return BAD_FUNC_ARG;
                if (check_aes_keylength(aes->keylen) != 0 ||
                    info->cipher.aesgcm_enc.sz == 0) {
                        return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
                }
                ret = ti_sa2ul_AesGcmEncrypt(aes,
                        info->cipher.aesgcm_enc.out,
                        info->cipher.aesgcm_enc.in,
                        info->cipher.aesgcm_enc.sz,
                        info->cipher.aesgcm_enc.iv,
                        info->cipher.aesgcm_enc.ivSz,
                        info->cipher.aesgcm_enc.authTag,
                        info->cipher.aesgcm_enc.authTagSz,
                        info->cipher.aesgcm_enc.authIn,
                        info->cipher.aesgcm_enc.authInSz);
            }
#  ifdef HAVE_AES_DECRYPT
            else {
                Aes* aes = info->cipher.aesgcm_dec.aes;
                if (aes == NULL)
                    return BAD_FUNC_ARG;
                if (check_aes_keylength(aes->keylen) != 0 ||
                    info->cipher.aesgcm_dec.sz == 0) {
                        return CRYPTOCB_UNAVAILABLE; /* fall back to sw */
                }
                ret = ti_sa2ul_AesGcmDecrypt(aes,
                        info->cipher.aesgcm_dec.out,
                        info->cipher.aesgcm_dec.in,
                        info->cipher.aesgcm_dec.sz,
                        info->cipher.aesgcm_dec.iv,
                        info->cipher.aesgcm_dec.ivSz,
                        info->cipher.aesgcm_dec.authTag,
                        info->cipher.aesgcm_dec.authTagSz,
                        info->cipher.aesgcm_dec.authIn,
                        info->cipher.aesgcm_dec.authInSz);
            }
#  endif /* HAVE_AES_DECRYPT */
        }
# endif /* HAVE_AESGCM */
#endif /* !NO_AES && !WOLFSSL_TI_AM64X_NO_AES */
    }
    else if (info->algo_type == WC_ALGO_TYPE_HASH)
    {
#if !defined(WOLFSSL_TI_AM64X_NO_SHA) && (!defined(NO_SHA256) || defined(WOLFSSL_SHA512))
        if (0) {
            /* nothing */
        }
# ifndef NO_SHA256
        else if (info->hash.type == WC_HASH_TYPE_SHA256) {
            if ((info->hash.sha256->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                ret = ti_sa2ul_Sha256Hash(info->hash.sha256,
                                          info->hash.in,
                                          info->hash.inSz,
                                          info->hash.digest);
            }
        }
# endif /* !NO_SHA256 */
# ifdef WOLFSSL_SHA512
        else if (info->hash.type == WC_HASH_TYPE_SHA512) {
            if (info->hash.sha512->hashType == WC_HASH_TYPE_SHA512 &&
                (info->hash.sha512->flags & WC_HASH_FLAG_ISCOPY) == 0) {
                ret = ti_sa2ul_Sha512Hash(info->hash.sha512,
                                          info->hash.in,
                                          info->hash.inSz,
                                          info->hash.digest);
                }
        }
# endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_TI_AM64X_NO_SHA && (!NO_SHA256 || WOLFSSL_SHA512) */
    }
#ifndef WC_NO_RNG
# ifdef WOLFSSL_TI_AM64X_RNG_CTR_DRBG
    else if (info->algo_type == WC_ALGO_TYPE_RNG)
    {
        ret = ti_sa2ul_trng_get(info->rng.out, info->rng.sz);
    }
# else
    else if (info->algo_type == WC_ALGO_TYPE_SEED)
    {
        ret = ti_sa2ul_trng_get(info->seed.seed, info->seed.sz);
    }
# endif
#endif /* !WC_NO_RNG */

    return ret;
}

void ti_sa2ul_soc_uid(byte* uid)
{
    if (_getSocUid() == 0)
        XMEMCPY(uid, socUid, sizeof(socUid));
    else
        XMEMSET(uid, 0xFFu, sizeof(socUid));
}

int ti_sa2ul_port_init(void)
{
    int ret = WC_HW_E;

#ifndef WC_NO_RNG
    ti_sa2ul_trng_init();
#endif /* WC_NO_RNG */

    handle = Crypto_open(&cryptoCtx);
    if (handle != NULL) {
        ret = wc_CryptoCb_RegisterDevice(WOLFSSL_TI_SA2UL_DEVID,
                                         ti_sa2ul_CryptoDevCb, NULL);
    }
    return ret;
}

#endif /* WOLFSSL_TI_AM64X */
