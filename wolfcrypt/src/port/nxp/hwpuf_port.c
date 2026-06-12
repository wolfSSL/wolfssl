/* hwpuf_port.c
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

#if defined(WOLFSSL_HWPUF) && defined(WOLFSSL_NXP_HWPUF)

#ifndef WOLF_CRYPTO_CB
    #error WOLFSSL_HWPUF support requires ./configure --enable-cryptocb or WOLF_CRYPTO_CB to be defined
#endif

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hwpuf.h>
#include <wolfssl/wolfcrypt/port/nxp/hwpuf_port.h>
#include "fsl_iap_ffr.h"
#include "fsl_puf.h"
#include "fsl_rng.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

typedef struct nxp_hwpuf_ctx {
    word32 keyMask; /* unique per reset */
} nxp_hwpuf_ctx;

static nxp_hwpuf_ctx ctx;
static puf_config_t conf;


static int getACFromPFR(byte *ac)
{
    int ret;
    flash_config_t flashInstance;

    memset(&flashInstance, 0, sizeof(flash_config_t));
    FLASH_Init(&flashInstance);
    FFR_Init(&flashInstance);

    ret = FFR_KeystoreGetAC(&flashInstance, ac);
    return ret != kStatus_Success;
}

static int keyCodeCheck(byte* keyCode, word32* keytype,
                        word32* keyidx, word32* keysize)
{
    *keytype = keyCode[0];
    *keyidx = keyCode[1];
    *keysize = keyCode[3] == 0 ? 512 : 8 * keyCode[3] ;

    if (*keytype >= 2)
        return 1;
    if (*keyidx >= 16)
        return 2;
    if ( !HWPUF_KEY_SIZE_IS_VALID(*keysize) )
        return 3;

    return 0;
}

static int nxp_hwpuf_Init(wc_HWPUF* hwpuf)
{
    WOLFSSL_ENTER("nxp_hwpuf_Init");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    PUF_GetDefaultConfig(&conf);
    if (PUF_Init(PUF, &conf) != kStatus_Success) {
        PUF_Deinit(PUF, &conf);
        return HWPUF_INIT_E;
    }
    ctx.keyMask = RNG->RANDOM_NUMBER;
    return 0;
}

static int nxp_hwpuf_Deinit(wc_HWPUF* hwpuf)
{
    WOLFSSL_ENTER("nxp_hwpuf_Deinit");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    PUF_Deinit(PUF, &conf);

    return 0;
}

static int nxp_hwpuf_Enroll(wc_HWPUF* hwpuf, byte* actCode, word32 actCodeSz)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Enroll");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    ret = PUF_Enroll(PUF, actCode, actCodeSz);
    if (ret == kStatus_EnrollNotAllowed) {
        /* power cycle and try again */
        (void)PUF_PowerCycle(PUF, &conf);
        ret = PUF_Enroll(PUF, actCode, actCodeSz);
    }
    if (ret != kStatus_Success) {
        return HWPUF_ENROLL_E;
    }

    /* wipe ctx if enroll succeeded (re-enroll will render ctx moot) */
    XMEMSET(&ctx, 0, sizeof(ctx));

    return 0;
}

static int nxp_hwpuf_Start(wc_HWPUF* hwpuf, byte* actCode, word32 actCodeSz)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Start");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    ret = PUF_Start(PUF, actCode, actCodeSz);
    if (ret == kStatus_StartNotAllowed) {
        /* power cycle and try again */
        (void)PUF_PowerCycle(PUF, &conf);
        ret = PUF_Start(PUF, actCode, actCodeSz);
    }
    if (ret != kStatus_Success) {
        return HWPUF_START_E;
    }

    return 0;
}

static int nxp_hwpuf_GenerateKey(wc_HWPUF* hwpuf, byte keyIdx, word32 keySz,
                                 byte* keyCode, word32 keyCodeSz)
{
    int ret;
    word32 kcSz;

    WOLFSSL_ENTER("nxp_hwpuf_GenerateKey");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (keyIdx > kPUF_KeyIndexMax)
        return BAD_FUNC_ARG;
    if ( !HWPUF_KEY_SIZE_IS_VALID(keySz) )
        return BAD_FUNC_ARG;
    kcSz = PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(keySz);
    if (keyCode == NULL || kcSz != keyCodeSz)
        return BAD_FUNC_ARG;

    ret = PUF_SetIntrinsicKey(PUF, (puf_key_index_register_t)keyIdx, keySz,
                              keyCode, keyCodeSz);
    if (ret != kStatus_Success)
        return HWPUF_GENERATE_KEY_E;

    return 0;
}

static int nxp_hwpuf_SetKey(wc_HWPUF* hwpuf, byte keyIdx,
                            byte* key, word32 keySz,
                            byte* keyCode, word32 keyCodeSz)
{
    WOLFSSL_ENTER("nxp_hwpuf_SetKey");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    return CRYPTOCB_UNAVAILABLE;
}

static int nxp_hwpuf_GetKey(wc_HWPUF* hwpuf, byte* keyCode, word32 keyCodeSz,
                            byte* key, word32 keySz)
{
    int ret;
    word32 keytype, keyidx, keysize;
    word32 kcSz;

    WOLFSSL_ENTER("nxp_hwpuf_GetKey");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;
    if (keyCode == NULL || keyCodeSz < PUF_MIN_KEY_CODE_SIZE)
        return BAD_FUNC_ARG;

    ret = keyCodeCheck(keyCode, &keytype, &keyidx, &keysize);
    if (ret != kStatus_Success)
        return BAD_FUNC_ARG;

    kcSz = PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(keysize);
    if (kcSz != keyCodeSz)
        return BAD_FUNC_ARG;
    if (keyidx != kPUF_KeyIndex_00 && (key == NULL || keysize != keySz))
        return BAD_FUNC_ARG;

    /* keyidx 0 means key is sent directly on hw bus, never exposed */
    if (keyidx == kPUF_KeyIndex_00) {
        /* keyslot 0 means send to aes engine */
        ret = PUF_GetHwKey(PUF, keyCode, keyCodeSz, kPUF_KeySlot0,
                           ctx.keyMask);
        if (ret != kStatus_Success)
            return HWPUF_GET_KEY_E;
        if (key)
            XMEMSET(key, 0, keySz); /* no key to return, zero out */
    }
    else {
        ret = PUF_GetKey(PUF, keyCode, keyCodeSz, key, keySz);
        if (ret != kStatus_Success)
            return HWPUF_GET_KEY_E;
    }
    return 0;
}

static int nxp_hwpuf_Zeroize(wc_HWPUF* hwpuf)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Zeroize");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    ForceZero(&ctx, sizeof(ctx));

    ret = PUF_Zeroize(PUF);
    PUF_Deinit(PUF, &conf);
    if (ret != kStatus_Success) {
        return HWPUF_ZEROIZE_E;
    }
    return 0;
}

static int nxp_hwpuf_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    WOLFSSL_ENTER("nxp_hwpuf_CryptoDevCb");

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (devId == INVALID_DEVID)
        return CRYPTOCB_UNAVAILABLE;
    if (info->algo_type != WC_ALGO_TYPE_HWPUF)
        return CRYPTOCB_UNAVAILABLE;

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    if (info->hwpuf.type == WC_HWPUF_TYPE_INIT) {
        ret = nxp_hwpuf_Init(info->hwpuf.hwpuf);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_DEINIT) {
        ret = nxp_hwpuf_Deinit(info->hwpuf.hwpuf);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_ENROLL) {
        ret = nxp_hwpuf_Enroll(info->hwpuf.hwpuf,
                               info->hwpuf.op.enroll.actCode,
                               info->hwpuf.op.enroll.actCodeSz);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_START) {
        ret = nxp_hwpuf_Start(info->hwpuf.hwpuf,
                              info->hwpuf.op.start.actCode,
                              info->hwpuf.op.start.actCodeSz);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_GENERATE_KEY) {
        ret = nxp_hwpuf_GenerateKey(info->hwpuf.hwpuf,
                                info->hwpuf.op.generateKey.keyIdx,
                                info->hwpuf.op.generateKey.keySz,
                                info->hwpuf.op.generateKey.keyCode,
                                info->hwpuf.op.generateKey.keyCodeSz);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_SET_KEY) {
        ret = nxp_hwpuf_SetKey(info->hwpuf.hwpuf,
                               info->hwpuf.op.setKey.keyIdx,
                               info->hwpuf.op.setKey.key,
                               info->hwpuf.op.setKey.keySz,
                               info->hwpuf.op.setKey.keyCode,
                               info->hwpuf.op.setKey.keyCodeSz);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_GET_KEY) {
        ret = nxp_hwpuf_GetKey(info->hwpuf.hwpuf,
                               info->hwpuf.op.getKey.keyCode,
                               info->hwpuf.op.getKey.keyCodeSz,
                               info->hwpuf.op.getKey.key,
                               info->hwpuf.op.getKey.keySz);
    }
    else if (info->hwpuf.type == WC_HWPUF_TYPE_ZEROIZE) {
        ret = nxp_hwpuf_Zeroize(info->hwpuf.hwpuf);
    }
    return ret;
}

WOLFSSL_API int nxp_hwpuf_RegisterDevice(wc_HWPUF* hwpuf)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_RegisterDevice");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    if (hwpuf->devId == INVALID_DEVID)
        hwpuf->devId = WOLFSSL_NXP_HWPUF_DEVID;

    ret = wc_CryptoCb_RegisterDevice(hwpuf->devId, nxp_hwpuf_CryptoDevCb, NULL);
    if (ret != 0) {
        WOLFSSL_ERROR_MSG("NXP_HWPUF: nxp_hwpuf_CryptoDevCb, "
                          "wc_CryptoCb_RegisterDevice() failed");
    }
    return ret;
}

WOLFSSL_API int nxp_hwpuf_UnregisterDevice(wc_HWPUF* hwpuf)
{
    WOLFSSL_ENTER("nxp_hwpuf_UnregisterDevice");

    if (hwpuf == NULL)
        return BAD_FUNC_ARG;

    wc_CryptoCb_UnRegisterDevice(hwpuf->devId);

    return 0;
}

#endif /* WOLFSSL_HWPUF && WOLFSSL_NXP_HWPUF */
