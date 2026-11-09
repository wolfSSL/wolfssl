/* cracen_cb_cmac.c
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

/* AES-CMAC through the BA411E engine with hardware state export.
 *
 * The Cmac object's software members are reused while the port owns it: the
 * key sits in cmac->aes.devKey, the running state in cmac->digest and the
 * held-back tail of the message in cmac->buffer. The engine applies the
 * final-block subkey itself when told how many bytes of the last block are
 * valid, so at least one byte (a whole block when the length is a multiple of
 * 16) is always held back for the final call. devCtx marks ownership: the init
 * call sets it, so an update or final that finds it NULL belongs to a software
 * context and is declined.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_CMAC) && \
    defined(WOLFSSL_CMAC) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_regs.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

static int cracen_cmac_blocks(Cmac* cmac, const byte* data, word32 sz)
{
    byte        state[WC_AES_BLOCK_SIZE];
    const byte* statePtr = NULL;
    int         ret;

    if (cmac->devCtx == WC_CRACEN_MARK_STATE) {
        XMEMCPY(state, cmac->digest, WC_AES_BLOCK_SIZE);
        statePtr = state;
    }
    ret = wc_CracenHw_AesCmac((const byte*)cmac->aes.devKey,
        (word32)cmac->aes.keylen, statePtr, data, sz, NULL, 0, cmac->digest, 0);
    if (ret == 0)
        cmac->devCtx = WC_CRACEN_MARK_STATE;
    else if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
        ret = WC_HW_E;
    ForceZero(state, sizeof(state));
    return ret;
}

static int cracen_cmac_init(Cmac* cmac, const byte* key, word32 keySz)
{
    wc_CracenHwInfo hw;

    if (keySz != 16 && keySz != 24 && keySz != 32)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (wc_CracenHw_GetInfo(&hw) != 0 ||
            (hw.engines & WC_CM_HW_BA411_AES) == 0 ||
            (hw.aesModes & (WC_CM_AES_MODE_CMAC >> WC_CM_AES_CFG_MODE_SHIFT)) == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMSET(cmac->aes.devKey, 0, sizeof(cmac->aes.devKey));
    XMEMCPY(cmac->aes.devKey, key, keySz);
    cmac->aes.keylen = (int)keySz;
    XMEMSET(cmac->digest, 0, sizeof(cmac->digest));
    cmac->bufferSz = 0;
    cmac->totalSz  = 0;
    cmac->devCtx   = WC_CRACEN_MARK_FRESH;
    return 0;
}

static int cracen_cmac_update(Cmac* cmac, const byte* in, word32 inSz)
{
    int    ret = 0;
    word32 full;

    if (inSz == 0)
        return 0;
    if (in == NULL)
        return BAD_FUNC_ARG;

    cmac->totalSz += inSz;

    if (cmac->bufferSz > 0) {
        word32 fill = WC_AES_BLOCK_SIZE - cmac->bufferSz;
        if (fill > inSz)
            fill = inSz;
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, fill);
        cmac->bufferSz += fill;
        in   += fill;
        inSz -= fill;
        if (inSz == 0)
            return 0; /* nothing follows: keep it for the final call */
        ret = cracen_cmac_blocks(cmac, cmac->buffer, WC_AES_BLOCK_SIZE);
        cmac->bufferSz = 0;
    }

    /* everything but the last 1..16 bytes */
    full = (inSz - 1) & ~15UL;
    if (ret == 0 && full > 0) {
        ret = cracen_cmac_blocks(cmac, in, full);
        in   += full;
        inSz -= full;
    }
    if (ret == 0) {
        XMEMCPY(cmac->buffer, in, inSz);
        cmac->bufferSz = inSz;
    }
    return ret;
}

static int cracen_cmac_final(Cmac* cmac, byte* out, word32* outSz)
{
    byte        state[WC_AES_BLOCK_SIZE];
    byte        mac[WC_AES_BLOCK_SIZE];
    const byte* statePtr = NULL;
    int         ret;

    if (out == NULL || outSz == NULL)
        return BAD_FUNC_ARG;
    if (cmac->bufferSz > WC_AES_BLOCK_SIZE ||
            (cmac->devCtx == WC_CRACEN_MARK_STATE && cmac->bufferSz == 0)) {
        return BAD_STATE_E;
    }

    if (cmac->devCtx == WC_CRACEN_MARK_STATE) {
        XMEMCPY(state, cmac->digest, WC_AES_BLOCK_SIZE);
        statePtr = state;
    }
    ret = wc_CracenHw_AesCmac((const byte*)cmac->aes.devKey,
        (word32)cmac->aes.keylen, statePtr, NULL, 0, cmac->buffer,
        cmac->bufferSz, mac, 1);
    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
        ret = WC_HW_E;
    if (ret == 0) {
        if (*outSz > WC_AES_BLOCK_SIZE)
            *outSz = WC_AES_BLOCK_SIZE;
        XMEMCPY(out, mac, *outSz);
    }

    ForceZero(cmac->aes.devKey, sizeof(cmac->aes.devKey));
    cmac->aes.keylen = 0;
    ForceZero(cmac->buffer, sizeof(cmac->buffer));
    ForceZero(cmac->digest, sizeof(cmac->digest));
    cmac->bufferSz = 0;
    cmac->devCtx   = NULL;
    ForceZero(state, sizeof(state));
    ForceZero(mac, sizeof(mac));
    return ret;
}

int wc_CracenCmac(wc_CryptoInfo* info)
{
    Cmac* cmac;
    int   ret = 0;

    if (info == NULL)
        return BAD_FUNC_ARG;
    if (info->algo_type != WC_ALGO_TYPE_CMAC)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    cmac = info->cmac.cmac;
    if (cmac == NULL)
        return BAD_FUNC_ARG;
    if (info->cmac.type != WC_CMAC_AES)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    /* One request may carry any of init (key), update (in) and final (out):
     * wc_InitCmac_ex, wc_CmacUpdate and wc_CmacFinal send one each, the
     * one-shot wc_AesCmacGenerate_ex sends them together. */
    if (info->cmac.key != NULL) {
        ret = cracen_cmac_init(cmac, info->cmac.key, info->cmac.keySz);
        if (ret != 0)
            return ret;
    }
    else if (cmac->devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (info->cmac.in != NULL || info->cmac.inSz > 0)
        ret = cracen_cmac_update(cmac, info->cmac.in, info->cmac.inSz);

    if (ret == 0 && info->cmac.out != NULL)
        ret = cracen_cmac_final(cmac, info->cmac.out, info->cmac.outSz);

    return ret;
}

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_CMAC && WOLFSSL_CMAC && !NO_AES */
