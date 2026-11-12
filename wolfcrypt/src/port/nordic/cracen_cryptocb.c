/* cracen_cryptocb.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_NRF54L_CRACEN

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_NRF54L_CRACEN requires WOLF_CRYPTO_CB"
#endif

/* Each handler runs the whole request and returns 0, CRYPTOCB_UNAVAILABLE to
 * let software take it, or a negative error. HMAC is not offloaded as such:
 * declining it leaves wolfCrypt's HMAC running on hash objects that carry this
 * devId, so the inner hashes still go to the hardware. */
static int wc_CracenCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devId;
    (void)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

    switch (info->algo_type) {
#ifdef WOLFSSL_CRACEN_HASH
        case WC_ALGO_TYPE_HASH:
            ret = wc_CracenHash(info);
            break;
#endif
#ifdef WOLFSSL_CRACEN_CIPHER
        case WC_ALGO_TYPE_CIPHER:
            ret = wc_CracenCipher(info);
            break;
#endif
#if defined(WOLFSSL_CRACEN_CMAC) && defined(WOLFSSL_CMAC) && !defined(NO_AES)
        case WC_ALGO_TYPE_CMAC:
            ret = wc_CracenCmac(info);
            break;
#endif
#if defined(WOLFSSL_CRACEN_TRNG) && !defined(WC_NO_RNG)
        case WC_ALGO_TYPE_SEED:
        case WC_ALGO_TYPE_RNG:
            ret = wc_CracenRng(info);
            break;
#endif
#ifdef WOLFSSL_CRACEN_PK
        case WC_ALGO_TYPE_PK:
            ret = wc_CracenPk(info);
            break;
#endif
        default:
            break;
    }

    return ret;
}

int wc_CracenCryptoCb_RegisterDevice(int devId)
{
    int ret = wc_CracenHw_Init();
    if (ret == 0)
        ret = wc_CryptoCb_RegisterDevice(devId, wc_CracenCryptoDevCb, NULL);
    return ret;
}

int wc_CracenCryptoCb_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
    return 0;
}

int wc_CracenInit(void)
{
    return wc_CracenCryptoCb_RegisterDevice(WOLFSSL_CRACEN_DEVID);
}

void wc_CracenCleanup(void)
{
    (void)wc_CracenCryptoCb_UnRegisterDevice(WOLFSSL_CRACEN_DEVID);
    wc_CracenHw_Cleanup();
}

int wc_CracenGetInfo(wc_CracenHwInfo* info)
{
    return wc_CracenHw_GetInfo(info);
}

int wc_CracenTrngRead(byte* out, word32 sz)
{
    int ret = wc_CracenHw_Init();
    if (ret == 0)
        ret = wc_CracenHw_TrngRead(out, sz);
    return ret;
}

void wc_CracenTrngOff(void)
{
    wc_CracenHw_TrngOff();
}

int wc_CracenTrngGetStats(wc_CracenTrngStats* stats)
{
    return wc_CracenHw_TrngGetStats(stats);
}

int wc_CracenPkLoadMicrocode(const word32* ucode, word32 words)
{
    int ret = wc_CracenHw_Init();
    if (ret == 0)
        ret = wc_CracenHw_PkLoadMicrocode(ucode, words);
    return ret;
}

int wc_CracenPkReady(void)
{
    return wc_CracenHw_PkReady();
}

#endif /* WOLFSSL_NRF54L_CRACEN */
