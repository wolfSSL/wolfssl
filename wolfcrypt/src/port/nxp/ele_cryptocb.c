/* ele_cryptocb.c
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

/* Crypto callback device for the NXP EdgeLock Secure Enclave (ELE). Only
 * seeding is implemented; the rest needs the enclave HSM interface
 * (/dev/hsm0_ch0) and NXP's imx-secure-enclave library, which not every BSP
 * ships. Anything unimplemented returns CRYPTOCB_UNAVAILABLE so wolfCrypt uses
 * its software implementation. The enclave exposes no post-quantum algorithms. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_NXP_ELE

#include <wolfssl/wolfcrypt/port/nxp/ele.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

int wc_EleCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
    #if defined(WOLFSSL_NXP_ELE_TRNG) && !defined(WC_NO_RNG)
        case WC_ALGO_TYPE_SEED:
            ret = wc_ele_trng_read(info->seed.seed, info->seed.sz);
            break;
    #endif

        /* Falling through keeps the software fallback automatic. */
        case WC_ALGO_TYPE_HASH:
        case WC_ALGO_TYPE_CIPHER:
        case WC_ALGO_TYPE_PK:
        case WC_ALGO_TYPE_HMAC:
        case WC_ALGO_TYPE_CMAC:
        case WC_ALGO_TYPE_RNG:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

int wc_EleCryptoCb_RegisterDevice(int devId)
{
    if (devId == INVALID_DEVID) {
        devId = WOLFSSL_NXP_ELE_DEVID;
    }

    return wc_CryptoCb_RegisterDevice(devId, wc_EleCryptoDevCb, NULL);
}

void wc_EleCryptoCb_UnRegisterDevice(int devId)
{
    if (devId == INVALID_DEVID) {
        devId = WOLFSSL_NXP_ELE_DEVID;
    }

    wc_CryptoCb_UnRegisterDevice(devId);
}

#endif /* WOLFSSL_NXP_ELE */
