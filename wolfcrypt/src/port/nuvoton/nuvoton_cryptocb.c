/* nuvoton_cryptocb.c
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

/* Crypto callback dispatcher for the Nuvoton NuMicro M2354. Routes each
 * wc_AlgoType to the engine file that handles it and turns everything else
 * into a decline, so an operation the CRPT accelerator cannot do runs in
 * software rather than failing. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

int wc_NuvotonCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
#ifdef WOLFSSL_NUVOTON_TRNG
        /* Seed only by default. Offloading the stream benchmarks ~7x faster,
         * but the engine PRNG's construction is undocumented while the
         * Hash-DRBG is specified and seeded from the same TRNG. Set
         * WOLFSSL_NUVOTON_RNG_OFFLOAD to prefer throughput. */
#ifdef WOLFSSL_NUVOTON_RNG_OFFLOAD
        case WC_ALGO_TYPE_RNG:
            ret = wc_NuvotonCb_Rng(info);
            break;
#endif
        case WC_ALGO_TYPE_SEED:
            ret = wc_NuvotonCb_Seed(info);
            break;
#endif
#ifdef WOLFSSL_NUVOTON_HASH
        case WC_ALGO_TYPE_HASH:
            ret = wc_NuvotonCb_Hash(info);
            break;
#endif
#ifdef WOLFSSL_NUVOTON_CIPHER
        case WC_ALGO_TYPE_CIPHER:
            ret = wc_NuvotonCb_Cipher(info);
            break;
#endif
#if defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)
        case WC_ALGO_TYPE_PK:
            ret = wc_NuvotonCb_Pk(info);
            break;
#endif
#if defined(WOLF_CRYPTO_CB_COPY) && defined(WOLFSSL_NUVOTON_HASH)
        case WC_ALGO_TYPE_COPY:
            ret = wc_NuvotonCb_HashCopy(info);
            break;
#endif
#ifdef WOLF_CRYPTO_CB_FREE
        case WC_ALGO_TYPE_FREE:
            ret = wc_NuvotonCb_Free(info);
            break;
#endif
        default:
            break; /* not ours; software handles it */
    }

    return ret;
}

int wc_NuvotonCryptoCb_RegisterDevice(int devId)
{
    int ret;

    ret = wc_nuvoton_hw_init();
    if (ret != 0) {
        WOLFSSL_MSG("Nuvoton: hardware init failed");
        return ret;
    }

    ret = wc_CryptoCb_RegisterDevice(devId, wc_NuvotonCryptoDevCb, NULL);
    if (ret != 0) {
        wc_nuvoton_hw_cleanup();
    }

    return ret;
}

void wc_NuvotonCryptoCb_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
    wc_nuvoton_hw_cleanup();
}

#ifdef WOLF_CRYPTO_CB_FREE
int wc_NuvotonCb_Free(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_NUVOTON_HASH
    if (info->free.algo == WC_ALGO_TYPE_HASH) {
        return wc_NuvotonHashFree(info);
    }
#endif

    /* A Key Store handle in devCtx belongs to whoever wrote it. Declining
     * leaves wolfCrypt's teardown, which does not touch devCtx. */
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLF_CRYPTO_CB_FREE */

#endif /* WOLFSSL_NUVOTON_M2354 && WOLF_CRYPTO_CB */
