/* nuvoton_cb_rng.c
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

/* Random numbers on the M2354. Only the seed comes from here by default; the
 * stream is wolfCrypt's Hash-DRBG. WOLFSSL_NUVOTON_RNG_OFFLOAD takes the
 * stream from the engine instead. See the dispatcher for why. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_TRNG) && \
    defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#ifdef WOLFSSL_NUVOTON_RNG_OFFLOAD
int wc_NuvotonCb_Rng(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->rng.out == NULL || info->rng.sz == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return wc_nuvoton_hw_trng(info->rng.out, info->rng.sz);
}
#endif /* WOLFSSL_NUVOTON_RNG_OFFLOAD */

int wc_NuvotonCb_Seed(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->seed.seed == NULL || info->seed.sz == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return wc_nuvoton_hw_trng(info->seed.seed, info->seed.sz);
}

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_TRNG && WOLF_CRYPTO_CB */
