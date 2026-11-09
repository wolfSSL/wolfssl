/* cracen_cb_rng.c
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

/* The CRACEN TRNG as the seed source for wolfCrypt's Hash-DRBG. Raw TRNG
 * output is handed out directly only with WOLFSSL_CRACEN_RNG_DIRECT. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NRF54L_CRACEN) && defined(WOLFSSL_CRACEN_TRNG) && \
    !defined(WC_NO_RNG)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>

int wc_CracenRng(wc_CryptoInfo* info)
{
    if (info == NULL)
        return BAD_FUNC_ARG;

    if (info->algo_type == WC_ALGO_TYPE_SEED) {
        if (info->seed.seed == NULL && info->seed.sz > 0)
            return BAD_FUNC_ARG;
        return wc_CracenHw_TrngRead(info->seed.seed, info->seed.sz);
    }
#ifdef WOLFSSL_CRACEN_RNG_DIRECT
    if (info->algo_type == WC_ALGO_TYPE_RNG) {
        if (info->rng.out == NULL && info->rng.sz > 0)
            return BAD_FUNC_ARG;
        return wc_CracenHw_TrngRead(info->rng.out, info->rng.sz);
    }
#endif
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#ifndef WOLFSSL_CRACEN_HOST_TEST
/* wc_GenerateSeed() when cracen_settings.h selected it as
 * CUSTOM_RAND_GENERATE_SEED, and usable directly as a raw entropy source. */
int wc_CracenGenerateSeed(unsigned char* output, unsigned int sz)
{
    int ret = wc_CracenHw_Init();
    if (ret == 0)
        ret = wc_CracenHw_TrngRead(output, sz);
    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
        ret = RNG_FAILURE_E;
    return ret;
}
#endif

#endif /* WOLFSSL_NRF54L_CRACEN && WOLFSSL_CRACEN_TRNG && !WC_NO_RNG */
