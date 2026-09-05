/* silabs_cb_rng.c
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

#if defined(WOLFSSL_SILABS_CRYPTOCB) && defined(WOLFSSL_SILABS_CRYPTOCB_TRNG)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_random.h>
/* for the SE types; silabs_hash.h pulls in em_device.h or the host shim */
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

#ifndef WOLFSSL_SILABS_HOST_TEST
    #include <sl_se_manager_entropy.h>
#endif

/* Ask the SE for random bytes. Unlike silabs_GenerateRand(), which flattens
 * every SE status to WC_HW_E, this maps through silabs_cb_status: a device
 * that reports the command is unsupported yields CRYPTOCB_UNAVAILABLE and
 * wolfCrypt seeds itself, while a genuine TRNG failure still returns WC_HW_E
 * rather than silently downgrading the entropy source. */
static int silabs_rng_bytes(byte* out, word32 sz)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_status_t status;

    status = sl_se_get_random(&cmd, out, sz);

    return silabs_cb_status((int)status);
}

/* WC_ALGO_TYPE_RNG and WC_ALGO_TYPE_SEED. The SE TRNG is a NIST SP800-90B
 * entropy source; wolfCrypt treats it as the seed for its own DRBG unless the
 * application asks for raw output. */
int wc_SilabsRng(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type == WC_ALGO_TYPE_SEED) {
        if (info->seed.seed == NULL) {
            return BAD_FUNC_ARG;
        }
        ret = silabs_rng_bytes(info->seed.seed, info->seed.sz);
    }
#ifdef WOLFSSL_SILABS_TRNG
    /* Only claim whole random blocks when the application opted in to the
     * TRNG feeding every byte; otherwise the wolfCrypt DRBG stays in charge
     * and just gets seeded from the SE above. */
    else if (info->algo_type == WC_ALGO_TYPE_RNG) {
        if (info->rng.out == NULL) {
            return BAD_FUNC_ARG;
        }
        ret = silabs_rng_bytes(info->rng.out, info->rng.sz);
    }
#endif

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_TRNG */
