/* asu_rng.c
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

#ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_rng.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "xasu_trng.h"
#include "xstatus.h"

/* One TRNG read request, passed as the transaction context. */
typedef struct {
    byte*  buf;
    word32 len;
} AsuTrngReq;

/* Submit thunk: queue one TRNG read of up to one strength block. Called by
 * wc_AsuTransact with the submit lock held, so it only queues the request. The
 * completion ISR copies the random bytes into buf, so no cache maintenance is
 * needed here. */
static int wc_AsuTrngSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuTrngReq* req = (AsuTrngReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_TrngGetRandomNum(params, req->buf, req->len);
}

/* Fill out with len bytes from the ASU TRNG. The TRNG returns at most one
 * strength block (32 bytes) per call, so larger requests run over several
 * transactions, each its own ASU unique id. */
static int wc_AsuTrngFill(byte* out, word32 len)
{
    AsuTrngReq req;
    word32 chunk;

    if (out == NULL) {
        return BAD_FUNC_ARG;
    }

    while (len > 0) {
        if (len < XASU_TRNG_RANDOM_NUM_IN_BYTES) {
            chunk = len;
        }
        else {
            chunk = XASU_TRNG_RANDOM_NUM_IN_BYTES;
        }

        req.buf = out;
        req.len = chunk;

        if (wc_AsuTransact(wc_AsuTrngSubmit, &req, NULL) != XST_SUCCESS) {
            return WC_HW_E;
        }

        out += chunk;
        len -= chunk;
    }

    return 0;
}

/* WC_ALGO_TYPE_SEED: provide the ASU TRNG as a seed source for the DRBG.
 * Internal helper reached through the wc_AsuRng dispatcher. */
static int wc_AsuRngSeed(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_AsuTrngFill(info->seed.seed, info->seed.sz);
}

/* WC_ALGO_TYPE_RNG: serve random blocks straight from the ASU TRNG.
 * Internal helper reached through the wc_AsuRng dispatcher. */
static int wc_AsuRngGenerate(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_AsuTrngFill(info->rng.out, info->rng.sz);
}

/* Single entry point for the ASU TRNG. The crypto callback dispatcher routes
 * both random number requests here and this handler decides which it is: seed a
 * DRBG (WC_ALGO_TYPE_SEED) or serve random blocks (WC_ALGO_TYPE_RNG). */
int wc_AsuRng(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_SEED:
            return wc_AsuRngSeed(info);
        case WC_ALGO_TYPE_RNG:
            return wc_AsuRngGenerate(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_TRNG */
