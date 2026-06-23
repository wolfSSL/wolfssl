/* asu_cryptocb.c
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

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_rng.h>
#endif
#ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_hash.h>
#endif
#ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_hmac.h>
#endif

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_VERSAL_GEN2_ASU requires WOLF_CRYPTO_CB"
#endif

/* Route a context copy (WC_ALGO_TYPE_COPY) to the engine that owns the object,
 * keyed on the copy sub-algo. Each engine's single entry handles the copy.
 * Engines added later (cipher, pk) get a case here. */
static int wc_AsuCopy(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    switch (info->copy.algo) {
    #ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
        case WC_ALGO_TYPE_HASH:
            ret = wc_AsuHash(info);
            break;
    #endif
    #ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC
        case WC_ALGO_TYPE_HMAC:
            ret = wc_AsuHmac(info);
            break;
    #endif
        default:
            break;
    }

    return ret;
}

/* Route a context free (WC_ALGO_TYPE_FREE) to the engine that owns the object,
 * keyed on the free sub-algo, the same way as wc_AsuCopy. */
static int wc_AsuFree(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    switch (info->free.algo) {
    #ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
        case WC_ALGO_TYPE_HASH:
            ret = wc_AsuHash(info);
            break;
    #endif
    #ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC
        case WC_ALGO_TYPE_HMAC:
            ret = wc_AsuHmac(info);
            break;
    #endif
        default:
            break;
    }

    return ret;
}

/* Crypto callback dispatcher. Each engine handler runs the full operation
 * (looping over ASU transactions as needed) and returns the wolfCrypt result:
 * 0 when the ASU handled it, CRYPTOCB_UNAVAILABLE to fall back to software, or a
 * negative error. Engine cases are filled in per milestone: M1 hash and rng,
 * M2 aes, M3 public key. */
static int wc_AsuCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_HASH:   /* M1 asu_hash */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
            ret = wc_AsuHash(info);
        #endif
            break;
        case WC_ALGO_TYPE_HMAC:   /* M1 asu_hmac */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC
            ret = wc_AsuHmac(info);
        #endif
            break;
        case WC_ALGO_TYPE_SEED:   /* M1 asu_rng  */
        case WC_ALGO_TYPE_RNG:    /* M1 asu_rng  */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
            ret = wc_AsuRng(info);
        #endif
            break;
        case WC_ALGO_TYPE_CIPHER: /* M2 asu_aes  */
            break;
        case WC_ALGO_TYPE_CMAC:   /* M2 asu_aes  */
            break;
        case WC_ALGO_TYPE_PK:     /* M3 asu_rsa and asu_ecc */
            break;
        case WC_ALGO_TYPE_COPY:   /* context copy: route by sub-algo to its engine */
            ret = wc_AsuCopy(info);
            break;
        case WC_ALGO_TYPE_FREE:   /* context free: route by sub-algo to its engine */
            ret = wc_AsuFree(info);
            break;
        default:
            break;
    }

    return ret;
}

int wc_AsuCryptoCb_RegisterDevice(int devId)
{
    return wc_CryptoCb_RegisterDevice(devId, wc_AsuCryptoDevCb, NULL);
}

void wc_AsuCryptoCb_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU */
