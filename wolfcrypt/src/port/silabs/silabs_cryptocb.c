/* silabs_cryptocb.c
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

#ifdef WOLFSSL_SILABS_CRYPTOCB

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_SILABS_CRYPTOCB requires WOLF_CRYPTO_CB"
#endif

/* Map an SE Manager status to a wolfCrypt error. SL_STATUS_NOT_SUPPORTED and
 * SL_STATUS_INVALID_PARAMETER become CRYPTOCB_UNAVAILABLE so that a request the
 * SE cannot service falls back to software instead of failing the caller. */
int silabs_cb_status(int slStatus)
{
    /* The raw-status helpers return a negative wolfCrypt error for argument
     * problems rather than an SE status; pass those straight through so they
     * are not flattened into WC_HW_E. */
    if (slStatus < 0) {
        return slStatus;
    }

    switch ((sl_status_t)slStatus) {
    case SL_STATUS_OK:
        return 0;
    case SL_STATUS_NOT_SUPPORTED:
    case SL_STATUS_INVALID_PARAMETER:
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    default:
        return WC_HW_E;
    }
}

/* Map a wolfCrypt hash type to the SE hash type and its digest length.
 * Returns SL_SE_HASH_NONE when the SE cannot do that hash. */
int silabs_cb_hash_type(int wcHashType, int* digestSz)
{
    int sz = 0;
    int se = SL_SE_HASH_NONE;

    switch (wcHashType) {
#ifndef NO_SHA
    case WC_HASH_TYPE_SHA:
        se = SL_SE_HASH_SHA1;    sz = WC_SHA_DIGEST_SIZE;    break;
#endif
#ifdef WOLFSSL_SHA224
    case WC_HASH_TYPE_SHA224:
        se = SL_SE_HASH_SHA224;  sz = WC_SHA224_DIGEST_SIZE; break;
#endif
#ifndef NO_SHA256
    case WC_HASH_TYPE_SHA256:
        se = SL_SE_HASH_SHA256;  sz = WC_SHA256_DIGEST_SIZE; break;
#endif
#ifdef WOLFSSL_SILABS_SE_SHA384
    case WC_HASH_TYPE_SHA384:
        se = SL_SE_HASH_SHA384;  sz = WC_SHA384_DIGEST_SIZE; break;
#endif
#ifdef WOLFSSL_SILABS_SE_SHA512
    case WC_HASH_TYPE_SHA512:
        se = SL_SE_HASH_SHA512;  sz = WC_SHA512_DIGEST_SIZE; break;
#endif
    default:
        break;
    }

    if (digestSz != NULL) {
        *digestSz = sz;
    }

    return se;
}

/* Route a context free (WC_ALGO_TYPE_FREE) to the engine that owns the object.
 * Only CMAC allocates, so it is the only case here. */
static int wc_SilabsFree(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    switch (info->free.algo) {
#if defined(WOLFSSL_SILABS_CRYPTOCB_CMAC) && defined(WOLFSSL_CMAC) && \
    !defined(NO_AES)
    case WC_ALGO_TYPE_CMAC:
        ret = wc_SilabsCmac(info);
        break;
#endif
    default:
        break;
    }

    return ret;
}

/* Crypto callback dispatcher. Each engine handler runs the full operation and
 * returns the wolfCrypt result: 0 when the SE handled it, CRYPTOCB_UNAVAILABLE
 * to fall back to software, or a negative error. */
static int wc_SilabsCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
    case WC_ALGO_TYPE_HASH:
#ifdef WOLFSSL_SILABS_CRYPTOCB_HASH
        ret = wc_SilabsHash(info);
#endif
        break;
    case WC_ALGO_TYPE_SEED:
    case WC_ALGO_TYPE_RNG:
#ifdef WOLFSSL_SILABS_CRYPTOCB_TRNG
        ret = wc_SilabsRng(info);
#endif
        break;
    case WC_ALGO_TYPE_CIPHER:
#ifdef WOLFSSL_SILABS_CRYPTOCB_CIPHER
        ret = wc_SilabsCipher(info);
#endif
        break;
    case WC_ALGO_TYPE_CMAC:
#if defined(WOLFSSL_SILABS_CRYPTOCB_CMAC) && defined(WOLFSSL_CMAC) && \
    !defined(NO_AES)
        ret = wc_SilabsCmac(info);
#endif
        break;
    case WC_ALGO_TYPE_PK:
#if defined(WOLFSSL_SILABS_CRYPTOCB_ECC) && defined(HAVE_ECC)
        ret = wc_SilabsPk(info);
#endif
        break;
    case WC_ALGO_TYPE_KDF:
#ifdef WOLFSSL_SILABS_CRYPTOCB_KDF
        ret = wc_SilabsKdf(info);
#endif
        break;
#ifdef WOLF_CRYPTO_CB_COPY
    case WC_ALGO_TYPE_COPY:
    #ifdef WOLFSSL_SILABS_CRYPTOCB_HASH
        if (info->copy.algo == WC_ALGO_TYPE_HASH) {
            ret = wc_SilabsHash(info);
        }
    #endif
        break;
#endif
    case WC_ALGO_TYPE_FREE:
        ret = wc_SilabsFree(info);
        break;
    default:
        break;
    }

    return ret;
}

int wc_SilabsCryptoCb_RegisterDevice(int devId)
{
    return wc_CryptoCb_RegisterDevice(devId, wc_SilabsCryptoDevCb, NULL);
}

int wc_SilabsCryptoCb_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
    return 0;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB */
