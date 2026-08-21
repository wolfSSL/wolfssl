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
#ifdef WOLFSSL_VERSAL_GEN2_ASU_CIPHER
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cipher.h>
#endif
#ifdef WOLFSSL_VERSAL_GEN2_ASU_CMAC
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cmac.h>
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && !defined(NO_RSA)
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_rsa.h>
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_ECC) && defined(HAVE_ECC) && \
    !defined(NO_ECC)
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecc.h>
#endif
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECDH
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecdh.h>
#endif
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECIES
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecies.h>
#endif

#ifndef WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#endif

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_VERSAL_GEN2_ASU requires WOLF_CRYPTO_CB"
#endif
#ifndef WOLF_CRYPTO_CB_CMD
    #error "WOLFSSL_VERSAL_GEN2_ASU requires WOLF_CRYPTO_CB_CMD"
#endif

/* Device commands. Register starts the ASU client, and an error here undoes
 * the registration. */
static int wc_AsuCmd(wc_CryptoInfo* info)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    switch (info->cmd.type) {
        case WC_CRYPTOCB_CMD_TYPE_REGISTER:
        #ifndef WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT
            ret = wc_AsuClientInit();
        #else
            ret = 0; /* application brought the client up before this */
        #endif
            break;
        case WC_CRYPTOCB_CMD_TYPE_UNREGISTER:
            ret = 0;
            break;
        default:
            break;
    }

    return ret;
}

/* Send a context copy to whichever engine owns it. */
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

/* Send a context free to whichever engine owns it. */
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
    #ifdef WOLFSSL_VERSAL_GEN2_ASU_CMAC
        case WC_ALGO_TYPE_CMAC:
            ret = wc_AsuCmac(info);
            break;
    #endif
        default:
            break;
    }

    return ret;
}

/* Main dispatcher. Returns 0 when handled, CRYPTOCB_UNAVAILABLE to use
 * software, or a negative error. */
static int wc_AsuCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_NONE:   /* register/unregister device commands */
            ret = wc_AsuCmd(info);
            break;
        case WC_ALGO_TYPE_HASH:   /* asu_hash */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_HASH
            ret = wc_AsuHash(info);
        #endif
            break;
        case WC_ALGO_TYPE_HMAC:   /* asu_hmac */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_HMAC
            ret = wc_AsuHmac(info);
        #endif
            break;
        case WC_ALGO_TYPE_SEED:   /* asu_rng */
        case WC_ALGO_TYPE_RNG:    /* asu_rng */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
            ret = wc_AsuRng(info);
        #endif
            break;
        case WC_ALGO_TYPE_CIPHER: /* asu_cipher */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_CIPHER
            ret = wc_AsuCipher(info);
        #endif
            break;
        case WC_ALGO_TYPE_CMAC:   /* asu_cmac */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_CMAC
            ret = wc_AsuCmac(info);
        #endif
            break;
        case WC_ALGO_TYPE_PK:     /* asu_rsa, asu_ecc, asu_ecdh, asu_ecies */
        #if defined(WOLFSSL_VERSAL_GEN2_ASU_RSA) && !defined(NO_RSA)
            ret = wc_AsuRsa(info);
        #endif
        #if defined(WOLFSSL_VERSAL_GEN2_ASU_ECC) && defined(HAVE_ECC) && \
            !defined(NO_ECC)
            if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                ret = wc_AsuEcc(info);
            }
        #endif
        #ifdef WC_ASU_ECDH_ENABLED
            if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                ret = wc_AsuEcdh(info);
            }
        #endif
        #ifdef WC_ASU_ECIES_ENABLED
            if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                ret = wc_AsuEcies(info);
            }
        #endif
            break;
        case WC_ALGO_TYPE_COPY:   /* send the copy to its engine */
            ret = wc_AsuCopy(info);
            break;
        case WC_ALGO_TYPE_FREE:   /* send the free to its engine */
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
