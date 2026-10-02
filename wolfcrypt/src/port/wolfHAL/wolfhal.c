/* wolfhal.c
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

#ifdef WOLFSSL_WOLFHAL

/* Application-supplied, on the include path, same contract settings.h has
 * with user_settings.h. Must come first: it brings in the wolfHAL platform
 * driver headers (and with them the direct API mapping defines) and names the
 * device for each algorithm. See wolfhal.h for what it has to provide. */
#include "wolfHAL_board.h"

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/wolfHAL/wolfhal.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <wolfHAL/error.h>

/* A stock wolfHAL_board.h already names its devices BOARD_*_DEV. Accept those
 * so such a board needs no wolfSSL-specific additions. */
#if !defined(WC_WOLFHAL_AES_ECB_DEV) && defined(BOARD_AES_ECB_DEV)
    #define WC_WOLFHAL_AES_ECB_DEV BOARD_AES_ECB_DEV
#endif
#if !defined(WC_WOLFHAL_AES_CBC_DEV) && defined(BOARD_AES_CBC_DEV)
    #define WC_WOLFHAL_AES_CBC_DEV BOARD_AES_CBC_DEV
#endif
#if !defined(WC_WOLFHAL_AES_GCM_DEV) && defined(BOARD_AES_GCM_DEV)
    #define WC_WOLFHAL_AES_GCM_DEV BOARD_AES_GCM_DEV
#endif
#if !defined(WC_WOLFHAL_AES_CCM_DEV) && defined(BOARD_AES_CCM_DEV)
    #define WC_WOLFHAL_AES_CCM_DEV BOARD_AES_CCM_DEV
#endif
#if !defined(WC_WOLFHAL_RNG_DEV) && defined(BOARD_RNG_DEV)
    #define WC_WOLFHAL_RNG_DEV BOARD_RNG_DEV
#endif

/* Offload gates. A mode is dispatched to hardware only when wolfCrypt enables
 * it and wolfHAL_board.h names a device for it. Anything else stays out of the
 * dispatch, returns CRYPTOCB_UNAVAILABLE, and falls back to software, so a
 * board offloads the subset its hardware covers without constraining the
 * wolfSSL build. */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_AES)
    #if defined(HAVE_AES_CBC) && defined(WC_WOLFHAL_AES_CBC_DEV)
        #define WC_WOLFHAL_OFFLOAD_AES_CBC
    #endif
    #if defined(HAVE_AESGCM) && defined(WC_WOLFHAL_AES_GCM_DEV)
        #define WC_WOLFHAL_OFFLOAD_AES_GCM
    #endif
    #if defined(HAVE_AESCCM) && defined(WC_WOLFHAL_AES_CCM_DEV)
        #define WC_WOLFHAL_OFFLOAD_AES_CCM
    #endif
    #if defined(HAVE_AES_ECB) && defined(WC_WOLFHAL_AES_ECB_DEV)
        #define WC_WOLFHAL_OFFLOAD_AES_ECB
    #endif
#endif

/* No fallback for the RNG: the board's TRNG is the only entropy source, so a
 * missing device is a build error rather than a dispatch that can decline. */
#if defined(WOLFSSL_WOLFHAL_RNG) && !defined(WC_WOLFHAL_RNG_DEV)
    #error "wolfHAL_board.h must define WC_WOLFHAL_RNG_DEV (or BOARD_RNG_DEV)"
#endif

static int wc_wolfHAL_TranslateError(whal_Error err)
{
    switch (err) {
        case WHAL_SUCCESS:   return 0;
        case WHAL_EINVAL:    return BAD_FUNC_ARG;
        case WHAL_ENOTSUP:   return CRYPTOCB_UNAVAILABLE;
        case WHAL_EHARDWARE: return WC_HW_E;
        case WHAL_ETIMEOUT:  return WC_TIMEOUT_E;
        default:             return WC_HW_E;
    }
}

#ifdef WOLF_CRYPTO_CB
#ifndef NO_AES

#ifdef WC_WOLFHAL_OFFLOAD_AES_CBC
static int wc_wolfHAL_AesCbc(wc_CryptoInfo* info)
{
    Aes* aes         = info->cipher.aescbc.aes;
    const byte* in   = info->cipher.aescbc.in;
    byte* out        = info->cipher.aescbc.out;
    word32 sz        = info->cipher.aescbc.sz;
    whal_Error err;

    /* wolfHAL is stateless across calls, so aes->reg must carry the last
     * ciphertext block into the next call. On decrypt capture it up front,
     * since wolfCrypt permits in-place operation (in == out). aes->tmp is
     * the same scratch the software path uses for this. */
    if (!info->cipher.enc && sz >= WC_AES_BLOCK_SIZE)
        XMEMCPY(aes->tmp, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

    err = whal_AesCbc_Oneshot(WC_WOLFHAL_AES_CBC_DEV,
            info->cipher.enc ? WHAL_CRYPTO_ENCRYPT : WHAL_CRYPTO_DECRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            (const byte*)aes->reg,
            in, out, (size_t)sz);
    if (err != WHAL_SUCCESS)
        return wc_wolfHAL_TranslateError(err);

    if (sz >= WC_AES_BLOCK_SIZE) {
        if (info->cipher.enc)
            XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        else
            XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
    }

    return 0;
}
#endif /* WC_WOLFHAL_OFFLOAD_AES_CBC */

#ifdef WC_WOLFHAL_OFFLOAD_AES_GCM
static int wc_wolfHAL_AesGcmEncrypt(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesgcm_enc.aes;
    whal_Error err;

    err = whal_AesGcm_Oneshot(WC_WOLFHAL_AES_GCM_DEV, WHAL_CRYPTO_ENCRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            info->cipher.aesgcm_enc.iv,     (size_t)info->cipher.aesgcm_enc.ivSz,
            info->cipher.aesgcm_enc.authIn, (size_t)info->cipher.aesgcm_enc.authInSz,
            info->cipher.aesgcm_enc.in,     info->cipher.aesgcm_enc.out,
            (size_t)info->cipher.aesgcm_enc.sz,
            info->cipher.aesgcm_enc.authTag,
            (size_t)info->cipher.aesgcm_enc.authTagSz);

    return wc_wolfHAL_TranslateError(err);
}

static int wc_wolfHAL_AesGcmDecrypt(wc_CryptoInfo* info)
{
    Aes* aes      = info->cipher.aesgcm_dec.aes;
    word32 tagSz  = info->cipher.aesgcm_dec.authTagSz;
    byte computedTag[WC_AES_BLOCK_SIZE];
    word32 i, diff = 0;
    whal_Error err;

    if (tagSz > sizeof(computedTag))
        return BAD_FUNC_ARG;

    /* wolfHAL always emits the tag rather than checking it, so the compare
     * stays here: constant-time, and fail-closed on mismatch. */
    err = whal_AesGcm_Oneshot(WC_WOLFHAL_AES_GCM_DEV, WHAL_CRYPTO_DECRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            info->cipher.aesgcm_dec.iv,     (size_t)info->cipher.aesgcm_dec.ivSz,
            info->cipher.aesgcm_dec.authIn, (size_t)info->cipher.aesgcm_dec.authInSz,
            info->cipher.aesgcm_dec.in,     info->cipher.aesgcm_dec.out,
            (size_t)info->cipher.aesgcm_dec.sz,
            computedTag, (size_t)tagSz);
    if (err != WHAL_SUCCESS)
        return wc_wolfHAL_TranslateError(err);

    for (i = 0; i < tagSz; i++)
        diff |= computedTag[i] ^ info->cipher.aesgcm_dec.authTag[i];
    if (diff != 0) {
        if (info->cipher.aesgcm_dec.out != NULL && info->cipher.aesgcm_dec.sz > 0)
            XMEMSET(info->cipher.aesgcm_dec.out, 0, info->cipher.aesgcm_dec.sz);
        return AES_GCM_AUTH_E;
    }
    return 0;
}
#endif /* WC_WOLFHAL_OFFLOAD_AES_GCM */

#ifdef WC_WOLFHAL_OFFLOAD_AES_CCM
static int wc_wolfHAL_AesCcmEncrypt(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesccm_enc.aes;
    whal_Error err;

    err = whal_AesCcm_Oneshot(WC_WOLFHAL_AES_CCM_DEV, WHAL_CRYPTO_ENCRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            info->cipher.aesccm_enc.nonce,  (size_t)info->cipher.aesccm_enc.nonceSz,
            info->cipher.aesccm_enc.authIn, (size_t)info->cipher.aesccm_enc.authInSz,
            info->cipher.aesccm_enc.in,     info->cipher.aesccm_enc.out,
            (size_t)info->cipher.aesccm_enc.sz,
            info->cipher.aesccm_enc.authTag,
            (size_t)info->cipher.aesccm_enc.authTagSz);

    return wc_wolfHAL_TranslateError(err);
}

static int wc_wolfHAL_AesCcmDecrypt(wc_CryptoInfo* info)
{
    Aes* aes      = info->cipher.aesccm_dec.aes;
    word32 tagSz  = info->cipher.aesccm_dec.authTagSz;
    byte computedTag[WC_AES_BLOCK_SIZE];
    word32 i, diff = 0;
    whal_Error err;

    if (tagSz > sizeof(computedTag))
        return BAD_FUNC_ARG;

    err = whal_AesCcm_Oneshot(WC_WOLFHAL_AES_CCM_DEV, WHAL_CRYPTO_DECRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            info->cipher.aesccm_dec.nonce,  (size_t)info->cipher.aesccm_dec.nonceSz,
            info->cipher.aesccm_dec.authIn, (size_t)info->cipher.aesccm_dec.authInSz,
            info->cipher.aesccm_dec.in,     info->cipher.aesccm_dec.out,
            (size_t)info->cipher.aesccm_dec.sz,
            computedTag, (size_t)tagSz);
    if (err != WHAL_SUCCESS)
        return wc_wolfHAL_TranslateError(err);

    for (i = 0; i < tagSz; i++)
        diff |= computedTag[i] ^ info->cipher.aesccm_dec.authTag[i];
    if (diff != 0) {
        if (info->cipher.aesccm_dec.out != NULL && info->cipher.aesccm_dec.sz > 0)
            XMEMSET(info->cipher.aesccm_dec.out, 0, info->cipher.aesccm_dec.sz);
        return AES_CCM_AUTH_E;
    }
    return 0;
}
#endif /* WC_WOLFHAL_OFFLOAD_AES_CCM */

#ifdef WC_WOLFHAL_OFFLOAD_AES_ECB
static int wc_wolfHAL_AesEcb(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesecb.aes;
    whal_Error err;

    err = whal_AesEcb_Oneshot(WC_WOLFHAL_AES_ECB_DEV,
            info->cipher.enc ? WHAL_CRYPTO_ENCRYPT : WHAL_CRYPTO_DECRYPT,
            (const byte*)aes->devKey, (size_t)aes->keylen,
            info->cipher.aesecb.in, info->cipher.aesecb.out,
            (size_t)info->cipher.aesecb.sz);

    return wc_wolfHAL_TranslateError(err);
}
#endif /* WC_WOLFHAL_OFFLOAD_AES_ECB */

#endif /* !NO_AES */

int wc_wolfHAL_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

    if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
#ifndef NO_AES
        switch (info->cipher.type) {
    #ifdef WC_WOLFHAL_OFFLOAD_AES_CBC
            case WC_CIPHER_AES_CBC:
                return wc_wolfHAL_AesCbc(info);
    #endif
    #ifdef WC_WOLFHAL_OFFLOAD_AES_GCM
            case WC_CIPHER_AES_GCM:
                if (info->cipher.enc)
                    return wc_wolfHAL_AesGcmEncrypt(info);
                else
                    return wc_wolfHAL_AesGcmDecrypt(info);
    #endif
    #ifdef WC_WOLFHAL_OFFLOAD_AES_CCM
            case WC_CIPHER_AES_CCM:
                if (info->cipher.enc)
                    return wc_wolfHAL_AesCcmEncrypt(info);
                else
                    return wc_wolfHAL_AesCcmDecrypt(info);
    #endif
    #ifdef WC_WOLFHAL_OFFLOAD_AES_ECB
            case WC_CIPHER_AES_ECB:
                return wc_wolfHAL_AesEcb(info);
    #endif
            default:
                break;
        }
#endif /* !NO_AES */
    }

    return CRYPTOCB_UNAVAILABLE;
}

int wc_wolfHAL_RegisterDevice(int devId)
{
    WOLFSSL_MSG("wolfHAL: registering crypto device");

    /* Peripheral bring-up (whal_Crypto_Init / whal_Rng_Init) is the board's
     * job; whal_Board_Init() must have run before this point. */
    return wc_CryptoCb_RegisterDevice(devId, wc_wolfHAL_CryptoDevCb, NULL);
}

void wc_wolfHAL_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
}
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLFSSL_WOLFHAL_RNG
int wc_wolfHAL_GenerateSeed(unsigned char* output, unsigned int sz)
{
    whal_Error err;

    if (output == NULL)
        return BAD_FUNC_ARG;

    err = whal_Rng_Generate(WC_WOLFHAL_RNG_DEV, output, (size_t)sz);
    return wc_wolfHAL_TranslateError(err);
}
#endif /* WOLFSSL_WOLFHAL_RNG */

#endif /* WOLFSSL_WOLFHAL */
