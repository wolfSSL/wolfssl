/* nuvoton_cb_cipher.c
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

/* AES on the M2354 CRPT engine: ECB, CBC and CTR.
 *
 * The key comes from aes->devKey, which wc_AesSetKey fills for any Aes built
 * with a crypto callback device id, and the chaining state from aes->reg. The
 * engine returns the value it would feed AES_IV for the next block in
 * AES_FDBCK, so the hardware layer writes that straight back into aes->reg and
 * a later software call picks up the stream where this one left off.
 *
 * GCM runs on the engine as a single packed packet of IV, AAD and payload,
 * which is what the one-shot crypto callback is handed. Its key register
 * convention is not the CBC one: the engine wants big-endian key words with
 * no KINSWAP. Decrypt runs the same packet with CRPT_AES_CTL_ENCRPT_Msk
 * clear, and the engine returns the tag it computed over the ciphertext,
 * which this file compares against the received one.
 *
 * CCM runs on the engine the same way, with its own first block and its own
 * counter, and with the key convention the block modes use rather than the
 * one GCM wants. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_CIPHER) && \
    defined(WOLF_CRYPTO_CB) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef WOLFSSL_NUVOTON_KS
    #include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h>
#endif

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

/* ForceZero() and ConstantCompare() for the GCM tag handling. */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Fill in the parts of a request that every mode shares. Returns 0 when the
 * engine can take it. */
static int wc_NuvotonAesSetup(wc_NuvotonAesReq* req, Aes* aes, byte* out,
    const byte* in, word32 sz, int mode, int enc)
{
    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz > 0 && (out == NULL || in == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* ECB, CBC and CTR go to the engine as whole blocks: a partial tail is
     * the caller's, and for CTR it is also the case wolfCrypt tracks in
     * aes->left. GCM is different - the payload is padded into the packed
     * buffer, so any length is fine, including none at all for an
     * authenticate-only call. */
    if (mode != WC_NUVOTON_AES_GCM) {
        if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    if (aes->keylen != 16 && aes->keylen != 24 && aes->keylen != 32) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMSET(req, 0, sizeof(*req));
    req->in      = in;
    req->out     = out;
    req->sz      = sz;
    req->keySz   = (word32)aes->keylen;
    req->mode    = mode;
    req->encrypt = enc;
    req->keySlot = WC_NUVOTON_NO_SLOT;

#ifdef WOLFSSL_NUVOTON_KS
    /* A Key Store handle in devCtx means the engine fetches the key itself
     * and no key material passes through here. */
    if (aes->devCtx != NULL) {
        wc_NuvotonKsKey* ksKey = (wc_NuvotonKsKey*)aes->devCtx;

        req->keyMem  = ksKey->mem;
        req->keySlot = ksKey->slot;
    }
    else
#endif
    {
        req->key = (const byte*)aes->devKey;
    }

    if (mode != WC_NUVOTON_AES_ECB) {
        req->iv = (byte*)aes->reg;
    }

    return 0;
}

/* Anything the engine reports as "cannot take this one" becomes a decline, so
 * the operation runs in software instead of failing. */
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Finish an authenticated decrypt: compare the tag the engine computed with
 * the one received. Nothing that fails to authenticate reaches the caller. */
static int wc_NuvotonAeadDecFinish(int ret, byte* tag, const byte* expected,
    word32 tagSz, byte* out, word32 sz, int authErr)
{
    if (ret == 0) {
        if (ConstantCompare(tag, expected, (int)tagSz) != 0) {
            if (sz > 0) {
                ForceZero(out, sz);
            }
            /* GCM and CCM callers each expect their own code. */
            ret = authErr;
        }
    }

    ForceZero(tag, WC_AES_BLOCK_SIZE);

    return ret;
}
#endif

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
/* Build an AEAD request: the IV is the caller's nonce, not aes->reg, and the
 * payload may be empty (GMAC). Caller sets the mode; GCM by default. */
static int wc_NuvotonAesGcmSetup(wc_NuvotonAesReq* req, Aes* aes, byte* out,
    const byte* in, word32 sz, byte* iv, word32 ivSz, const byte* aad,
    word32 aadSz, word32 tagSz, int enc)
{
    int ret;

    if (iv == NULL || ivSz == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (tagSz == 0 || tagSz > WC_AES_BLOCK_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wc_NuvotonAesSetup(req, aes, out, in, sz, WC_NUVOTON_AES_GCM, enc);
    if (ret != 0) {
        return ret;
    }

    req->iv    = iv;
    req->ivSz  = ivSz;
    req->aad   = aad;
    req->aadSz = aadSz;
    req->tagSz = tagSz;

    return 0;
}
#endif

static int wc_NuvotonAesRun(wc_NuvotonAesReq* req)
{
    int ret = wc_nuvoton_hw_aes(req);

    if (ret == WC_NO_ERR_TRACE(BAD_LENGTH_E) ||
        ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        /* Declining sends the operation to software, which is right for a
         * plain key. A Key Store key has no software counterpart - the
         * material never left the store - so the fallback cannot run and
         * wolfCrypt reports MISSING_KEY from somewhere unrelated. Say what
         * actually happened instead. */
        if (req->keySlot != WC_NUVOTON_NO_SLOT) {
            WOLFSSL_MSG("Nuvoton: stored key, and the engine declined the "
                        "operation");
            ret = WC_HW_E;
        }
        else {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    return ret;
}

int wc_NuvotonCb_Cipher(wc_CryptoInfo* info)
{
    wc_NuvotonAesReq req;
    int              ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = wc_NuvotonAesSetup(&req, info->cipher.aescbc.aes,
                info->cipher.aescbc.out, info->cipher.aescbc.in,
                info->cipher.aescbc.sz, WC_NUVOTON_AES_CBC, info->cipher.enc);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            /* CTR is a stream cipher to wolfCrypt: aes->left counts the bytes
             * of the current key stream block it has not handed out yet. The
             * engine has no way to be told to start part way into a block, so
             * offload only a call that begins on a block boundary. */
            if (info->cipher.aesctr.aes != NULL &&
                info->cipher.aesctr.aes->left != 0) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = wc_NuvotonAesSetup(&req, info->cipher.aesctr.aes,
                info->cipher.aesctr.out, info->cipher.aesctr.in,
                info->cipher.aesctr.sz, WC_NUVOTON_AES_CTR, 1);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
        case WC_CIPHER_AES_ECB:
            ret = wc_NuvotonAesSetup(&req, info->cipher.aesecb.aes,
                info->cipher.aesecb.out, info->cipher.aesecb.in,
                info->cipher.aesecb.sz, WC_NUVOTON_AES_ECB, info->cipher.enc);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            if (info->cipher.enc) {
                ret = wc_NuvotonAesGcmSetup(&req,
                    info->cipher.aesgcm_enc.aes,
                    info->cipher.aesgcm_enc.out, info->cipher.aesgcm_enc.in,
                    info->cipher.aesgcm_enc.sz,
                    (byte*)info->cipher.aesgcm_enc.iv,
                    info->cipher.aesgcm_enc.ivSz,
                    info->cipher.aesgcm_enc.authIn,
                    info->cipher.aesgcm_enc.authInSz,
                    info->cipher.aesgcm_enc.authTagSz, 1);
                if (ret != 0) {
                    return ret;
                }
                /* On encrypt the tag goes straight to the caller. */
                req.tag = info->cipher.aesgcm_enc.authTag;

                return wc_NuvotonAesRun(&req);
            }
            else {
                byte tag[WC_AES_BLOCK_SIZE];

                ret = wc_NuvotonAesGcmSetup(&req,
                    info->cipher.aesgcm_dec.aes,
                    info->cipher.aesgcm_dec.out, info->cipher.aesgcm_dec.in,
                    info->cipher.aesgcm_dec.sz,
                    (byte*)info->cipher.aesgcm_dec.iv,
                    info->cipher.aesgcm_dec.ivSz,
                    info->cipher.aesgcm_dec.authIn,
                    info->cipher.aesgcm_dec.authInSz,
                    info->cipher.aesgcm_dec.authTagSz, 0);
                if (ret != 0) {
                    return ret;
                }

                /* The engine computes the tag over the ciphertext. */
                XMEMSET(tag, 0, sizeof(tag));
                req.tag = tag;

                ret = wc_NuvotonAesRun(&req);

                return wc_NuvotonAeadDecFinish(ret, tag,
                    info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_dec.authTagSz,
                    info->cipher.aesgcm_dec.out, info->cipher.aesgcm_dec.sz,
                    WC_NO_ERR_TRACE(AES_GCM_AUTH_E));
            }
#endif
#ifdef HAVE_AESCCM
        case WC_CIPHER_AES_CCM:
            if (info->cipher.enc) {
                ret = wc_NuvotonAesGcmSetup(&req,
                    info->cipher.aesccm_enc.aes,
                    info->cipher.aesccm_enc.out, info->cipher.aesccm_enc.in,
                    info->cipher.aesccm_enc.sz,
                    (byte*)info->cipher.aesccm_enc.nonce,
                    info->cipher.aesccm_enc.nonceSz,
                    info->cipher.aesccm_enc.authIn,
                    info->cipher.aesccm_enc.authInSz,
                    info->cipher.aesccm_enc.authTagSz, 1);
                if (ret != 0) {
                    return ret;
                }
                req.mode = WC_NUVOTON_AES_CCM;
                req.tag  = info->cipher.aesccm_enc.authTag;

                return wc_NuvotonAesRun(&req);
            }
            else {
                byte tag[WC_AES_BLOCK_SIZE];

                ret = wc_NuvotonAesGcmSetup(&req,
                    info->cipher.aesccm_dec.aes,
                    info->cipher.aesccm_dec.out, info->cipher.aesccm_dec.in,
                    info->cipher.aesccm_dec.sz,
                    (byte*)info->cipher.aesccm_dec.nonce,
                    info->cipher.aesccm_dec.nonceSz,
                    info->cipher.aesccm_dec.authIn,
                    info->cipher.aesccm_dec.authInSz,
                    info->cipher.aesccm_dec.authTagSz, 0);
                if (ret != 0) {
                    return ret;
                }
                req.mode = WC_NUVOTON_AES_CCM;

                XMEMSET(tag, 0, sizeof(tag));
                req.tag = tag;

                ret = wc_NuvotonAesRun(&req);

                return wc_NuvotonAeadDecFinish(ret, tag,
                    info->cipher.aesccm_dec.authTag,
                    info->cipher.aesccm_dec.authTagSz,
                    info->cipher.aesccm_dec.out, info->cipher.aesccm_dec.sz,
                    WC_NO_ERR_TRACE(AES_CCM_AUTH_E));
            }
#endif
        default:
            break;
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_CIPHER && WOLF_CRYPTO_CB &&
        * !NO_AES */
