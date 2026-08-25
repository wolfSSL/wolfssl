/* silabs_cb_cipher.c
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

#if defined(WOLFSSL_SILABS_CRYPTOCB) && defined(WOLFSSL_SILABS_CRYPTOCB_CIPHER)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_cryptocb.h>

#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_aes.h>
#endif

/* silabs_hash.h pulls in em_device.h (or the host-test shim), which is what
 * defines _SILICON_LABS_SECURITY_FEATURE for the Vault checks below. */
#include <wolfssl/wolfcrypt/port/silabs/silabs_hash.h>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif

/* ChaCha20-Poly1305 is a Secure Vault High feature; on a Vault Mid part the SE
 * has no ChaCha20 key type and the AEAD stays in software. */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
    defined(_SILICON_LABS_SECURITY_FEATURE) && \
    (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    #define WOLFSSL_SILABS_CHACHA_POLY
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_AES

/* Point the SE key descriptor at the raw key wolfCrypt kept for offload.
 * wc_AesSetKey stores the expanded schedule in aes->key and the raw key in
 * aes->devKey whenever a devId is set, which is the case here. The descriptor
 * references that buffer, which lives as long as the Aes. */
static int silabs_cipher_setkey(Aes* aes)
{
    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }
    /* A wrapped or built-in key was bound by wc_SilabsSe_AesUse*Key(); the
     * descriptor already names it and there is no plaintext key to rebuild
     * from. */
    if (aes->ctx.keySet) {
        return 0;
    }
    if (aes->keylen <= 0 || (word32)aes->keylen > sizeof(aes->devKey)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return silabs_aes_init_key_desc(&(aes->ctx), (const byte*)aes->devKey,
        (word32)aes->keylen);
}

#ifdef WOLFSSL_AES_COUNTER
/* AES-CTR. The SE tracks the keystream with an mbedTLS-style nc_off, while
 * wolfCrypt tracks bytes still unused in aes->tmp via aes->left. Rather than
 * translate between the two mid-keystream, only whole-block requests made on a
 * block boundary are offloaded; anything else falls back to software, which
 * keeps both representations consistent because the SE updates the counter in
 * aes->reg exactly as the software path does. */
static int silabs_cipher_ctr(wc_CryptoInfo* info)
{
#ifdef WOLFSSL_ARMASM
    /* The ARM assembly CTR implementation keeps the keystream remainder in
     * aes->tmp/aes->left on a different contract than the C one, so a stream
     * split between it and the SE does not line up. Verified on an EFR32FG25:
     * the wolfCrypt AES-CTR vectors pass with either implementation alone and
     * fail when the two share a stream. Leave CTR to software here, which also
     * validates the arguments. */
    (void)info;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
#else
    Aes* aes = info->cipher.aesctr.aes;
    unsigned char streamBlock[SLI_SE_AES_CTR_NUM_BLOCKS_BUFFERED *
                              SL_SE_AES_BLOCK_SIZE];
    uint32_t ncOff = 0;
    sl_status_t status;
    int ret;

    if (aes == NULL || info->cipher.aesctr.out == NULL ||
        info->cipher.aesctr.in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aes->left != 0 ||
        (info->cipher.aesctr.sz % WC_AES_BLOCK_SIZE) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = silabs_cipher_setkey(aes);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(streamBlock, 0, sizeof(streamBlock));
    status = sl_se_aes_crypt_ctr(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        info->cipher.aesctr.sz,
        &ncOff,
        (unsigned char*)aes->reg,
        streamBlock,
        info->cipher.aesctr.in,
        info->cipher.aesctr.out);

    ForceZero(streamBlock, sizeof(streamBlock));

    return silabs_cb_status((int)status);
#endif /* WOLFSSL_ARMASM */
}
#endif /* WOLFSSL_AES_COUNTER */

#endif /* !NO_AES */

#ifdef WOLFSSL_SILABS_CHACHA_POLY
/* ChaCha20-Poly1305 AEAD. The one-shot API has no key object, so the key
 * descriptor and command context are built on the stack per call. */
static int silabs_cipher_chachapoly(wc_CryptoInfo* info)
{
    sl_se_command_context_t cmd = SL_SE_COMMAND_CONTEXT_INIT;
    sl_se_key_descriptor_t key;
    sl_status_t status;
    const byte* inKey;
    int ret;

    inKey = info->cipher.enc ? info->cipher.chacha20_poly1305_enc.inKey
                             : info->cipher.chacha20_poly1305_dec.inKey;
    if (inKey == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&key, 0, sizeof(key));
    key.type = SL_SE_KEY_TYPE_CHACHA20;
    key.size = CHACHA20_POLY1305_AEAD_KEYSIZE;
    key.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT;
    key.storage.location.buffer.pointer = (void*)inKey;
    key.storage.location.buffer.size = CHACHA20_POLY1305_AEAD_KEYSIZE;

    if (info->cipher.enc) {
        status = sl_se_chacha20_poly1305_encrypt_and_tag(
            &cmd, &key,
            info->cipher.chacha20_poly1305_enc.inSz,
            info->cipher.chacha20_poly1305_enc.inIV,
            info->cipher.chacha20_poly1305_enc.inAAD,
            info->cipher.chacha20_poly1305_enc.inAADSz,
            info->cipher.chacha20_poly1305_enc.in,
            info->cipher.chacha20_poly1305_enc.out,
            info->cipher.chacha20_poly1305_enc.outAuthTag);
    }
    else {
        status = sl_se_chacha20_poly1305_auth_decrypt(
            &cmd, &key,
            info->cipher.chacha20_poly1305_dec.inSz,
            info->cipher.chacha20_poly1305_dec.inIV,
            info->cipher.chacha20_poly1305_dec.inAAD,
            info->cipher.chacha20_poly1305_dec.inAADSz,
            info->cipher.chacha20_poly1305_dec.in,
            info->cipher.chacha20_poly1305_dec.out,
            info->cipher.chacha20_poly1305_dec.inAuthTag);
        /* Match wc_ChaCha20Poly1305_Decrypt: when the operation actually ran
         * and failed, clear the output so a caller that ignores the return
         * code cannot read plaintext the tag never authenticated. The callback
         * result goes straight back to the caller, so that function's own
         * ForceZero never runs for this path.
         *
         * A decline is deliberately excluded: it means the SE did not touch
         * the buffer and software is about to run, and wolfCrypt permits
         * in-place AEAD (out == in), so clearing here would destroy the
         * ciphertext the fallback still has to read. */
        ret = silabs_cb_status((int)status);
        if (ret != 0 && ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            if (info->cipher.chacha20_poly1305_dec.out != NULL &&
                info->cipher.chacha20_poly1305_dec.inSz > 0) {
                ForceZero(info->cipher.chacha20_poly1305_dec.out,
                    info->cipher.chacha20_poly1305_dec.inSz);
            }
            if (status == SL_STATUS_INVALID_SIGNATURE) {
                return MAC_CMP_FAILED_E;
            }
        }
        return ret;
    }

    return silabs_cb_status((int)status);
}
#endif /* WOLFSSL_SILABS_CHACHA_POLY */

/* Map a raw SE status for an AEAD operation. An authentication failure keeps
 * its algorithm-specific error so callers can tell a forged tag from anything
 * else, while an unsupported command still becomes CRYPTOCB_UNAVAILABLE so the
 * software implementation can run. */
static int silabs_cipher_aead_status(int status, int authErr)
{
    if (status >= 0 && (sl_status_t)status == SL_STATUS_INVALID_SIGNATURE) {
        return authErr;
    }
    return silabs_cb_status(status);
}

/* Decrypt counterpart: on any terminal failure the plaintext buffer is cleared
 * so a caller that ignores the return code cannot read data the tag never
 * authenticated, matching what the software AEADs do. A decline is excluded -
 * the SE did not touch the buffer, software is about to run, and wolfCrypt
 * permits in-place AEAD, so clearing would destroy the ciphertext it still
 * has to read. */
static int silabs_cipher_aead_dec_status(int status, int authErr,
    byte* out, word32 sz)
{
    int ret = silabs_cipher_aead_status(status, authErr);

    if (ret != 0 && ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE) &&
        out != NULL && sz > 0) {
        ForceZero(out, sz);
    }

    return ret;
}

/* The Aes a cipher request operates on, or NULL when the type carries none. */
static Aes* silabs_cipher_aes(const wc_CryptoInfo* info)
{
    switch (info->cipher.type) {
#ifndef NO_AES
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
    case WC_CIPHER_AES_ECB:
        return info->cipher.aesecb.aes;
#endif
#ifdef HAVE_AES_CBC
    case WC_CIPHER_AES_CBC:
        return info->cipher.aescbc.aes;
#endif
#ifdef WOLFSSL_AES_COUNTER
    case WC_CIPHER_AES_CTR:
        return info->cipher.aesctr.aes;
#endif
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM:
        return info->cipher.enc ? info->cipher.aesgcm_enc.aes
                                : info->cipher.aesgcm_dec.aes;
#endif
#ifdef HAVE_AESCCM
    case WC_CIPHER_AES_CCM:
        return info->cipher.enc ? info->cipher.aesccm_enc.aes
                                : info->cipher.aesccm_dec.aes;
#endif
#endif /* !NO_AES */
    default:
        return NULL;
    }
}

static int silabs_cipher_dispatch(wc_CryptoInfo* info)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->cipher.type) {
#ifndef NO_AES
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
    case WC_CIPHER_AES_ECB:
        if (info->cipher.aesecb.aes == NULL) {
            return BAD_FUNC_ARG;
        }
        if ((info->cipher.aesecb.sz % WC_AES_BLOCK_SIZE) != 0) {
            return BAD_LENGTH_E;
        }
        ret = silabs_cipher_setkey(info->cipher.aesecb.aes);
        if (ret == 0) {
            ret = silabs_aes_ecb_status(info->cipher.aesecb.aes,
                info->cipher.aesecb.out, info->cipher.aesecb.in,
                info->cipher.aesecb.sz,
                info->cipher.enc ? SL_SE_ENCRYPT : SL_SE_DECRYPT);
            ret = silabs_cb_status(ret);
        }
        break;
#endif
#ifdef HAVE_AES_CBC
    case WC_CIPHER_AES_CBC:
        if (info->cipher.aescbc.aes == NULL) {
            return BAD_FUNC_ARG;
        }
        ret = silabs_cipher_setkey(info->cipher.aescbc.aes);
        if (ret == 0) {
            ret = silabs_aes_cbc_status(info->cipher.aescbc.aes,
                info->cipher.aescbc.out, info->cipher.aescbc.in,
                info->cipher.aescbc.sz,
                info->cipher.enc ? SL_SE_ENCRYPT : SL_SE_DECRYPT);
            ret = silabs_cb_status(ret);
        }
        break;
#endif
#ifdef WOLFSSL_AES_COUNTER
    case WC_CIPHER_AES_CTR:
        ret = silabs_cipher_ctr(info);
        break;
#endif
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM:
        if (info->cipher.enc) {
            /* The SE computes only full-length GCM tags. */
            if (info->cipher.aesgcm_enc.authTagSz <
                    WC_AES_BLOCK_SIZE) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            /* GMAC authenticates AAD with no plaintext, so wolfCrypt passes a
             * zero length and NULL in/out. The SE helper requires both, so
             * leave that case to software. */
            if (info->cipher.aesgcm_enc.sz == 0 ||
                info->cipher.aesgcm_enc.in == NULL ||
                info->cipher.aesgcm_enc.out == NULL) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            /* The SE accepts only a 96-bit GCM IV. Decline anything else
             * rather than let the helper report it as an auth failure. */
            if (info->cipher.aesgcm_enc.ivSz != GCM_NONCE_MID_SZ) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = silabs_cipher_setkey(info->cipher.aesgcm_enc.aes);
            if (ret == 0) {
                ret = wc_AesGcmEncrypt_silabs_status(
                    info->cipher.aesgcm_enc.aes,
                    info->cipher.aesgcm_enc.out,
                    info->cipher.aesgcm_enc.in,
                    info->cipher.aesgcm_enc.sz,
                    info->cipher.aesgcm_enc.iv,
                    info->cipher.aesgcm_enc.ivSz,
                    info->cipher.aesgcm_enc.authTag,
                    info->cipher.aesgcm_enc.authTagSz,
                    info->cipher.aesgcm_enc.authIn,
                    info->cipher.aesgcm_enc.authInSz);
                ret = silabs_cipher_aead_status(ret, AES_GCM_AUTH_E);
            }
        }
        else {
            if (info->cipher.aesgcm_dec.authTagSz <
                    WC_AES_BLOCK_SIZE) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            if (info->cipher.aesgcm_dec.sz == 0 ||
                info->cipher.aesgcm_dec.in == NULL ||
                info->cipher.aesgcm_dec.out == NULL) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            if (info->cipher.aesgcm_dec.ivSz != GCM_NONCE_MID_SZ) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = silabs_cipher_setkey(info->cipher.aesgcm_dec.aes);
            if (ret == 0) {
                ret = wc_AesGcmDecrypt_silabs_status(
                    info->cipher.aesgcm_dec.aes,
                    info->cipher.aesgcm_dec.out,
                    info->cipher.aesgcm_dec.in,
                    info->cipher.aesgcm_dec.sz,
                    info->cipher.aesgcm_dec.iv,
                    info->cipher.aesgcm_dec.ivSz,
                    info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_dec.authTagSz,
                    info->cipher.aesgcm_dec.authIn,
                    info->cipher.aesgcm_dec.authInSz);
                ret = silabs_cipher_aead_dec_status(ret,
                    AES_GCM_AUTH_E, info->cipher.aesgcm_dec.out,
                    info->cipher.aesgcm_dec.sz);
            }
        }
        break;
#endif
#ifdef HAVE_AESCCM
    case WC_CIPHER_AES_CCM:
        if (info->cipher.enc) {
            if (info->cipher.aesccm_enc.sz == 0 ||
                info->cipher.aesccm_enc.in == NULL ||
                info->cipher.aesccm_enc.out == NULL) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = silabs_cipher_setkey(info->cipher.aesccm_enc.aes);
            if (ret == 0) {
                ret = wc_AesCcmEncrypt_silabs_status(
                    info->cipher.aesccm_enc.aes,
                    info->cipher.aesccm_enc.out,
                    info->cipher.aesccm_enc.in,
                    info->cipher.aesccm_enc.sz,
                    info->cipher.aesccm_enc.nonce,
                    info->cipher.aesccm_enc.nonceSz,
                    info->cipher.aesccm_enc.authTag,
                    info->cipher.aesccm_enc.authTagSz,
                    info->cipher.aesccm_enc.authIn,
                    info->cipher.aesccm_enc.authInSz);
                ret = silabs_cipher_aead_status(ret, AES_CCM_AUTH_E);
            }
        }
        else {
            if (info->cipher.aesccm_dec.sz == 0 ||
                info->cipher.aesccm_dec.in == NULL ||
                info->cipher.aesccm_dec.out == NULL) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = silabs_cipher_setkey(info->cipher.aesccm_dec.aes);
            if (ret == 0) {
                ret = wc_AesCcmDecrypt_silabs_status(
                    info->cipher.aesccm_dec.aes,
                    info->cipher.aesccm_dec.out,
                    info->cipher.aesccm_dec.in,
                    info->cipher.aesccm_dec.sz,
                    info->cipher.aesccm_dec.nonce,
                    info->cipher.aesccm_dec.nonceSz,
                    info->cipher.aesccm_dec.authTag,
                    info->cipher.aesccm_dec.authTagSz,
                    info->cipher.aesccm_dec.authIn,
                    info->cipher.aesccm_dec.authInSz);
                ret = silabs_cipher_aead_dec_status(ret,
                    AES_CCM_AUTH_E, info->cipher.aesccm_dec.out,
                    info->cipher.aesccm_dec.sz);
            }
        }
        break;
#endif
#endif /* !NO_AES */
#ifdef WOLFSSL_SILABS_CHACHA_POLY
    case WC_CIPHER_CHACHA:
        ret = silabs_cipher_chachapoly(info);
        break;
#endif
    default:
        break;
    }

    return ret;
}

/* WC_ALGO_TYPE_CIPHER.
 *
 * A wrapped or built-in key lives inside the SE and the Aes carries no
 * plaintext key material, so declining would hand the operation to the
 * software AES path, which would then run with an unset key schedule and
 * silently produce wrong ciphertext. Whenever such a key is bound, an
 * unsupported request has to fail outright instead. */
int wc_SilabsCipher(wc_CryptoInfo* info)
{
    int  ret;
    Aes* aes;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = silabs_cipher_dispatch(info);
    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        aes = silabs_cipher_aes(info);
        if (aes != NULL && aes->ctx.keySet) {
            return WC_HW_E;
        }
    }

    return ret;
}

#endif /* WOLFSSL_SILABS_CRYPTOCB && WOLFSSL_SILABS_CRYPTOCB_CIPHER */
