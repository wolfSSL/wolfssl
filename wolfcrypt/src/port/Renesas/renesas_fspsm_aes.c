/* renesas_fspsm_aes.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef NO_AES

#if (defined(WOLFSSL_RENESAS_FSPSM_TLS) || \
     defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)) && \
    !defined(NO_WOLFSSL_RENESAS_FSPSM_AES)

#include "wolfssl/wolfcrypt/port/Renesas/renesas_fspsm_internal.h"

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/aes.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

struct Aes;

void *Renesas_cmn_GetCbCtxBydevId(int devId);

#define SCE_AES_GCM_AUTH_TAG_SIZE  16

#if defined(WOLFSSL_RENESAS_RSIP)
extern FSPSM_INSTANCE   gFSPSM_ctrl;
#endif

typedef fsp_err_t (*aesGcmEncInitFn)
        (FSPSM_AESGCM_HANDLE*, FSPSM_AES_PWKEY, uint8_t*, uint32_t);
typedef fsp_err_t (*aesGcmEncUpdateFn)
        (FSPSM_AESGCM_HANDLE*,uint8_t*, uint8_t*, uint32_t, uint8_t*, uint32_t,
        uint32_t*);
typedef fsp_err_t (*aesGcmEncFinalFn)
        (FSPSM_AESGCM_HANDLE*, uint8_t*, uint32_t*, uint8_t*);

typedef fsp_err_t (*aesGcmDecInitFn)
        (FSPSM_AESGCM_HANDLE*, FSPSM_AES_PWKEY, uint8_t*, uint32_t);
typedef fsp_err_t (*aesGcmDecUpdateFn)
        (FSPSM_AESGCM_HANDLE*,uint8_t*, uint8_t*, uint32_t, uint8_t*, uint32_t,
        uint32_t*);
typedef fsp_err_t (*aesGcmDecFinalFn)
        (FSPSM_AESGCM_HANDLE*, uint8_t*, uint32_t*, uint8_t*, uint32_t);

#if defined(WOLFSSL_RENESAS_RSIP)
/* wrapper for Gcm encrypt init */
static fsp_err_t _R_RSIP_AES_GCM_EncryptInit(FSPSM_AESGCM_HANDLE* h,
                                        FSPSM_AES_PWKEY k, uint8_t* iv,
                                        uint32_t iv_l)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void)h;
    return R_RSIP_AES_AEAD_Init(&gFSPSM_ctrl, RSIP_AES_AEAD_MODE_GCM_ENC,
                                (FSPSM_AES_PWKEY const)k,
                                (uint8_t* const)iv, iv_l);
   #else
    (void) h;
    return R_RSIP_AES_GCM_EncryptInit(&gFSPSM_ctrl, (FSPSM_AES_PWKEY const)k,
                                            (uint8_t* const)iv, iv_l);
   #endif
}

/* wrapper for Gcm encrypt/decript ADD update */
#if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
static fsp_err_t _R_RSIP_AES_GCM_ADDUpdate(uint8_t* p_add, uint32_t add_len)
{
    return R_RSIP_AES_AEAD_AADUpdate(&gFSPSM_ctrl, p_add, add_len);
}
#endif
/* wrapper for Gcm encrypt update */
static fsp_err_t _R_RSIP_AES_GCM_EncryptUpdate(FSPSM_AESGCM_HANDLE* h,
        uint8_t* p_plain, uint8_t* p_cipher, uint32_t plain_length,
        uint8_t* p_add, uint32_t add_len, uint32_t* out_len)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    (void) p_add;
    (void) add_len;
    return R_RSIP_AES_AEAD_Update(&gFSPSM_ctrl, (uint8_t* const) p_plain,
                                      (uint32_t const) plain_length,
                                      (uint8_t* const) p_cipher,
                                      (uint32_t* const) out_len);
   #else
    (void) h;
    return R_RSIP_AES_GCM_EncryptUpdate(&gFSPSM_ctrl, (uint8_t* const) p_plain,
                                      (uint8_t* const) p_cipher,
                                      (uint32_t const) plain_length,
                                      (uint8_t* const) p_add,
                                      (uint32_t const) add_len);
   #endif
}
/* wrapper for Gcm encrypt final */
static fsp_err_t _R_RSIP_AES_GCM_EncryptFinal(FSPSM_AESGCM_HANDLE* h,
                                        uint8_t* p_cipher, uint32_t* c_len,
                                        uint8_t* p_atag)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_AEAD_Finish(&gFSPSM_ctrl, (uint8_t* const) p_cipher,
                                    (uint32_t* const) c_len,
                                    (uint8_t* const) p_atag);
   #else
    (void) h;
    return R_RSIP_AES_GCM_EncryptFinal(&gFSPSM_ctrl, (uint8_t* const) p_cipher,
                                      (uint32_t* const) c_len,
                                      (uint8_t* const) p_atag);
   #endif
}
/* wrapper for Gcm decrypt init */
static fsp_err_t _R_RSIP_AES_GCM_DecryptInit(FSPSM_AESGCM_HANDLE* h,
                                FSPSM_AES_PWKEY k, uint8_t* iv, uint32_t iv_l)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void)h;
    return R_RSIP_AES_AEAD_Init(&gFSPSM_ctrl, RSIP_AES_AEAD_MODE_GCM_DEC,
                                (FSPSM_AES_PWKEY const)k,
                                (uint8_t* const)iv, iv_l);
   #else
    (void) h;
    return R_RSIP_AES_GCM_DecryptInit(&gFSPSM_ctrl, (FSPSM_AES_PWKEY const)k,
                                                    (uint8_t* const)iv, iv_l);
   #endif
}
/* wrapper for Gcm decrypt update */
static fsp_err_t _R_RSIP_AES_GCM_DecryptUpdate(FSPSM_AESGCM_HANDLE* h,
        uint8_t* p_cipher, uint8_t* p_plain, uint32_t c_length,
        uint8_t* p_add, uint32_t add_len, uint32_t* out_len)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    (void) p_add;
    (void) add_len;
    return R_RSIP_AES_AEAD_Update(&gFSPSM_ctrl, (uint8_t* const) p_cipher,
                                      (uint32_t const) c_length,
                                      (uint8_t* const) p_plain,
                                      (uint32_t* const) out_len);
   #else
    (void) h;
    return R_RSIP_AES_GCM_DecryptUpdate(&gFSPSM_ctrl, (uint8_t* const) p_cipher,
                                      (uint8_t* const) p_plain,
                                      (uint32_t const) c_length,
                                      (uint8_t* const) p_add,
                                      (uint32_t const) add_len);
   #endif
}
/* wrapper for Gcm decrypt final */
static fsp_err_t _R_RSIP_AES_GCM_DecryptFinal(FSPSM_AESGCM_HANDLE* h,
                                        uint8_t* p_plain, uint32_t* plain_len,
                                        uint8_t* p_atag, uint32_t atag_len)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_AEAD_Verify(&gFSPSM_ctrl, (uint8_t* const) p_plain,
                                      (uint32_t* const) plain_len,
                                      (uint8_t* const) p_atag,
                                      (uint32_t const) atag_len);
   #else
    (void) h;
    return R_RSIP_AES_GCM_DecryptFinal(&gFSPSM_ctrl, (uint8_t* const) p_plain,
                                      (uint32_t* const) plain_len,
                                      (uint8_t* const) p_atag,
                                      (uint32_t const) atag_len);
   #endif
}
/* wrapper for aes cbc encrypt init */
static fsp_err_t _R_RSIP_AESCBC_Cipher_EncryptInit(FSPSM_AES_HANDLE* h,
                                      FSPSM_AES_PWKEY k,
                                      uint8_t* iv)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_Cipher_Init(&gFSPSM_ctrl,
                                        RSIP_AES_CIPHER_MODE_CBC_ENC,
                                        k, iv);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_EncryptInit(&gFSPSM_ctrl,
                                        RSIP_AES_MODE_CBC,
                                        k, iv);
   #endif
}
/* wrapper for aes cbc encrypt update */
static fsp_err_t _R_RSIP_AESCBC_Cipher_EncryptUpdate(FSPSM_AES_HANDLE* h,
                                      uint8_t* p_plain,
                                      uint8_t* p_cipher,
                                      uint32_t plain_length)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_Cipher_Update(&gFSPSM_ctrl,
                                        (const uint8_t* const)p_plain,
                                        (uint8_t* const)p_cipher,
                                        (const uint32_t)plain_length);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_EncryptUpdate(&gFSPSM_ctrl,
                                        (const uint8_t* const)p_plain,
                                        (uint8_t* const)p_cipher,
                                        (const uint32_t)plain_length);
   #endif
}
/* wrapper for aes cbc encrypt final */
static fsp_err_t _R_RSIP_AESCBC_Cipher_EncryptFinal(FSPSM_AES_HANDLE* h,
                                      uint8_t* p_cipher,
                                      uint32_t* cipher_length)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    (void) p_cipher;
    (void) cipher_length;
    return R_RSIP_AES_Cipher_Finish(&gFSPSM_ctrl);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_EncryptFinal(&gFSPSM_ctrl,
                                        (uint8_t* const)p_cipher,
                                        (uint32_t* const)cipher_length);
   #endif
}
/* wrapper for aes cbc decrypt init */
static fsp_err_t _R_RSIP_AESCBC_Cipher_DecryptInit(FSPSM_AES_HANDLE* h,
                                      FSPSM_AES_PWKEY k,
                                      uint8_t* iv)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_Cipher_Init(&gFSPSM_ctrl,
                                        RSIP_AES_CIPHER_MODE_CBC_DEC,
                                        k, iv);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_DecryptInit(&gFSPSM_ctrl,
                                        RSIP_AES_MODE_CBC,
                                        k, iv);
   #endif
}
/* wrapper for aes cbc decrypt update */
static fsp_err_t _R_RSIP_AESCBC_Cipher_DecryptUpdate(FSPSM_AES_HANDLE* h,
                                      uint8_t* p_cipher,
                                      uint8_t* p_plain,
                                      uint32_t cipher_lengh)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    return R_RSIP_AES_Cipher_Update(&gFSPSM_ctrl,
                                        (const uint8_t* const)p_cipher,
                                        (uint8_t* const)p_plain,
                                        (const uint32_t)cipher_lengh);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_DecryptUpdate(&gFSPSM_ctrl,
                                        (const uint8_t* const)p_cipher,
                                        (uint8_t* const)p_plain,
                                        (const uint32_t)cipher_lengh);
   #endif
}
/* wrapper for aes cbc encrypt final */
static fsp_err_t _R_RSIP_AESCBC_Cipher_DecryptFinal(FSPSM_AES_HANDLE* h,
                                      uint8_t* p_plain,
                                      uint32_t* plain_lengh)
{
   #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
    (void) h;
    (void) p_plain;
    (void) plain_lengh;
    return R_RSIP_AES_Cipher_Finish(&gFSPSM_ctrl);
   #else
    (void) h;
    return R_RSIP_AES_Cipher_DecryptFinal(&gFSPSM_ctrl,
                                        (uint8_t* const)p_plain,
                                        (uint32_t* const)plain_lengh);
   #endif
}
#endif
/* Perform Aes Gcm encryption by FSP SM
 *
 * aes    The AES object.
 * out    Buffer to hold cipher text
 * in     Buffer to hold plaintext
 * sz     Length of cipher text/plaintext in bytes
 * iv     Buffer holding IV/nonce
 * ivSz   Length of IV/nonce in bytes
 * authTag Buffer to hold authentication data
 * authTagSz Length of authentication data in bytes
 * ctx    The callback context
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
int  wc_fspsm_AesGcmEncrypt(struct Aes* aes, byte* out,
                              const byte* in, word32 sz,
                              byte* iv, word32 ivSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz,
                              void* ctx)
{
    int ret;
    FSPSM_AESGCM_HANDLE _handle;
    uint32_t            dataLen = sz;
    uint32_t            out_len = 0;
    uint32_t            out_len_tmp = 0;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;

    aesGcmEncInitFn     initFn;
    aesGcmEncUpdateFn   updateFn;
    aesGcmEncFinalFn    finalFn;

    uint8_t* plainBuf  = NULL;
    uint8_t* cipherBuf = NULL;
    uint8_t* aTagBuf   = NULL;
    uint8_t  delta;
    const uint8_t* iv_l = NULL;
    uint32_t ivSz_l = 0;

#ifdef WOLFSSL_RENESAS_FSPSM_TLS
    FSPSM_HMAC_WKEY key_client_mac;
    FSPSM_HMAC_WKEY key_server_mac;
#endif
    FSPSM_AES_PWKEY      key_client_aes = NULL;
    FSPSM_AES_PWKEY      key_server_aes = NULL;
    (void) key_server_aes;

    /* sanity check */
    if (aes == NULL || authTagSz > WC_AES_BLOCK_SIZE || ivSz == 0 ||
        info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ) {
        WOLFSSL_MSG("GcmEncrypt authTagSz too small error");
        return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("keySize is invalid, neither 16 or 32.");
        return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize == 16) {
        initFn   = FSPSM_AES128GCMEnc_Init;
        updateFn = FSPSM_AES128GCMEnc_Up;
        finalFn  = FSPSM_AES128GCMEnc_Final;
    }
    else {
        initFn   = FSPSM_AES256GCMEnc_Init;
        updateFn = FSPSM_AES256GCMEnc_Up;
        finalFn  = FSPSM_AES256GCMEnc_Final;
    }


    /* check if AES GCM can be used by FSP SM */
    if ((ret = wc_fspsm_hw_lock()) == 0) {

        /* allocate buffers for plain text, cipher text and authTag to make sure
         * those buffers 32bit aligned as SCE requests.
         */
         delta = ((sz % WC_AES_BLOCK_SIZE) == 0) ? 0 :
                             (byte)(WC_AES_BLOCK_SIZE - (sz % WC_AES_BLOCK_SIZE));
        plainBuf  = XMALLOC(sz, aes->heap, DYNAMIC_TYPE_AES);
        cipherBuf = XMALLOC(sz + delta, aes->heap, DYNAMIC_TYPE_AES);
        aTagBuf   = XMALLOC(SCE_AES_GCM_AUTH_TAG_SIZE, aes->heap,
                                                        DYNAMIC_TYPE_AES);

        if ((sz > 0 && plainBuf == NULL) ||
            ((sz + delta) > 0 && cipherBuf == NULL) || aTagBuf == NULL) {
            WOLFSSL_MSG("wc_fspsm_AesGcmEncrypt: buffer allocation failed");
            ret = -1;
        }

        if (ret == 0) {
            XMEMCPY(plainBuf, in, sz);
            XMEMSET((void*)cipherBuf, 0, sz + delta);
            XMEMSET((void*)authTag,   0, authTagSz);
        }

      #if defined(WOLFSSL_RENESAS_FSPSM_TLS)
       if (ret == 0 &&
           info->internal->keyflgs_tls.bits.session_key_set == 1) {
            /* generate AES-GCM session key. The key stored in
             * Aes.ctx.tsip_keyIdx is not used here.
             */
            key_client_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AES);
            key_server_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AES);
            if (key_client_aes == NULL || key_server_aes == NULL) {
                XFREE(plainBuf,  aes->heap, DYNAMIC_TYPE_AES);
                XFREE(cipherBuf, aes->heap, DYNAMIC_TYPE_AES);
                XFREE(aTagBuf,   aes->heap, DYNAMIC_TYPE_AES);
                return MEMORY_E;
            }

            ret = FSPSM_SESSIONKEY_GEN_FUNC(
                    info->internal->cipher,
                    (uint32_t*)info->internal->masterSecret,
                    (uint8_t*) info->internal->clientRandom,
                    (uint8_t*) info->internal->serverRandom,
                    &iv[AESGCM_IMP_IV_SZ], /* use exp_IV */
                    &key_client_mac,
                    &key_server_mac,
                    key_client_aes,
                    key_server_aes,
                    NULL, NULL);
            if (ret != FSP_SUCCESS) {
                WOLFSSL_MSG("R_XXX_TLS_SessionKeyGenerate failed");
                ret = -1;
            }

        }
        else {
       #else
        if (ret == 0) {
       #endif
            if (info->keyflgs_crypt.bits.aes256_installedkey_set == 1 ||
                info->keyflgs_crypt.bits.aes128_installedkey_set == 1) {
                key_client_aes = aes->ctx.wrapped_key;
                iv_l = iv;
                ivSz_l = ivSz;
            }
            else {
                WOLFSSL_MSG("AES key for FSP SM is not set.");
                ret = -1;
            }
        }

        if (ret == 0) {

            /* since generated session key is coupled to iv, no need to pass
             * them init func.
             */
            ret = initFn(&_handle, key_client_aes, (uint8_t*)iv_l, ivSz_l);

            if (ret == FSP_SUCCESS) {
                /* pass only AAD and it's size before passing cipher text */
               #if defined(WOLFSSL_RENESAS_RSIP) &&\
                                    (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                ret = _R_RSIP_AES_GCM_ADDUpdate((uint8_t*)authIn, authInSz);
               #else
                ret = updateFn(&_handle, NULL, NULL, 0UL, (uint8_t*)authIn,
                                                                authInSz,
                                                                &out_len_tmp);
               #endif
            }

            if (ret == FSP_SUCCESS) {
                out_len_tmp = 0;
                ret = updateFn(&_handle, plainBuf, cipherBuf, sz, NULL, 0UL,
                                                                &out_len_tmp);
                out_len += out_len_tmp;
            }
            if (ret != FSP_SUCCESS) {
                WOLFSSL_MSG("R_XXXX_AesXXXGcmEncryptUpdate2: failed");
                ret = -1;
            }

            if (ret == FSP_SUCCESS) {
                /* Once R_SCE_AesxxxGcmEncryptInit or R_SCE_AesxxxEncryptUpdate is
                * called, R_SCE_AesxxxGcmEncryptFinal must be called regardless of
                * the result of the previous call. Otherwise, SCE can not come out
                * from its error state and all the trailing APIs will fail.
                */
                dataLen = 0;
                out_len_tmp = 0;
                ret = finalFn(&_handle,
                           cipherBuf + (sz + delta - WC_AES_BLOCK_SIZE),
                #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                              &out_len_tmp,
                #else
                              &dataLen,
                #endif
                              aTagBuf);

                if (ret == FSP_SUCCESS) {
                #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                    out_len += out_len_tmp;
                    dataLen = out_len;
                #endif
                   /* copy encrypted data to out */
                    if (sz != dataLen) {
                        WOLFSSL_MSG("sz is not equal to dataLen!!!!");
                        ret = -1;
                    } else {
                        XMEMCPY(out, cipherBuf, dataLen);
                        /* copy auth tag to caller's buffer */
                        XMEMCPY((void*)authTag, (void*)aTagBuf,
                                    min(authTagSz, SCE_AES_GCM_AUTH_TAG_SIZE ));
                    }
                }
                else {
                    WOLFSSL_MSG("R_SCE_AesxxxGcmEncryptFinal: failed");
                    ret = -1;
                }
            }
        }

        XFREE(plainBuf,  aes->heap, DYNAMIC_TYPE_AES);
        XFREE(cipherBuf, aes->heap, DYNAMIC_TYPE_AES);
        XFREE(aTagBuf,   aes->heap, DYNAMIC_TYPE_AES);
        if (info->internal->keyflgs_tls.bits.session_key_set == 1 &&
            key_client_aes != NULL)
            XFREE(key_client_aes, aes->heap, DYNAMIC_TYPE_AES);
        if (info->internal->keyflgs_tls.bits.session_key_set == 1 &&
            key_server_aes != NULL)
            XFREE(key_server_aes, aes->heap, DYNAMIC_TYPE_AES);
        wc_fspsm_hw_unlock();
    }

    return ret;
}
/* Perform Aes Gcm decryption by FSP SM
 *
 * aes    The AES object.
 * out    Buffer to hold plaintext
 * in     Buffer to hold cipher text
 * sz     Length of cipher text/plaintext in bytes
 * iv     Buffer holding IV/nonce
 * ivSz   Length of IV/nonce in bytes
 * authTag Buffer to hold authentication data
 * authTagSz Length of authentication data in bytes
 * ctx    The Callback context
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
int  wc_fspsm_AesGcmDecrypt(struct Aes* aes, byte* out,
                          const byte* in, word32 sz,
                          const byte* iv, word32 ivSz,
                          const byte* authTag, word32 authTagSz,
                          const byte* authIn, word32 authInSz,
                          void* ctx)
{
    int ret;
    FSPSM_AESGCM_HANDLE _handle;
    uint32_t            dataLen = sz;
    uint32_t            out_len = 0;
    uint32_t            out_len_tmp = 0;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;

    aesGcmDecInitFn     initFn;
    aesGcmDecUpdateFn   updateFn;
    aesGcmDecFinalFn    finalFn;

    uint8_t* cipherBuf = NULL;
    uint8_t* plainBuf  = NULL;
    uint8_t* aTagBuf = NULL;
    uint8_t  delta;
    const uint8_t* iv_l = NULL;
    uint32_t ivSz_l = 0;

#ifdef WOLFSSL_RENESAS_FSPSM_TLS
    FSPSM_HMAC_WKEY key_client_mac;
    FSPSM_HMAC_WKEY key_server_mac;
#endif
    FSPSM_AES_PWKEY      key_client_aes = NULL;
    FSPSM_AES_PWKEY      key_server_aes = NULL;
    (void) key_client_aes;
    /* sanity check */
    if (aes == NULL || authTagSz > WC_AES_BLOCK_SIZE || ivSz == 0 ||
        info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ) {
        WOLFSSL_MSG("GcmEncrypt authTagSz too small error");
        return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("keySize is invalid, neither 16 or 32.");
        return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize == 16) {
        initFn   = FSPSM_AES128GCMDec_Init;
        updateFn = FSPSM_AES128GCMDec_Up;
        finalFn  = FSPSM_AES128GCMDec_Final;
    }
    else {
        initFn   = FSPSM_AES256GCMDec_Init;
        updateFn = FSPSM_AES256GCMDec_Up;
        finalFn  = FSPSM_AES256GCMDec_Final;
    }


    if ((ret = wc_fspsm_hw_lock()) == 0) {
       /* allocate buffers for plain-text, cipher-text, authTag and AAD.
         * TSIP requests those buffers 32bit aligned.
         */
         delta = ((sz % WC_AES_BLOCK_SIZE) == 0) ? 0 :
                            (byte)(WC_AES_BLOCK_SIZE - (sz % WC_AES_BLOCK_SIZE));
        cipherBuf = XMALLOC(sz, aes->heap, DYNAMIC_TYPE_AES);
        plainBuf  = XMALLOC(sz + delta, aes->heap, DYNAMIC_TYPE_AES);
        aTagBuf   = XMALLOC(SCE_AES_GCM_AUTH_TAG_SIZE, aes->heap,
                                                        DYNAMIC_TYPE_AES);

        if (plainBuf == NULL || cipherBuf == NULL || aTagBuf == NULL) {
            ret = -1;
        }

        if (ret == 0) {
            XMEMSET((void*)plainBuf,  0, sz);
            XMEMCPY(cipherBuf, in, sz);
            XMEMCPY(aTagBuf, authTag, authTagSz);
        }
       #if defined(WOLFSSL_RENESAS_FSPSM_TLS)
        if (ret == 0 &&
            info->internal->keyflgs_tls.bits.session_key_set == 1) {
            /* generate AES-GCM session key. The key stored in
             * Aes.ctx.tsip_keyIdx is not used here.
             */
            key_client_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AES);
            key_server_aes = (FSPSM_AES_PWKEY)XMALLOC(sizeof(FSPSM_AES_WKEY),
                                            aes->heap, DYNAMIC_TYPE_AES);
            if (key_client_aes == NULL || key_server_aes == NULL) {
                XFREE(plainBuf,  aes->heap, DYNAMIC_TYPE_AES);
                XFREE(cipherBuf, aes->heap, DYNAMIC_TYPE_AES);
                XFREE(aTagBuf,   aes->heap, DYNAMIC_TYPE_AES);
                return MEMORY_E;
            }

            ret = FSPSM_SESSIONKEY_GEN_FUNC(
                    info->internal->cipher,
                    (uint32_t*)info->internal->masterSecret,
                    (uint8_t*) info->internal->clientRandom,
                    (uint8_t*) info->internal->serverRandom,
                    (uint8_t*)&iv[AESGCM_IMP_IV_SZ], /* use exp_IV */
                    &key_client_mac,
                    &key_server_mac,
                    key_client_aes,
                    key_server_aes,
                    NULL, NULL);
            if (ret != FSP_SUCCESS) {
                WOLFSSL_MSG("R_XXXX_TLS_SessionKeyGenerate failed");
                ret = -1;
            }
        }
        else {
       #else
        if (ret == 0) {
       #endif
            if (info->keyflgs_crypt.bits.aes256_installedkey_set == 1 ||
                info->keyflgs_crypt.bits.aes128_installedkey_set == 1) {
                key_server_aes = aes->ctx.wrapped_key;
                iv_l = iv;
                ivSz_l = ivSz;
            }
            else {
                WOLFSSL_MSG("AES key for FSP SM is not set.");
                ret = -1;
            }
        }

        if (ret == 0) {
            /* since key_index has iv and ivSz in it, no need to pass them init
             * func. Pass NULL and 0 as 3rd and 4th parameter respectively.
             */
             ret = initFn(&_handle, key_server_aes, (uint8_t*)iv_l, ivSz_l);


            if (ret == FSP_SUCCESS) {
                /* pass only AAD and it's size before passing cipher text */
               #if defined(WOLFSSL_RENESAS_RSIP) &&\
                                        (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                ret = _R_RSIP_AES_GCM_ADDUpdate((uint8_t*)authIn, authInSz);
               #else
                ret = updateFn(&_handle, NULL, NULL, 0UL, (uint8_t*)authIn,
                                                        authInSz, &out_len_tmp);
               #endif
            }
            if (ret == FSP_SUCCESS) {
                out_len_tmp = 0;
                ret = updateFn(&_handle, cipherBuf,
                                        plainBuf, sz, NULL, 0UL, &out_len_tmp);
                out_len += out_len_tmp;
            }
            if (ret != FSP_SUCCESS) {
                WOLFSSL_MSG("R_XXXX_AesXXXGcmDecryptUpdate: failed in decrypt");
                ret = -1;
            }

            if (ret == FSP_SUCCESS) {
                dataLen = 0;
                out_len_tmp = 0;
                ret = finalFn(&_handle,
                                  plainBuf + (sz + delta - WC_AES_BLOCK_SIZE),
                #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                            &out_len_tmp,
                #else
                            &dataLen,
                #endif
                            aTagBuf,
                            min(16, authTagSz));

                if (ret == FSP_SUCCESS) {
                #if (WOLFSSL_RENESAS_RZFSP_VER >= 220)
                    out_len += out_len_tmp;
                    dataLen = out_len;
                #endif
                    /* copy plain data to out */
                    if (sz != dataLen) {
                        WOLFSSL_MSG("sz is not equal to dataLen!!!!");
                        ret = -1;
                    }
                    else {
                        XMEMCPY(out, plainBuf, dataLen);
                    }
                }
                else {
                    WOLFSSL_MSG("R_XXXX_AesXXXGcmDecryptFinal: failed");
                    ret = -1;
                }
            }
        }

        XFREE(aTagBuf,   aes->heap, DYNAMIC_TYPE_AES);
        XFREE(plainBuf,  aes->heap, DYNAMIC_TYPE_AES);
        XFREE(cipherBuf, aes->heap, DYNAMIC_TYPE_AES);
        if (info->internal->keyflgs_tls.bits.session_key_set == 1 &&
            key_client_aes != NULL)
            XFREE(key_client_aes, aes->heap, DYNAMIC_TYPE_AES);
        if (info->internal->keyflgs_tls.bits.session_key_set == 1 &&
            key_server_aes != NULL)
            XFREE(key_server_aes, aes->heap, DYNAMIC_TYPE_AES);
        wc_fspsm_hw_unlock();
    }

    return ret;
}
/* Perform Aes Cbc encryption by FSP SM
 *
 * aes    The AES object.
 * out    Buffer to hold cipher text
 * in     Buffer to hold plain text
 * sz     Length of cipher text/plaintext in bytes
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
int wc_fspsm_AesCbcEncrypt(struct Aes* aes, byte* out,
                                                const byte* in, word32 sz)
{
    FSPSM_AES_HANDLE _handle;
    int ret;
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    uint32_t dataLength;
    byte *iv;

    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;

    /* while doing TLS handshake, SCE driver keeps true-key and iv *
     * on the device. iv is dummy                                   */
    iv = (uint8_t*)aes->reg;

    if ((ret = wc_fspsm_hw_lock()) != 0) {
        WOLFSSL_MSG("Failed to lock");
        return ret;
    }

    if (aes->ctx.keySize == 16) {
        ret = FSPSM_AES128CBCEnc_Init(&_handle,
            aes->ctx.wrapped_key,
            iv);
    }
    else if (aes->ctx.keySize == 32) {
        ret = FSPSM_AES256CBCEnc_Init(&_handle,
            aes->ctx.wrapped_key,
            iv);
    }
    else {
        WOLFSSL_MSG("invalid key Size for SCE. Key size is neither 16 or 32.");
        wc_fspsm_hw_unlock();
        return -1;
    }

    while (ret == FSP_SUCCESS && blocks--) {

        if (aes->ctx.keySize == 16)
            ret = FSPSM_AES128CBCEnc_Up(&_handle, (uint8_t*)in,
                                    (uint8_t*)out, (uint32_t)WC_AES_BLOCK_SIZE);
        else
            ret = FSPSM_AES256CBCEnc_Up(&_handle, (uint8_t*)in,
                                    (uint8_t*)out, (uint32_t)WC_AES_BLOCK_SIZE);

        in  += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }

    if (ret == FSP_SUCCESS) {
        if (aes->ctx.keySize == 16) {
            ret = FSPSM_AES128CBCEnc_Final(&_handle, out, &dataLength);
        }
        else {
            ret = FSPSM_AES256CBCEnc_Final(&_handle, out, &dataLength);
        }
    }
    else {
        WOLFSSL_MSG("SCE AES CBC encryption failed");
        ret = -1;
    }

    wc_fspsm_hw_unlock();
    return ret;
}
/* Perform Aes Cbc decryption by SCE
 *
 * aes    The AES object.
 * out    Buffer to hold plain text
 * in     Buffer to hold cipher text
 * sz     Length of cipher text/plaintext in bytes
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
int wc_fspsm_AesCbcDecrypt(struct Aes* aes, byte* out,
                                                    const byte* in, word32 sz)
{
    FSPSM_AES_HANDLE _handle;
    int ret;
    word32 blocks = (sz / WC_AES_BLOCK_SIZE);
    uint32_t dataLength;
    byte *iv;

    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;

    iv = (uint8_t*)aes->reg;

    if ((ret = wc_fspsm_hw_lock()) != 0) {
        WOLFSSL_MSG("Failed to lock");
        return ret;
    }

    if (aes->ctx.keySize == 16) {
        ret = FSPSM_AES128CBCDec_Init(&_handle,
            aes->ctx.wrapped_key,
            iv);
    }
    else if (aes->ctx.keySize == 32) {
        ret = FSPSM_AES256CBCDec_Init(&_handle,
            aes->ctx.wrapped_key,
            iv);
    }
    else {
        wc_fspsm_hw_unlock();
        return -1;
    }

    while (ret == FSP_SUCCESS && blocks--) {

        if (aes->ctx.keySize == 16)
            ret = FSPSM_AES128CBCDec_Up(&_handle, (uint8_t*)in,
                                        (uint8_t*)out, (uint32_t)WC_AES_BLOCK_SIZE);
        else
            ret = FSPSM_AES256CBCDec_Up(&_handle, (uint8_t*)in,
                                        (uint8_t*)out, (uint32_t)WC_AES_BLOCK_SIZE);

        in  += WC_AES_BLOCK_SIZE;
        out += WC_AES_BLOCK_SIZE;
    }

    if (ret == FSP_SUCCESS) {
        if (aes->ctx.keySize == 16)
            ret = FSPSM_AES128CBCDec_Final(&_handle, out, &dataLength);
        else
            ret = FSPSM_AES256CBCDec_Final(&_handle, out, &dataLength);
    }
    else {
        WOLFSSL_MSG("SCE AES CBC decryption failed");
        ret = -1;
    }

    wc_fspsm_hw_unlock();
    return ret;
}


/* free contentx related to FSP SM
 *
 * aes    The AES object.
 * return none
 */
void wc_fspsm_Aesfree(Aes* aes)
{
#if defined(WOLFSSL_RENESAS_FSPSM_TLS)
    /* In the case of session key, memory is allocated
     * therefore, it should be freed here
     */
    if (aes->ctx.setup == 1 && aes->ctx.wrapped_key) {
        XFREE(aes->ctx.wrapped_key, aes->heap, DYNAMIC_TYPE_AES);
        aes->ctx.setup = 0;
    }
#else
    if (aes->ctx.wrapped_key) {
        /* aes ctx just points user created wrapped key
         * in the case of CryptOnly Mode
         * therefore, it just sets pointing to NULL.
         * user key should be freed by owner(user)
         */
        aes->ctx.wrapped_key = NULL;
    }
#endif
}

#if defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)
int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
    const byte* iv, int dir)
{
    (void) userKey;
    (void) dir;

    if (aes == NULL || userKey == NULL ||
            !((keylen == 16) || (keylen == 32))) {
        return BAD_FUNC_ARG;
    }

    if (aes->devId == INVALID_DEVID) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS)
    aes->left = 0;
#endif

    /* if there is previous key, free */
    if(aes->ctx.wrapped_key)
        wc_fspsm_Aesfree(aes);
    /* Generate aes key based on length */
    aes->ctx.wrapped_key = (FSPSM_AES_PWKEY)userKey;
    aes->keylen = (int)keylen;
    aes->ctx.keySize = keylen;

    return wc_AesSetIV(aes, iv);
}
#endif

int wc_fspsm_AesCipher(int devIdArg, wc_CryptoInfo* info,
                                                                    void* ctx)
{
    int ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    FSPSM_ST* cbInfo = (FSPSM_ST*)ctx;
    (void)devIdArg;

    WOLFSSL_ENTER("wc_fspsm_AesCipher");

    if (info == NULL || cbInfo == NULL || cbInfo->internal == NULL) {
        return BAD_FUNC_ARG;
    }

    #if !defined(NO_AES)
    #ifdef HAVE_AESGCM
        if (info->cipher.type == WC_CIPHER_AES_GCM) {
            if (info->cipher.enc &&
                (cbInfo->internal->keyflgs_tls.bits.session_key_set == 1 ||
                 (cbInfo->keyflgs_crypt.bits.aes256_installedkey_set == 1 &&
                  info->cipher.aesgcm_enc.aes->keylen == 32) ||
                 (cbInfo->keyflgs_crypt.bits.aes128_installedkey_set == 1 &&
                  info->cipher.aesgcm_enc.aes->keylen == 16))) {

                ret = wc_fspsm_AesGcmEncrypt(
                        info->cipher.aesgcm_enc.aes,
                        (byte*)info->cipher.aesgcm_enc.out,
                        (byte*)info->cipher.aesgcm_enc.in,
                        info->cipher.aesgcm_enc.sz,
                        (byte*)info->cipher.aesgcm_enc.iv,
                        info->cipher.aesgcm_enc.ivSz,
                        (byte*)info->cipher.aesgcm_enc.authTag,
                        info->cipher.aesgcm_enc.authTagSz,
                        (byte*)info->cipher.aesgcm_enc.authIn,
                        info->cipher.aesgcm_enc.authInSz,
                        (void*)ctx);

            }
            else if (cbInfo->internal->keyflgs_tls.bits.session_key_set == 1 ||
                    (cbInfo->keyflgs_crypt.bits.aes256_installedkey_set == 1 &&
                       info->cipher.aesgcm_dec.aes->keylen == 32) ||
                    (cbInfo->keyflgs_crypt.bits.aes128_installedkey_set == 1 &&
                       info->cipher.aesgcm_dec.aes->keylen == 16)) {

                ret = wc_fspsm_AesGcmDecrypt(
                        info->cipher.aesgcm_dec.aes,
                        (byte*)info->cipher.aesgcm_dec.out,
                        (byte*)info->cipher.aesgcm_dec.in,
                        info->cipher.aesgcm_dec.sz,
                        (byte*)info->cipher.aesgcm_dec.iv,
                        info->cipher.aesgcm_dec.ivSz,
                        (byte*)info->cipher.aesgcm_dec.authTag,
                        info->cipher.aesgcm_dec.authTagSz,
                        (byte*)info->cipher.aesgcm_dec.authIn,
                        info->cipher.aesgcm_dec.authInSz,
                        (void*)ctx);
            }
        }
    #endif /* HAVE_AESGCM */
    #ifdef HAVE_AES_CBC
        if ((info->cipher.type == WC_CIPHER_AES_CBC) &&
            (cbInfo->internal->keyflgs_tls.bits.session_key_set == 1 ||
            (cbInfo->keyflgs_crypt.bits.aes256_installedkey_set == 1 &&
                info->cipher.aescbc.aes->keylen == 32) ||
            (cbInfo->keyflgs_crypt.bits.aes128_installedkey_set == 1 &&
                info->cipher.aescbc.aes->keylen == 16))) {
                if (info->cipher.enc) {
                    ret = wc_fspsm_AesCbcEncrypt(
                        info->cipher.aescbc.aes,
                        (byte*)info->cipher.aescbc.out,
                        (byte*)info->cipher.aescbc.in,
                        info->cipher.aescbc.sz);
                }
                else {
                    ret = wc_fspsm_AesCbcDecrypt(
                        info->cipher.aescbc.aes,
                        (byte*)info->cipher.aescbc.out,
                        (byte*)info->cipher.aescbc.in,
                        info->cipher.aescbc.sz);
                }
        }
    #endif /* HAVE_AES_CBC */
    #endif /* !NO_AES */
    (void)cbInfo;
    WOLFSSL_LEAVE("wc_fspsm_AesCipher", ret);
    return ret;
}
#endif /* WOLFSSL_RENESAS_FSPSM_TLS
          WOLFSSL_RENESAS_FSPSM_CRYPTONLY
          NO_WOLFSSL_RENESAS_FSPSM_AES */
#endif /* NO_AES */
