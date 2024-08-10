/* renesas_fspsm_rsa.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(NO_RSA) && \
    defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)

#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>

#if defined(WOLFSSL_RENESAS_RSIP)
extern FSPSM_INSTANCE   gFSPSM_ctrl;
#endif

/* Set Ctx pointer to NULL.
 * A created wrapped key should be freed by user
 *
 * key    RsaKey object
 * return none
 */
WOLFSSL_LOCAL void wc_fspsm_RsaKeyFree(RsaKey *key)
{
    if (key == NULL)
        return;

    if(key->ctx.wrapped_pri1024_key)
        key->ctx.wrapped_pri1024_key = NULL;

    if(key->ctx.wrapped_pub1024_key)
        key->ctx.wrapped_pub1024_key = NULL;

    if(key->ctx.wrapped_pri2048_key)
        key->ctx.wrapped_pri2048_key = NULL;

    if(key->ctx.wrapped_pub2048_key)
        key->ctx.wrapped_pub2048_key = NULL;
}

/* Set Rsa key by pre-created wrapped user key
 *
 * key    RsaKey object
 * size   desired keylenth, in bits. supports 1024 or 2048 bits
 * ctx    Callback context including pointer to hold generated key
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
WOLFSSL_LOCAL int wc_fspsm_MakeRsaKey(RsaKey *key, int size, void* ctx)
{
    FSPSM_ST    *info = (FSPSM_ST*)ctx;

    /* sanity check */
    if (key == NULL || size < 0 || ctx == NULL)
        return BAD_FUNC_ARG;

    if (size == 1024) {
        if(info->keyflgs_crypt.bits.rsapri1024_installedkey_set != 1 ||
           info->keyflgs_crypt.bits.rsapub1024_installedkey_set != 1) {
            WOLFSSL_MSG("Caller should create user key in advance.");
            WOLFSSL_MSG("Caller also need to installedkey to 1.");
            return BAD_FUNC_ARG;
        }
        key->ctx.wrapped_pri1024_key = info->wrapped_key_rsapri1024;
        key->ctx.wrapped_pub1024_key = info->wrapped_key_rsapub1024;
        key->ctx.keySz = 1024;
    } else if (size == 2048) {
        if(info->keyflgs_crypt.bits.rsapri2048_installedkey_set != 1 ||
            info->keyflgs_crypt.bits.rsapub2048_installedkey_set != 1) {
                WOLFSSL_MSG("Caller should create user key in advance.");
                WOLFSSL_MSG("Caller also need to installedkey to 1.");
                return BAD_FUNC_ARG;
        }
        key->ctx.wrapped_pri2048_key = info->wrapped_key_rsapri2048;
        key->ctx.wrapped_pub2048_key = info->wrapped_key_rsapub2048;
        key->ctx.keySz = 2048;
    } else if (size == 0) {
        if((info->keyflgs_crypt.bits.rsapri2048_installedkey_set != 1) &&
           (info->keyflgs_crypt.bits.rsapub2048_installedkey_set != 1) &&
           (info->keyflgs_crypt.bits.rsapri1024_installedkey_set != 1) &&
           (info->keyflgs_crypt.bits.rsapub1024_installedkey_set != 1)) {
                WOLFSSL_MSG("Caller should create user key in advance.");
                WOLFSSL_MSG("Caller also need to installedkey to 1.");
                return BAD_FUNC_ARG;
        }

        if (info->keyflgs_crypt.bits.rsapri1024_installedkey_set == 1) {
            key->ctx.wrapped_pri1024_key = info->wrapped_key_rsapri1024;
            key->ctx.keySz = 1024;
        }
        if (info->keyflgs_crypt.bits.rsapub1024_installedkey_set == 1) {
            key->ctx.wrapped_pub1024_key = info->wrapped_key_rsapub1024;
            key->ctx.keySz = 1024;
        }

        if (info->keyflgs_crypt.bits.rsapri2048_installedkey_set == 1) {
            key->ctx.wrapped_pri2048_key = info->wrapped_key_rsapri2048;
            key->ctx.keySz = 2048;
        }
        if (info->keyflgs_crypt.bits.rsapub2048_installedkey_set == 1) {
            key->ctx.wrapped_pub2048_key = info->wrapped_key_rsapub2048;
            key->ctx.keySz = 2048;
        }
    } else
        return CRYPTOCB_UNAVAILABLE;

    return 0;
}

/* Perform rsa encryption/decryption by FSP SM
 * Assumes to be called by Crypt Callback
 *
 * in     Buffer to hold plain text
 * inLen  Length of plain text in bytes
 * out    Buffer to hold cipher text
 * outLen Length of cipher in bytes
 * key    Rsa key object
 * rng    rng object
 * ctx    Callback context
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
WOLFSSL_LOCAL int wc_fspsm_RsaFunction(const byte* in, word32 inLen, byte* out,
                    word32 *outLen, int type, struct RsaKey* key,
                    struct WC_RNG* rng)
{
    int ret;

    FSPSM_RSA_DATA plain;
    FSPSM_RSA_DATA cipher;

    int keySize;

    (void) key;
    (void) rng;

    /* sanity check */
    if (in == NULL || out == NULL || key == NULL){
        return BAD_FUNC_ARG;
    }

    keySize = (int)key->ctx.keySz;

    if (keySize == 0) {
        WOLFSSL_MSG("keySize is invalid, neither 128 or 256 bytes, "
                                                        "1024 or 2048 bits.");
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (type == RSA_PUBLIC_ENCRYPT) {

            plain.pdata = (byte*)in;
            plain.data_length = inLen;
            cipher.pdata = out;
            cipher.data_length = *outLen;

            if (keySize == 1024) {
               ret = FSPSM_RSA1024_PKCSENC_FUNC(&plain, &cipher,
                            (FSPSM_RSA1024_WPB_KEY*)
                                     key->ctx.wrapped_pub1024_key);
            }
            else {
               ret = FSPSM_RSA2048_PKCSENC_FUNC(&plain, &cipher,
                            (FSPSM_RSA2048_WPB_KEY*)
                                    key->ctx.wrapped_pub2048_key);
            }
        }
        else if (type == RSA_PRIVATE_DECRYPT) {
            plain.pdata = out;
            plain.data_length = *outLen;
            cipher.pdata = (byte*)in;
            cipher.data_length = inLen;

            if (keySize == 1024) {
                ret = FSPSM_RSA1024_PKCSDEC_FUNC(&cipher, &plain,
                            (FSPSM_RSA1024_WPI_KEY*)
                                key->ctx.wrapped_pri1024_key, &outLen);
            }
            else {
                ret = FSPSM_RSA2048_PKCSDEC_FUNC(&cipher, &plain,
                            (FSPSM_RSA2048_WPI_KEY*)
                                key->ctx.wrapped_pri2048_key, &outLen);
            }
        }

        wc_fspsm_hw_unlock();
    }
    return ret;
}

/* Perform Rsa sign by FSP SM
 * Assumes to be called by Crypt Callback
 *
 * in     Buffer to hold plaintext
 * inLen  Length of plaintext in bytes
 * out    Buffer to hold generated signature
 * outLen Length of signature in bytes
 * key    rsa key object
 * ctx    The callback context
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */

WOLFSSL_LOCAL int wc_fspsm_RsaSign(const byte* in, word32 inLen, byte* out,
                    word32* outLen, struct RsaKey* key, void* ctx)
{
    int ret;

    FSPSM_RSA_DATA message_hash;
    FSPSM_RSA_DATA signature;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;
    int keySize;

    /* sanity check */
    if (in == NULL || out == NULL || *outLen <= 0 || info == NULL ||
       key == NULL){
        return BAD_FUNC_ARG;
    }

    keySize = (int)key->ctx.keySz;

    message_hash.pdata = (byte *)in;
    message_hash.data_length = inLen;
    message_hash.data_type =
            info->keyflgs_crypt.bits.message_type;/* message 0, hash 1 */
    signature.pdata = out;
    signature.data_length = (word32*)outLen;

    #if defined(WOLFSSL_RENESAS_RSIP)
    message_hash.hash_type = signature.hash_type =
                info->hash_type;   /* hash type */
    #endif

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (keySize == 1024) {

            ret = FSPSM_RSA1024_SIGN_FUNC(&message_hash,
                        &signature,
                        (FSPSM_RSA1024_WPI_KEY *)
                                    key->ctx.wrapped_pri1024_key,
                        HW_SCE_RSA_HASH_SHA256);
        }
        else {

            ret = FSPSM_RSA2048_SIGN_FUNC(&message_hash,
                        &signature,
                        (FSPSM_RSA2048_WPI_KEY *)
                                    key->ctx.wrapped_pri2048_key,
                        HW_SCE_RSA_HASH_SHA256);
        }

        wc_fspsm_hw_unlock();
    }

    return ret;
}

/* Perform Rsa verify by FSP SM
 * Assumes to be called by Crypt Callback
 *
 * in     Buffer to hold plaintext
 * inLen  Length of plaintext in bytes
 * out    Buffer to hold generated signature
 * outLen Length of signature in bytes
 * key    rsa key object
 * ctx    The callback context
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */

WOLFSSL_LOCAL int wc_fspsm_RsaVerify(const byte* in, word32 inLen, byte* out,
                    word32* outLen,struct RsaKey* key, void* ctx)
{
    int ret;

    FSPSM_RSA_DATA message_hash;
    FSPSM_RSA_DATA signature;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;
    int keySize;

    (void) key;

    /* sanity check */
    if (in == NULL || out == NULL || *outLen <= 0 || info == NULL ||
       key == NULL){
        return BAD_FUNC_ARG;
    }

    keySize = (int)key->ctx.keySz;


    message_hash.pdata =(byte*)in;
    message_hash.data_length = inLen;
    message_hash.data_type =
            info->keyflgs_crypt.bits.message_type;/* message 0, hash 1 */

    signature.pdata = out;
    signature.data_length = (word32)*outLen;
    #if defined(WOLFSSL_RENESAS_RSIP)
    message_hash.hash_type = signature.hash_type =
                info->hash_type;   /* hash type */
    #endif

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (keySize == 1024) {
            ret = FSPSM_RSA1024_VRY_FUNC(&signature,
                  &message_hash,
                  (FSPSM_RSA1024_WPB_KEY *)
                        key->ctx.wrapped_pub1024_key,
                  HW_SCE_RSA_HASH_SHA256);
        }
        else {
                ret = FSPSM_RSA2048_VRY_FUNC(&signature,
                    &message_hash,
                    (FSPSM_RSA2048_WPB_KEY *)
                         key->ctx.wrapped_pub2048_key,
                    HW_SCE_RSA_HASH_SHA256 );
        }
        wc_fspsm_hw_unlock();
    }

    return ret;
}

#endif /* !NO_RSA && WOLFSSL_RENESAS_FSPSM_CRYPTONLY */
