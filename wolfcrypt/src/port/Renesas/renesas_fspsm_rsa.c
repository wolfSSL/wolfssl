/* renesas_fspsm_rsa.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* Make Rsa key for SCE and set it to callback ctx
 * Assumes to be called by Crypt Callback
 *
 * size   desired keylenth, in bits. supports 1024 or 2048 bits
 * ctx    Callback context including pointer to hold generated key
 * return FSP_SUCCESS(0) on Success, otherwise negative value
 */
WOLFSSL_LOCAL int wc_fspsm_MakeRsaKey(int size, void* ctx)
{
    fsp_err_t   ret;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;

    FSPSM_RSA1024_WPA_KEY *wrapped_pair1024_key = NULL;
    FSPSM_RSA2048_WPA_KEY *wrapped_pair2048_key = NULL;

    /* sanity check */
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    

    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (size == 1024) {
            wrapped_pair1024_key = 
            (FSPSM_RSA1024_WPA_KEY*)XMALLOC(
                sizeof(FSPSM_RSA1024_WPA_KEY), NULL,
                                                DYNAMIC_TYPE_RSA_BUFFER);
            if (wrapped_pair1024_key == NULL)
                return MEMORY_E;
                
            ret = FSPSM_RSA1024_KEYPA_GEN(wrapped_pair1024_key);
        }
        else if (size == 2048) {
            wrapped_pair2048_key = 
            (FSPSM_RSA2048_WPA_KEY*)XMALLOC(
                sizeof(FSPSM_RSA2048_WPA_KEY), NULL, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
            if (wrapped_pair2048_key == NULL)
                return MEMORY_E;
                
            ret = FSPSM_RSA1024_KEYPA_GEN(wrapped_pair2048_key);
        }
        else
            return CRYPTOCB_UNAVAILABLE;
            
        if (ret == FSP_SUCCESS) {
            if (size == 1024) {
                if (info->wrapped_key_rsapri1024 != NULL) {
                    XFREE(info->wrapped_key_rsapri1024, NULL, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
                }
                if (info->wrapped_key_rsapub1024 != NULL) {
                    XFREE(info->wrapped_key_rsapub1024, NULL, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
                }
                info->wrapped_key_rsapri1024 = 
                (FSPSM_RSA1024_WPI_KEY*)XMALLOC(
                    sizeof(FSPSM_RSA1024_WPI_KEY), NULL, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
                    
                if (info->wrapped_key_rsapri1024 == NULL) {
                    XFREE(wrapped_pair1024_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }
                
                info->wrapped_key_rsapub1024 =
                (FSPSM_RSA1024_WPB_KEY*)XMALLOC(
                    sizeof(FSPSM_RSA1024_WPB_KEY), NULL, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
                    
                if (info->wrapped_key_rsapub1024 == NULL) {
                    XFREE(wrapped_pair1024_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                    XFREE(info->wrapped_key_rsapub1024, 0, 
                                                DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }
                /* copy generated key pair and free malloced key */
                XMEMCPY(info->wrapped_key_rsapri1024, 
                                    &wrapped_pair1024_key->priv_key,
                                    sizeof(FSPSM_RSA1024_WPI_KEY));
                XMEMCPY(info->wrapped_key_rsapub1024, 
                                    &wrapped_pair1024_key->pub_key,
                                    sizeof(FSPSM_RSA1024_WPB_KEY));
                XFREE(wrapped_pair1024_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                
                info->keyflgs_crypt.bits.rsapri1024_installedkey_set = 1;
                info->keyflgs_crypt.bits.rsapub1024_installedkey_set = 1;
            }
            else if (size == 2048) {
                if (info->wrapped_key_rsapri2048 != NULL) {
                    XFREE(info->wrapped_key_rsapri2048, NULL, 
                                    DYNAMIC_TYPE_RSA_BUFFER);
                }
                if (info->wrapped_key_rsapub2048 != NULL) {
                    XFREE(info->wrapped_key_rsapub2048, NULL, 
                                    DYNAMIC_TYPE_RSA_BUFFER);
                }
                info->wrapped_key_rsapri2048 = 
                (FSPSM_RSA2048_WPI_KEY*)XMALLOC(
                    sizeof(FSPSM_RSA2048_WPI_KEY), NULL, 
                                    DYNAMIC_TYPE_RSA_BUFFER);
                    
                if (info->wrapped_key_rsapri2048 == NULL) {
                    XFREE(wrapped_pair2048_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }
                
                info->wrapped_key_rsapub2048 =
                (FSPSM_RSA2048_WPB_KEY*)XMALLOC(
                    sizeof(FSPSM_RSA2048_WPB_KEY), NULL, 
                                    DYNAMIC_TYPE_RSA_BUFFER);
                    
                if (info->wrapped_key_rsapub2048 == NULL) {
                    XFREE(wrapped_pair2048_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                    XFREE(info->wrapped_key_rsapub1024, 0, 
                                    DYNAMIC_TYPE_RSA_BUFFER);
                    return MEMORY_E;
                }
                /* copy generated key pair and free malloced key */
                XMEMCPY(info->wrapped_key_rsapri2048, 
                            &wrapped_pair2048_key->priv_key,
                            sizeof(FSPSM_RSA2048_WPI_KEY));
                XMEMCPY(info->wrapped_key_rsapub2048, 
                            &wrapped_pair2048_key->pub_key,
                            sizeof(FSPSM_RSA2048_WPB_KEY));
                XFREE(wrapped_pair2048_key, 0, DYNAMIC_TYPE_RSA_BUFFER);
                
                info->keyflgs_crypt.bits.rsapri2048_installedkey_set = 1;
                info->keyflgs_crypt.bits.rsapub2048_installedkey_set = 1;
                
            }
        }
        else {
            WOLFSSL_MSG("Failed to generate key pair by SCE");
            return CRYPTOCB_UNAVAILABLE;
        }
        
        wc_fspsm_hw_unlock();
    }
}

/* Perform rsa encryption/decryption by SCE
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
                    word32 outLen, int type, struct RsaKey* key, 
                    struct WC_RNG* rng, void* ctx)
{
    int ret;
    
    FSPSM_RSA_DATA plain;
    FSPSM_RSA_DATA cipher;
    FSPSM_ST    *info = (FSPSM_ST*)ctx;
    
    int keySize;
    
    (void) key;
    (void) rng;
    
    /* sanity check */
    if (in == NULL || out == NULL || outLen == NULL ||
                                            ctx == NULL){
        return BAD_FUNC_ARG;
    }
    
    keySize = 0;
    if (info->keyflgs_crypt.bits.rsapri2048_installedkey_set == 1 ||
        info->keyflgs_crypt.bits.rsapub2048_installedkey_set == 1 )
        keySize = 2048;
    else if (info->keyflgs_crypt.bits.rsapri1024_installedkey_set == 1 ||
             info->keyflgs_crypt.bits.rsapub1024_installedkey_set == 1 )
        keySize = 1024;
    
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
            cipher.data_length = outLen;

            if (keySize == 1024) {
                if(info->keyflgs_crypt.bits.rsapub1024_installedkey_set == 1)
                    ret = FSPSM_RSA1024_PKCSENC_FUNC(&plain, &cipher,
                        (FSPSM_RSA1024_WPB_KEY*)
                            info->wrapped_key_rsapub1024);
                else {
                    WOLFSSL_MSG("wrapped public 1024 bits key is not set.");
                    return BAD_FUNC_ARG;
                }
            }
            else {
                if(info->keyflgs_crypt.bits.rsapub2048_installedkey_set == 1)
                    ret = FSPSM_RSA2048_PKCSENC_FUNC(&plain, &cipher,
                            (FSPSM_RSA2048_WPB_KEY*)
                                info->wrapped_key_rsapub2048);
                else {
                    WOLFSSL_MSG("wrapped public 2048 bits key is not set.");
                    return BAD_FUNC_ARG;
                }
            }
        }
        else if (type == RSA_PRIVATE_DECRYPT) {
            plain.pdata = out;
            plain.data_length = outLen;
            cipher.pdata = (byte*)in;
            cipher.data_length = inLen;
            
            if (keySize == 1024) {
                if(info->keyflgs_crypt.bits.rsapri1024_installedkey_set == 1)
                    ret = FSPSM_RSA1024_PKCSDEC_FUNC(&cipher, &plain,
                            (FSPSM_RSA1024_WPI_KEY*)
                                info->wrapped_key_rsapri1024);
                else {
                    WOLFSSL_MSG("wrapped private 2048 bits key is not set.");
                    return BAD_FUNC_ARG;
                }
            }
            else {
                if(info->keyflgs_crypt.bits.rsapri2048_installedkey_set == 1)
                    ret = FSPSM_RSA2048_PKCSDEC_FUNC(&cipher, &plain,
                            (FSPSM_RSA2048_WPI_KEY*)
                                info->wrapped_key_rsapri2048);
                else {
                    WOLFSSL_MSG("wrapped private 2048 bits key is not set.");
                    return BAD_FUNC_ARG;
                }
            }
        }
        
        wc_fspsm_hw_unlock();
    }
    return ret;
}

/* Perform Rsa sign by SCE
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
    
    (void) key;
    
    /* sanity check */
    if (in == NULL || out == NULL || outLen == NULL ||
                                key == NULL || ctx == NULL){
        return BAD_FUNC_ARG;
    }
    
    keySize = 0;
    if (info->keyflgs_crypt.bits.rsapri2048_installedkey_set == 1 ||
        info->keyflgs_crypt.bits.rsapub2048_installedkey_set == 1 )
        keySize = 2048;
    else if (info->keyflgs_crypt.bits.rsapri1024_installedkey_set == 1 ||
             info->keyflgs_crypt.bits.rsapub1024_installedkey_set == 1 )
        keySize = 1024;
        
    if (keySize == 0) {
        WOLFSSL_MSG("keySize is invalid, neither 1024 or 2048 bits.");
        return BAD_FUNC_ARG;
    }
    
    message_hash.pdata = in;
    message_hash.data_length = inLen;
    message_hash.data_type = 
            info->keyflgs_crypt.bits.message_type;/* message 0, hash 1 */
    signature.pdata = out;
    signature.data_length = outLen;
    
    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (keySize == 1024) {
            
            ret = FSPSM_RSA1024_SIGN_FUNC(&message_hash, 
                        &signature,
                        (FSPSM_RSA1024_WPI_KEY *)
                                    info->wrapped_key_rsapri1024,
                        HW_SCE_RSA_HASH_SHA256);
        }
        else {
            
            ret = FSPSM_RSA2048_SIGN_FUNC(&message_hash, 
                        &signature,
                        (FSPSM_RSA2048_WPI_KEY *)
                                    info->wrapped_key_rsapri2048,
                        HW_SCE_RSA_HASH_SHA256);
        }
        
        wc_fspsm_hw_unlock();
    }
    
    return ret;
}

/* Perform Rsa verify by SCE
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
    if (in == NULL || out == NULL || outLen == NULL ||
                                key == NULL || ctx == NULL){
        return BAD_FUNC_ARG;
    }
    
    keySize = 0;
    if (info->keyflgs_crypt.bits.rsapri2048_installedkey_set == 1 ||
        info->keyflgs_crypt.bits.rsapub2048_installedkey_set == 1 )
        keySize = 2048;
    else if (info->keyflgs_crypt.bits.rsapri1024_installedkey_set == 1 ||
             info->keyflgs_crypt.bits.rsapub1024_installedkey_set == 1 )
        keySize = 1024;
        
    if (keySize == 0) {
        WOLFSSL_MSG("keySize is invalid, neither 1024 or 2048 bits.");
        return BAD_FUNC_ARG;
    }
    
    
    message_hash.pdata = in;
    message_hash.data_length = inLen;
    message_hash.data_type = 
            info->keyflgs_crypt.bits.message_type;/* message 0, hash 1 */
    
    signature.pdata = out;
    signature.data_length = outLen;
    
    if ((ret = wc_fspsm_hw_lock()) == 0) {
        if (keySize == 1024) {
            
            ret = FSPSM_RSA1024_VRY_FUNC(&signature,
                  &message_hash,
                  (FSPSM_RSA1024_WPB_KEY *)
                        info->wrapped_key_rsapub1024,
                  HW_SCE_RSA_HASH_SHA256);
        }
        else {
            
                ret = FSPSM_RSA2048_VRY_FUNC(&signature, 
                    &message_hash,
                    (FSPSM_RSA2048_WPB_KEY *)
                         info->wrapped_key_rsapub2048,
                    HW_SCE_RSA_HASH_SHA256 );
        }
        
        wc_fspsm_hw_unlock();
    }
    
    return ret;
}

#endif /* !NO_RSA && WOLFSSL_RENESAS_FSPSM_CRYPTONLY */
