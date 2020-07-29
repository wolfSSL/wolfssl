/* renesas_tsip_aes.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <stdio.h>

#ifndef NO_AES

#if defined(WOLFSSL_RENESAS_TSIP_CRYPT) && \
    !defined(NO_WOLFSSL_RENESAS_TSIP_CRYPT_AES)

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/aes.h>
#include "wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h"

struct Aes;

int wc_tsip_AesCbcEncrypt(struct Aes* aes, byte* out, const byte* in, word32 sz)
{
    tsip_aes_handle_t _handle;
    word32 ret;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    uint32_t dataLength;
    byte *iv;
    
    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;
    
    /* while doing TLS handshake, TSIP driver keeps true-key and iv *
     * on the device. iv is dummy                                   */
    iv = (uint8_t*)aes->reg;
    
    if((ret = tsip_hw_lock()) != 0){
        WOLFSSL_MSG("Failed to lock");
        return ret;
    }
    
    if (aes->ctx.keySize == 16) {
        ret = R_TSIP_Aes128CbcEncryptInit(&_handle, &aes->ctx.tsip_keyIdx, iv);
    } else if (aes->ctx.keySize == 32) {
        ret = R_TSIP_Aes256CbcEncryptInit(&_handle, &aes->ctx.tsip_keyIdx, iv);
    } else {
        tsip_hw_unlock();
        return -1;
    }
    
    while (ret == TSIP_SUCCESS && blocks--) {
        
        if (aes->ctx.keySize == 16)
            ret = R_TSIP_Aes128CbcEncryptUpdate(&_handle, (uint8_t*)in, 
                                    (uint8_t*)out, (uint32_t)AES_BLOCK_SIZE);
        else
            ret = R_TSIP_Aes256CbcEncryptUpdate(&_handle, (uint8_t*)in, 
                                    (uint8_t*)out, (uint32_t)AES_BLOCK_SIZE);
        
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    
    if (ret == TSIP_SUCCESS) {
        if (aes->ctx.keySize == 16) {
            ret = R_TSIP_Aes128CbcEncryptFinal(&_handle, out, &dataLength);
        } else {
            ret = R_TSIP_Aes256CbcEncryptFinal(&_handle, out, &dataLength);
        }
    } else {
        WOLFSSL_MSG("TSIP AES CBC encryption failed");
        ret = -1;
    }
    
    tsip_hw_unlock();
    return ret;
}

int wc_tsip_AesCbcDecrypt(struct Aes* aes, byte* out, const byte* in, word32 sz)
{
   tsip_aes_handle_t _handle;
    word32 ret;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    uint32_t dataLength;
    byte *iv;
    
    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;
    
    iv = (uint8_t*)aes->reg;

    if((ret = tsip_hw_lock()) != 0){
        WOLFSSL_MSG("Failed to lock");
        return ret;
    }
    
    if (aes->ctx.keySize == 16) {
        ret = R_TSIP_Aes128CbcDecryptInit(&_handle, &aes->ctx.tsip_keyIdx, iv);
    } else if (aes->ctx.keySize == 32) {
        ret = R_TSIP_Aes256CbcDecryptInit(&_handle, &aes->ctx.tsip_keyIdx, iv);
    } else {
        tsip_hw_unlock();
        return -1;
    }
    
    while (ret == TSIP_SUCCESS && blocks--) {
        
        if (aes->ctx.keySize == 16)
            ret = R_TSIP_Aes128CbcDecryptUpdate(&_handle, (uint8_t*)in, 
                                        (uint8_t*)out, (uint32_t)AES_BLOCK_SIZE);
        else
            ret = R_TSIP_Aes256CbcDecryptUpdate(&_handle, (uint8_t*)in, 
                                        (uint8_t*)out, (uint32_t)AES_BLOCK_SIZE);
        
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    
    if (ret == TSIP_SUCCESS) {
        if (aes->ctx.keySize == 16)
            ret = R_TSIP_Aes128CbcDecryptFinal(&_handle, out, &dataLength);
        else
            ret = R_TSIP_Aes256CbcDecryptFinal(&_handle, out, &dataLength);
    } else {
        WOLFSSL_MSG("TSIP AES CBC decryption failed");
        ret = -1;
    }
    
    tsip_hw_unlock();
    return ret;
}
/*-------------------------------------------------------------------

    wc_tsip_AesGcmEncrypt

-------------------------------------------------------------------*/
int wc_tsip_AesGcmEncrypt(
            Aes*  aes, 
            byte* out, const byte* in,  word32 sz,
            byte*       iv,             word32 ivSz,
            byte*       authTag,        word32 authTagSz,
            const byte* authIn,         word32 authInSz)
{

    tsip_gcm_handle_t   hdl;
    word32              ret;
    uint32_t            dataLen;  
    word32              blocks = (sz/ AES_BLOCK_SIZE);

    if ( in == NULL  || out == NULL || aes == NULL ||
         iv == NULL  || authTag == NULL || authIn == NULL ){   
        WOLFSSL_MSG("<< wc_tsip_AesGcmEncrypt: Bad Arg");
      return BAD_FUNC_ARG;
    }
 
    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("<< wc_tsip_AesGcmEncrypt: illegal key size");
        return  BAD_FUNC_ARG;
    }

    if((ret = tsip_hw_lock()) != 0){
        WOLFSSL_MSG("<< wc_tsip_AesGcmEncrypt: Failed to lock");
        return ret;
    }

    /* Initialization step */

    if (aes->ctx.keySize == 16) {
        ret = R_TSIP_Aes128GcmEncryptInit(&hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);
    } else{
        ret = R_TSIP_Aes256GcmEncryptInit(&hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);
    }
    if( ret != TSIP_SUCCESS){
        WOLFSSL_MSG("<< R_TSIP_AesXXXGcmEncryptInit : failed");
        goto finalize;
    }

    /* passing additional authentication data step */

    if (aes->ctx.keySize == 16){
        ret = R_TSIP_Aes128GcmEncryptUpdate(
            &hdl,(uint8_t*)NULL,(uint8_t*)out,(uint32_t)0,
            (uint8_t*)authIn,authInSz);
    }
    else{
        ret = R_TSIP_Aes256GcmEncryptUpdate(
            &hdl,(uint8_t*)NULL,(uint8_t*)out,(uint32_t)0,
            (uint8_t*)authIn,authInSz);
    }

    if(ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesxxxGcmEncryptUpdate : failed");
        goto finalize;
    }
  
    while (ret == TSIP_SUCCESS && blocks--) {

        if (aes->ctx.keySize == 16){

            ret = R_TSIP_Aes128GcmEncryptUpdate(
                    &hdl,(uint8_t*)in,(uint8_t*)out,(uint32_t)AES_BLOCK_SIZE,  NULL, 0);

        }
        else{

            ret = R_TSIP_Aes256GcmEncryptUpdate(
                    &hdl,(uint8_t*)in,(uint8_t*)out,(uint32_t)AES_BLOCK_SIZE,
                    NULL, 0);

        }
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }

    if(ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesxxxGcmEncryptUpdate: failed");
        goto finalize;
    }

finalize:

    /* Once R_TSIP_Aed EncryptInit or R_TSIP_Aed Encrypt Update is called,
     * R_TSIP_AesxxxGcmEncryptFinal must be called regardres of the result
     * of the previous call. Otherwise, TSIP can not come out from its 
     * error state and all the trailing APIs will fail. 
     */   
    if (aes->ctx.keySize == 16) {
        ret = R_TSIP_Aes128GcmEncryptFinal(
                &hdl,out,&dataLen,authTag);
    } 
    else {
        ret = R_TSIP_Aes256GcmEncryptFinal(
                &hdl,out,&dataLen,authTag);
    }
    if(ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesxxxGcmEncryptFinal: failed");
    }

exit:    
    tsip_hw_unlock();

    return ret;
}
/*-------------------------------------------------------------------

    wc_tsip_AesGcmDecrypt

-------------------------------------------------------------------*/
int wc_tsip_AesGcmDecrypt(
            Aes*  aes, 
            byte* out, const byte* in,  word32 sz,
            byte*       iv,             word32 ivSz,
            byte*       authTag,        word32 authTagSz,
            const byte* authIn,         word32 authInSz)
{                            

    tsip_gcm_handle_t   hdl;
    word32              ret;
    word32              blocks = (sz/ AES_BLOCK_SIZE);
    uint32_t            dataLen;
    
    if ( in == NULL  || out == NULL || aes == NULL ||
         iv == NULL  || authTag == NULL || authIn == NULL ){    
      return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("<< wc_tsip_AesGcmEncrypt: illegal key size");
        return  BAD_FUNC_ARG;
    }

    if((ret = tsip_hw_lock()) != 0){
        WOLFSSL_MSG("<< wc_tsip_AesGcmDecrypt: Failed to lock");
        return ret;
    }

    /*  */
    if (aes->ctx.keySize == 16) {
        ret = R_TSIP_Aes128GcmDecryptInit(
                &hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);
    } 
    else{
        ret = R_TSIP_Aes256GcmDecryptInit(
                &hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);
    }
    if( ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptInit: failed ");
        goto finalize;
    }  


    /* pass only AuthTag and it's size before passing cipher text */
    if (aes->ctx.keySize == 16){

        ret = R_TSIP_Aes128GcmDecryptUpdate(
                    &hdl,
                    (uint8_t*)NULL, /* buffer for cipher text*/
                    (uint8_t*)out, /* buffer for plain text */
                    (uint32_t)0,
                    (uint8_t*)authIn,
                    authInSz);
    }
    else{
        ret = R_TSIP_Aes256GcmDecryptUpdate(
                    &hdl,
                    (uint8_t*)NULL, 
                    (uint8_t*)out,
                    (uint32_t)0,
                    (uint8_t*)authIn,
                    authInSz);
    }

    if(ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptUpdate: failed");
        goto finalize;
    }

    /* pass chipher text repeatedly */
              
    while ((ret == TSIP_SUCCESS) && blocks--) {

        if (aes->ctx.keySize == 16){ 
            ret = R_TSIP_Aes128GcmDecryptUpdate(
                    &hdl,
                    (uint8_t*)in, 
                    (uint8_t*)out,
                    (uint32_t)AES_BLOCK_SIZE,
                    NULL,
                    0);
        }
        else{

            ret = R_TSIP_Aes256GcmDecryptUpdate(
                    &hdl,
                    (uint8_t*)in, 
                    (uint8_t*)out,
                    (uint32_t)AES_BLOCK_SIZE,
                    NULL,
                    0);
        }
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    
    if( ret != TSIP_SUCCESS){
        WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptUpdate: failed");
        goto finalize;
    }

finalize:
    
    if (aes->ctx.keySize == 16) {
 
        ret = R_TSIP_Aes128GcmDecryptFinal(
                    &hdl,
                    out,
                    &dataLen,
                    authTag,
                    authTagSz);       
    } 
    else {

        ret = R_TSIP_Aes256GcmDecryptFinal(
                    &hdl,
                    out,
                    &dataLen,
                    authTag,
                    authTagSz);
    }
    
    if( ret != TSIP_SUCCESS ){
        WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptFinal: failed");
        ret = 0;
    }

exit:
    
    tsip_hw_unlock();

    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP_CRYPT */
#endif /* NO_AES */
