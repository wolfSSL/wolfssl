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
/*
 * This key store keeps the key-index which TSIP generated.
 * The key will not be used for TLS communication but crypt-test and
 * benchmark purpose only.
 */
static TSIP_AES_CTX  tsip_AES_KeyStore;


/*
 * tsip_AesGenKey
 *
 This API is intended to generate an AES key and share it between the Aes
 structures for encryption and the one for decryption. Key share is done
 via the tsip_AES_keyStore variable and dir (the fifth parameter of this
  function).
 The expected use case is as follows:
 1. wc_AesSetKey API is called to set raw AES key and iv to the given
    Aes structure.
 2. tsip_AesGenKey is called underneath the API. When "dir" is
    AES_ENCRYPTION, it generate a AES key of the specified key length then
    stores it into aes->ctx with other info. aes->ctx is also stored into
    tsip_AES_keyStore variable. The given raw AES key will not be used nor
    stored.
 3. Data encryption will be performed with the key generated in 2.
 4. wc_AesSetKey API is called to set the raw AES key and iv to the given
    Aes structure for decryption with "dir" is AES_DECRYPTION. In this case,
    Aes key is not generated but restored from tsip_AES_keyStore variable
    with other information.
 5. Data decryption will be performed with the shared AES key.

 Above use case occurs only in crypt-test and benchmark.
 */
int tsip_AesGenKey(struct Aes* aes, word32 keylen, const byte* iv, int dir)
{
    int ret;

    if ((aes == NULL) || (keylen == 0) )
        return BAD_FUNC_ARG;

    /* TSIP accepts 128bit or 256bit key only*/
    if( keylen != 16 && keylen != 32)
        return BAD_FUNC_ARG;

    tsip_hw_lock();

    if( dir == AES_ENCRYPTION )
	{
        if( keylen == 16)
        {
            ret = R_TSIP_GenerateAes128RandomKeyIndex(&aes->ctx.tsip_keyIdx);
        }
        else
        {
            ret = R_TSIP_GenerateAes256RandomKeyIndex(&aes->ctx.tsip_keyIdx);
        }
        if( ret != TSIP_SUCCESS)
        {
            WOLFSSL_MSG("R_TSIP_GenerateAesXXXRandomKeyIndex failed" );
            tsip_hw_unlock();
            return WC_HW_E;
        }

        aes->ctx.keySize = keylen;
        aes->keylen      = keylen;
        aes->rounds      = (keylen/4) + 6;

        ret = wc_AesSetIV(aes, iv);

        /* store generated key-index into static area for a succeeding
         * decryption and the given raw key data will not be used.
         */
        tsip_AES_KeyStore = aes->ctx;
    }
    else /* AES_DECRYPTION */
    {
        /* restore Aes key-index which previous
         * wc_AesSetKey(..,AES_ENCRYPTION ) stored
         */

        aes->ctx    = tsip_AES_KeyStore;
        aes->keylen = keylen;
        aes->rounds = (keylen/4) + 6;

        wc_AesSetIV(aes, iv);

    }
    tsip_hw_unlock();
    return 0;
}


int wc_AesCbcEncrypt(struct Aes* aes, byte* out, const byte* in, word32 sz)
{
    tsip_aes_handle_t _handle;
    int ret;
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

int wc_AesCbcDecrypt(struct Aes* aes, byte* out, const byte* in, word32 sz)
{
   tsip_aes_handle_t _handle;
    int ret;
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

int wc_AesGcmEncrypt(
    Aes*        aes,            byte* out,
    const byte* in,             word32 sz,
    const byte* iv,             word32 ivSz,
          byte* authTag,        word32 authTagSz,
    const byte* authIn,         word32 authInSz)
{

    tsip_gcm_handle_t   hdl;
    word32              ret;
    word32              blocks = (sz/ AES_BLOCK_SIZE);
    uint32_t            dataLen = sz;
    uint32_t            byteToProc = min( sz,AES_BLOCK_SIZE);

    if( in == NULL || out == NULL  || sz == 0 )
        return 0;	/* do nothing and return successfully */

    if ( aes == NULL ){
        WOLFSSL_MSG("wc_tsip_AesGcmEncrypt: Bad Arg");
      return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("wc_tsip_AesGcmEncrypt: illegal key size");
        return  BAD_FUNC_ARG;
    }

    if((ret = tsip_hw_lock()) == 0){

        if (aes->ctx.keySize == 16) {
            ret = R_TSIP_Aes128GcmEncryptInit(&hdl,
                                                &aes->ctx.tsip_keyIdx,iv,ivSz);
        } else{
            ret = R_TSIP_Aes256GcmEncryptInit(&hdl,
                                                &aes->ctx.tsip_keyIdx,iv,ivSz);
        }

        if( ret == TSIP_SUCCESS){

            if (aes->ctx.keySize == 16){
                ret = R_TSIP_Aes128GcmEncryptUpdate(
                                &hdl,(uint8_t*)NULL,(uint8_t*)NULL,(uint32_t)0,
                                (uint8_t*)authIn,authInSz);
            }
            else{
                ret = R_TSIP_Aes256GcmEncryptUpdate(
                                &hdl,(uint8_t*)NULL,(uint8_t*)NULL,(uint32_t)0,
                                (uint8_t*)authIn,authInSz);
            }

            if(ret == TSIP_SUCCESS){

                while (ret == TSIP_SUCCESS && dataLen) {

                    byteToProc  = min( dataLen,AES_BLOCK_SIZE);

                    if (aes->ctx.keySize == 16){
                        ret = R_TSIP_Aes128GcmEncryptUpdate(
                                &hdl,
								(uint8_t*)in,
								(uint8_t*)out,
								(uint32_t)byteToProc,
								NULL, 0);
                    }
                    else{
                        ret = R_TSIP_Aes256GcmEncryptUpdate(
                                &hdl,
								(uint8_t*)in,
								(uint8_t*)out,
								(uint32_t)byteToProc,
                                NULL, 0);
                    }
                    dataLen    -= byteToProc;
                    in         += byteToProc;
                    out        += byteToProc;
                }
                if( ret != TSIP_SUCCESS){
                    WOLFSSL_MSG("R_TSIP_AesXXXGcmEncryptUpdate: failed");
                }
            }
        }

        /* Once R_TSIP_AesxxxGcmEncryptInit or R_TSIP_AesxxxEncryptUpdate is
         * called, R_TSIP_AesxxxGcmEncryptFinal must be called regardless of
         * the result of the previous call. Otherwise, TSIP can not come out
         * from its error state and all the trailing APIs will fail.
         */
        if (aes->ctx.keySize == 16) {
            ret = R_TSIP_Aes128GcmEncryptFinal(
                    &hdl,
					out - byteToProc,
					&dataLen,
					authTag);

        }
        else {

            ret = R_TSIP_Aes256GcmEncryptFinal(
                    &hdl,
					out - byteToProc,
					&dataLen,
					authTag);

        }
        if(ret != TSIP_SUCCESS){
            WOLFSSL_MSG("R_TSIP_AesxxxGcmEncryptFinal: failed");
        }

        tsip_hw_unlock();
    }
    return ret;
}
int wc_AesGcmDecrypt(
    Aes*        aes,            byte* out,
    const byte* in,             word32 sz,
    const byte* iv,             word32 ivSz,
    const byte* authTag,        word32 authTagSz,
    const byte* authIn,         word32 authInSz)
{

    tsip_gcm_handle_t   hdl;
    word32              ret;
    word32              blocks = (sz/ AES_BLOCK_SIZE);
    uint32_t            dataLen = sz;
    uint32_t            byteToProc = min(sz, AES_BLOCK_SIZE);

    if( in == NULL || out == NULL || sz == 0 )
        return 0;	/* do nothing and return successfully */

    if ( aes == NULL ){
        return BAD_FUNC_ARG;
    }

    if (aes->ctx.keySize != 16 && aes->ctx.keySize != 32) {
        WOLFSSL_MSG("<< wc_tsip_AesGcmDecrypt: illegal key size");
        return  BAD_FUNC_ARG;
    }

    if((ret = tsip_hw_lock()) == 0){

        if (aes->ctx.keySize == 16) {
            ret = R_TSIP_Aes128GcmDecryptInit(
                    &hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);

        }
        else{
            ret = R_TSIP_Aes256GcmDecryptInit(
                    &hdl,&aes->ctx.tsip_keyIdx,iv,ivSz);

        }

        if( ret == TSIP_SUCCESS ){

            /* pass only AAD and it's size before passing cipher text */
            if (aes->ctx.keySize == 16){

                ret = R_TSIP_Aes128GcmDecryptUpdate(
                            &hdl,
                            (uint8_t*)NULL, /* buffer for cipher text*/
                            (uint8_t*)NULL, /* buffer for plain text */
                            (uint32_t)0,
                            (uint8_t*)authIn,/* additional auth data */
                            authInSz);

            }
            else{
                ret = R_TSIP_Aes256GcmDecryptUpdate(
                            &hdl,
                            (uint8_t*)NULL,
                            (uint8_t*)NULL,
                            (uint32_t)0,
                            (uint8_t*)authIn,
                            authInSz);

            }

            if(ret == TSIP_SUCCESS){

                while ((ret == TSIP_SUCCESS) && dataLen ) {

                    byteToProc  = min(dataLen, AES_BLOCK_SIZE);

                    if (aes->ctx.keySize == 16){
                        ret = R_TSIP_Aes128GcmDecryptUpdate(
                                &hdl,
                                (uint8_t*)in,
                                (uint8_t*)out,
                                (uint32_t)byteToProc,
                                NULL,
                                0);

                    }
                    else{

                        ret = R_TSIP_Aes256GcmDecryptUpdate(
                                &hdl,
                                (uint8_t*)in,
                                (uint8_t*)out,
                                (uint32_t)byteToProc,
                                NULL,
                                0);

                    }
                    dataLen    -= byteToProc;
                    in         += byteToProc;
                    out        += byteToProc;
                }
                if(ret != TSIP_SUCCESS){
                    WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptUpdate: failed in decrypt");
                }
            }
            if(ret != TSIP_SUCCESS){
                WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptUpdate: failed with AAD");
            }
        }
        else{
            WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptInit: failed");
        }


        if (aes->ctx.keySize == 16) {
            ret = R_TSIP_Aes128GcmDecryptFinal(
                    &hdl,
					out- byteToProc,
					&dataLen,
					authTag,
					min(16, authTagSz)); /* TSIP accepts upto 16 byte AuthTag*/

        }
        else {
            ret = R_TSIP_Aes256GcmDecryptFinal(
                    &hdl,
					out- byteToProc,
					&dataLen,
					authTag,
					min(16, authTagSz));

        }

        if( ret != TSIP_SUCCESS ){
            WOLFSSL_MSG("R_TSIP_AesXXXGcmDecryptFinal: failed");
        }

        tsip_hw_unlock();
    }
    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP_CRYPT */
#endif /* NO_AES */
