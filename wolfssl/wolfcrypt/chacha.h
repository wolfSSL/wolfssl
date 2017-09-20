/* chacha.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_CHACHA_H
#define WOLF_CRYPT_CHACHA_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_CHACHA

#ifdef __cplusplus
    extern "C" {
#endif

/* Size of the IV */
#define CHACHA_IV_WORDS    3
#define CHACHA_IV_BYTES    (CHACHA_IV_WORDS * sizeof(word32))

/* Size of ChaCha chunks */
#define CHACHA_CHUNK_WORDS 16
#define CHACHA_CHUNK_BYTES (CHACHA_CHUNK_WORDS * sizeof(word32))

enum {
	CHACHA_ENC_TYPE = 7     /* cipher unique type */
};

typedef struct ChaCha {
    word32 X[CHACHA_CHUNK_WORDS];           /* state of cipher */
} ChaCha;

/**
  * IV(nonce) changes with each record
  * counter is for what value the block counter should start ... usually 0
  */
/*!
    \ingroup ChaCha
    
    \brief This function sets the initialization vector (nonce) for a ChaCha object, initializing it for use as a cipher. It should be called after the key has been set, using wc_Chacha_SetKey. A difference nonce should be used for each round of encryption.
    
    \return 0 Returned upon successfully setting the initialization vector
    \return BAD_FUNC_ARG returned if there is an error processing the ctx input argument
    
    \param ctx pointer to the ChaCha structure on which to set the iv
    \param inIv pointer to a buffer containing the 12 byte initialization vector with which to initialize the ChaCha structure
    \param counter the value at which the block counter should start--usually zero.

    _Example_
    \code
    ChaCha enc;
    // initialize enc with wc_Chacha_SetKey
    byte iv[12];
    // initialize iv 
    if( wc_Chacha_SetIV(&enc, iv, 0) != 0) { 
	    // error initializing ChaCha structure
    }
    \endcode
    
    \sa wc_Chacha_SetKey
    \sa wc_Chacha_Process
*/
WOLFSSL_API int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter);

/*!
    \ingroup ChaCha
    
    \brief This function processes the text from the buffer input, encrypts or decrypts it, and stores the result in the buffer output.
    
    \return 0 Returned upon successfully encrypting or decrypting the input
    \return BAD_FUNC_ARG returned if there is an error processing the ctx input argument
    
    \param ctx pointer to the ChaCha structure on which to set the iv
    \param output pointer to a buffer in which to store the output ciphertext or decrypted plaintext
    \param input pointer to the buffer containing the input plaintext to encrypt or the input ciphertext to decrypt
    \param msglen length of the message to encrypt or the ciphertext to decrypt

    _Example_
    \code
    ChaCha enc;
    // initialize enc with wc_Chacha_SetKey and wc_Chacha_SetIV

    byte plain[] = { // initialize plaintext };
    byte cipher[sizeof(plain)];
    if( wc_Chacha_Process(&enc, cipher, plain, sizeof(plain)) != 0) { 
	    // error processing ChaCha cipher
    }
    \endcode
    
    \sa wc_Chacha_SetKey
    \sa wc_Chacha_Process
*/
WOLFSSL_API int wc_Chacha_Process(ChaCha* ctx, byte* cipher, const byte* plain,
                              word32 msglen);
/*!
    \ingroup ChaCha
    
    \brief This function sets the key for a ChaCha object, initializing it for use as a cipher. It should be called before setting the nonce with wc_Chacha_SetIV, and before using it for encryption with wc_Chacha_Process.
    
    \return 0 Returned upon successfully setting the key
    \return BAD_FUNC_ARG returned if there is an error processing the ctx input argument or if the key is not 16 or 32 bytes long
    
    \param ctx pointer to the ChaCha structure in which to set the key
    \param key pointer to a buffer containing the 16 or 32 byte key with which to initialize the ChaCha structure
    \param keySz the length of the key passed in
    
    _Example_
    \code
    ChaCha enc;
    byte key[] = { // initialize key };

    if( wc_Chacha_SetKey(&enc, key, sizeof(key)) != 0) { 
	    // error initializing ChaCha structure
    }
    \endcode
    
    \sa wc_Chacha_SetIV
    \sa wc_Chacha_Process
*/
WOLFSSL_API int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_CHACHA */
#endif /* WOLF_CRYPT_CHACHA_H */

