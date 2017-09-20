/* camellia.h ver 1.2.0
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* camellia.h
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

#ifndef WOLF_CRYPT_CAMELLIA_H
#define WOLF_CRYPT_CAMELLIA_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_CAMELLIA

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    CAMELLIA_BLOCK_SIZE = 16
};

#define CAMELLIA_TABLE_BYTE_LEN 272
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / sizeof(word32))

typedef word32 KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];

typedef struct Camellia {
    word32 keySz;
    KEY_TABLE_TYPE key;
    word32 reg[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
    word32 tmp[CAMELLIA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
} Camellia;

/*!
    \ingroup Camellia
    
    \brief This function sets the key and initialization vector for a camellia object, initializing it for use as a cipher.
    
    \return 0 Returned upon successfully setting the key and initialization vector
    \return BAD_FUNC_ARG returned if there is an error processing one of the input arguments
    \return MEMORY_E returned if there is an error allocating memory with XMALLOC

    \param cam pointer to the camellia structure on which to set the key and iv
    \param key pointer to the buffer containing the 16, 24, or 32 byte key to use for encryption and decryption
    \param len length of the key passed in
    \param iv pointer to the buffer containing the 16 byte initialization vector for use with this camellia structure
    
    _Example_
    \code
    Camellia cam;
    byte key[32];
    // initialize key
    byte iv[16];
    // initialize iv
    if( wc_CamelliaSetKey(&cam, key, sizeof(key), iv) != 0) { 
    	// error initializing camellia structure
    }
    \endcode
    
    \sa wc_CamelliaEncryptDirect
    \sa wc_CamelliaDecryptDirect
    \sa wc_CamelliaCbcEncrypt
    \sa wc_CamelliaCbcDecrypt
*/
WOLFSSL_API int  wc_CamelliaSetKey(Camellia* cam,
                                   const byte* key, word32 len, const byte* iv);
/*!
    \ingroup Camellia
    
    \brief This function sets the initialization vector for a camellia object.
    
    \return 0 Returned upon successfully setting the key and initialization vector
    \return BAD_FUNC_ARG returned if there is an error processing one of the input arguments
    
    \param cam pointer to the camellia structure on which to set the iv
    \param iv pointer to the buffer containing the 16 byte initialization vector for use with this camellia structure
    
    _Example_
    \code
    Camellia cam;
    byte iv[16];
    // initialize iv
    if( wc_CamelliaSetIV(&cam, iv) != 0) { 
	// error initializing camellia structure
    }
    \endcode
    
    \sa wc_CamelliaSetKey
    */
WOLFSSL_API int  wc_CamelliaSetIV(Camellia* cam, const byte* iv);
/*!
    \ingroup Camellia
    
    \brief This function does a one-block encrypt using the provided camellia object. It parses the first 16 byte block from the buffer in and stores the encrypted result in the buffer out. Before using this function, one should initialize the camellia object using wc_CamelliaSetKey. 
    
    \return none No returns.
    
    \param cam pointer to the camellia structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted block
    \param in pointer to the buffer containing the plaintext block to encrypt
    
    _Example_
    \code
    Camellia cam;
    // initialize cam structure with key and iv
    byte plain[] = { // initialize with message to encrypt };
    byte cipher[16];
    
    wc_CamelliaEncrypt(&ca, cipher, plain);
    \endcode
    
    \sa wc_CamelliaDecryptDirect
*/
WOLFSSL_API int  wc_CamelliaEncryptDirect(Camellia* cam, byte* out,
                                                                const byte* in);
/*!
    \ingroup Camellia
    
    \brief This function does a one-block decrypt using the provided camellia object. It parses the first 16 byte block from the buffer in, decrypts it, and stores the result in the buffer out. Before using this function, one should initialize the camellia object using wc_CamelliaSetKey.
    
    \return none No returns.
    
    \param cam pointer to the camellia structure to use for encryption
    \param out pointer to the buffer in which to store the decrypted plaintext block
    \param in pointer to the buffer containing the ciphertext block to decrypt
    
    _Example_
    \code
    Camellia cam;
    // initialize cam structure with key and iv
    byte cipher[] = { // initialize with encrypted message to decrypt };
    byte decrypted[16];

    wc_CamelliaDecryptDirect(&cam, decrypted, cipher);
    \endode
    
    \sa wc_CamelliaEncryptDirect
*/
WOLFSSL_API int  wc_CamelliaDecryptDirect(Camellia* cam, byte* out,
                                                                const byte* in);
/*!
    \ingroup Camellia
    
    \brief This function encrypts the plaintext from the buffer in and stores the output in the buffer out. It performs this encryption using Camellia with Cipher Block Chaining (CBC).
    
    \return none No returns.
    
    \param cam pointer to the camellia structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted ciphertext
    \param in pointer to the buffer containing the plaintext to encrypt
    \param sz the size of the message to encrypt
    
    _Example_
    \code
    Camellia cam;
    // initialize cam structure with key and iv
    byte plain[] = { // initialize with encrypted message to decrypt };
    byte cipher[sizeof(plain)];
    
    wc_CamelliaCbcEncrypt(&cam, cipher, plain, sizeof(plain));
    \endcode
    
    \sa wc_CamelliaCbcDecrypt
*/
WOLFSSL_API int wc_CamelliaCbcEncrypt(Camellia* cam,
                                          byte* out, const byte* in, word32 sz);
/*!
    \ingroup Camellia    
    
    \brief This function decrypts the ciphertext from the buffer in and stores the output in the buffer out. It performs this decryption using Camellia with Cipher Block Chaining (CBC).
    
    \return none No returns.
    
    \param cam pointer to the camellia structure to use for encryption
    \param out pointer to the buffer in which to store the decrypted message
    \param in pointer to the buffer containing the encrypted ciphertext
    \param sz the size of the message to encrypt

    _Example_
    \code
    Camellia cam;
    // initialize cam structure with key and iv
    byte cipher[] = { // initialize with encrypted message to decrypt };
    byte decrypted[sizeof(cipher)];

    wc_CamelliaCbcDecrypt(&cam, decrypted, cipher, sizeof(cipher));
    \endcode
    
    \sa wc_CamelliaCbcEncrypt
*/
WOLFSSL_API int wc_CamelliaCbcDecrypt(Camellia* cam,
                                          byte* out, const byte* in, word32 sz);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_CAMELLIA */
#endif /* WOLF_CRYPT_CAMELLIA_H */

