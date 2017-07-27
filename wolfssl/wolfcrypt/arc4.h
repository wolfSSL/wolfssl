/* arc4.h
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

#ifndef WOLF_CRYPT_ARC4_H
#define WOLF_CRYPT_ARC4_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

enum {
	ARC4_ENC_TYPE   = 4,    /* cipher unique type */
    ARC4_STATE_SIZE = 256
};

/* ARC4 encryption and decryption */
typedef struct Arc4 {
    byte x;
    byte y;
    byte state[ARC4_STATE_SIZE];
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif
    void* heap;
} Arc4;
/*!
    \ingroup ARC4
    \brief This function encrypts an input message from the buffer in, placing the ciphertext in the output buffer out, or decrypts a ciphertext from the buffer in, placing the plaintext in the output buffer out, using ARC4 encryption. This function is used for both encryption and decryption. Before this method may be called, one must first initialize the ARC4 structure using wc_Arc4SetKey.
    
    \return none
    
    \param arc4 pointer to the ARC4 structure used to process the message
    \param out pointer to the output buffer in which to store the processed message
    \param in pointer to the input buffer containing the message to process
    \param length length of the message to process
    
    _Example_
    \code
    Arc4 enc;
    byte key[] = { key to use for encryption };
    wc_Arc4SetKey(&enc, key, sizeof(key));

    byte plain[] = { plain text to encode };
    byte cipher[sizeof(plain)];
    byte decrypted[sizeof(plain)];

    wc_Arc4Process(&enc, cipher, plain, sizeof(plain)); // encrypt the plain into cipher
    wc_Arc4Process(&enc, decrypted, cipher, sizeof(cipher)); // decrypt the cipher
    \endcode
    
    \sa wc_Arc4SetKey
*/
WOLFSSL_API int wc_Arc4Process(Arc4*, byte*, const byte*, word32);
/*!
    \ingroup ARC4
    
    \brief This function sets the key for a ARC4 object, initializing it for use as a cipher. It should be called before using it for encryption with wc_Arc4Process.
    
    \return none
    
    \param arc4 pointer to an arc4 structure to be used for encryption
    \param key key with which to initialize the arc4 structure
    \param length length of the key used to initialize the arc4 structure
    
    _Example_
    \code
    Arc4 enc;
    byte key[] = { initialize with key to use for encryption };
    wc_Arc4SetKey(&enc, key, sizeof(key));
    \endcode
    
    \sa wc_Arc4Process
*/
WOLFSSL_API int wc_Arc4SetKey(Arc4*, const byte*, word32);

WOLFSSL_API int  wc_Arc4Init(Arc4*, void*, int);
WOLFSSL_API void wc_Arc4Free(Arc4*);

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLF_CRYPT_ARC4_H */

