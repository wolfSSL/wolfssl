/* hc128.h
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

#ifndef WOLF_CRYPT_HC128_H
#define WOLF_CRYPT_HC128_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_HC128

#ifdef __cplusplus
    extern "C" {
#endif

enum {
	HC128_ENC_TYPE    =  6    /* cipher unique type */
};

/* HC-128 stream cipher */
typedef struct HC128 {
    word32 T[1024];             /* P[i] = T[i];  Q[i] = T[1024 + i ]; */
    word32 X[16];
    word32 Y[16];
    word32 counter1024;         /* counter1024 = i mod 1024 at the ith step */
    word32 key[8];
    word32 iv[8];
#ifdef XSTREAM_ALIGN
    void*  heap;  /* heap hint, currently XMALLOC only used with aligning */
#endif
} HC128;


/*!
    \ingroup HC128
    
    \brief This function encrypts or decrypts a message of any size from the input buffer input, and stores the resulting plaintext/ciphertext in the output buffer output.
    
    \return 0 Returned upon successfully encrypting/decrypting the given input
    \return MEMORY_E Returned if the input and output buffers are not aligned along a 4-byte boundary, and there is an error allocating memory
    \return BAD_ALIGN_E Returned if the input or output buffers are not aligned along a 4-byte boundary, and NO_WOLFSSL_ALLOC_ALIGN is defined
    
    \param ctx pointer to a HC-128 context object with an initialized key to use for encryption or decryption
    \param output buffer in which to store the processed input
    \param input  buffer containing the plaintext to encrypt or the ciphertext to decrypt
    \param msglen length of the plaintext to encrypt or the ciphertext to decrypt
    
    _Example_
    \code
    HC128 enc;
    byte key[] = { // initialize with key };
    byte iv[]  = { // initialize with iv };
    wc_Hc128_SetKey(&enc, key, iv);

    byte msg[] = { // initialize with message };
    byte cipher[sizeof(msg)];

    if (wc_Hc128_Process(*enc, cipher, plain, sizeof(plain)) != 0) {
    	// error encrypting msg
    }
    \endcode
    
    \sa wc_Hc128_SetKey
*/
WOLFSSL_API int wc_Hc128_Process(HC128*, byte*, const byte*, word32);
/*!
    \ingroup HC128
    
    \brief This function initializes an HC128 context object by setting its key and iv.
    
    \return 0 Returned upon successfully setting the key and iv for the HC128 context object
    
    \param ctx pointer to an HC-128 context object to initialize
    \param key pointer to the buffer containing the 16 byte key to use with encryption/decryption
    \param iv pointer to the buffer containing the 16 byte iv (nonce) with which to initialize the HC128 object
    
    _Example_
    \code
    HC128 enc;
    byte key[] = { // initialize with key };
    byte iv[]  = { // initialize with iv };
    wc_Hc128_SetKey(&enc, key, iv);
    \endcode
    
    \sa wc_Hc128_Process
*/
WOLFSSL_API int wc_Hc128_SetKey(HC128*, const byte* key, const byte* iv);

WOLFSSL_LOCAL int wc_Hc128_SetHeap(HC128* ctx, void* heap);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_HC128 */
#endif /* WOLF_CRYPT_HC128_H */

