/* chacha20_poly1305.h
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


/* This implementation of the ChaCha20-Poly1305 AEAD is based on "ChaCha20
 * and Poly1305 for IETF protocols" (draft-irtf-cfrg-chacha20-poly1305-10):
 * https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-10
 */

#ifndef WOLF_CRYPT_CHACHA20_POLY1305_H
#define WOLF_CRYPT_CHACHA20_POLY1305_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#ifdef __cplusplus
    extern "C" {
#endif

#define CHACHA20_POLY1305_AEAD_KEYSIZE      32
#define CHACHA20_POLY1305_AEAD_IV_SIZE      12
#define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 16

enum {
    CHACHA20_POLY_1305_ENC_TYPE = 8    /* cipher unique type */
};

    /*
     * The IV for this implementation is 96 bits to give the most flexibility.
     *
     * Some protocols may have unique per-invocation inputs that are not
     * 96-bit in length. For example, IPsec may specify a 64-bit nonce. In
     * such a case, it is up to the protocol document to define how to
     * transform the protocol nonce into a 96-bit nonce, for example by
     * concatenating a constant value.
     */

/*!
    \ingroup ChaCha20Poly1305
    
    \brief This function encrypts an input message, inPlaintext, using the ChaCha20 stream cipher, into the output buffer, outCiphertext. It also performs Poly-1305 authentication (on the cipher text), and stores the generated authentication tag in the output buffer, outAuthTag.
    
    \return 0 Returned upon successfully encrypting the message
    \return BAD_FUNC_ARG returned if there is an error during the encryption process
    
    \param inKey pointer to a buffer containing the 32 byte key to use for encryption
    \param inIv pointer to a buffer containing the 12 byte iv to use for encryption
    \param inAAD pointer to the buffer containing arbitrary length additional authenticated data (AAD)
    \param inAADLen length of the input AAD
    \param inPlaintext pointer to the buffer containing the plaintext to encrypt
    \param inPlaintextLen the length of the plain text to  encrypt
    \param outCiphertext pointer to the buffer in which to store the ciphertext
    \param outAuthTag pointer to a 16 byte wide buffer in which to store the authentication tag
    
    _Example_
    \code
    byte key[] = { // initialize 32 byte key };
    byte iv[]  = { // initialize 12 byte key };
    byte inAAD[] = { // initialize AAD };

    byte plain[] = { // initialize message to encrypt };
    byte cipher[sizeof(plain)];
    byte authTag[16];

    int ret = wc_ChaCha20Poly1305_Encrypt(key, iv, inAAD, sizeof(inAAD),
    plain, sizeof(plain), cipher, authTag);

    if(ret != 0) {
    	// error running encrypt
    }
    \endcode
    
    \sa wc_ChaCha20Poly1305_Decrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/
WOLFSSL_API
int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inPlaintext, const word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]);

/*!
    \ingroup ChaCha20Poly1305    
    
    \brief This function decrypts input ciphertext, inCiphertext, using the ChaCha20 stream cipher, into the output buffer, outPlaintext. It also performs Poly-1305 authentication, comparing the given inAuthTag to an authentication generated with the inAAD (arbitrary length additional authentication data). Note: If the generated authentication tag does not match the supplied authentication tag, the text is not decrypted.
    
    \return 0 Returned upon successfully decrypting the message
    \return BAD_FUNC_ARG Returned if any of the function arguments do not match what is expected
    \return MAC_CMP_FAILED_E Returned if the generated authentication tag does not match the supplied inAuthTag.
    
    \param inKey pointer to a buffer containing the 32 byte key to use for decryption
    \param inIv pointer to a buffer containing the 12 byte iv to use for decryption
    \param inAAD pointer to the buffer containing arbitrary length additional authenticated data (AAD)
    \param inAADLen length of the input AAD
    \param inCiphertext pointer to the buffer containing the ciphertext to decrypt
    \param outCiphertextLen the length of the ciphertext to decrypt
    \param inAuthTag pointer to the buffer containing the 16 byte digest for authentication
    \param outPlaintext pointer to the buffer in which to store the plaintext

    _Example_
    \code
    byte key[]   = { // initialize 32 byte key };
    byte iv[]    = { // initialize 12 byte key };
    byte inAAD[] = { // initialize AAD };

    byte cipher[]    = { // initialize with received ciphertext };
    byte authTag[16] = { // initialize with received authentication tag };

    byte plain[sizeof(cipher)];

    int ret = wc_ChaCha20Poly1305_Decrypt(key, iv, inAAD, sizeof(inAAD),
    cipher, sizeof(cipher), plain, authTag);

    if(ret == MAC_CMP_FAILED_E) {
    	// error during authentication
    } else if( ret != 0) {
    	// error with function arguments
    }
    \endcode
    
    \sa wc_ChaCha20Poly1305_Encrypt
    \sa wc_ChaCha_*
    \sa wc_Poly1305*
*/
WOLFSSL_API
int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inCiphertext, const word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
#endif /* WOLF_CRYPT_CHACHA20_POLY1305_H */
