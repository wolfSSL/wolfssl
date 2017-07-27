/* des3.h
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

#ifndef WOLF_CRYPT_DES3_H
#define WOLF_CRYPT_DES3_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_DES3

#ifdef HAVE_FIPS
/* included for fips @wc_fips */
#include <cyassl/ctaocrypt/des3.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* to avoid redefinition of macros */

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

enum {
    DES_ENC_TYPE    = 2,     /* cipher unique type */
    DES3_ENC_TYPE   = 3,     /* cipher unique type */
    DES_BLOCK_SIZE  = 8,
    DES_KS_SIZE     = 32,

    DES_ENCRYPTION  = 0,
    DES_DECRYPTION  = 1
};

#define DES_IVLEN 8
#define DES_KEYLEN 8
#define DES3_IVLEN 8
#define DES3_KEYLEN 24


#if defined(STM32F2_CRYPTO) || defined(STM32F4_CRYPTO)
enum {
    DES_CBC = 0,
    DES_ECB = 1
};
#endif


/* DES encryption and decryption */
typedef struct Des {
    word32 reg[DES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    word32 tmp[DES_BLOCK_SIZE / sizeof(word32)];      /* same         */
    word32 key[DES_KS_SIZE];
} Des;


/* DES3 encryption and decryption */
typedef struct Des3 {
    word32 key[3][DES_KS_SIZE];
    word32 reg[DES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    word32 tmp[DES_BLOCK_SIZE / sizeof(word32)];      /* same         */
#ifdef WOLFSSL_ASYNC_CRYPT
    const byte* key_raw;
    const byte* iv_raw;
    WC_ASYNC_DEV asyncDev;
#endif
    void* heap;
} Des3;
#endif /* HAVE_FIPS */


/*!
    \ingroup 3DES
    
    \brief This function sets the key and initialization vector (iv) for the Des structure given as argument. It also initializes and allocates space for the buffers needed for encryption and decryption, if these have not yet been initialized. Note: If no iv is provided (i.e. iv == NULL) the initialization vector defaults to an iv of 0.
    
    \return 0 On successfully setting the key and initialization vector for the Des structure
    
    \param des pointer to the Des structure to initialize
    \param key pointer to the buffer containing the 8 byte key with which to initialize the Des structure
    \param iv pointer to the buffer containing the 8 byte iv with which to initialize the Des structure. If this is not provided, the iv defaults to 0
    \param dir direction of encryption. Valid options are: DES_ENCRYPTION, and DES_DECRYPTION
    
    _Example_
    \code
    Des enc; // Des structure used for encryption
    int ret;
    byte key[] = { // initialize with 8 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    ret = wc_Des_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// error initializing des structure
    }
    \endcode
    
    \sa wc_Des_SetIV
    \sa wc_Des3_SetKey
*/
WOLFSSL_API int  wc_Des_SetKey(Des* des, const byte* key,
                               const byte* iv, int dir);
/*!
    \ingroup 3DES
    
    \brief This function sets the initialization vector (iv) for the Des structure given as argument. When passed a NULL iv, it sets the initialization vector to 0.
    
    \return none No returns.
    
    \param des pointer to the Des structure for which to set the iv
    \param iv pointer to the buffer containing the 8 byte iv with which to initialize the Des structure. If this is not provided, the iv defaults to 0

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey
    byte iv[]  = { // initialize with 8 byte iv };
    wc_Des_SetIV(&enc, iv);
    }
    \endcode
    
    \sa wc_Des_SetKey
*/
WOLFSSL_API void wc_Des_SetIV(Des* des, const byte* iv);
/*!
    \ingroup 3DES
    
    \brief This function encrypts the input message, in, and stores the result in the output buffer, out. It uses DES encryption with cipher block chaining (CBC) mode.
    
    \return 0 Returned upon successfully encrypting the given input message
    
    \param des pointer to the Des structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted ciphertext
    \param in pointer to the input buffer containing the message to encrypt
    \param sz length of the message to encrypt

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message };
    byte cipher[sizeof(plain)];

    if ( wc_Des_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) { 
	    // error encrypting message
    }
    \endcode
    
    \sa wc_Des_SetKey
    \sa wc_Des_CbcDecrypt
*/
WOLFSSL_API int  wc_Des_CbcEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);
/*!
    \ingroup 3DES
    
    \brief This function decrypts the input ciphertext, in, and stores the resulting plaintext in the output buffer, out. It uses DES encryption with cipher block chaining (CBC) mode.
    
    \return 0 Returned upon successfully decrypting the given ciphertext
    
    \param des pointer to the Des structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt
    
    _Example_
    \code
    Des dec; // Des structure used for decryption
    // initialize dec with wc_Des_SetKey, use mode DES_DECRYPTION

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) { 
    	// error decrypting message
    }
    \endcode
    
    \sa wc_Des_SetKey
    \sa wc_Des_CbcEncrypt
*/
WOLFSSL_API int  wc_Des_CbcDecrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);
/*!
    \ingroup 3DES
    
    \brief This function encrypts the input message, in, and stores the result in the output buffer, out. It uses Des encryption with Electronic Codebook (ECB) mode.
    
    \return 0: Returned upon successfully encrypting the given plaintext.
    
    \param des pointer to the Des structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted message
    \param in pointer to the input buffer containing the plaintext to encrypt
    \param sz length of the plaintext to encrypt

    _Example_
    \code
    Des enc; // Des structure used for encryption
    // initialize enc with wc_Des_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message to encrypt };
    byte cipher[sizeof(plain)];

    if ( wc_Des_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) { 
    	// error encrypting message
    }
    \endcode
    
    \sa wc_Des_SetKe
*/
WOLFSSL_API int  wc_Des_EcbEncrypt(Des* des, byte* out,
                                   const byte* in, word32 sz);
/*!
    \ingroup 3DES
    
    \brief This function encrypts the input message, in, and stores the result in the output buffer, out. It uses Des3 encryption with Electronic Codebook (ECB) mode. Warning: In nearly all use cases ECB mode is considered to be less secure. Please avoid using ECB API’s directly whenever possible.
    
    \return 0 Returned upon successfully encrypting the given plaintext
    
    \param des3 pointer to the Des3 structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted message
    \param in pointer to the input buffer containing the plaintext to encrypt
    \param sz length of the plaintext to encrypt

    _Example_
    /code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message to encrypt };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_EcbEncrypt(&enc,cipher, plain, sizeof(plain)) != 0) { 
        // error encrypting message
    }
    /endcode
    
    \sa wc_Des3_SetKey
*/
WOLFSSL_API int wc_Des3_EcbEncrypt(Des3* des, byte* out,
                                   const byte* in, word32 sz);

/* ECB decrypt same process as encrypt but with decrypt key */
#define wc_Des_EcbDecrypt  wc_Des_EcbEncrypt
#define wc_Des3_EcbDecrypt wc_Des3_EcbEncrypt

/*!
    \ingroup 3DES
    
    \brief This function sets the key and initialization vector (iv) for the Des3 structure given as argument. It also initializes and allocates space for the buffers needed for encryption and decryption, if these have not yet been initialized. Note: If no iv is provided (i.e. iv == NULL) the initialization vector defaults to an iv of 0.
    
    \return 0 On successfully setting the key and initialization vector for the Des structure
    
    \param des3 pointer to the Des3 structure to initialize
    \param key pointer to the buffer containing the 24 byte key with which to initialize the Des3 structure
    \param iv pointer to the buffer containing the 8 byte iv with which to initialize the Des3 structure. If this is not provided, the iv defaults to 0
    \param dir direction of encryption. Valid options are: DES_ENCRYPTION, and DES_DECRYPTION
    
    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    int ret;
    byte key[] = { // initialize with 24 byte key };
    byte iv[]  = { // initialize with 8 byte iv };

    ret = wc_Des3_SetKey(&des, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
    	// error initializing des structure
    }
    \endcode
    
    \sa wc_Des3_SetIV
    \sa wc_Des3_CbcEncrypt
    \sa wc_Des3_CbcDecrypt
*/
WOLFSSL_API int  wc_Des3_SetKey(Des3* des, const byte* key,
                                const byte* iv,int dir);
/*!
    \ingroup 3DES
    
    \brief This function sets the initialization vector (iv) for the Des3 structure given as argument. When passed a NULL iv, it sets the initialization vector to 0.
    
    \return none No returns.
    
    \param des pointer to the Des3 structure for which to set the iv
    \param iv pointer to the buffer containing the 8 byte iv with which to initialize the Des3 structure. If this is not provided, the iv defaults to 0

    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey

    byte iv[]  = { // initialize with 8 byte iv };

    wc_Des3_SetIV(&enc, iv);
    }
    \endcode
    
    \sa wc_Des3_SetKey
*/
WOLFSSL_API int  wc_Des3_SetIV(Des3* des, const byte* iv);
/*!
    \ingroup 3DES
    
    \brief This function encrypts the input message, in, and stores the result in the output buffer, out. It uses Triple Des (3DES) encryption with cipher block chaining (CBC) mode.
    
    \return 0 Returned upon successfully encrypting the given input message
    
    \param des pointer to the Des3 structure to use for encryption
    \param out pointer to the buffer in which to store the encrypted ciphertext
    \param in pointer to the input buffer containing the message to encrypt
    \param sz length of the message to encrypt
    
    _Example_
    \code
    Des3 enc; // Des3 structure used for encryption
    // initialize enc with wc_Des3_SetKey, use mode DES_ENCRYPTION

    byte plain[]  = { // initialize with message };
    byte cipher[sizeof(plain)];

    if ( wc_Des3_CbcEncrypt(&enc, cipher, plain, sizeof(plain)) != 0) { 
	    // error encrypting message
    }
    \endcode
    
    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcDecrypt
*/
WOLFSSL_API int  wc_Des3_CbcEncrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);
/*!
    \ingroup 3DES
    
    \brief This function decrypts the input ciphertext, in, and stores the resulting plaintext in the output buffer, out. It uses Triple Des (3DES) encryption with cipher block chaining (CBC) mode.
    
    \return 0 Returned upon successfully decrypting the given ciphertext
    
    \param des pointer to the Des3 structure to use for decryption
    \param out pointer to the buffer in which to store the decrypted plaintext
    \param in pointer to the input buffer containing the encrypted ciphertext
    \param sz length of the ciphertext to decrypt
    
    _Example_
    \code
    Des3 dec; // Des structure used for decryption
    // initialize dec with wc_Des3_SetKey, use mode DES_DECRYPTION

    byte cipher[]  = { // initialize with ciphertext };
    byte decoded[sizeof(cipher)];

    if ( wc_Des3_CbcDecrypt(&dec, decoded, cipher, sizeof(cipher)) != 0) { 
    	// error decrypting message
    }
    \endcode

    \sa wc_Des3_SetKey
    \sa wc_Des3_CbcEncrypt
*/
WOLFSSL_API int  wc_Des3_CbcDecrypt(Des3* des, byte* out,
                                    const byte* in,word32 sz);

/* These are only required when using either:
  static memory (WOLFSSL_STATIC_MEMORY) or asynchronous (WOLFSSL_ASYNC_CRYPT) */
WOLFSSL_API int  wc_Des3Init(Des3*, void*, int);
WOLFSSL_API void wc_Des3Free(Des3*);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_DES3 */
#endif /* WOLF_CRYPT_DES3_H */

