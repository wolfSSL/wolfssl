/* idea.h
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

#ifndef WOLF_CRYPT_IDEA_H
#define WOLF_CRYPT_IDEA_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_IDEA

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    IDEA_MODULO     = 0x10001,             /* 2^16+1 */
    IDEA_2EXP16     = 0x10000,             /* 2^16 */
    IDEA_MASK       = 0xFFFF,              /* 16 bits set to one */
    IDEA_ROUNDS     = 8,                   /* number of rounds for IDEA */
    IDEA_SK_NUM     = (6*IDEA_ROUNDS + 4), /* number of subkeys */
    IDEA_KEY_SIZE   = 16,                  /* size of key in bytes */
    IDEA_BLOCK_SIZE = 8,                   /* size of IDEA blocks in bytes */
    IDEA_IV_SIZE    = 8,                   /* size of IDEA IV in bytes */
    IDEA_ENCRYPTION = 0,
    IDEA_DECRYPTION = 1
};

/* IDEA encryption and decryption */
typedef struct Idea {
    word32  reg[IDEA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
    word32  tmp[IDEA_BLOCK_SIZE / sizeof(word32)]; /* for CBC mode */
    word16  skey[IDEA_SK_NUM]; /* 832 bits expanded key */
} Idea;

/*!
    \ingroup IDEA
    
    \brief Generate the 52, 16-bit key sub-blocks from the 128 key.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returns if idea or key is null, keySz is not equal to IDEA_KEY_SIZE, or dir is not IDEA_ENCRYPTION or IDEA_DECRYPTION.
    
    \param idea Pointer to Idea structure.
    \param key Pointer to key in memory.
    \param keySz Size of key.
    \param iv Value for IV in Idea structure.  Can be null.
    \param dir Direction, either IDEA_ENCRYPTION or IDEA_DECRYPTION

    _Example_
    \code
    byte v_key[IDEA_KEY_SIZE] = { /* Some Key }
    Idea idea;
    int ret = wc_IdeaSetKey(&idea v_key, IDEA_KEY_SIZE, NULL, IDEA_ENCRYPTION);
    if (ret != 0)
    {
        // There was an error
    }
    \endcode
    
    \sa wc_IdeaSetIV
*/
WOLFSSL_API int wc_IdeaSetKey(Idea *idea, const byte* key, word16 keySz,
                              const byte *iv, int dir);
/*!
    \ingroup IDEA
    
    \brief Sets the IV in an Idea key structure.

    \return 0 Success
    \return BAD_FUNC_ARG Returns if idea is null.

    \param idea Pointer to idea key structure.
    \param iv The IV value to set, can be null.
    
    _Example_
    \code
    Idea idea;
    // Initialize idea

    byte iv[] = { /* Some IV }
    int ret = wc_IdeaSetIV(&idea, iv);
    if(ret != 0)
    {
        // Some error occured
    }
    \endcode
    
    \sa wc_IdeaSetKey
*/
WOLFSSL_API int wc_IdeaSetIV(Idea *idea, const byte* iv);
/*!
    \ingroup IDEA
    
    \brief Encryption or decryption for a block (64 bits).
    
    \return 0 upon success.
    \return <0 an error occured
    
    \param idea Pointer to idea key structure.
    \param out Pointer to destination.
    \param in Pointer to input data to encrypt or decrypt.

    _Example_
    \code
    byte v_key[IDEA_KEY_SIZE] = { /* Some Key }
    byte data[IDEA_BLOCK_SIZE] = { /* Some encrypted data }
    Idea idea;
    wc_IdeaSetKey(&idea, v_key, IDEA_KEY_SIZE, NULL, IDEA_DECRYPTION);
    int ret = wc_IdeaCipher(&idea, data, data);

    if (ret != 0)
    {
        // There was an error
    }
    \endcode
    
    \sa wc_IdeaSetKey
    \sa wc_IdeaSetIV
    \sa wc_IdeaCbcEncrypt
    \sa wc_IdeaCbcDecrypt
*/
WOLFSSL_API int wc_IdeaCipher(Idea *idea, byte* out, const byte* in);
/*!
    \ingroup IDEA
    
    \brief Encrypt data using IDEA CBC mode.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returns if any arguments are null.

    \param idea Pointer to Idea key structure.
    \param out Pointer to destination for encryption.
    \param in Pointer to input for encryption.
    \param len length of input.
    
    _Example_
    \code
    Idea idea;
    // Initialize idea structure for encryption
    const char *message = "International Data Encryption Algorithm";
    byte msg_enc[40], msg_dec[40];

    memset(msg_enc, 0, sizeof(msg_enc));
    ret = wc_IdeaCbcEncrypt(&idea, msg_enc, (byte *)message,
                                (word32)strlen(message)+1);
    if(ret != 0)
    {
        // Some error occured
    }
    \endcode
    
    \sa wc_IdeaCbcDecrypt
    \sa wc_IdeaCipher
    \sa wc_IdeaSetKey
*/
WOLFSSL_API int wc_IdeaCbcEncrypt(Idea *idea, byte* out,
                                  const byte* in, word32 len);
/*!
    \ingroup IDEA
    
    \brief Decrypt data using IDEA CBC mode.

    \return 0 Success
    \return BAD_FUNC_ARG Returns if any arguments are null.
    
    \param idea Pointer to Idea key structure.
    \param out Pointer to destination for encryption.
    \param in Pointer to input for encryption.
    \param len length of input.
    
    _Example_
    \code
    Idea idea;
    // Initialize idea structure for decryption
    const char *message = "International Data Encryption Algorithm";
    byte msg_enc[40], msg_dec[40];

    memset(msg_dec, 0, sizeof(msg_dec));
    ret = wc_IdeaCbcDecrypt(&idea, msg_dec, msg_enc,
                                (word32)strlen(message)+1);
    if(ret != 0)
    {
        // Some error occured
    }
    \endcode
    
    \sa wc_IdeaCbcEncrypt
    \sa wc_IdeaCipher
    \sa wc_IdeaSetKey
*/
WOLFSSL_API int wc_IdeaCbcDecrypt(Idea *idea, byte* out,
                                  const byte* in, word32 len);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_IDEA */
#endif /* WOLF_CRYPT_IDEA_H */
