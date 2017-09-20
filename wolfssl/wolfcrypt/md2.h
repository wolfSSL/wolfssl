/* md2.h
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

#ifndef WOLF_CRYPT_MD2_H
#define WOLF_CRYPT_MD2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_MD2

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    MD2             =  6,    /* hash type unique */
    MD2_BLOCK_SIZE  = 16,
    MD2_DIGEST_SIZE = 16,
    MD2_PAD_SIZE    = 16,
    MD2_X_SIZE      = 48
};


/* Md2 digest */
typedef struct Md2 {
    word32  count;   /* bytes % PAD_SIZE  */
    byte    X[MD2_X_SIZE];
    byte    C[MD2_BLOCK_SIZE];
    byte    buffer[MD2_BLOCK_SIZE];
} Md2;


/*!
    \ingroup MD2
    
    \brief This function initializes md2. This is automatically called by wc_Md2Hash.
    
    \return 0 Returned upon successfully initializing
    
    \param md2 pointer to the md2 structure to use for encryption
    
    _Example_
    \code
    md2 md2[1];
    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode
    
    \sa wc_Md2Hash
    \sa wc_Md2Update
    \sa wc_Md2Final
*/
WOLFSSL_API void wc_InitMd2(Md2*);
/*!
    \ingroup MD2
    
    \brief Can be called to continually hash the provided byte array of length len.
    
    \return 0 Returned upon successfully adding the data to the digest.
    
    \param md2 pointer to the md2 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    md2 md2[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode
    
    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
WOLFSSL_API void wc_Md2Update(Md2*, const byte*, word32);
/*!
    \ingroup MD2
    
    \brief Finalizes hashing of data. Result is placed into hash.
    
    \return 0 Returned upon successfully finalizing.

    \param md2 pointer to the md2 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md2 md2[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd2(md2)) != 0) {
       WOLFSSL_MSG("wc_Initmd2 failed");
    }
    else {
       wc_Md2Update(md2, data, len);
       wc_Md2Final(md2, hash);
    }
    \endcode
    
    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
WOLFSSL_API void wc_Md2Final(Md2*, byte*);
/*!
    \ingroup MD2
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode
    
    \sa wc_Md2Hash
    \sa wc_Md2Final
    \sa wc_InitMd2
*/
WOLFSSL_API int  wc_Md2Hash(const byte*, word32, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_MD2 */
#endif /* WOLF_CRYPT_MD2_H */

