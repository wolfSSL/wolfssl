/* md4.h
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

#ifndef WOLF_CRYPT_MD4_H
#define WOLF_CRYPT_MD4_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_MD4

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    MD4_BLOCK_SIZE  = 64,
    MD4_DIGEST_SIZE = 16,
    MD4_PAD_SIZE    = 56
};


/* MD4 digest */
typedef struct Md4 {
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    word32  digest[MD4_DIGEST_SIZE / sizeof(word32)];
    word32  buffer[MD4_BLOCK_SIZE  / sizeof(word32)];
} Md4;


/*!
    \ingroup MD4
    
    \brief This function initializes md4. This is automatically called by wc_Md4Hash.
    
    \return 0 Returned upon successfully initializing
    
    \param md4 pointer to the md4 structure to use for encryption
    
    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode
    
    \sa wc_Md4Hash
    \sa wc_Md4Update
    \sa wc_Md4Final
*/
WOLFSSL_API void wc_InitMd4(Md4*);
/*!
    \ingroup MD4
    
    \brief Can be called to continually hash the provided byte array of length len.
    
    \return 0 Returned upon successfully adding the data to the digest.
    
    \param md4 pointer to the md4 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed
    
    _Example_
    \code
    md4 md4[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd4(md4)) != 0) {
       WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
       wc_Md4Update(md4, data, len);
       wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
WOLFSSL_API void wc_Md4Update(Md4*, const byte*, word32);
/*!
    \ingroup MD4
    
    \brief Finalizes hashing of data. Result is placed into hash.
    
    \return 0 Returned upon successfully finalizing.
    
    \param md4 pointer to the md4 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md4 md4[1];
    if ((ret = wc_InitMd4(md4)) != 0) {
        WOLFSSL_MSG("wc_Initmd4 failed");
    }
    else {
        wc_Md4Update(md4, data, len);
        wc_Md4Final(md4, hash);
    }
    \endcode

    \sa wc_Md4Hash
    \sa wc_Md4Final
    \sa wc_InitMd4
*/
WOLFSSL_API void wc_Md4Final(Md4*, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_MD4 */
#endif /* WOLF_CRYPT_MD4_H */

