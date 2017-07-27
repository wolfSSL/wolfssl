/* ripemd.h
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

#ifndef WOLF_CRYPT_RIPEMD_H
#define WOLF_CRYPT_RIPEMD_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_RIPEMD

#ifdef __cplusplus
    extern "C" {
#endif


/* in bytes */
enum {
    RIPEMD             =  3,    /* hash type unique */
    RIPEMD_BLOCK_SIZE  = 64,
    RIPEMD_DIGEST_SIZE = 20,
    RIPEMD_PAD_SIZE    = 56
};


/* RipeMd 160 digest */
typedef struct RipeMd {
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    word32  digest[RIPEMD_DIGEST_SIZE / sizeof(word32)];
    word32  buffer[RIPEMD_BLOCK_SIZE  / sizeof(word32)];
} RipeMd;


/*!
    \ingroup RIPEMD
    
    \brief This function initializes a ripemd structure by initializing ripemd’s digest, buffer, loLen and hiLen.
    
    \return 0 returned on successful execution of the function. The RipeMd structure is initialized.
    \return BAD_FUNC_ARG returned if the RipeMd structure is NULL.
    
    \param ripemd pointer to the ripemd structure to initialize
    
    _Example_
    \code
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret != 0) {
    	// Failure case.
    }
    \endcode
    
    \sa wc_RipeMdUpdate
    \sa wc_RipeMdFinal
*/
WOLFSSL_API int wc_InitRipeMd(RipeMd*);
/*!
    \ingroup RIPEMD
    
    \brief This function generates the RipeMd digest of the data input and stores the result in the ripemd->digest buffer. After running wc_RipeMdUpdate, one should compare the generated ripemd->digest to a known authentication tag to verify the authenticity of a message.
    
    \return 0 Returned on successful execution of the function.
    \return BAD_FUNC_ARG Returned if the RipeMd structure is NULL or if data is NULL and len is not zero. This function should execute if data is NULL and len is 0.
    
    \param ripemd: pointer to the ripemd structure to be initialized with wc_InitRipeMd
    \param data data to be hashed
    \param len sizeof data in bytes

    _Example_
    \code
    const byte* data; // The data to be hashed
    ....
    RipeMd md;
    int ret;
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    if (ret != 0) {
	// Failure case …
    \endcode
    
    \sa wc_InitRipeMd
    \sa wc_RipeMdFinal
*/
WOLFSSL_API int wc_RipeMdUpdate(RipeMd*, const byte*, word32);
/*!
    \ingroup RIPEMD 
    
    \brief This function copies the computed digest into hash.  If there is a partial unhashed block, this method will pad the block with 0s, and include that block’s round in the digest before copying to hash. State of ripemd is reset.
    
    \return 0 Returned on successful execution of the function. The state of the RipeMd structure has been reset.
    \return BAD_FUNC_ARG Returned if the RipeMd structure or hash parameters are NULL.
    
    \param ripemd pointer to the ripemd structure to be initialized with wc_InitRipeMd, and containing hashes from wc_RipeMdUpdate.  State will be reset
    \param hash buffer to copy digest to.  Should be RIPEMD_DIGEST_SIZE bytes
    
    _Example_
    \code
    RipeMd md;
    int ret;
    byte   digest[RIPEMD_DIGEST_SIZE];
    const byte* data; // The data to be hashed
    ... 
    ret = wc_InitRipeMd(&md);
    if (ret == 0) {
    ret = wc_RipeMdUpdate(&md, plain, sizeof(plain));
    	if (ret != 0) {
    		// RipeMd Update Failure Case.
    }
    ret = wc_RipeMdFinal(&md, digest);
    if (ret != 0) {
    	// RipeMd Final Failure Case.
    }...
    \endcode
    
    \sa none
*/
WOLFSSL_API int wc_RipeMdFinal(RipeMd*, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_RIPEMD */
#endif /* WOLF_CRYPT_RIPEMD_H */
