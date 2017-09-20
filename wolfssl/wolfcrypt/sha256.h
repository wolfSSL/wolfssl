/* sha256.h
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


/* code submitted by raphael.huck@efixo.com */

#ifndef WOLF_CRYPT_SHA256_H
#define WOLF_CRYPT_SHA256_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_SHA256

#ifdef HAVE_FIPS
    /* for fips @wc_fips */
    #include <cyassl/ctaocrypt/sha256.h>
#endif

#ifdef FREESCALE_LTC_SHA
    #include "fsl_ltc.h"
#endif


#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* avoid redefinition of structs */

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

/* in bytes */
enum {
    SHA256              =  2,   /* hash type unique */
    SHA256_BLOCK_SIZE   = 64,
    SHA256_DIGEST_SIZE  = 32,
    SHA256_PAD_SIZE     = 56
};

#ifndef WOLFSSL_TI_HASH

/* Sha256 digest */
typedef struct Sha256 {
#ifdef FREESCALE_LTC_SHA
    ltc_hash_ctx_t ctx;
#else
    /* alignment on digest and buffer speeds up ARMv8 crypto operations */
    ALIGN16 word32  digest[SHA256_DIGEST_SIZE / sizeof(word32)];
    ALIGN16 word32  buffer[SHA256_BLOCK_SIZE  / sizeof(word32)];
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    void*   heap;
#ifdef WOLFSSL_PIC32MZ_HASH
    hashUpdCache cache; /* cache for updates */
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif /* WOLFSSL_ASYNC_CRYPT */
#endif /* FREESCALE_LTC_SHA */
} Sha256;

#else /* WOLFSSL_TI_HASH */
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#endif

#endif /* HAVE_FIPS */

/*!
    \ingroup SHA
    
    \brief This function initializes SHA256. This is automatically called by wc_Sha256Hash.
    
    \return 0 Returned upon successfully initializing
    
    \param sha256 pointer to the sha256 structure to use for encryption
    
    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha356(sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode
    
    \sa wc_Sha256Hash
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
WOLFSSL_API int wc_InitSha256(Sha256*);
WOLFSSL_API int wc_InitSha256_ex(Sha256*, void*, int);
/*!
    \ingroup SHA
    
    \brief Can be called to continually hash the provided byte array of length len.
    
    \return 0 Returned upon successfully adding the data to the digest.
    
    \param sha256 pointer to the sha256 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed
    
    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(sha256, data, len);
        wc_Sha256Final(sha256, hash);
    }
    \endcode
    
    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
WOLFSSL_API int wc_Sha256Update(Sha256*, const byte*, word32);
/*!
    \ingroup SHA
    
    \brief Finalizes hashing of data. Result is placed into hash. Resets state of sha256 struct.
    
    \return 0 Returned upon successfully finalizing.
    
    \param sha256 pointer to the sha256 structure to use for encryption
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    Sha256 sha256[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha356(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256Final(sha256, hash);
    }
    \endcode
    
    \sa wc_Sha256Hash
    \sa wc_Sha256GetHash
    \sa wc_InitSha256
*/
WOLFSSL_API int wc_Sha256Final(Sha256*, byte*);
/*!
    \ingroup SHA
    
    \brief Resets the Sha256 structure.  Note: this is only supported if you have WOLFSSL_TI_HASH defined.
    
    \return none No returns.
    
    \param sha256 Pointer to the sha256 structure to be freed.

    _Example_
    \code
    Sha256 sha256;
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha256(&sha256)) != 0) {
        WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
        wc_Sha256Update(&sha256, data, len);
        wc_Sha256Final(&sha256, hash);
        wc_Sha256Free(&sha256);
    }
    \endcode
    
    \sa wc_InitSha256
    \sa wc_Sha256Update
    \sa wc_Sha256Final
*/
WOLFSSL_API void wc_Sha256Free(Sha256*);

/*!
    \ingroup SHA
    
    \brief Gets hash data. Result is placed into hash.  Does not reset state of sha256 struct.
    
    \return 0 Returned upon successfully finalizing.
    
    \param sha256 pointer to the sha256 structure to use for encryption
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    Sha256 sha256[1];
    if ((ret = wc_InitSha356(sha256)) != 0) {
       WOLFSSL_MSG("wc_InitSha256 failed");
    }
    else {
       wc_Sha256Update(sha256, data, len);
       wc_Sha256GetHash(sha256, hash);
    }
    \endcode
    
    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
WOLFSSL_API int wc_Sha256GetHash(Sha256*, byte*);
WOLFSSL_API int wc_Sha256Copy(Sha256* src, Sha256* dst);

#ifdef WOLFSSL_PIC32MZ_HASH
WOLFSSL_API void wc_Sha256SizeSet(Sha256*, word32);
#endif

#ifdef WOLFSSL_SHA224

#ifndef HAVE_FIPS /* avoid redefinition of structs */
/* in bytes */
enum {
    SHA224              =   8,   /* hash type unique */
    SHA224_BLOCK_SIZE   =   SHA256_BLOCK_SIZE,
    SHA224_DIGEST_SIZE  =   28,
    SHA224_PAD_SIZE     =   SHA256_PAD_SIZE
};

typedef Sha256 Sha224;
#endif /* HAVE_FIPS */

WOLFSSL_API int wc_InitSha224(Sha224*);
WOLFSSL_API int wc_InitSha224_ex(Sha224*, void*, int);
WOLFSSL_API int wc_Sha224Update(Sha224*, const byte*, word32);
WOLFSSL_API int wc_Sha224Final(Sha224*, byte*);
WOLFSSL_API void wc_Sha224Free(Sha224*);

WOLFSSL_API int wc_Sha224GetHash(Sha224*, byte*);
WOLFSSL_API int wc_Sha224Copy(Sha224* src, Sha224* dst);

#endif /* WOLFSSL_SHA224 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_SHA256 */
#endif /* WOLF_CRYPT_SHA256_H */

