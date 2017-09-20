/* hmac.h
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

#ifndef NO_HMAC

#ifndef WOLF_CRYPT_HMAC_H
#define WOLF_CRYPT_HMAC_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif

#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif

#if !defined(NO_SHA256) || defined(WOLFSSL_SHA224)
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef WOLFSSL_SHA512
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
#endif

#ifdef HAVE_FIPS
/* for fips */
    #include <cyassl/ctaocrypt/hmac.h>
#endif


#ifdef __cplusplus
    extern "C" {
#endif
#ifndef HAVE_FIPS

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

enum {
    HMAC_FIPS_MIN_KEY = 14,   /* 112 bit key length minimum */

    IPAD    = 0x36,
    OPAD    = 0x5C,

/* If any hash is not enabled, add the ID here. */
#ifdef NO_MD5
    MD5     = 0,
#endif
#ifdef NO_SHA
    SHA     = 1,
#endif
#ifdef NO_SHA256
    SHA256  = 2,
#endif
#ifndef WOLFSSL_SHA512
    SHA512  = 4,
#endif
#ifndef WOLFSSL_SHA384
    SHA384  = 5,
#endif
#ifndef HAVE_BLAKE2
    BLAKE2B_ID = 7,
#endif
#ifndef WOLFSSL_SHA224
    SHA224  = 8,
#endif

/* Select the largest available hash for the buffer size. */
#if defined(WOLFSSL_SHA512)
    MAX_DIGEST_SIZE = SHA512_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = SHA512_BLOCK_SIZE,
#elif defined(HAVE_BLAKE2)
    MAX_DIGEST_SIZE = BLAKE2B_OUTBYTES,
    HMAC_BLOCK_SIZE = BLAKE2B_BLOCKBYTES,
#elif defined(WOLFSSL_SHA384)
    MAX_DIGEST_SIZE = SHA384_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = SHA384_BLOCK_SIZE
#elif !defined(NO_SHA256)
    MAX_DIGEST_SIZE = SHA256_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = SHA256_BLOCK_SIZE
#elif defined(WOLFSSL_SHA224)
    MAX_DIGEST_SIZE = SHA224_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = SHA224_BLOCK_SIZE
#elif !defined(NO_SHA)
    MAX_DIGEST_SIZE = SHA_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = SHA_BLOCK_SIZE,
#elif !defined(NO_MD5)
    MAX_DIGEST_SIZE = MD5_DIGEST_SIZE,
    HMAC_BLOCK_SIZE = MD5_BLOCK_SIZE,
#else
    #error "You have to have some kind of hash if you want to use HMAC."
#endif
};


/* hash union */
typedef union {
#ifndef NO_MD5
    Md5 md5;
#endif
#ifndef NO_SHA
    Sha sha;
#endif
#ifdef WOLFSSL_SHA224
    Sha224 sha224;
#endif
#ifndef NO_SHA256
    Sha256 sha256;
#endif
#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_SHA384
    Sha384 sha384;
#endif
    Sha512 sha512;
#endif
#ifdef HAVE_BLAKE2
    Blake2b blake2b;
#endif
} Hash;

/* Hmac digest */
typedef struct Hmac {
    Hash    hash;
    word32  ipad[HMAC_BLOCK_SIZE  / sizeof(word32)];  /* same block size all*/
    word32  opad[HMAC_BLOCK_SIZE  / sizeof(word32)];
    word32  innerHash[MAX_DIGEST_SIZE / sizeof(word32)];
    void*   heap;                 /* heap hint */
    byte    macType;              /* md5 sha or sha256 */
    byte    innerHashKeyed;       /* keyed flag */

#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
    word16       keyLen;          /* hmac key length (key in ipad) */
    #ifdef HAVE_CAVIUM
        byte*    data;            /* buffered input data for one call */
        word16   dataLen;
    #endif /* HAVE_CAVIUM */
#endif /* WOLFSSL_ASYNC_CRYPT */
} Hmac;

#endif /* HAVE_FIPS */

/* does init */
/*!
    \ingroup HMAC
    
    \brief This function initializes an Hmac object, setting its encryption type, key and HMAC length.
    
    \return 0 Returned on successfully initializing the Hmac object
    \return BAD_FUNC_ARG Returned if the input type is invalid. Valid options are: MD5, SHA, SHA256, SHA384, SHA512, BLAKE2B_ID
    \return MEMORY_E Returned if there is an error allocating memory for the structure to use for hashing
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation and the key length specified is shorter than the minimum acceptable FIPS standard
    
    \param hmac pointer to the Hmac object to initialize
    \param type type specifying which encryption method the Hmac object should use. Valid options are: MD5, SHA, SHA256, SHA384, SHA512, BLAKE2B_ID
    \param key pointer to a buffer containing the key with which to initialize the Hmac object
    \param length length of the key
    
    _Example_
    \code
    Hmac hmac;
    byte key[] = { // initialize with key to use for encryption };
    if (wc_HmacSetKey(&hmac, MD5, key, sizeof(key)) != 0) {
    	// error initializing Hmac object
    }
    \endcode
    
    \sa wc_HmacUpdate
    \sa wc_HmacFinal
*/
WOLFSSL_API int wc_HmacSetKey(Hmac*, int type, const byte* key, word32 keySz);
/*!
    \ingroup HMAC
    
    \brief This function updates the message to authenticate using HMAC. It should be called after the Hmac object has been initialized with wc_HmacSetKey. This function may be called multiple times to update the message to hash. After calling wc_HmacUpdate as desired, one should call wc_HmacFinal to obtain the final authenticated message tag. 
    
    \return 0 Returned on successfully updating the message to authenticate
    \return MEMORY_E Returned if there is an error allocating memory for use with a hashing algorithm
    
    \param hmac pointer to the Hmac object for which to update the message
    \param msg pointer to the buffer containing the message to append
    \param length length of the message to append
    
    _Example_
    \code
    Hmac hmac;
    byte msg[] = { // initialize with message to authenticate };
    byte msg2[] = { // initialize with second half of message };
    // initialize hmac
    if( wc_HmacUpdate(&hmac, msg, sizeof(msg)) != 0) {
    	// error updating message
    }
    if( wc_HmacUpdate(&hmac, msg2, sizeof(msg)) != 0) {
    	// error updating with second message
    }
    \endcode
    
    \sa wc_HmacSetKey
    \sa wc_HmacFinal
*/
WOLFSSL_API int wc_HmacUpdate(Hmac*, const byte*, word32);
/*!
    \ingroup HMAC
    
    \brief This function computes the final hash of an Hmac object's message.
    
    \return 0 Returned on successfully computing the final hash
    \return MEMORY_E Returned if there is an error allocating memory for use with a hashing algorithm
    
    \param hmac pointer to the Hmac object for which to calculate the final hash
    \param hash pointer to the buffer in which to store the final hash. Should have room available as required by the hashing algorithm chosen
    
    _Example_
    \code
    Hmac hmac;
    byte hash[MD5_DIGEST_SIZE];
    // initialize hmac with MD5 as type
    // wc_HmacUpdate() with messages

    if (wc_HmacFinal(&hmac, hash) != 0) {
    	// error computing hash
    }
    \endcode
    
    \sa wc_HmacSetKey
    \sa wc_HmacUpdate
*/
WOLFSSL_API int wc_HmacFinal(Hmac*, byte*);
WOLFSSL_API int wc_HmacSizeByType(int type);

WOLFSSL_API int wc_HmacInit(Hmac* hmac, void* heap, int devId);
WOLFSSL_API void wc_HmacFree(Hmac*);

/*!
    \ingroup HMAC
    
    \brief This function returns the largest HMAC digest size available based on the configured cipher suites.
    
    \return Success Returns the largest HMAC digest size available based on the configured cipher suites
    
    \param none No parameters.
    
    _Example_
    \code
    int maxDigestSz = wolfSSL_GetHmacMaxSize();
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_GetHmacMaxSize(void);

#ifdef HAVE_HKDF

WOLFSSL_API int wc_HKDF_Extract(int type, const byte* salt, word32 saltSz,
                                const byte* inKey, word32 inKeySz, byte* out);
WOLFSSL_API int wc_HKDF_Expand(int type, const byte* inKey, word32 inKeySz,
                               const byte* info, word32 infoSz,
                               byte* out,        word32 outSz);

/*!
    \ingroup HMAC
    
    \brief This function provides access to a HMAC Key Derivation Function (HKDF). It utilizes HMAC to convert inKey, with an optional salt and optional info into a derived key, which it stores in out. The hash type defaults to MD5 if 0 or NULL is given.
    
    \return 0 Returned upon successfully generating a key with the given inputs
    \return BAD_FUNC_ARG Returned if an invalid hash type is given as argument. Valid types are: MD5, SHA, SHA256, SHA384, SHA512, BLAKE2B_ID
    \return MEMORY_E Returned if there is an error allocating memory
    \return HMAC_MIN_KEYLEN_E May be returned when using a FIPS implementation and the key length specified is shorter than the minimum acceptable FIPS standard
    
    \param type hash type to use for the HKDF.  Valid types are: MD5, SHA, SHA256, SHA384, SHA512, BLAKE2B_ID
    \param inKey pointer to the buffer containing the key to use for KDF
    \param inKeySz length of the input key
    \param salt pointer to a buffer containing an optional salt. Use NULL instead if not using a salt
    \param saltSz length of the salt. Use 0 if not using a salt
    \param info pointer to a buffer containing optional additional info. Use NULL if not appending extra info
    \param infoSz length of additional info. Use 0 if not using additional info
    \param out pointer to the buffer in which to store the derived key
    \param outSz space available in the output buffer to store the generated key
    
    _Example_
    \code
    byte key[] = { // initialize with key };
    byte salt[] = { // initialize with salt };
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF(SHA512, key, sizeof(key), salt, sizeof(salt),
    NULL, 0, derivedKey, sizeof(derivedKey));
    if ( ret != 0 ) {
	    // error generating derived key
    }
    \endcode
    
    \sa wc_HmacSetKey
*/
WOLFSSL_API int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);

#endif /* HAVE_HKDF */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_HMAC_H */

#endif /* NO_HMAC */

