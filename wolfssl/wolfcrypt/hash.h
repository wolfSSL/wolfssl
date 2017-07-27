/* hash.h
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


#ifndef WOLF_CRYPT_HASH_H
#define WOLF_CRYPT_HASH_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#if defined(WOLFSSL_SHA224) || !defined(NO_SHA256)
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Hash types */
enum wc_HashType {
    WC_HASH_TYPE_NONE = 0,
    WC_HASH_TYPE_MD2 = 1,
    WC_HASH_TYPE_MD4 = 2,
    WC_HASH_TYPE_MD5 = 3,
    WC_HASH_TYPE_SHA = 4, /* SHA-1 (not old SHA-0) */
    WC_HASH_TYPE_SHA224 = 9,
    WC_HASH_TYPE_SHA256 = 5,
    WC_HASH_TYPE_SHA384 = 6,
    WC_HASH_TYPE_SHA512 = 7,
    WC_HASH_TYPE_MD5_SHA = 8,
};

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
    #ifdef WOLFSSL_SHA384
        Sha384 sha384;
    #endif
    #ifdef WOLFSSL_SHA512
        Sha512 sha512;
    #endif
} wc_HashAlg;

/* Find largest possible digest size
   Note if this gets up to the size of 80 or over check smallstack build */
#if defined(WOLFSSL_SHA512)
    #define WC_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif defined(WOLFSSL_SHA384)
    #define WC_MAX_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif !defined(NO_SHA256)
    #define WC_MAX_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif defined(WOLFSSL_SHA224)
    #define WC_MAX_DIGEST_SIZE SHA224_DIGEST_SIZE
#elif !defined(NO_SHA)
    #define WC_MAX_DIGEST_SIZE SHA_DIGEST_SIZE
#elif !defined(NO_MD5)
    #define WC_MAX_DIGEST_SIZE MD5_DIGEST_SIZE
#else
    #define WC_MAX_DIGEST_SIZE 64 /* default to max size of 64 */
#endif

#if !defined(NO_ASN) || !defined(NO_DH) || defined(HAVE_ECC)
/*!
    \ingroup wolfCrypt
    
    \brief This function will return the OID for the wc_HashType provided.
    
    \return OID returns value greater than 0
    \return HASH_TYPE_E hash type not supported.
    \return BAD_FUNC_ARG one of the provided arguments is incorrect.
    
    \param hash_type A hash type from the “enum  wc_HashType” such as “WC_HASH_TYPE_SHA256”.
    
    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int oid = wc_HashGetOID(hash_type);
    if (oid > 0) {
    	// Success
    }
    \endcode
    
    \sa wc_HashGetDigestSize
    \sa wc_Hash
*/
WOLFSSL_API int wc_HashGetOID(enum wc_HashType hash_type);
#endif

/*!
    \ingroup wolfCrypt
    
    \brief This function returns the size of the digest (output) for a hash_type. The returns size is used to make sure the output buffer provided to wc_Hash is large enough.
    
    \return Success A positive return value indicates the digest size for the hash.
    \return Error Returns HASH_TYPE_E if hash_type is not supported. 
    \return Failure Returns BAD_FUNC_ARG if an invalid hash_type was used.
    
    \param hash_type A hash type from the “enum  wc_HashType” such as “WC_HASH_TYPE_SHA256”.
    
    _Example_
    \code
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
    WOLFSSL_MSG("Invalid hash type/len");
    return BAD_FUNC_ARG;
    }
    \endcode
    
    \sa wc_Hash
*/
WOLFSSL_API int wc_HashGetDigestSize(enum wc_HashType hash_type);
/*!
    \ingroup wolfCrypt
    
    \brief This function performs a hash on the provided data buffer and returns it in the hash buffer provided.
    
    \return 0 Success, else error (such as BAD_FUNC_ARG or BUFFER_E).
    
    \param hash_type A hash type from the “enum  wc_HashType” such as “WC_HASH_TYPE_SHA256”.
    \param data Pointer to buffer containing the data to hash.
    \param data_len Length of the data buffer.
    \param hash Pointer to buffer used to output the final hash to.
    \param hash_len Length of the hash buffer.
    
    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len > 0) {
        int ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
        if(ret == 0) {
		    // Success
        }
    }
    \endcode
    
    \sa wc_HashGetDigestSize
*/
WOLFSSL_API int wc_Hash(enum wc_HashType hash_type,
    const byte* data, word32 data_len,
    byte* hash, word32 hash_len);

/* generic hash operation wrappers */
WOLFSSL_API int wc_HashInit(wc_HashAlg* hash, enum wc_HashType type);
WOLFSSL_API int wc_HashUpdate(wc_HashAlg* hash, enum wc_HashType type,
    const byte* data, word32 dataSz);
WOLFSSL_API int wc_HashFinal(wc_HashAlg* hash, enum wc_HashType type,
    byte* out);


#ifndef NO_MD5
#include <wolfssl/wolfcrypt/md5.h>
/*!
    \ingroup MD5
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte* hash;
    int ret;
    ... 
    ret = wc_Md5Hash(data, data_len, hash);
    if (ret != 0) {
         // Md5 Hash Failure Case.
    }
    \endcode
    
    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
WOLFSSL_API int wc_Md5Hash(const byte* data, word32 len, byte* hash);
#endif

#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
/*!
    \ingroup SHA
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully ….
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
WOLFSSL_API int wc_ShaHash(const byte*, word32, byte*);
#endif

#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
/*!
    \ingroup SHA
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully …
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
WOLFSSL_API int wc_Sha256Hash(const byte*, word32, byte*);

    #if defined(WOLFSSL_SHA224)
/*!
    \ingroup SHA
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Success
    \return <0 Error
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    none
    \endcode
    
    \sa wc_InitSha224
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
        WOLFSSL_API int wc_Sha224Hash(const byte*, word32, byte*);
    #endif /* defined(WOLFSSL_SHA224) */
#endif

#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
/*!
    \ingroup SHA
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.
    
    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode
    
    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
WOLFSSL_API int wc_Sha512Hash(const byte*, word32, byte*);

    #if defined(WOLFSSL_SHA384)
/*!
    \ingroup SHA
    
    \brief Convenience function, handles all the hashing and places the result into hash.
    
    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    none
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
        WOLFSSL_API int wc_Sha384Hash(const byte*, word32, byte*);
    #endif /* defined(WOLFSSL_SHA384) */
#endif /* WOLFSSL_SHA512 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_HASH_H */
