/* pwdbased.h
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

#ifndef WOLF_CRYPT_PWDBASED_H
#define WOLF_CRYPT_PWDBASED_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_PWDBASED

#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>       /* for hash type */
#endif

#include <wolfssl/wolfcrypt/sha.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * hashType renamed to typeH to avoid shadowing global declaration here:
 * wolfssl/wolfcrypt/asn.h line 173 in enum Oid_Types
 */
/*!
    \ingroup Password
    
    \brief This function implements the Password Based Key Derivation Function 1 (PBKDF1), converting an input password with a concatenated salt  into a more secure key, which it stores in output. It allows the user to select between SHA and MD5 as hash functions.
    
    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given (valid type are: MD5 and SHA), iterations is less than 1, or the key length (kLen) requested is greater than the hash length of the provided hash
    \return MEMORY_E Returned if there is an error allocating memory for a SHA or MD5 object
    
    \param output pointer to the buffer in which to store the generated key. Should be at least kLen long
    \param passwd pointer to the buffer containing the password to use for the key derivation
    \param pLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use for key derivation
    \param sLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key. Should not be longer than the digest size of the hash chosen
    \param hashType the hashing algorithm to use. Valid choices are MD5 and SHA
    
    _Example_
    \code
    int ret;
    byte key[MD5_DIGEST_SIZE];
    byte pass[] = { /* initialize with password };
    byte salt[] = { /* initialize with salt };

    ret = wc_PBKDF1(key, pass, sizeof(pass), salt, sizeof(salt), 1000, sizeof(key), MD5);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode
    
    \sa wc_PBKDF2
    \sa wc_PKCS12_PBKDF
*/
WOLFSSL_API int wc_PBKDF1(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
/*!
    \ingroup Password
    
    \brief This function implements the Password Based Key Derivation Function 2 (PBKDF2), converting an input password with a concatenated salt into a more secure key, which it stores in output. It allows the user to select any of the supported HMAC hash functions, including: MD5, SHA, SHA256, SHA384, SHA512, and BLAKE2B
    
    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given or iterations is less than 1
    \return MEMORY_E Returned if there is an allocating memory for the HMAC object

    \param output pointer to the buffer in which to store the generated key. Should be kLen long
    \param passwd pointer to the buffer containing the password to use for the key derivation
    \param pLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use for key derivation
    \param sLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key
    \param hashType the hashing algorithm to use. Valid choices are: MD5, SHA, SHA256, SHA384, SHA512, and BLAKE2B
    
    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { /* initialize with password };
    byte salt[] = { /* initialize with salt };

    ret = wc_PBKDF2(key, pass, sizeof(pass), salt, sizeof(salt), 2048, sizeof(key), 
    SHA512);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode
    
    \sa wc_PBKDF1
    \sa wc_PKCS12_PBKDF
*/
WOLFSSL_API int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
/*!
    \ingroup Password
    
    \brief This function implements the Password Based Key Derivation Function (PBKDF) described in RFC 7292 Appendix B. This function converts an input password with a concatenated salt into a more secure key, which it stores in output. It allows the user to select any of the supported HMAC hash functions, including: MD5, SHA, SHA256, SHA384, SHA512, and BLAKE2B.
    
    \return 0 Returned on successfully deriving a key from the input password
    \return BAD_FUNC_ARG Returned if there is an invalid hash type given, iterations is less than 1, or the key length (kLen) requested is greater than the hash length of the provided hash
    \return MEMORY_E Returned if there is an allocating memory
    \return MP_INIT_E may be returned if there is an error during key generation
    \return MP_READ_E may be returned if there is an error during key generation
    \return MP_CMP_E may be returned if there is an error during key generation
    \return MP_INVMOD_E may be returned if there is an error during key generation
    \return MP_EXPTMOD_E may be returned if there is an error during key generation
    \return MP_MOD_E may be returned if there is an error during key generation
    \return MP_MUL_E may be returned if there is an error during key generation
    \return MP_ADD_E may be returned if there is an error during key generation
    \return MP_MULMOD_E may be returned if there is an error during key generation
    \return MP_TO_E may be returned if there is an error during key generation
    \return MP_MEM may be returned if there is an error during key generation
    
    \param output pointer to the buffer in which to store the generated key. Should be kLen long
    \param passwd pointer to the buffer containing the password to use for the key derivation
    \param pLen length of the password to use for key derivation
    \param salt pointer to the buffer containing the salt to use for key derivation
    \param sLen length of the salt
    \param iterations number of times to process the hash
    \param kLen desired length of the derived key
    \param hashType the hashing algorithm to use. Valid choices are: MD5, SHA, SHA256, SHA384, SHA512, and BLAKE2B
    \param id this is a byte indetifier indicating the purpose of key generation. It is used to diversify the key output, and should be assigned as follows: ID=1: pseudorandom bits are to be used as key material for performing encryption or decryption. ID=2: pseudorandom bits are to be used an IV (Initial Value) for encryption or decryption. ID=3: pseudorandom bits are to be used as an integrity key for MACing.
    
    _Example_
    \code
    int ret;
    byte key[64];
    byte pass[] = { /* initialize with password };
    byte salt[] = { /* initialize with salt };

    ret = wc_PKCS512_PBKDF(key, pass, sizeof(pass), salt, sizeof(salt), 2048, 
    sizeof(key), SHA512, 1);
    if ( ret != 0 ) {
    	// error deriving key from password
    }
    \endcode
    
    \sa wc_PBKDF1
    \sa wc_PBKDF2
*/
WOLFSSL_API int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int pLen,
                            const byte* salt, int sLen, int iterations,
                            int kLen, int typeH, int purpose);
WOLFSSL_API int wc_PKCS12_PBKDF_ex(byte* output, const byte* passwd,int passLen,
                       const byte* salt, int saltLen, int iterations, int kLen,
                       int hashType, int id, void* heap);

#ifdef HAVE_SCRYPT
WOLFSSL_API int wc_scrypt(byte* output, const byte* passwd, int passLen,
                          const byte* salt, int saltLen, int cost,
                          int blockSize, int parallel, int dkLen);
#endif

/* helper functions */
WOLFSSL_LOCAL int GetDigestSize(int typeH);
WOLFSSL_LOCAL int GetPKCS12HashSizes(int typeH, word32* v, word32* u);
WOLFSSL_LOCAL int DoPKCS12Hash(int typeH, byte* buffer, word32 totalLen,
                               byte* Ai, word32 u, int iterations);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_PWDBASED */
#endif /* WOLF_CRYPT_PWDBASED_H */
