/* ssl_crypto.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_SSL_CRYPTO_INCLUDED
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_crypto.c does not need to be compiled separately from ssl.c
    #endif
#else

/*******************************************************************************
 * START OF Digest APIs
 ******************************************************************************/

#ifdef OPENSSL_EXTRA
#ifndef NO_MD4
/* Initialize MD4 hash operation.
 *
 * @param [in, out] md4  MD4 context object.
 */
void wolfSSL_MD4_Init(WOLFSSL_MD4_CTX* md4)
{
    /* Ensure WOLFSSL_MD4_CTX is big enough for wolfCrypt Md4. */
    WOLFSSL_ASSERT_SIZEOF_GE(md4->buffer, wc_Md4);

    WOLFSSL_ENTER("MD4_Init");

    /* Initialize wolfCrypt MD4 object. */
    wc_InitMd4((wc_Md4*)md4);
}

/* Update MD4 hash with data.
 *
 * @param [in, out] md4   MD4 context object.
 * @param [in]      data  Data to be hashed.
 * @param [in]      len   Length of data in bytes.
 */
void wolfSSL_MD4_Update(WOLFSSL_MD4_CTX* md4, const void* data,
    unsigned long len)
{
    WOLFSSL_ENTER("MD4_Update");

    /* Update wolfCrypt MD4 object with data. */
    wc_Md4Update((wc_Md4*)md4, (const byte*)data, (word32)len);
}

/* Finalize MD4 hash and return output.
 *
 * @param [out]     digest  Hash output.
 *                          Must be able to hold MD4_DIGEST_SIZE bytes.
 * @param [in, out] md4     MD4 context object.
 */
void wolfSSL_MD4_Final(unsigned char* digest, WOLFSSL_MD4_CTX* md4)
{
    WOLFSSL_ENTER("MD4_Final");

    /* Finalize wolfCrypt MD4 hash into digest. */
    wc_Md4Final((wc_Md4*)md4, digest);
}

#endif /* NO_MD4 */
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)
#ifndef NO_MD5
/* Initialize MD5 hash operation.
 *
 * @param [in, out] md5  MD5 context object.
 * @return  1 on success.
 * @return  0 when md5 is NULL.
 */
int wolfSSL_MD5_Init(WOLFSSL_MD5_CTX* md5)
{
    /* Ensure WOLFSSL_MD5_CTX is big enough for wolfCrypt wc_Md5. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_MD5_CTX, wc_Md5);

    WOLFSSL_ENTER("MD5_Init");

    /* Initialize wolfCrypt MD5 object. */
    return wc_InitMd5((wc_Md5*)md5) == 0;
}

/* Update MD5 hash with data.
 *
 * @param [in, out] md5    MD5 context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when md5 is NULL.
 */
int wolfSSL_MD5_Update(WOLFSSL_MD5_CTX* md5, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("MD5_Update");

    /* Update wolfCrypt MD5 object with data. */
    return wc_Md5Update((wc_Md5*)md5, (const byte*)input, (word32)sz) == 0;
}

/* Finalize MD5 hash and return output.
 *
 * @param [out]     digest  Hash output.
 *                          Must be able to hold MD5_DIGEST_SIZE bytes.
 * @param [in, out] md5     MD5 context object.
 * @return  1 on success.
 * @return  0 when md5 or output is NULL.
 */
int wolfSSL_MD5_Final(byte* output, WOLFSSL_MD5_CTX* md5)
{
    int ret;

    WOLFSSL_ENTER("MD5_Final");

    /* Finalize wolfCrypt MD5 hash into output. */
    ret = (wc_Md5Final((wc_Md5*)md5, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include MD5_Free(). */
    wc_Md5Free((wc_Md5*)md5);

    return ret;
}

/* Apply MD5 transformation to the data.
 *
 * 'data' has words reversed in this function when big endian.
 *
 * @param [in, out] md5   MD5 context object.
 * @param [in, out] data  One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when md5 or data is NULL.
 */
int wolfSSL_MD5_Transform(WOLFSSL_MD5_CTX* md5, const unsigned char* data)
{
    WOLFSSL_ENTER("MD5_Transform");

#if defined(BIG_ENDIAN_ORDER)
    /* Byte reversal done outside transform. */
    if ((md5 != NULL) && (data != NULL)) {
        ByteReverseWords((word32*)data, (word32*)data, WC_MD5_BLOCK_SIZE);
    }
#endif
    /* Transform block of data with wolfCrypt MD5 object. */
    return wc_Md5Transform((wc_Md5*)md5, data) == 0;
}

/* One shot MD5 hash of data.
 *
 * When hash is null, a static buffer of MD5_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to be hashed.
 * @param [in]  len   Length of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold MD5_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_MD5(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static unsigned char dgst[WC_MD5_DIGEST_SIZE];

    WOLFSSL_ENTER("wolfSSL_MD5");

    /* Ensure buffer available for digest result. */
    if (hash == NULL) {
        hash = dgst;
    }
    /* One shot MD5 hash with wolfCrypt. */
    if (wc_Md5Hash(data, (word32)len, hash) != 0) {
        WOLFSSL_MSG("wc_Md5Hash error");
        hash = NULL;
    }

    return hash;
}
#endif /* !NO_MD5 */

#ifndef NO_SHA
/* Initialize SHA hash operation.
 *
 * @param [in, out] sha  SHA context object.
 * @return  1 on success.
 * @return  0 when sha is NULL.
 */
int wolfSSL_SHA_Init(WOLFSSL_SHA_CTX* sha)
{
    /* Ensure WOLFSSL_SHA_CTX is big enough for wolfCrypt wc_Sha. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA_CTX, wc_Sha);

    WOLFSSL_ENTER("SHA_Init");

    /* Initialize wolfCrypt SHA object. */
    return wc_InitSha((wc_Sha*)sha) == 0;
}

/* Update SHA hash with data.
 *
 * @param [in, out] sha    SHA context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when md5 is NULL.
 */
int wolfSSL_SHA_Update(WOLFSSL_SHA_CTX* sha, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA_Update");

    /* Update wolfCrypt SHA object with data. */
    return wc_ShaUpdate((wc_Sha*)sha, (const byte*)input, (word32)sz) == 0;
}

/* Finalize SHA hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA_DIGEST_SIZE bytes.
 * @param [in, out] sha     SHA context object.
 * @return  1 on success.
 * @return  0 when sha or output is NULL.
 */
int wolfSSL_SHA_Final(byte* output, WOLFSSL_SHA_CTX* sha)
{
    int ret;

    WOLFSSL_ENTER("SHA_Final");

    /* Finalize wolfCrypt SHA hash into output. */
    ret = (wc_ShaFinal((wc_Sha*)sha, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA_Free(). */
    wc_ShaFree((wc_Sha*)sha);

    return ret;
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
/* Apply SHA transformation to the data.
 *
 * 'data' has words reversed in this function when little endian.
 *
 * @param [in, out] sha   SHA context object.
 * @param [in, out] data  One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha or data is NULL.
 */
int wolfSSL_SHA_Transform(WOLFSSL_SHA_CTX* sha, const unsigned char* data)
{
    WOLFSSL_ENTER("SHA_Transform");

#if defined(LITTLE_ENDIAN_ORDER)
    /* Byte reversal done outside transform. */
    if ((sha != NULL) && (data != NULL)) {
        ByteReverseWords((word32*)data, (word32*)data, WC_SHA_BLOCK_SIZE);
    }
#endif
    /* Transform block of data with wolfCrypt SHA object. */
    return wc_ShaTransform((wc_Sha*)sha, data) == 0;
}
#endif

/* Initialize SHA-1 hash operation.
 *
 * @param [in, out] sha  SHA context object.
 * @return  1 on success.
 * @return  0 when sha is NULL.
 */
int wolfSSL_SHA1_Init(WOLFSSL_SHA_CTX* sha)
{
    WOLFSSL_ENTER("SHA1_Init");

    return wolfSSL_SHA_Init(sha);
}


/* Update SHA-1 hash with data.
 *
 * @param [in, out] sha    SHA context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha is NULL.
 */
int wolfSSL_SHA1_Update(WOLFSSL_SHA_CTX* sha, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA1_Update");

    return wolfSSL_SHA_Update(sha, input, sz);
}

/* Finalize SHA-1 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA_DIGEST_SIZE bytes.
 * @param [in, out] sha     SHA context object.
 * @return  1 on success.
 * @return  0 when sha or output is NULL.
 */
int wolfSSL_SHA1_Final(byte* output, WOLFSSL_SHA_CTX* sha)
{
    WOLFSSL_ENTER("SHA1_Final");

    return wolfSSL_SHA_Final(output, sha);
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
/* Apply SHA-1 transformation to the data.
 *
 * 'data' has words reversed in this function when little endian.
 *
 * @param [in, out] sha   SHA context object.
 * @param [in, out] data  One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha or data is NULL.
 */
int wolfSSL_SHA1_Transform(WOLFSSL_SHA_CTX* sha, const unsigned char* data)
{
   WOLFSSL_ENTER("SHA1_Transform");

   return wolfSSL_SHA_Transform(sha, data);
}
#endif
#endif /* !NO_SHA */

#ifndef NO_SHA256
#ifdef WOLFSSL_SHA224
/* Initialize SHA-224 hash operation.
 *
 * @param [in, out] sha224  SHA-224 context object.
 * @return  1 on success.
 * @return  0 when sha224 is NULL.
 */
int wolfSSL_SHA224_Init(WOLFSSL_SHA224_CTX* sha224)
{
    /* Ensure WOLFSSL_SHA224_CTX is big enough for wolfCrypt wc_Sha224. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA224_CTX, wc_Sha224);

    WOLFSSL_ENTER("SHA224_Init");

    /* Initialize wolfCrypt SHA-224 object. */
    return wc_InitSha224((wc_Sha224*)sha224) == 0;
}

/* Update SHA-224 hash with data.
 *
 * @param [in, out] sha224  SHA-224 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha224 is NULL.
 */
int wolfSSL_SHA224_Update(WOLFSSL_SHA224_CTX* sha224, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA224_Update");

    /* Update wolfCrypt SHA-224 object with data. */
    return wc_Sha224Update((wc_Sha224*)sha224, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA-224 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA224_DIGEST_SIZE bytes.
 * @param [in, out] sha224  SHA-224 context object.
 * @return  1 on success.
 * @return  0 when sha224 or output is NULL.
 */
int wolfSSL_SHA224_Final(byte* output, WOLFSSL_SHA224_CTX* sha224)
{
    int ret;

    WOLFSSL_ENTER("SHA224_Final");

    /* Finalize wolfCrypt SHA-224 hash into output. */
    ret = (wc_Sha224Final((wc_Sha224*)sha224, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA224_Free(). */
    wc_Sha224Free((wc_Sha224*)sha224);

    return ret;
}

#endif /* WOLFSSL_SHA224 */

/* Initialize SHA-256 hash operation.
 *
 * @param [in, out] sha256  SHA-256 context object.
 * @return  1 on success.
 * @return  0 when sha256 is NULL.
 */
int wolfSSL_SHA256_Init(WOLFSSL_SHA256_CTX* sha256)
{
    /* Ensure WOLFSSL_SHA256_CTX is big enough for wolfCrypt wc_Sha256. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA256_CTX, wc_Sha256);

    WOLFSSL_ENTER("SHA256_Init");

    /* Initialize wolfCrypt SHA-256 object. */
    return wc_InitSha256((wc_Sha256*)sha256) == 0;
}

/* Update SHA-256 hash with data.
 *
 * @param [in, out] sha256  SHA-256 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha256 is NULL.
 */
int wolfSSL_SHA256_Update(WOLFSSL_SHA256_CTX* sha256, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA256_Update");

    /* Update wolfCrypt SHA-256 object with data. */
    return wc_Sha256Update((wc_Sha256*)sha256, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA-256 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA256_DIGEST_SIZE bytes.
 * @param [in, out] sha256  SHA-256 context object.
 * @return  1 on success.
 * @return  0 when sha256 or output is NULL.
 */
int wolfSSL_SHA256_Final(byte* output, WOLFSSL_SHA256_CTX* sha256)
{
    int ret;

    WOLFSSL_ENTER("SHA256_Final");

    /* Finalize wolfCrypt SHA-256 hash into output. */
    ret = (wc_Sha256Final((wc_Sha256*)sha256, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA256_Free(). */
    wc_Sha256Free((wc_Sha256*)sha256);

    return ret;
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
    !defined(WOLFSSL_DEVCRYPTO_HASH) && !defined(WOLFSSL_AFALG_HASH) && \
    !defined(WOLFSSL_KCAPI_HASH) /* doesn't support direct transform */
/* Apply SHA-256 transformation to the data.
 *
 * 'data' has words reversed in this function when little endian.
 *
 * @param [in, out] sha256  SHA256 context object.
 * @param [in, out] data    One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha256 or data is NULL.
 */
int wolfSSL_SHA256_Transform(WOLFSSL_SHA256_CTX* sha256,
    const unsigned char* data)
{
    WOLFSSL_ENTER("SHA256_Transform");

#if defined(LITTLE_ENDIAN_ORDER)
    /* Byte reversal done outside transform. */
    if ((sha256 != NULL) && (data != NULL)) {
        ByteReverseWords((word32*)data, (word32*)data, WC_SHA256_BLOCK_SIZE);
    }
#endif
    /* Transform block of data with wolfCrypt SHA-256 object. */
    return wc_Sha256Transform((wc_Sha256*)sha256, data) == 0;
}
#endif
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA384

/* Initialize SHA-384 hash operation.
 *
 * @param [in, out] sha384  SHA-384 context object.
 * @return  1 on success.
 * @return  0 when sha384 is NULL.
 */
int wolfSSL_SHA384_Init(WOLFSSL_SHA384_CTX* sha384)
{
    /* Ensure WOLFSSL_SHA384_CTX is big enough for wolfCrypt wc_Sha384. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA384_CTX, wc_Sha384);

    WOLFSSL_ENTER("SHA384_Init");

    /* Initialize wolfCrypt SHA-384 object. */
    return wc_InitSha384((wc_Sha384*)sha384) == 0;
}

/* Update SHA-384 hash with data.
 *
 * @param [in, out] sha384  SHA-384 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha384 is NULL.
 */
int wolfSSL_SHA384_Update(WOLFSSL_SHA384_CTX* sha384, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA384_Update");

    /* Update wolfCrypt SHA-384 object with data. */
    return wc_Sha384Update((wc_Sha384*)sha384, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA-384 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA384_DIGEST_SIZE bytes.
 * @param [in, out] sha384  SHA-384 context object.
 * @return  1 on success.
 * @return  0 when sha384 or output is NULL.
 */
int wolfSSL_SHA384_Final(byte* output, WOLFSSL_SHA384_CTX* sha384)
{
    int ret;

    WOLFSSL_ENTER("SHA384_Final");

    /* Finalize wolfCrypt SHA-384 hash into output. */
    ret = (wc_Sha384Final((wc_Sha384*)sha384, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA384_Free(). */
    wc_Sha384Free((wc_Sha384*)sha384);

    return ret;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
/* Initialize SHA-512 hash operation.
 *
 * @param [in, out] sha512  SHA-512 context object.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_Init(WOLFSSL_SHA512_CTX* sha512)
{
    /* Ensure WOLFSSL_SHA512_CTX is big enough for wolfCrypt wc_Sha512. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA512_CTX, wc_Sha512);

    WOLFSSL_ENTER("SHA512_Init");

    /* Initialize wolfCrypt SHA-512 object. */
    return wc_InitSha512((wc_Sha512*)sha512) == 0;
}

/* Update SHA-512 hash with data.
 *
 * @param [in, out] sha512  SHA-512 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_Update(WOLFSSL_SHA512_CTX* sha512, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA512_Update");

    /* Update wolfCrypt SHA-512 object with data. */
    return wc_Sha512Update((wc_Sha512*)sha512, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA-512 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA512_DIGEST_SIZE bytes.
 * @param [in, out] sha512  SHA-512 context object.
 * @return  1 on success.
 * @return  0 when sha512 or output is NULL.
 */
int wolfSSL_SHA512_Final(byte* output, WOLFSSL_SHA512_CTX* sha512)
{
    int ret;

    WOLFSSL_ENTER("SHA512_Final");

    /* Finalize wolfCrypt SHA-512 hash into output. */
    ret = (wc_Sha512Final((wc_Sha512*)sha512, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA512_Free(). */
    wc_Sha512Free((wc_Sha512*)sha512);

    return ret;
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
    !defined(WOLFSSL_KCAPI_HASH) /* doesn't support direct transform */
/* Apply SHA-512 transformation to the data.
 *
 * @param [in, out] sha512  SHA512 context object.
 * @param [in]      data    One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha512 or data is NULL.
 */
int wolfSSL_SHA512_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data)
{
    WOLFSSL_ENTER("SHA512_Transform");

    /* Transform block of data with wolfCrypt SHA-512 object. */
    return wc_Sha512Transform((wc_Sha512*)sha512, data) == 0;
}
#endif /* !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
          (HAVE_FIPS_VERSION > 2)) && !WOLFSSL_KCAPI_HASH */

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
/* Initialize SHA-512-224 hash operation.
 *
 * @param [in, out] sha512  SHA-512-224 context object.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_224_Init(WOLFSSL_SHA512_224_CTX* sha512)
{
    WOLFSSL_ENTER("SHA512_224_Init");

    /* Initialize wolfCrypt SHA-512-224 object. */
    return wc_InitSha512_224((wc_Sha512*)sha512) == 0;
}

/* Update SHA-512-224 hash with data.
 *
 * @param [in, out] sha512  SHA-512-224 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_224_Update(WOLFSSL_SHA512_224_CTX* sha512, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA512_224_Update");

    /* Update wolfCrypt SHA-512-224 object with data. */
    return wc_Sha512_224Update((wc_Sha512*)sha512, (const byte*)input,
        (word32)sz) == 0;
}

/* Finalize SHA-512-224 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA224_DIGEST_SIZE bytes.
 * @param [in, out] sha512  SHA-512-224 context object.
 * @return  1 on success.
 * @return  0 when sha512 or output is NULL.
 */
int wolfSSL_SHA512_224_Final(byte* output, WOLFSSL_SHA512_224_CTX* sha512)
{
    int ret;

    WOLFSSL_ENTER("SHA512_224_Final");

    /* Finalize wolfCrypt SHA-512-224 hash into output. */
    ret = (wc_Sha512_224Final((wc_Sha512*)sha512, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA512_224_Free(). */
    wc_Sha512_224Free((wc_Sha512*)sha512);

    return ret;
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
/* Apply SHA-512-224 transformation to the data.
 *
 * @param [in, out] sha512  SHA512 context object.
 * @param [in]      data    One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha512 or data is NULL.
 */
int wolfSSL_SHA512_224_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data)
{
    WOLFSSL_ENTER("SHA512_224_Transform");

    /* Transform block of data with wolfCrypt SHA-512-224 object. */
    return wc_Sha512_224Transform((wc_Sha512*)sha512, data) == 0;
}
#endif /* !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
          (HAVE_FIPS_VERSION > 2)) */

#endif /* !WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
/* Initialize SHA-512-256 hash operation.
 *
 * @param [in, out] sha512  SHA-512-256 context object.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_256_Init(WOLFSSL_SHA512_256_CTX* sha)
{
    WOLFSSL_ENTER("SHA512_256_Init");

    /* Initialize wolfCrypt SHA-512-256 object. */
    return wc_InitSha512_256((wc_Sha512*)sha) == 0;
}

/* Update SHA-512-256 hash with data.
 *
 * @param [in, out] sha512  SHA-512-256 context object.
 * @param [in]      input   Data to be hashed.
 * @param [in]      sz      Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha512 is NULL.
 */
int wolfSSL_SHA512_256_Update(WOLFSSL_SHA512_256_CTX* sha512, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA512_256_Update");

    /* Update wolfCrypt SHA-512-256 object with data. */
    return wc_Sha512_256Update((wc_Sha512*)sha512, (const byte*)input,
        (word32)sz) == 0;
}

/* Finalize SHA-512-256 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA256_DIGEST_SIZE bytes.
 * @param [in, out] sha512  SHA-512-256 context object.
 * @return  1 on success.
 * @return  0 when sha512 or output is NULL.
 */
int wolfSSL_SHA512_256_Final(byte* output, WOLFSSL_SHA512_256_CTX* sha512)
{
    int ret;

    WOLFSSL_ENTER("SHA512_256_Final");

    /* Finalize wolfCrypt SHA-512-256 hash into output. */
    ret = (wc_Sha512_256Final((wc_Sha512*)sha512, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA512_256_Free(). */
    wc_Sha512_224Free((wc_Sha512*)sha512);

    return ret;
}

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
/* Apply SHA-512-256 transformation to the data.
 *
 * @param [in, out] sha512  SHA512 context object.
 * @param [in]      data    One block of data to be hashed.
 * @return  1 on success.
 * @return  0 when sha512 or data is NULL.
 */
int wolfSSL_SHA512_256_Transform(WOLFSSL_SHA512_CTX* sha512,
    const unsigned char* data)
{
    WOLFSSL_ENTER("SHA512_256_Transform");

    /* Transform block of data with wolfCrypt SHA-512-256 object. */
    return wc_Sha512_256Transform((wc_Sha512*)sha512, data) == 0;
}
#endif /* !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
          (HAVE_FIPS_VERSION > 2)) */
#endif /* !WOLFSSL_NOSHA512_256 && !FIPS ... */
#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
/* Initialize SHA3-224 hash operation.
 *
 * @param [in, out] sha3_224  SHA3-224 context object.
 * @return  1 on success.
 * @return  0 when sha3_224 is NULL.
 */
int wolfSSL_SHA3_224_Init(WOLFSSL_SHA3_224_CTX* sha3_224)
{
    /* Ensure WOLFSSL_SHA3_224_CTX is big enough for wolfCrypt wc_Sha3. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA3_224_CTX, wc_Sha3);

    WOLFSSL_ENTER("SHA3_224_Init");

    /* Initialize wolfCrypt SHA3-224 object. */
    return wc_InitSha3_224((wc_Sha3*)sha3_224, NULL, INVALID_DEVID) == 0;
}

/* Update SHA3-224 hash with data.
 *
 * @param [in, out] sha3   SHA3-224 context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha3 is NULL.
 */
int wolfSSL_SHA3_224_Update(WOLFSSL_SHA3_224_CTX* sha3, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA3_224_Update");

    /* Update wolfCrypt SHA3-224 object with data. */
    return wc_Sha3_224_Update((wc_Sha3*)sha3, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA3-224 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA3_224_DIGEST_SIZE bytes.
 * @param [in, out] sha3    SHA3-224 context object.
 * @return  1 on success.
 * @return  0 when sha3 or output is NULL.
 */
int wolfSSL_SHA3_224_Final(byte* output, WOLFSSL_SHA3_224_CTX* sha3)
{
    int ret;

    WOLFSSL_ENTER("SHA3_224_Final");

    /* Finalize wolfCrypt SHA3-224 hash into output. */
    ret = (wc_Sha3_224_Final((wc_Sha3*)sha3, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA3_224_Free(). */
    wc_Sha3_224_Free((wc_Sha3*)sha3);

    return ret;
}
#endif /* WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256
/* Initialize SHA3-256 hash operation.
 *
 * @param [in, out] sha3_256  SHA3-256 context object.
 * @return  1 on success.
 * @return  0 when sha3_256 is NULL.
 */
int wolfSSL_SHA3_256_Init(WOLFSSL_SHA3_256_CTX* sha3_256)
{
    /* Ensure WOLFSSL_SHA3_256_CTX is big enough for wolfCrypt wc_Sha3. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA3_256_CTX, wc_Sha3);

    WOLFSSL_ENTER("SHA3_256_Init");

    /* Initialize wolfCrypt SHA3-256 object. */
    return wc_InitSha3_256((wc_Sha3*)sha3_256, NULL, INVALID_DEVID) == 0;
}

/* Update SHA3-256 hash with data.
 *
 * @param [in, out] sha3   SHA3-256 context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha3 is NULL.
 */
int wolfSSL_SHA3_256_Update(WOLFSSL_SHA3_256_CTX* sha3, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA3_256_Update");

    /* Update wolfCrypt SHA3-256 object with data. */
    return wc_Sha3_256_Update((wc_Sha3*)sha3, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA3-256 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA3_256_DIGEST_SIZE bytes.
 * @param [in, out] sha3    SHA3-256 context object.
 * @return  1 on success.
 * @return  0 when sha3 or output is NULL.
 */
int wolfSSL_SHA3_256_Final(byte* output, WOLFSSL_SHA3_256_CTX* sha3)
{
    int ret;

    WOLFSSL_ENTER("SHA3_256_Final");

    /* Finalize wolfCrypt SHA3-256 hash into output. */
    ret = (wc_Sha3_256_Final((wc_Sha3*)sha3, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA3_256_Free(). */
    wc_Sha3_256_Free((wc_Sha3*)sha3);

    return ret;
}
#endif /* WOLFSSL_NOSHA3_256 */

#ifndef WOLFSSL_NOSHA3_384
/* Initialize SHA3-384 hash operation.
 *
 * @param [in, out] sha3_384  SHA3-384 context object.
 * @return  1 on success.
 * @return  0 when sha3_384 is NULL.
 */
int wolfSSL_SHA3_384_Init(WOLFSSL_SHA3_384_CTX* sha3_384)
{
    /* Ensure WOLFSSL_SHA3_384_CTX is big enough for wolfCrypt wc_Sha3. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA3_384_CTX, wc_Sha3);

    WOLFSSL_ENTER("SHA3_384_Init");

    /* Initialize wolfCrypt SHA3-384 object. */
    return wc_InitSha3_384((wc_Sha3*)sha3_384, NULL, INVALID_DEVID) == 0;
}

/* Update SHA3-384 hash with data.
 *
 * @param [in, out] sha3   SHA3-384 context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha3 is NULL.
 */
int wolfSSL_SHA3_384_Update(WOLFSSL_SHA3_384_CTX* sha3, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA3_384_Update");

    /* Update wolfCrypt SHA3-384 object with data. */
    return wc_Sha3_384_Update((wc_Sha3*)sha3, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA3-384 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA3_384_DIGEST_SIZE bytes.
 * @param [in, out] sha3    SHA3-384 context object.
 * @return  1 on success.
 * @return  0 when sha3 or output is NULL.
 */
int wolfSSL_SHA3_384_Final(byte* output, WOLFSSL_SHA3_384_CTX* sha3)
{
    int ret;

    WOLFSSL_ENTER("SHA3_384_Final");

    /* Finalize wolfCrypt SHA3-384 hash into output. */
    ret = (wc_Sha3_384_Final((wc_Sha3*)sha3, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA3_384_Free(). */
    wc_Sha3_384_Free((wc_Sha3*)sha3);

    return ret;
}
#endif /* WOLFSSL_NOSHA3_384 */

#ifndef WOLFSSL_NOSHA3_512
/* Initialize SHA3-512 hash operation.
 *
 * @param [in, out] sha3_512  SHA3-512 context object.
 * @return  1 on success.
 * @return  0 when sha3_512 is NULL.
 */
int wolfSSL_SHA3_512_Init(WOLFSSL_SHA3_512_CTX* sha3_512)
{
    /* Ensure WOLFSSL_SHA3_512_CTX is big enough for wolfCrypt wc_Sha3. */
    WOLFSSL_ASSERT_SIZEOF_GE(WOLFSSL_SHA3_512_CTX, wc_Sha3);

    WOLFSSL_ENTER("SHA3_512_Init");

    /* Initialize wolfCrypt SHA3-512 object. */
    return wc_InitSha3_512((wc_Sha3*)sha3_512, NULL, INVALID_DEVID) == 0;
}

/* Update SHA3-512 hash with data.
 *
 * @param [in, out] sha3   SHA3-512 context object.
 * @param [in]      input  Data to be hashed.
 * @param [in]      sz     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when sha3 is NULL.
 */
int wolfSSL_SHA3_512_Update(WOLFSSL_SHA3_512_CTX* sha3, const void* input,
    unsigned long sz)
{
    WOLFSSL_ENTER("SHA3_512_Update");

    /* Update wolfCrypt SHA3-512 object with data. */
    return wc_Sha3_512_Update((wc_Sha3*)sha3, (const byte*)input, (word32)sz)
        == 0;
}

/* Finalize SHA3-512 hash and return output.
 *
 * @param [out]     output  Hash output.
 *                          Must be able to hold SHA3_512_DIGEST_SIZE bytes.
 * @param [in, out] sha3    SHA3-512 context object.
 * @return  1 on success.
 * @return  0 when sha3 or output is NULL.
 */
int wolfSSL_SHA3_512_Final(byte* output, WOLFSSL_SHA3_512_CTX* sha3)
{
    int ret;

    WOLFSSL_ENTER("SHA3_512_Final");

    /* Finalize wolfCrypt SHA3-512 hash into output. */
    ret = (wc_Sha3_512_Final((wc_Sha3*)sha3, output) == 0);
    /* Free resources here, as OpenSSL API doesn't include SHA3_512_Free(). */
    wc_Sha3_512_Free((wc_Sha3*)sha3);

    return ret;
}
#endif /* WOLFSSL_NOSHA3_512 */
#endif /* WOLFSSL_SHA3 */
#endif /* OPENSSL_EXTRA || HAVE_CURL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)

#ifndef NO_SHA
/* One shot SHA1 hash of data.
 *
 * When hash is null, a static buffer of SHA_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Size of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold SHA_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_SHA1(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static byte dgst[WC_SHA_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha* sha;
#else
    wc_Sha sha[1];
#endif
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_SHA1");

    /* Use static buffer if none passed in. */
    if (hash == NULL) {
        WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA1 IS NOT "
                    "THREAD SAFE WHEN hash == NULL");
        hash = dgst;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate dynamic memory for a wolfSSL SHA object. */
    sha = (wc_Sha*)XMALLOC(sizeof(wc_Sha), NULL, DYNAMIC_TYPE_DIGEST);
    if (sha == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Initialize wolfCrypt SHA object. */
        ret = wc_InitSha_ex(sha, NULL, INVALID_DEVID);
        if (ret != 0) {
            WOLFSSL_MSG("SHA1 Init failed");
            hash = NULL;
        }
    }
    if (ret == 0) {
        /* Update wolfCrypt SHA object with data. */
        ret = wc_ShaUpdate(sha, (const byte*)data, (word32)len);
        if (ret != 0) {
            WOLFSSL_MSG("SHA1 Update failed");
            hash = NULL;
        }

        if (ret == 0) {
            /* Finalize wolfCrypt SHA hash into hash. */
            ret = wc_ShaFinal(sha, hash);
            if (ret != 0) {
                WOLFSSL_MSG("SHA1 Final failed");
                hash = NULL;
            }
        }
        /* Dispose of dynamic memory associated with SHA object. */
        wc_ShaFree(sha);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL SHA object. */
    XFREE(sha, NULL, DYNAMIC_TYPE_DIGEST);
#endif
    return hash;
}
#endif /* ! NO_SHA */

#ifdef WOLFSSL_SHA224
/* One shot SHA-224 hash of data.
 *
 * When hash is null, a static buffer of SHA224_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Size of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold SHA224_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_SHA224(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static byte dgst[WC_SHA224_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha224* sha224;
#else
    wc_Sha224 sha224[1];
#endif
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_SHA224");

    /* Use static buffer if none passed in. */
    if (hash == NULL) {
        WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA224 IS NOT "
                    "THREAD SAFE WHEN hash == NULL");
        hash = dgst;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate dynamic memory for a wolfSSL SHA-224 object. */
    sha224 = (wc_Sha224*)XMALLOC(sizeof(wc_Sha224), NULL, DYNAMIC_TYPE_DIGEST);
    if (sha224 == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Initialize wolfCrypt SHA224 object. */
        ret = wc_InitSha224_ex(sha224, NULL, INVALID_DEVID);
        if (ret != 0) {
            WOLFSSL_MSG("SHA224 Init failed");
            hash = NULL;
        }
    }
    if (ret == 0) {
        /* Update wolfCrypt SHA-224 object with data. */
        ret = wc_Sha224Update(sha224, (const byte*)data, (word32)len);
        if (ret != 0) {
            WOLFSSL_MSG("SHA224 Update failed");
            hash = NULL;
        }

        if (ret == 0) {
            /* Finalize wolfCrypt SHA-224 hash into hash. */
            ret = wc_Sha224Final(sha224, hash);
            if (ret != 0) {
                WOLFSSL_MSG("SHA224 Final failed");
                hash = NULL;
            }
        }
        /* Dispose of dynamic memory associated with SHA-224 object. */
        wc_Sha224Free(sha224);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL SHA-224 object. */
    XFREE(sha224, NULL, DYNAMIC_TYPE_DIGEST);
#endif
    return hash;
}
#endif

#ifndef NO_SHA256
/* One shot SHA-256 hash of data.
 *
 * When hash is null, a static buffer of SHA256_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Size of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold SHA256_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_SHA256(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static byte dgst[WC_SHA256_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha256* sha256;
#else
    wc_Sha256 sha256[1];
#endif
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_SHA256");

    /* Use static buffer if none passed in. */
    if (hash == NULL) {
        WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA256 IS NOT "
                    "THREAD SAFE WHEN hash == NULL");
        hash = dgst;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate dynamic memory for a wolfSSL SHA-256 object. */
    sha256 = (wc_Sha256*)XMALLOC(sizeof(wc_Sha256), NULL, DYNAMIC_TYPE_DIGEST);
    if (sha256 == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Initialize wolfCrypt SHA256 object. */
        ret = wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
        if (ret != 0) {
            WOLFSSL_MSG("SHA256 Init failed");
            hash = NULL;
        }
    }
    if (ret == 0) {
        /* Update wolfCrypt SHA-256 object with data. */
        ret = wc_Sha256Update(sha256, (const byte*)data, (word32)len);
        if (ret != 0) {
            WOLFSSL_MSG("SHA256 Update failed");
            hash = NULL;
        }

        if (ret == 0) {
            /* Finalize wolfCrypt SHA-256 hash into hash. */
            ret = wc_Sha256Final(sha256, hash);
            if (ret != 0) {
                WOLFSSL_MSG("SHA256 Final failed");
                hash = NULL;
            }
        }
        /* Dispose of dynamic memory associated with SHA-256 object. */
        wc_Sha256Free(sha256);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL SHA object. */
    XFREE(sha256, NULL, DYNAMIC_TYPE_DIGEST);
#endif
    return hash;
}
#endif /* ! NO_SHA256 */

#ifdef WOLFSSL_SHA384
/* One shot SHA-384 hash of data.
 *
 * When hash is null, a static buffer of SHA384_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Size of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold SHA384_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_SHA384(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static byte dgst[WC_SHA384_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha384* sha384;
#else
    wc_Sha384 sha384[1];
#endif
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_SHA384");

    /* Use static buffer if none passed in. */
    if (hash == NULL) {
        WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA384 IS NOT "
                    "THREAD SAFE WHEN hash == NULL");
        hash = dgst;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate dynamic memory for a wolfSSL SHA-384 object. */
    sha384 = (wc_Sha384*)XMALLOC(sizeof(wc_Sha384), NULL, DYNAMIC_TYPE_DIGEST);
    if (sha384 == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Initialize wolfCrypt SHA384 object. */
        ret = wc_InitSha384_ex(sha384, NULL, INVALID_DEVID);
        if (ret != 0) {
            WOLFSSL_MSG("SHA384 Init failed");
            hash = NULL;
        }
    }
    if (ret == 0) {
        /* Update wolfCrypt SHA-384 object with data. */
        ret = wc_Sha384Update(sha384, (const byte*)data, (word32)len);
        if (ret != 0) {
            WOLFSSL_MSG("SHA384 Update failed");
            hash = NULL;
        }

        if (ret == 0) {
            /* Finalize wolfCrypt SHA-384 hash into hash. */
            ret = wc_Sha384Final(sha384, hash);
            if (ret != 0) {
                WOLFSSL_MSG("SHA384 Final failed");
                hash = NULL;
            }
        }
        /* Dispose of dynamic memory associated with SHA-384 object. */
        wc_Sha384Free(sha384);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL SHA-384 object. */
    XFREE(sha384, NULL, DYNAMIC_TYPE_DIGEST);
#endif
    return hash;
}
#endif /* WOLFSSL_SHA384  */

#if defined(WOLFSSL_SHA512)
/* One shot SHA-512 hash of data.
 *
 * When hash is null, a static buffer of SHA512_DIGEST_SIZE is used.
 * When the static buffer is used this function is not thread safe.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Size of data in bytes.
 * @param [out] hash  Buffer to hold digest. May be NULL.
 *                    Must be able to hold SHA512_DIGEST_SIZE bytes.
 * @return  Buffer holding hash on success.
 * @return  NULL when hashing fails.
 */
unsigned char* wolfSSL_SHA512(const unsigned char* data, size_t len,
    unsigned char* hash)
{
    /* Buffer to use when hash is NULL. */
    static byte dgst[WC_SHA512_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha512* sha512;
#else
    wc_Sha512 sha512[1];
#endif
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_SHA512");

    /* Use static buffer if none passed in. */
    if (hash == NULL) {
        WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA512 IS NOT "
                    "THREAD SAFE WHEN hash == NULL");
        hash = dgst;
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate dynamic memory for a wolfSSL SHA-512 object. */
    sha512 = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512), NULL, DYNAMIC_TYPE_DIGEST);
    if (sha512 == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        /* Initialize wolfCrypt SHA512 object. */
        ret = wc_InitSha512_ex(sha512, NULL, INVALID_DEVID);
        if (ret != 0) {
            WOLFSSL_MSG("SHA512 Init failed");
            hash = NULL;
        }
    }
    if (ret == 0) {
        /* Update wolfCrypt SHA-512 object with data. */
        ret = wc_Sha512Update(sha512, (const byte*)data, (word32)len);
        if (ret != 0) {
            WOLFSSL_MSG("SHA512 Update failed");
            hash = NULL;
        }

        if (ret == 0) {
            /* Finalize wolfCrypt SHA-512 hash into hash. */
            ret = wc_Sha512Final(sha512, hash);
            if (ret != 0) {
                WOLFSSL_MSG("SHA512 Final failed");
                hash = NULL;
            }
        }
        /* Dispose of dynamic memory associated with SHA-512 object. */
        wc_Sha512Free(sha512);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL SHA-512 object. */
    XFREE(sha512, NULL, DYNAMIC_TYPE_DIGEST);
#endif
    return hash;
}
#endif /* WOLFSSL_SHA512 */
#endif /* OPENSSL_EXTRA || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
        * HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */

/*******************************************************************************
 * END OF Digest APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF HMAC API
 ******************************************************************************/

/* _Internal Hmac object initialization. */
#define _HMAC_Init _InitHmac

#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)

/*
 * Helper Functions
 */

/* Copy a wolfSSL HMAC object.
 *
 * Requires that hash structures have no dynamic parts to them.
 *
 * @param [out] dst  Copy into this object.
 * @param [in]  src  Copy from this object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_HmacCopy(Hmac* dst, Hmac* src)
{
    void* heap;
    int ret = 1;

#ifndef HAVE_FIPS
    heap = src->heap;
#else
    heap = NULL;
#endif

    /* Initialize the destination object to reset state. */
    if (wc_HmacInit(dst, heap, 0) != 0) {
        ret = 0;
    }

    if (ret == 1) {
        int rc;

        /* Copy the digest object based on the MAC type. */
        switch (src->macType) {
    #ifndef NO_MD5
        case WC_MD5:
            rc = wc_Md5Copy(&src->hash.md5, &dst->hash.md5);
            break;
    #endif /* !NO_MD5 */

    #ifndef NO_SHA
        case WC_SHA:
            rc = wc_ShaCopy(&src->hash.sha, &dst->hash.sha);
            break;
    #endif /* !NO_SHA */

    #ifdef WOLFSSL_SHA224
        case WC_SHA224:
            rc = wc_Sha224Copy(&src->hash.sha224, &dst->hash.sha224);
            break;
    #endif /* WOLFSSL_SHA224 */

    #ifndef NO_SHA256
        case WC_SHA256:
            rc = wc_Sha256Copy(&src->hash.sha256, &dst->hash.sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            rc = wc_Sha384Copy(&src->hash.sha384, &dst->hash.sha384);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            rc = wc_Sha512Copy(&src->hash.sha512, &dst->hash.sha512);
            break;
    #endif /* WOLFSSL_SHA512 */
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case WC_SHA3_224:
            rc = wc_Sha3_224_Copy(&src->hash.sha3, &dst->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_224 */
    #ifndef WOLFSSL_NOSHA3_256
        case WC_SHA3_256:
            rc = wc_Sha3_256_Copy(&src->hash.sha3, &dst->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_256 */
    #ifndef WOLFSSL_NOSHA3_384
        case WC_SHA3_384:
            rc = wc_Sha3_384_Copy(&src->hash.sha3, &dst->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_384 */
    #ifndef WOLFSSL_NOSHA3_512
        case WC_SHA3_512:
            rc = wc_Sha3_512_Copy(&src->hash.sha3, &dst->hash.sha3);
            break;
    #endif /* WOLFSSL_NO_SHA3_512 */
#endif /* WOLFSSL_SHA3 */

        default:
            /* Digest algorithm not supported. */
            rc = BAD_FUNC_ARG;
        }

        /* Check result of digest object copy. */
        if (rc != 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Copy the pads which are derived from the key. */
        XMEMCPY((byte*)dst->ipad, (byte*)src->ipad, WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte*)dst->opad, (byte*)src->opad, WC_HMAC_BLOCK_SIZE);
        /* Copy the inner hash that is the current state. */
        XMEMCPY((byte*)dst->innerHash, (byte*)src->innerHash,
            WC_MAX_DIGEST_SIZE);
        /* Copy other fields. */
    #ifndef HAVE_FIPS
        dst->heap    = heap;
    #endif
        dst->macType = src->macType;
        dst->innerHashKeyed = src->innerHashKeyed;

#ifdef WOLFSSL_ASYNC_CRYPT
        XMEMCPY(&dst->asyncDev, &src->asyncDev, sizeof(WC_ASYNC_DEV));
        dst->keyLen = src->keyLen;
    #ifdef HAVE_CAVIUM
        /* Copy the dynamic data. */
        dst->data = (byte*)XMALLOC(src->dataLen, dst->heap, DYNAMIC_TYPE_HMAC);
        if (dst->data == NULL) {
            ret = BUFFER_E;
        }
        else {
            XMEMCPY(dst->data, src->data, src->dataLen);
            dst->dataLen = src->dataLen;
       }
    #endif /* HAVE_CAVIUM */
#endif /* WOLFSSL_ASYNC_CRYPT */
    }

    return ret;
}


/*
 * wolfSSL_HMAC_CTX APIs.
 */

/* Allocate a new HMAC context object and initialize.
 *
 * @return  A cleared HMAC context object on success.
 * @return  NULL on failure.
 */
WOLFSSL_HMAC_CTX* wolfSSL_HMAC_CTX_new(void)
{
    WOLFSSL_HMAC_CTX* hmac_ctx;

    /* Allocate dynamic memory for HMAC context object. */
    hmac_ctx = (WOLFSSL_HMAC_CTX*)XMALLOC(sizeof(WOLFSSL_HMAC_CTX), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (hmac_ctx != NULL) {
        /* Initialize HMAC context object. */
        wolfSSL_HMAC_CTX_Init(hmac_ctx);
    }

    return hmac_ctx;
}

/* Initialize a HMAC context object.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in, out] ctx  HMAC context object.
 * @return  1 indicating success.
 */
int wolfSSL_HMAC_CTX_Init(WOLFSSL_HMAC_CTX* ctx)
{
    WOLFSSL_MSG("wolfSSL_HMAC_CTX_Init");

    if (ctx != NULL) {
        /* Clear all fields. */
        XMEMSET(ctx, 0, sizeof(WOLFSSL_HMAC_CTX));
        /* type field is 0 == WC_HASH_TYPE_NONE. */
        /* TODO: for FIPS and selftest 0 == WC_HASH_TYPE_MD5 instead. */
    }

    return 1;
}

/* Deep copy of information from one HMAC context object to another.
 *
 * @param [out] dst  Copy into this object.
 * @param [in]  src  Copy from this object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_HMAC_CTX_copy(WOLFSSL_HMAC_CTX* dst, WOLFSSL_HMAC_CTX* src)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_HMAC_CTX_copy");

    /* Validate parameters. */
    if ((dst == NULL) || (src == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Copy hash type. */
        dst->type = src->type;
        /* Move pads derived from key into save space. */
        XMEMCPY((byte *)&dst->save_ipad, (byte *)&src->hmac.ipad,
            WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte *)&dst->save_opad, (byte *)&src->hmac.opad,
            WC_HMAC_BLOCK_SIZE);
        /* Copy the wolfSSL Hmac ocbject. */
        ret = wolfSSL_HmacCopy(&dst->hmac, &src->hmac);
    }

    return ret;
}

/* Cleanup internal state of HMAC context object.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in, out] ctx  HMAC context object.
 */
void wolfSSL_HMAC_CTX_cleanup(WOLFSSL_HMAC_CTX* ctx)
{
    if (ctx != NULL) {
        /* Cleanup HMAC operation data. */
        wolfSSL_HMAC_cleanup(ctx);
    }
}

/* Free HMAC context object.
 *
 * ctx is deallocated and can no longer be used after this call.
 *
 * @param [in] ctx  HMAC context object.
 */
void wolfSSL_HMAC_CTX_free(WOLFSSL_HMAC_CTX* ctx)
{
    if (ctx != NULL) {
        /* Cleanup HMAC context object, including freeing dynamic data. */
        wolfSSL_HMAC_CTX_cleanup(ctx);
        /* Dispose of the memory for the HMAC context object. */
        XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Get the EVP digest of the HMAC context.
 *
 * @param [in] ctx  HMAC context object.
 * @return  EVP digest object.
 * @return  NULL when ctx is NULL or EVP digest not set.
 */
const WOLFSSL_EVP_MD* wolfSSL_HMAC_CTX_get_md(const WOLFSSL_HMAC_CTX* ctx)
{
    const WOLFSSL_EVP_MD* ret = NULL;

    if (ctx != NULL) {
        /* Get EVP digest based on digest type. */
        ret = wolfSSL_macType2EVP_md((enum wc_HashType)ctx->type);
    }

    return ret;
}

/*
 * wolfSSL_HMAC APIs.
 */

/* Initialize the HMAC operation.
 *
 * @param [in, out] ctx    HMAC context object.
 * @param [in]      key    Array of bytes representing key.
 *                         May be NULL indicating to use the same key as
 *                         previously.
 * @param [in]      keySz  Number of bytes in key.
 *                         0+ in non-FIPS, 14+ in FIPS.
 * @param [in]      type   EVP digest indicate digest type.
 *                         May be NULL if initialized previously.
 * @param [in]      e      wolfSSL engine. Ignored.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_HMAC_Init_ex(WOLFSSL_HMAC_CTX* ctx, const void* key, int keySz,
    const WOLFSSL_EVP_MD* type, WOLFSSL_ENGINE* e)
{
    WOLFSSL_ENTER("wolfSSL_HMAC_Init_ex");

    /* WOLFSSL_ENGINE not used, call wolfSSL_HMAC_Init */
    (void)e;

    return wolfSSL_HMAC_Init(ctx, key, keySz, type);
}

/* Initialize the HMAC operation.
 *
 * @param [in, out] ctx    HMAC context object.
 * @param [in]      key    Array of bytes representing key.
 *                         May be NULL indicating to use the same key as
 *                         previously.
 * @param [in]      keySz  Number of bytes in key.
 *                         0+ in non-FIPS, 14+ in FIPS.
 * @param [in]      type   EVP digest indicate digest type.
 *                         May be NULL if initialized previously.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_HMAC_Init(WOLFSSL_HMAC_CTX* ctx, const void* key, int keylen,
    const WOLFSSL_EVP_MD* type)
{
    int ret = 1;
    void* heap = NULL;
    int rc;

    WOLFSSL_MSG("wolfSSL_HMAC_Init");

    /* Validate parameters. */
    if (ctx == NULL) {
        WOLFSSL_MSG("no ctx on init");
        ret = 0;
    }
    /* Digest type must have been previously set if not specified. */
    if ((ret == 1) && (type == NULL) && (ctx->type == (int)WC_HASH_TYPE_NONE)) {
        WOLFSSL_MSG("no hash type");
        ret = 0;
    }
    /* wolfSSL HMAC object must have been setup with a key if not specified. */
    if ((ret == 1) && (key == NULL) &&
            (ctx->hmac.macType == (int)WC_HASH_TYPE_NONE)) {
        WOLFSSL_MSG("wolfCrypt hash not setup");
        ret = 0;
    }

    if (ret == 1) {
    #ifndef HAVE_FIPS
        heap = ctx->hmac.heap;
    #endif

        if (type != NULL) {
            WOLFSSL_MSG("init has type");
            /* Get the digest type based on EVP digest. */
            if (wolfssl_evp_md_to_hash_type(type, &ctx->type) != 0) {
                WOLFSSL_MSG("bad init type");
                ret = 0;
            }
        }
    }

    if (ret == 1) {
        /* Check if init has been called before */
        int inited = (ctx->hmac.macType != WC_HASH_TYPE_NONE);
        /* Free if wolfSSL HMAC object when initialized. */
        if (inited) {
            wc_HmacFree(&ctx->hmac);
        }
        /* Initialize wolfSSL HMAC object for new HMAC operation. */
        rc = wc_HmacInit(&ctx->hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            ret = 0;
        }
    }
    if ((ret == 1) && (key != NULL)) {
        /* Set the key into wolfSSL HMAC object. */
        rc = wc_HmacSetKey(&ctx->hmac, ctx->type, (const byte*)key,
            (word32)keylen);
        if (rc != 0) {
            /* in FIPS mode a key < 14 characters will fail here */
            WOLFSSL_MSG("hmac set key error");
            WOLFSSL_ERROR(rc);
            wc_HmacFree(&ctx->hmac);
            ret = 0;
        }
        if (ret == 1) {
            /* Save the pads which are derived from the key. Used to re-init. */
            XMEMCPY((byte *)&ctx->save_ipad, (byte *)&ctx->hmac.ipad,
                WC_HMAC_BLOCK_SIZE);
            XMEMCPY((byte *)&ctx->save_opad, (byte *)&ctx->hmac.opad,
                WC_HMAC_BLOCK_SIZE);
        }
    }
    else if (ret == 1) {
        WOLFSSL_MSG("recover hmac");
        /* Set state of wolfSSL HMAC object. */
        ctx->hmac.macType = (byte)ctx->type;
        ctx->hmac.innerHashKeyed = 0;
        /* Restore key by copying in saved pads. */
        XMEMCPY((byte *)&ctx->hmac.ipad, (byte *)&ctx->save_ipad,
            WC_HMAC_BLOCK_SIZE);
        XMEMCPY((byte *)&ctx->hmac.opad, (byte *)&ctx->save_opad,
            WC_HMAC_BLOCK_SIZE);
        /* Initialize the wolfSSL HMAC object. */
        rc = _HMAC_Init(&ctx->hmac, ctx->hmac.macType, heap);
        if (rc != 0) {
            WOLFSSL_MSG("hmac init error");
            WOLFSSL_ERROR(rc);
            ret = 0;
        }
    }

    return ret;
}

/* Update the HMAC operation with more data.
 *
 * TODO: 'len' should be a signed type.
 *
 * @param [in, out] ctx   HMAC context object.
 * @param [in]      data  Array of byted to MAC. May be NULL.
 * @param [in]      len   Number of bytes to MAC. May be 0.
 * @return  1 on success.
 * @return  0 when ctx is NULL or HMAC update fails.
 */
int wolfSSL_HMAC_Update(WOLFSSL_HMAC_CTX* ctx, const unsigned char* data,
    int len)
{
    int ret = 1;

    WOLFSSL_MSG("wolfSSL_HMAC_Update");

    /* Validate parameters. */
    if (ctx == NULL) {
        WOLFSSL_MSG("no ctx");
        ret = 0;
    }

    /* Update when there is data to add. */
    if ((ret == 1) && (data != NULL) && (len > 0)) {
        int rc;

        WOLFSSL_MSG("updating hmac");
        /* Update wolfSSL HMAC object. */
        rc = wc_HmacUpdate(&ctx->hmac, data, (word32)len);
        if (rc != 0){
            WOLFSSL_MSG("hmac update error");
            ret = 0;
        }
    }

    return ret;
}

/* Finalize HMAC operation.
 *
 * @param [in, out] ctx   HMAC context object.
 * @param [out]     hash  Buffer to hold HMAC result.
 *                        Must be able to hold bytes equivalent to digest size.
 * @param [out]     len   Length of HMAC result. May be NULL.
 * @return  1 on success.
 * @return  0 when ctx or hash is NULL.
 * @return  0 when HMAC finalization fails.
 */
int wolfSSL_HMAC_Final(WOLFSSL_HMAC_CTX* ctx, unsigned char* hash,
    unsigned int* len)
{
    int ret = 1;
    int rc;

    WOLFSSL_MSG("wolfSSL_HMAC_Final");

    /* Validate parameters. */
    if ((ctx == NULL) || (hash == NULL)) {
        WOLFSSL_MSG("invalid parameter");
        ret = 0;
    }

    if (ret == 1) {
        WOLFSSL_MSG("final hmac");
        /* Finalize wolfSSL HMAC object. */
        rc = wc_HmacFinal(&ctx->hmac, hash);
        if (rc != 0){
            WOLFSSL_MSG("final hmac error");
            ret = 0;
        }
    }
    if ((ret == 1) && (len != NULL)) {
        WOLFSSL_MSG("setting output len");
        /* Get the length of the output based on digest type. */
        *len = wolfssl_mac_len((unsigned char)ctx->type);
    }

    return ret;
}


/* Cleanup the HMAC operation.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in, out] ctx  HMAC context object.
 * @return  1 indicating success.
 */
int wolfSSL_HMAC_cleanup(WOLFSSL_HMAC_CTX* ctx)
{
    WOLFSSL_MSG("wolfSSL_HMAC_cleanup");

    if (ctx != NULL) {
        /* Free the dynamic data in the wolfSSL HMAC object. */
        wc_HmacFree(&ctx->hmac);
    }

    return 1;
}

/* HMAC data using the specified EVP digest.
 *
 * @param [in]  evp_md  EVP digest.
 * @param [in]  key     Array of bytes representing key.
 * @param [in]  keySz   Number of bytes in key.
 *                      0+ in non-FIPS, 14+ in FIPS.
 * @param [in]  data    Data to MAC.
 * @param [in]  len     Length in bytes of data to MAC.
 * @param [out] md      HMAC output.
 * @param [out] md_len  Length of HMAC output in bytes. May be NULL.
 * @return  Buffer holding HMAC output.
 * @return  NULL on failure.
 */
unsigned char* wolfSSL_HMAC(const WOLFSSL_EVP_MD* evp_md, const void* key,
    int key_len, const unsigned char* data, size_t len, unsigned char* md,
    unsigned int* md_len)
{
    unsigned char* ret = NULL;
    int rc = 0;
    int type = 0;
    int hmacLen = 0;
#ifdef WOLFSSL_SMALL_STACK
    Hmac* hmac = NULL;
#else
    Hmac  hmac[1];
#endif
    void* heap = NULL;

    /* Validate parameters. */
    if ((evp_md == NULL) || (key == NULL) || (md == NULL)) {
        rc = BAD_FUNC_ARG;
    }

    if (rc == 0) {
        /* Get the hash type corresponding to the EVP digest. */
        rc = wolfssl_evp_md_to_hash_type(evp_md, &type);
    }
#ifdef WOLFSSL_SMALL_STACK
    if (rc == 0) {
        /* Allocate dynamic memory for a wolfSSL HMAC object. */
        hmac = (Hmac*)XMALLOC(sizeof(Hmac), heap, DYNAMIC_TYPE_HMAC);
        if (hmac == NULL) {
            rc = MEMORY_E;
        }
    }
#endif
    if (rc == 0)  {
        /* Get the HMAC output length. */
        hmacLen = (int)wolfssl_mac_len((unsigned char)type);
        /* 0 indicates the digest is not supported. */
        if (hmacLen == 0) {
            rc = BAD_FUNC_ARG;
        }
    }
    /* Initialize the wolfSSL HMAC object. */
    if ((rc == 0) && (wc_HmacInit(hmac, heap, INVALID_DEVID) == 0)) {
        /* Set the key into the wolfSSL HMAC object. */
        rc = wc_HmacSetKey(hmac, type, (const byte*)key, (word32)key_len);
        if (rc == 0) {
           /* Update the wolfSSL HMAC object with data. */
            rc = wc_HmacUpdate(hmac, data, (word32)len);
        }
        /* Finalize the wolfSSL HMAC object. */
        if ((rc == 0) && (wc_HmacFinal(hmac, md) == 0)) {
            /* Return the length of the HMAC output if required. */
            if (md_len != NULL) {
                *md_len = (unsigned int)hmacLen;
            }
            /* Set the buffer to return. */
            ret = md;
        }
        /* Dispose of dynamic memory associated with the wolfSSL HMAC object. */
        wc_HmacFree(hmac);
    }

#ifdef WOLFSSL_SMALL_STACK
    /* Free dynamic memory of a wolfSSL HMAC object. */
    XFREE(hmac, heap, DYNAMIC_TYPE_HMAC);
#endif
    return ret;
}

/* Get the HMAC output size.
 *
 * @param [in] ctx  HMAC context object.
 * @return  Size of HMAC output in bytes.
 * @return  0 when ctx is NULL or no digest algorithm set.
 */
size_t wolfSSL_HMAC_size(const WOLFSSL_HMAC_CTX* ctx)
{
    size_t ret = 0;

    if (ctx != NULL) {
        /* Look up digest size with wolfSSL. */
        ret = (size_t)wc_HashGetDigestSize((enum wc_HashType)ctx->hmac.macType);
    }

    return ret;
}
#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF HMAC API
 ******************************************************************************/

/*******************************************************************************
 * START OF CMAC API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
#if defined(WOLFSSL_CMAC) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_AES_DIRECT)
/* Allocate a new CMAC context object.
 *
 * TODO: make fields static.
 *
 * @return  A CMAC context object on success.
 * @return  NULL on failure.
 */
WOLFSSL_CMAC_CTX* wolfSSL_CMAC_CTX_new(void)
{
    WOLFSSL_CMAC_CTX* ctx = NULL;

    /* Allocate memory for CMAC context object. */
    ctx = (WOLFSSL_CMAC_CTX*)XMALLOC(sizeof(WOLFSSL_CMAC_CTX), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ctx != NULL) {
        /* Memory for wolfSSL CMAC object is allocated in
         * wolfSSL_CMAC_Init().
         */
        ctx->internal = NULL;
        /* Allocate memory for EVP cipher context object. */
        ctx->cctx = wolfSSL_EVP_CIPHER_CTX_new();
        if (ctx->cctx == NULL) {
            XFREE(ctx->internal, NULL, DYNAMIC_TYPE_CMAC);
            XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
            ctx = NULL;
        }
    }

    return ctx;
}

/* Free CMAC context object and dynamically allocated fields.
 *
 * ctx is deallocated and can no longer be used after this call.
 *
 * @param [in] ctx  CMAC context object.
 */
void wolfSSL_CMAC_CTX_free(WOLFSSL_CMAC_CTX *ctx)
{
    if (ctx != NULL) {
        /* Deallocate dynamically allocated fields. */
        if (ctx->internal != NULL) {
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
            wc_CmacFree((Cmac*)ctx->internal);
#endif
            XFREE(ctx->internal, NULL, DYNAMIC_TYPE_CMAC);
        }
        if (ctx->cctx != NULL) {
            wolfSSL_EVP_CIPHER_CTX_cleanup(ctx->cctx);
            wolfSSL_EVP_CIPHER_CTX_free(ctx->cctx);
        }
        /* Deallocate CMAC context object. */
        XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Return a reference to the EVP cipher context.
 *
 * @param [in] ctx  CMAC context object.
 * @return  EVP cipher context.
 * @return  NULL when ctx is NULL.
 */
WOLFSSL_EVP_CIPHER_CTX* wolfSSL_CMAC_CTX_get0_cipher_ctx(WOLFSSL_CMAC_CTX* ctx)
{
    WOLFSSL_EVP_CIPHER_CTX* cctx = NULL;

    if (ctx != NULL) {
        /* Return EVP cipher context object. */
        cctx = ctx->cctx;
    }

    return cctx;
}

/* Initialize the CMAC operation.
 *
 * @param [in, out] cmac    CMAC context object.
 * @param [in]      key     Symmetric key to use.
 * @param [in]      keySz   Length of key in bytes.
 * @param [in]      cipher  EVP cipher object describing encryption algorithm
 *                          to use.
 * @param [in]      engine  wolfSSL Engine. Not used.
 * @return  1 on success.
 * @return  0 when ctx or cipher is NULL.
 * @return  0 when cipher is not an AES-CBC algorithm.
 * @return  0 when key length does not match cipher.
 */
int wolfSSL_CMAC_Init(WOLFSSL_CMAC_CTX* ctx, const void *key, size_t keySz,
    const WOLFSSL_EVP_CIPHER* cipher, WOLFSSL_ENGINE* engine)
{
    int ret = 1;

    (void)engine;

    WOLFSSL_ENTER("wolfSSL_CMAC_Init");

    /* Validate parameters. */
    if ((ctx == NULL) || (cipher == NULL)) {
        ret = 0;
    }
    /* Only AES-CBC ciphers are supported. */
    if ((ret == 1) && (cipher != EVP_AES_128_CBC) &&
            (cipher != EVP_AES_192_CBC) && (cipher != EVP_AES_256_CBC)) {
        WOLFSSL_MSG("wolfSSL_CMAC_Init: requested cipher is unsupported");
        ret = 0;
    }
    /* Key length must match cipher. */
    if ((ret == 1) && ((int)keySz != wolfSSL_EVP_Cipher_key_length(cipher))) {
        WOLFSSL_MSG("wolfSSL_CMAC_Init: "
                    "supplied key size doesn't match requested cipher");
        ret = 0;
    }

    if ((ret == 1) && (ctx->internal == NULL)) {
        /* Allocate memory for wolfSSL CMAC object. */
        ctx->internal = (Cmac*)XMALLOC(sizeof(Cmac), NULL, DYNAMIC_TYPE_CMAC);
        if (ctx->internal == NULL)
            ret = 0;
    }

    /* Initialize the wolfCrypt CMAC object. */
    if ((ret == 1) && (wc_InitCmac((Cmac*)ctx->internal, (const byte*)key,
            (word32)keySz, WC_CMAC_AES, NULL) != 0)) {
        WOLFSSL_MSG("wolfSSL_CMAC_Init: wc_InitCmac() failed");
        XFREE(ctx->internal, NULL, DYNAMIC_TYPE_CMAC);
        ctx->internal = NULL;
        ret = 0;
    }
    if (ret == 1) {
        /* Initialize the EVP cipher context object for encryption. */
        ret = wolfSSL_EVP_CipherInit(ctx->cctx, cipher, (const byte*)key, NULL,
            1);
        if (ret != WOLFSSL_SUCCESS)
            WOLFSSL_MSG("wolfSSL_CMAC_Init: wolfSSL_EVP_CipherInit() failed");
    }

    WOLFSSL_LEAVE("wolfSSL_CMAC_Init", ret);

    return ret;
}

/* Update the CMAC operation with data.
 *
 * @param [in, out] ctx   CMAC context object.
 * @param [in]      data  Data to MAC as a byte array.
 * @param [in]      len   Length of data in bytes.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_CMAC_Update(WOLFSSL_CMAC_CTX* ctx, const void* data, size_t len)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CMAC_Update");

    /* Validate parameters. */
    if (ctx == NULL) {
        ret = 0;
    }

    /* Update the wolfCrypto CMAC object with data. */
    if ((ret == 1) && (data != NULL) && (wc_CmacUpdate((Cmac*)ctx->internal,
            (const byte*)data, (word32)len) != 0)) {
        ret = 0;
    }

    WOLFSSL_LEAVE("wolfSSL_CMAC_Update", ret);

    return ret;
}

/* Finalize the CMAC operation into output buffer.
 *
 * @param [in, out] ctx  CMAC context object.
 * @param [out]     out  Buffer to place CMAC result into.
 *                       Must be able to hold WC_AES_BLOCK_SIZE bytes.
 * @param [out]     len  Length of CMAC result. May be NULL.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_CMAC_Final(WOLFSSL_CMAC_CTX* ctx, unsigned char* out, size_t* len)
{
    int ret = 1;
    int blockSize;
    word32 len32;

    WOLFSSL_ENTER("wolfSSL_CMAC_Final");

    /* Validate parameters. */
    if (ctx == NULL) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get the expected output size. */
        blockSize = wolfSSL_EVP_CIPHER_CTX_block_size(ctx->cctx);
        /* Check value is valid. */
        if (blockSize <= 0) {
            ret = 0;
        }
        else {
            /* wolfCrypt CMAC expects buffer size. */
            len32 = (word32)blockSize;
            /* Return size if required. */
            if (len != NULL) {
                *len = (size_t)blockSize;
            }
        }
    }
    if ((ret == 1) && (out != NULL)) {
        /* Calculate MAC result with wolfCrypt CMAC object. */
        if (wc_CmacFinal((Cmac*)ctx->internal, out, &len32) != 0) {
            ret = 0;
        }
        /* TODO: Is this necessary? Length should not change. */
        /* Return actual size if required. */
        else if (len != NULL) {
            *len = (size_t)len32;
        }

        XFREE(ctx->internal, NULL, DYNAMIC_TYPE_CMAC);
        ctx->internal = NULL;
    }

    WOLFSSL_LEAVE("wolfSSL_CMAC_Final", ret);

    return ret;
}
#endif /* WOLFSSL_CMAC && OPENSSL_EXTRA && WOLFSSL_AES_DIRECT */
#endif /* OPENSSL_EXTRA && !WOLFCRYPT_ONLY */

/*******************************************************************************
 * END OF CMAC API
 ******************************************************************************/

/*******************************************************************************
 * START OF DES API
 ******************************************************************************/

#ifdef OPENSSL_EXTRA
#ifndef NO_DES3
/* Set parity of the DES key.
 *
 * @param [in, out] key  DES key.
 */
void wolfSSL_DES_set_odd_parity(WOLFSSL_DES_cblock* key)
{
    int i;

    WOLFSSL_ENTER("wolfSSL_DES_set_odd_parity");

    for (i = 0; i < DES_KEY_SIZE; i++) {
        unsigned char c = (*key)[i];
        /* Set bottom bit to odd parity - XOR of each bit is to be 1.
         * XOR 1 to XOR of each bit.
         * When even parity, the value will be 1 and the bottom bit will be
         * flipped.
         * When odd parity, the value will be 0 and the bottom bit will be
         * unchanged.
         */
        c ^= ((c >> 0) ^ (c >> 1) ^ (c >> 2) ^ (c >> 3) ^ (c >> 4) ^ (c >> 5) ^
              (c >> 6) ^ (c >> 7) ^ 0x01) & 0x01;
        (*key)[i] = c;
    }
}

/* Check parity of the DES key.
 *
 * @param [in] key  DES key.
 * @return  1 when odd parity on all bytes.
 * @return  0 when even parity on any byte.
 */
int wolfSSL_DES_check_key_parity(WOLFSSL_DES_cblock *key)
{
    int i;
    /* Assume odd parity. */
    unsigned char p = 1;

    WOLFSSL_ENTER("wolfSSL_DES_check_key_parity");

    for (i = 0; i < DES_KEY_SIZE; i++) {
        unsigned char c = (*key)[i];
        /* p will be 0 when parity is even (XOR of bits is 0). */
        p &= (c >> 0) ^ (c >> 1) ^ (c >> 2) ^ (c >> 3) ^ (c >> 4) ^ (c >> 5) ^
             (c >> 6) ^ (c >> 7);
    }

    /* Only care about bottom bit. */
    return p & 1;
}

/* Check whether key data is the two 32-bit words.
 *
 * return true in fail case (1)
 *
 * @param [in] k1   First part of key.
 * @param [in] k2   Second part of key.
 * @param [in] key  DES key as an array of bytes.
 **/
static int wolfssl_des_check(word32 k1, word32 k2, unsigned char* key)
{
    /* Compare the two 32-bit words. */
    return (((word32*)key)[0] == k1) && (((word32*)key)[1] == k2);
}

/* Check key is not weak.
 *
 * Weak key list from Nist "Recommendation for the Triple Data Encryption
 * Algorithm (TDEA) Block Cipher"
 *
 * @param [in] key  DES key.
 * @return  0 when #key is not a weak key.
 * @return  1 when #key is a weak key.
 */
int wolfSSL_DES_is_weak_key(WOLFSSL_const_DES_cblock* key)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_DES_is_weak_key");

    /* Validate parameter. */
    if (key == NULL) {
        WOLFSSL_MSG("NULL key passed in");
        ret = 1;
    }

    /* Check weak keys - endian doesn't matter. */
    if ((ret == 0) && (wolfssl_des_check(0x01010101, 0x01010101, *key) ||
                       wolfssl_des_check(0xFEFEFEFE, 0xFEFEFEFE, *key) ||
                       wolfssl_des_check(0xE0E0E0E0, 0xF1F1F1F1, *key) ||
                       wolfssl_des_check(0x1F1F1F1F, 0x0E0E0E0E, *key))) {
        WOLFSSL_MSG("Weak key found");
        ret = 1;
    }

    /* Check semi-weak keys - endian doesn't matter. */
    if ((ret == 0) && (wolfssl_des_check(0x011F011F, 0x010E010E, *key) ||
                       wolfssl_des_check(0x1F011F01, 0x0E010E01, *key) ||
                       wolfssl_des_check(0x01E001E0, 0x01F101F1, *key) ||
                       wolfssl_des_check(0xE001E001, 0xF101F101, *key) ||
                       wolfssl_des_check(0x01FE01FE, 0x01FE01FE, *key) ||
                       wolfssl_des_check(0xFE01FE01, 0xFE01FE01, *key) ||
                       wolfssl_des_check(0x1FE01FE0, 0x0EF10EF1, *key) ||
                       wolfssl_des_check(0xE01FE01F, 0xF10EF10E, *key) ||
                       wolfssl_des_check(0x1FFE1FFE, 0x0EFE0EFE, *key) ||
                       wolfssl_des_check(0xFE1FFE1F, 0xFE0EFE0E, *key) ||
                       wolfssl_des_check(0xE0FEE0FE, 0xF1FEF1FE, *key) ||
                       wolfssl_des_check(0xFEE0FEE0, 0xFEF1FEF1, *key))) {
        WOLFSSL_MSG("Semi-weak key found");
        ret = 1;
    }

    return ret;
}

/* Set key into schedule if key parity is odd and key is not weak.
 *
 * @param [in]  key       DES key data.
 * @param [out] schedule  DES key schedule.
 * @return  0 on success.
 * @return  -1 when parity is not odd.
 * @return  -2 when key or schedule is NULL.
 * @return  -2 when key is weak or semi-weak.
 */
int wolfSSL_DES_set_key_checked(WOLFSSL_const_DES_cblock* key,
    WOLFSSL_DES_key_schedule* schedule)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (schedule == NULL)) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_DES_set_key_checked");
        ret = -2;
    }

    /* Check key parity is odd. */
    if ((ret == 0) && (!wolfSSL_DES_check_key_parity(key))) {
        WOLFSSL_MSG("Odd parity test fail");
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Check whether key is weak. */
    if ((ret == 0) && wolfSSL_DES_is_weak_key(key)) {
        WOLFSSL_MSG("Weak key found");
        ret = -2;
    }
    if (ret == 0) {
        /* Key data passed checks, now copy key into schedule. */
        XMEMCPY(schedule, key, DES_KEY_SIZE);
    }

    return ret;
}

/* Set key into schedule - no checks on key data performed.
 *
 * @param [in]  key       DES key data.
 * @param [out] schedule  DES key schedule.
 */
void wolfSSL_DES_set_key_unchecked(WOLFSSL_const_DES_cblock* key,
    WOLFSSL_DES_key_schedule* schedule)
{
    /* Validate parameters. */
    if ((key != NULL) && (schedule != NULL)) {
        /* Copy the key data into the schedule. */
        XMEMCPY(schedule, key, DES_KEY_SIZE);
    }
}

/* Set key into schedule.
 *
 * @param [in]  key       DES key data.
 * @param [out] schedule  DES key schedule.
 * @return  0 on success.
 * @return  -1 when parity is not odd.
 * @return  -2 when key or schedule is NULL.
 * @return  -2 when key is weak or semi-weak.
 */
int wolfSSL_DES_set_key(WOLFSSL_const_DES_cblock* key,
    WOLFSSL_DES_key_schedule* schedule)
{
#ifdef WOLFSSL_CHECK_DESKEY
    return wolfSSL_DES_set_key_checked(key, schedule);
#else
    wolfSSL_DES_set_key_unchecked(key, schedule);
    return 0;
#endif
}

/* Set the key schedule from the DES key.
 *
 * TODO: OpenSSL checks parity and weak keys.
 *
 * @param [in]  key       DES key data.
 * @param [out] schedule  DES key schedule.
 * @return  0 on success.
 */
int wolfSSL_DES_key_sched(WOLFSSL_const_DES_cblock* key,
    WOLFSSL_DES_key_schedule* schedule)
{
    WOLFSSL_ENTER("wolfSSL_DES_key_sched");

    /* Check parameters are usable. */
    if ((key == NULL) || (schedule == NULL)) {
        WOLFSSL_MSG("Null argument passed in");
    }
    else {
        /* Copy the key data into the schedule. */
        XMEMCPY(schedule, key, sizeof(WOLFSSL_const_DES_cblock));
    }

    return 0;
}

/* Encrypt with DES-CBC to create a checksum.
 *
 * Intended to behave similar to Kerberos mit_des_cbc_cksum.
 * Returns the last 4 bytes of cipher text.
 *
 * TODO: Encrypt one block at a time instead of allocating a large amount.
 *
 * @param [in]  in      Data to encrypt.
 * @param [out] out     Last encrypted block.
 * @param [in]  length  Length of data to encrypt.
 * @param [in]  sc      Key schedule for encryption.
 * @param [in]  iv      Initialization vector for CBC.
 * @return  Checksum of encryption.
 * @return  0 on error.
 */
WOLFSSL_DES_LONG wolfSSL_DES_cbc_cksum(const unsigned char* in,
    WOLFSSL_DES_cblock* out, long length, WOLFSSL_DES_key_schedule* sc,
    WOLFSSL_const_DES_cblock* iv)
{
    WOLFSSL_DES_LONG ret = 0;
    int err = 0;
    unsigned char* data = (unsigned char*)in;
    unsigned char* tmp = NULL;
    long dataSz = length;

    WOLFSSL_ENTER("wolfSSL_DES_cbc_cksum");

    /* Validate parameters. */
    if ((in == NULL) || (out == NULL) || (sc == NULL) || (iv == NULL)) {
        WOLFSSL_MSG("Bad argument passed in");
        err = 1;
    }

    /* When input length is not a multiple of DES_BLOCK_SIZE pad with 0s. */
    if ((!err) && (dataSz % DES_BLOCK_SIZE)) {
        /* Allocate a buffer big enough to hold padded input. */
        dataSz += DES_BLOCK_SIZE - (dataSz % DES_BLOCK_SIZE);
        data = (unsigned char*)XMALLOC(dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (data == NULL) {
            WOLFSSL_MSG("Issue creating temporary buffer");
            err = 1;
        }
        else {
            /* Copy input and pad with 0s. */
            XMEMCPY(data, in, length);
            XMEMSET(data + length, 0, dataSz - length);
        }
    }

    if (!err) {
        /* Allocate buffer to hold encrypted data. */
        tmp = (unsigned char*)XMALLOC(dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            WOLFSSL_MSG("Issue creating temporary buffer");
            err = 1;
        }
    }

    if (!err) {
        /* Encrypt data into temporary. */
        wolfSSL_DES_cbc_encrypt(data, tmp, dataSz, sc, (WOLFSSL_DES_cblock*)iv,
            WC_DES_ENCRYPT);
        /* Copy out last block. */
        XMEMCPY((unsigned char*)out, tmp + (dataSz - DES_BLOCK_SIZE),
            DES_BLOCK_SIZE);

        /* Use the last half of the encrypted block as the checksum. */
        ret = (((*((unsigned char*)out + 4) & 0xFF) << 24) |
               ((*((unsigned char*)out + 5) & 0xFF) << 16) |
               ((*((unsigned char*)out + 6) & 0xFF) <<  8) |
                (*((unsigned char*)out + 7) & 0xFF)      );
    }

    /* Dispose of allocated memory. */
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (data != in) {
        XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/* Encrypt/decrypt data with DES-CBC.
 *
 * TODO: OpenSSL expects a length that is a multiple of the block size but
 *       we are padding the last block. This is not a padding API.
 * TODO: Validate parameters?
 *
 * @param [in]  input     Data to encipher.
 * @param [out] output    Enciphered data.
 * @param [in]  length    Length of data to encipher.
 * @param [in]  schedule  Key schedule.
 * @param [in]  ivec      IV for CBC operation.
 * @param [in]  enc       Whether to encrypt.
 */
void wolfSSL_DES_cbc_encrypt(const unsigned char* input, unsigned char* output,
    long length, WOLFSSL_DES_key_schedule* schedule, WOLFSSL_DES_cblock* ivec,
    int enc)
{
#ifdef WOLFSSL_SMALL_STACK
    Des* des = NULL;
#else
    Des  des[1];
#endif
    byte lastBlock[DES_BLOCK_SIZE];

    WOLFSSL_ENTER("wolfSSL_DES_cbc_encrypt");

#ifdef WOLFSSL_SMALL_STACK
    des = (Des*)XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_CIPHER);
    if (des == NULL) {
        WOLFSSL_MSG("Failed to allocate memory for Des object");
    }
    else
#endif
    /* OpenSSL compat, no ret */
    if (wc_Des_SetKey(des, (const byte*)schedule, (const byte*)ivec,
            !enc) != 0) {
        WOLFSSL_MSG("wc_Des_SetKey return error.");
    }
    else {
        /* Last incomplete block size. 0 means none over. */
        int    lb_sz = length % DES_BLOCK_SIZE;
        /* Length of data that is a multiple of a block. */
        word32 len   = (word32)(length - lb_sz);

        if (enc == WC_DES_ENCRYPT) {
            /* Encrypt full blocks into output. */
            wc_Des_CbcEncrypt(des, output, input, len);
            if (lb_sz != 0) {
                /* Create a 0 padded block from remaining bytes. */
                XMEMSET(lastBlock, 0, DES_BLOCK_SIZE);
                XMEMCPY(lastBlock, input + len, lb_sz);
                /* Encrypt last block into output. */
                wc_Des_CbcEncrypt(des, output + len, lastBlock,
                    (word32)DES_BLOCK_SIZE);
            }
        }
        else {
            /* Decrypt full blocks into output. */
            wc_Des_CbcDecrypt(des, output, input, len);
            if (lb_sz != 0) {
                /* Decrypt the last block that is not going to be full size. */
                wc_Des_CbcDecrypt(des, lastBlock, input + len,
                    (word32)DES_BLOCK_SIZE);
                /* Copy out the required amount of the decrypted block. */
                XMEMCPY(output + len, lastBlock, lb_sz);
            }
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(des, NULL, DYNAMIC_TYPE_CIPHER);
#endif
}

/* Encrypt/decrypt data with DES-CBC. Sets the IV for following operation.
 *
 * TODO: OpenSSL expects a length that is a multiple of the block size but
 *       we are padding the last block. This is not a padding API.
 * TODO: Validate parameters?
 *
 * @param [in]      input     Data to encipher.
 * @param [out]     output    Enciphered data.
 * @param [in]      length    Length of data to encipher.
 * @param [in]      schedule  Key schedule.
 * @param [in, out] ivec      IV for CBC operation.
 * @param [in]      enc       Whether to encrypt.
 */
void wolfSSL_DES_ncbc_encrypt(const unsigned char* input, unsigned char* output,
    long length, WOLFSSL_DES_key_schedule* schedule, WOLFSSL_DES_cblock* ivec,
    int enc)
{
    unsigned char tmp[DES_IV_SIZE];
    /* Calculate length to a multiple of block size. */
    size_t offset = (size_t)length;

    WOLFSSL_ENTER("wolfSSL_DES_ncbc_encrypt");

    offset = (offset + DES_BLOCK_SIZE - 1) / DES_BLOCK_SIZE;
    offset *= DES_BLOCK_SIZE;
    offset -= DES_BLOCK_SIZE;
    if (enc == WC_DES_ENCRYPT) {
        /* Encrypt data. */
        wolfSSL_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
        /* Use last encrypted block as new IV. */
        XMEMCPY(ivec, output + offset, DES_IV_SIZE);
    }
    else {
        /* Get last encrypted block for new IV. */
        XMEMCPY(tmp, input + offset, DES_IV_SIZE);
        /* Decrypt data. */
        wolfSSL_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
        /* Use last encrypted block as new IV. */
        XMEMCPY(ivec, tmp, DES_IV_SIZE);
    }
}

/* Encrypt/decrypt data with DES-CBC.
 *
 * WOLFSSL_DES_key_schedule is an unsigned char array of size 8.
 *
 * TODO: OpenSSL expects a length that is a multiple of the block size but
 *       we are padding the last block. This is not a padding API.
 * TODO: Validate parameters?
 *
 * @param [in]      input     Data to encipher.
 * @param [out]     output    Enciphered data.
 * @param [in]      length    Length of data to encipher.
 * @param [in]      schedule  Key schedule.
 * @param [in, out] ivec      IV for CBC operation.
 * @param [in]      enc       Whether to encrypt.
 */
void wolfSSL_DES_ede3_cbc_encrypt(const unsigned char* input,
    unsigned char* output, long sz, WOLFSSL_DES_key_schedule* ks1,
    WOLFSSL_DES_key_schedule* ks2, WOLFSSL_DES_key_schedule* ks3,
    WOLFSSL_DES_cblock* ivec, int enc)
{
#ifdef WOLFSSL_SMALL_STACK
    Des3* des3;
#else
    Des3  des3[1];
#endif

    WOLFSSL_ENTER("wolfSSL_DES_ede3_cbc_encrypt");

#ifdef WOLFSSL_SMALL_STACK
    des3 = (Des3*)XMALLOC(sizeof(Des3), NULL, DYNAMIC_TYPE_CIPHER);
    if (des3 == NULL) {
        WOLFSSL_MSG("Failed to allocate memory for Des3 object");
        sz = 0;
    }
#endif

    if (sz > 0) {
        int    ret;
        byte   key[DES3_KEY_SIZE];
        byte   lastBlock[DES_BLOCK_SIZE];
        int    lb_sz;
        word32 len;

        /* Copy the three keys into the buffer for wolfCrypt DES. */
        XMEMCPY(key + 0 * DES_BLOCK_SIZE, *ks1, DES_BLOCK_SIZE);
        XMEMCPY(key + 1 * DES_BLOCK_SIZE, *ks2, DES_BLOCK_SIZE);
        XMEMCPY(key + 2 * DES_BLOCK_SIZE, *ks3, DES_BLOCK_SIZE);

        /* Last incomplete block size. 0 means none over. */
        lb_sz = sz % DES_BLOCK_SIZE;
        /* Length of data that is a multiple of a block. */
        len   = (word32)(sz - lb_sz);

        /* Initialize wolfCrypt DES3 object. */
        XMEMSET(des3, 0, sizeof(Des3));
        ret = wc_Des3Init(des3, NULL, INVALID_DEVID);
        (void)ret;

        if (enc == WC_DES_ENCRYPT) {
            /* Initialize wolfCrypt DES3 object. */
            if (wc_Des3_SetKey(des3, key, (const byte*)ivec, DES_ENCRYPTION)
                    == 0) {
                /* Encrypt full blocks into output. */
                ret = wc_Des3_CbcEncrypt(des3, output, input, len);
                (void)ret;
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &des3->asyncDev, WC_ASYNC_FLAG_NONE);
                (void)ret;
            #endif
                if (lb_sz != 0) {
                    /* Create a 0 padded block from remaining bytes. */
                    XMEMSET(lastBlock, 0, DES_BLOCK_SIZE);
                    XMEMCPY(lastBlock, input + len, lb_sz);
                    /* Encrypt last block into output. */
                    ret = wc_Des3_CbcEncrypt(des3, output + len, lastBlock,
                        (word32)DES_BLOCK_SIZE);
                    (void)ret;
                #if defined(WOLFSSL_ASYNC_CRYPT)
                    ret = wc_AsyncWait(ret, &des3->asyncDev,
                        WC_ASYNC_FLAG_NONE);
                    (void)ret;
                #endif
                    /* Copy the last encrypted block as IV for next decrypt. */
                    XMEMCPY(ivec, output + len, DES_BLOCK_SIZE);
                }
                else {
                    /* Copy the last encrypted block as IV for next decrypt. */
                    XMEMCPY(ivec, output + len - DES_BLOCK_SIZE,
                        DES_BLOCK_SIZE);
                }
            }
        }
        else {
            /* Initialize wolfCrypt DES3 object. */
            if (wc_Des3_SetKey(des3, key, (const byte*)ivec, DES_DECRYPTION)
                    == 0) {
                /* Copy the last encrypted block as IV for next decrypt. */
                if (lb_sz != 0) {
                    XMEMCPY(ivec, input + len, DES_BLOCK_SIZE);
                }
                else {
                    XMEMCPY(ivec, input + len - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
                }
                /* Decrypt full blocks into output. */
                ret = wc_Des3_CbcDecrypt(des3, output, input, len);
                (void)ret;
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &des3->asyncDev, WC_ASYNC_FLAG_NONE);
                (void)ret;
            #endif
                if (lb_sz != 0) {
                   /* Decrypt the last block that is not going to be full size.
                    */
                    ret = wc_Des3_CbcDecrypt(des3, lastBlock, input + len,
                        (word32)DES_BLOCK_SIZE);
                    (void)ret;
                #if defined(WOLFSSL_ASYNC_CRYPT)
                    ret = wc_AsyncWait(ret, &des3->asyncDev,
                        WC_ASYNC_FLAG_NONE);
                    (void)ret;
                #endif
                    /* Copy out the required amount of the decrypted block. */
                    XMEMCPY(output + len, lastBlock, lb_sz);
                }
            }
        }
        wc_Des3Free(des3);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(des3, NULL, DYNAMIC_TYPE_CIPHER);
#endif
}

#ifdef WOLFSSL_DES_ECB
/* Encrypt or decrypt input message desa with key and get output in desb.
 *
 * @param [in]  in   Block to encipher with DES-ECB.
 * @param [out] out  Enciphered block.
 * @param [in]  key  DES key schedule.
 * @param [in]  enc  Whether to encrypt.
 */
void wolfSSL_DES_ecb_encrypt(WOLFSSL_DES_cblock* in, WOLFSSL_DES_cblock* out,
    WOLFSSL_DES_key_schedule* key, int enc)
{
#ifdef WOLFSSL_SMALL_STACK
    Des* des = NULL;
#else
    Des  des[1];
#endif

    WOLFSSL_ENTER("wolfSSL_DES_ecb_encrypt");

    /* Validate parameters. */
    if ((in == NULL) || (out == NULL) || (key == NULL) ||
           ((enc != WC_DES_ENCRYPT) && (enc != WC_DES_DECRYPT))) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_DES_ecb_encrypt");
    }
#ifdef WOLFSSL_SMALL_STACK
    else if ((des = (Des*)XMALLOC(sizeof(Des), NULL, DYNAMIC_TYPE_CIPHER))
             == NULL)
    {
        WOLFSSL_MSG("Failed to allocate memory for Des object");
    }
#endif
    /* Set key in wolfCrypt DES object for encryption or decryption.
     * WC_DES_ENCRYPT = 1, wolfSSL DES_ENCRYPTION = 0.
     * WC_DES_DECRYPT = 0, wolfSSL DES_DECRYPTION = 1.
     */
    else if (wc_Des_SetKey(des, (const byte*)key, NULL, !enc) != 0) {
        WOLFSSL_MSG("wc_Des_SetKey return error.");
    }
    else if (enc == WC_DES_ENCRYPT) {
        /* Encrypt a block with wolfCrypt DES object. */
        if (wc_Des_EcbEncrypt(des, (byte*)out, (const byte*)in, DES_KEY_SIZE)
                != 0) {
            WOLFSSL_MSG("wc_Des_EcbEncrypt return error.");
        }
    }
    else {
        /* Decrypt a block with wolfCrypt DES object. */
        if (wc_Des_EcbDecrypt(des, (byte*)out, (const byte*)in, DES_KEY_SIZE)
                != 0) {
            WOLFSSL_MSG("wc_Des_EcbDecrpyt return error.");
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(des, NULL, DYNAMIC_TYPE_CIPHER);
#endif
}
#endif
#endif /* NO_DES3 */
#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF DES API
 ******************************************************************************/

/*******************************************************************************
 * START OF AES API
 ******************************************************************************/

#ifdef OPENSSL_EXTRA

#if !defined(NO_AES) && !defined(WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API)

/* Sets the key into the AES key object for encryption or decryption.
 *
 * TODO: check bits value?
 *
 * @param [in]  key   Key data.
 * @param [in]  bits  Number of bits in key.
 * @param [out] aes   AES key object.
 * @param [in]  enc   Whether to encrypt. AES_ENCRYPTION or AES_DECRYPTION.
 * @return  0 on success.
 * @return  -1 when key or aes is NULL.
 * @return  -1 when setting key with wolfCrypt fails.
 */
static int wolfssl_aes_set_key(const unsigned char *key, const int bits,
    WOLFSSL_AES_KEY *aes, int enc)
{
    wc_static_assert(sizeof(WOLFSSL_AES_KEY) >= sizeof(Aes));

    /* Validate parameters. */
    if ((key == NULL) || (aes == NULL)) {
        WOLFSSL_MSG("Null argument passed in");
        return WOLFSSL_FATAL_ERROR;
    }

    XMEMSET(aes, 0, sizeof(WOLFSSL_AES_KEY));

    if (wc_AesInit((Aes*)aes, NULL, INVALID_DEVID) != 0) {
        WOLFSSL_MSG("Error in initting AES key");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wc_AesSetKey((Aes*)aes, key, ((bits)/8), NULL, enc) != 0) {
        WOLFSSL_MSG("Error in setting AES key");
        return WOLFSSL_FATAL_ERROR;
    }
    return 0;
}

/* Sets the key into the AES key object for encryption.
 *
 * @param [in]  key   Key data.
 * @param [in]  bits  Number of bits in key.
 * @param [out] aes   AES key object.
 * @return  0 on success.
 * @return  -1 when key or aes is NULL.
 * @return  -1 when setting key with wolfCrypt fails.
 */
int wolfSSL_AES_set_encrypt_key(const unsigned char *key, const int bits,
    WOLFSSL_AES_KEY *aes)
{
    WOLFSSL_ENTER("wolfSSL_AES_set_encrypt_key");

    return wolfssl_aes_set_key(key, bits, aes, AES_ENCRYPTION);
}

/* Sets the key into the AES key object for decryption.
 *
 * @param [in]  key   Key data.
 * @param [in]  bits  Number of bits in key.
 * @param [out] aes   AES key object.
 * @return  0 on success.
 * @return  -1 when key or aes is NULL.
 * @return  -1 when setting key with wolfCrypt fails.
 */
int wolfSSL_AES_set_decrypt_key(const unsigned char *key, const int bits,
    WOLFSSL_AES_KEY *aes)
{
    WOLFSSL_ENTER("wolfSSL_AES_set_decrypt_key");

    return wolfssl_aes_set_key(key, bits, aes, AES_DECRYPTION);
}

#ifdef WOLFSSL_AES_DIRECT
/* Encrypt a 16-byte block of data using AES-ECB.
 *
 * wolfSSL_AES_set_encrypt_key() must have been called.
 *
 * #input must contain WC_AES_BLOCK_SIZE bytes of data.
 * #output must be a buffer at least WC_AES_BLOCK_SIZE bytes in length.
 *
 * @param [in]  input   Data to encrypt.
 * @param [out] output  Encrypted data.
 * @param [in]  key     AES key to use for encryption.
 */
void wolfSSL_AES_encrypt(const unsigned char* input, unsigned char* output,
    WOLFSSL_AES_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_AES_encrypt");

    /* Validate parameters. */
    if ((input == NULL) || (output == NULL) || (key == NULL)) {
        WOLFSSL_MSG("Null argument passed in");
    }
    else
#if !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)) \
    || defined(WOLFSSL_LINUXKM))
    /* Encrypt a block with wolfCrypt AES. */
    if (wc_AesEncryptDirect((Aes*)key, output, input) != 0) {
        WOLFSSL_MSG("wc_AesEncryptDirect failed");
    }
#else
    {
        /* Encrypt a block with wolfCrypt AES. */
        wc_AesEncryptDirect((Aes*)key, output, input);
    }
#endif
}


/* Decrypt a 16-byte block of data using AES-ECB.
 *
 * wolfSSL_AES_set_decrypt_key() must have been called.
 *
 * #input must contain WC_AES_BLOCK_SIZE bytes of data.
 * #output must be a buffer at least WC_AES_BLOCK_SIZE bytes in length.
 *
 * @param [in]  input   Data to decrypt.
 * @param [out] output  Decrypted data.
 * @param [in]  key     AES key to use for encryption.
 */
void wolfSSL_AES_decrypt(const unsigned char* input, unsigned char* output,
    WOLFSSL_AES_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_AES_decrypt");

    /* Validate parameters. */
    if ((input == NULL) || (output == NULL) || (key == NULL)) {
        WOLFSSL_MSG("Null argument passed in");
    }
    else
#if !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION3_GE(5,3,0)))
    /* Decrypt a block with wolfCrypt AES. */
    if (wc_AesDecryptDirect((Aes*)key, output, input) != 0) {
        WOLFSSL_MSG("wc_AesDecryptDirect failed");
    }
#else
    {
        /* Decrypt a block with wolfCrypt AES. */
        wc_AesDecryptDirect((Aes*)key, output, input);
    }
#endif
}
#endif /* WOLFSSL_AES_DIRECT */



#ifdef HAVE_AES_ECB
/* Encrypt/decrypt a 16-byte block of data using AES-ECB.
 *
 * wolfSSL_AES_set_encrypt_key() or wolfSSL_AES_set_decrypt_key ()must have been
 * called.
 *
 * #input must contain WC_AES_BLOCK_SIZE bytes of data.
 * #output must be a buffer at least WC_AES_BLOCK_SIZE bytes in length.
 *
 * @param [in]  in   Data to encipher.
 * @param [out] out  Enciphered data.
 * @param [in]  key  AES key to use for encryption/decryption.
 * @param [in]  enc  Whether to encrypt.
 *                   AES_ENCRPT for encryption, AES_DECRYPTION for decryption.
 */
void wolfSSL_AES_ecb_encrypt(const unsigned char *in, unsigned char* out,
    WOLFSSL_AES_KEY *key, const int enc)
{
    WOLFSSL_ENTER("wolfSSL_AES_ecb_encrypt");

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL) || (out == NULL)) {
        WOLFSSL_MSG("Error, Null argument passed in");
    }
    else if (enc == AES_ENCRYPTION) {
        /* Encrypt block. */
        if (wc_AesEcbEncrypt((Aes*)key, out, in, WC_AES_BLOCK_SIZE) != 0) {
            WOLFSSL_MSG("Error with AES CBC encrypt");
        }
    }
    else {
    #ifdef HAVE_AES_DECRYPT
        /* Decrypt block. */
        if (wc_AesEcbDecrypt((Aes*)key, out, in, WC_AES_BLOCK_SIZE) != 0) {
            WOLFSSL_MSG("Error with AES CBC decrypt");
        }
    #else
        WOLFSSL_MSG("AES decryption not compiled in");
    #endif
    }
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
/* Encrypt/decrypt data with IV using AES-CBC.
 *
 * wolfSSL_AES_set_encrypt_key() or wolfSSL_AES_set_decrypt_key() must have been
 * called.
 *
 * @param [in]       in   Data to encipher.
 * @param [out]      out  Enciphered data.
 * @param [in]       len  Length of data to encipher.
 * @param [in]       key  AES key to use for encryption/decryption.
 * @param [in, out]  iv   Initialization Vector (IV) of CBC mode.
 *                        On in, used with first block.
 *                        On out, IV for further operations.
 * @param [in]       enc  Whether to encrypt.
 *                   AES_ENCRPT for encryption, AES_DECRYPTION for decryption.
 */
void wolfSSL_AES_cbc_encrypt(const unsigned char *in, unsigned char* out,
    size_t len, WOLFSSL_AES_KEY *key, unsigned char* iv, const int enc)
{
    WOLFSSL_ENTER("wolfSSL_AES_cbc_encrypt");

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL) || (out == NULL) || (iv == NULL) ||
            (len == 0)) {
        WOLFSSL_MSG("Error, Null argument passed in");
    }
    /* Set IV for operation. */
    else {
        int ret;
        Aes* aes = (Aes*)key;

        if ((ret = wc_AesSetIV(aes, (const byte*)iv)) != 0) {
            WOLFSSL_MSG("Error with setting iv");
        }
        else if (enc == AES_ENCRYPTION) {
            /* Encrypt with wolfCrypt AES object. */
            if ((ret = wc_AesCbcEncrypt(aes, out, in, (word32)len)) != 0) {
                WOLFSSL_MSG("Error with AES CBC encrypt");
            }
        }
        else {
            /* Decrypt with wolfCrypt AES object. */
            if ((ret = wc_AesCbcDecrypt(aes, out, in, (word32)len)) != 0) {
                WOLFSSL_MSG("Error with AES CBC decrypt");
            }
        }

        if (ret == 0) {
            /* Get IV for next operation. */
            XMEMCPY(iv, (byte*)(aes->reg), WC_AES_BLOCK_SIZE);
        }
    }
}
#endif /* HAVE_AES_CBC */


/* Encrypt/decrypt data with IV using AES-CFB.
 *
 * wolfSSL_AES_set_encrypt_key() must have been called.
 *
 * @param [in]       in   Data to encipher.
 * @param [out]      out  Enciphered data.
 * @param [in]       len  Length of data to encipher.
 * @param [in]       key  AES key to use for encryption/decryption.
 * @param [in, out]  iv   Initialization Vector (IV) of CFB mode.
 *                        On in, used with first block.
 *                        On out, IV for further operations.
 * @param [out]      num  Number of bytes used from last incomplete block.
 * @param [in]       enc  Whether to encrypt.
 *                   AES_ENCRPT for encryption, AES_DECRYPTION for decryption.
 */
void wolfSSL_AES_cfb128_encrypt(const unsigned char *in, unsigned char* out,
    size_t len, WOLFSSL_AES_KEY *key, unsigned char* iv, int* num, const int enc)
{
#ifndef WOLFSSL_AES_CFB
    WOLFSSL_MSG("CFB mode not enabled please use macro WOLFSSL_AES_CFB");

    (void)in;
    (void)out;
    (void)len;
    (void)key;
    (void)iv;
    (void)num;
    (void)enc;
#else
    WOLFSSL_ENTER("wolfSSL_AES_cfb_encrypt");

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL) || (out == NULL) || (iv == NULL)) {
        WOLFSSL_MSG("Error, Null argument passed in");
    }
    else {
        int ret;
        Aes* aes = (Aes*)key;

        /* Copy the IV directly into reg here because wc_AesSetIV clears
         * leftover bytes field "left", and this function relies on the leftover
         * bytes being preserved between calls.
         */
        XMEMCPY(aes->reg, iv, WC_AES_BLOCK_SIZE);

        if (enc == AES_ENCRYPTION) {
            /* Encrypt data with AES-CFB. */
            if ((ret = wc_AesCfbEncrypt(aes, out, in, (word32)len)) != 0) {
                WOLFSSL_MSG("Error with AES CBC encrypt");
            }
        }
        else {
            /* Decrypt data with AES-CFB. */
            if ((ret = wc_AesCfbDecrypt(aes, out, in, (word32)len)) != 0) {
                WOLFSSL_MSG("Error with AES CBC decrypt");
            }
        }

        if (ret == 0) {
            /* Copy IV out after operation. */
            XMEMCPY(iv, (byte*)(aes->reg), WC_AES_BLOCK_SIZE);

            /* Store number of left over bytes to num. */
            if (num != NULL) {
                *num = (WC_AES_BLOCK_SIZE - aes->left) % WC_AES_BLOCK_SIZE;
            }
        }
    }
#endif /* WOLFSSL_AES_CFB */
}

/* wc_AesKey*Wrap_ex API not available in FIPS and SELFTEST */
#if defined(HAVE_AES_KEYWRAP) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
/* Wrap (encrypt) a key using RFC3394 AES key wrap.
 *
 * @param [in, out] key   AES key.
 * @param [in]      iv    Initialization vector used by encryption mode.
 * @param [out]     out   Wrapped key.
 * @param [in]      in    Key data to wrap.
 * @param [in]      inSz  Length of key to wrap in bytes.
 * @return  Length of encrypted key in bytes.
 * @return  0 when key, iv, out or in is NULL.
 * @return  0 when key length is not valid.
 */
int wolfSSL_AES_wrap_key(WOLFSSL_AES_KEY *key, const unsigned char *iv,
    unsigned char *out, const unsigned char *in, unsigned int inSz)
{
    int ret = 0;
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_AES_wrap_key");

    /* Validate parameters. */
    if ((out == NULL) || (in == NULL)) {
        WOLFSSL_MSG("Error, Null argument passed in");
        ret = BAD_FUNC_ARG;
    }

    /* Wrap key. */
    if ((ret == 0) && ((ret = wc_AesKeyWrap_ex((Aes*)key, in, inSz, out,
            inSz + KEYWRAP_BLOCK_SIZE, iv)) > 0)) {
        /* Get the length of the wrapped key. */
        len = ret;
    }

    return len;
}

/* Unwrap (decrypt) a key using RFC3394 AES key wrap.
 *
 * @param [in, out] key   AES key.
 * @param [in]      iv    Initialization vector used by decryption mode.
 * @param [out]     out   Unwrapped key.
 * @param [in]      in    Wrapped key data.
 * @param [in]      inSz  Length of wrapped key data in bytes.
 * @return  Length of decrypted key in bytes.
 * @return  0 when key, iv, out or in is NULL.
 * @return  0 when wrapped key data length is not valid.
 */
int wolfSSL_AES_unwrap_key(WOLFSSL_AES_KEY *key, const unsigned char *iv,
    unsigned char *out, const unsigned char *in, unsigned int inSz)
{
    int ret = 0;
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_AES_wrap_key");

    /* Validate parameters. */
    if ((out == NULL) || (in == NULL)) {
        WOLFSSL_MSG("Error, Null argument passed in");
        ret = BAD_FUNC_ARG;
    }

    /* Unwrap key. */
    if ((ret == 0) && ((ret = wc_AesKeyUnWrap_ex((Aes*)key, in, inSz, out,
            inSz + KEYWRAP_BLOCK_SIZE, iv)) > 0)) {
        /* Get the length of the unwrapped key. */
        len = ret;
    }

    return len;
}
#endif /* HAVE_AES_KEYWRAP && !HAVE_FIPS && !HAVE_SELFTEST */

#ifdef HAVE_CTS
/* Ciphertext stealing encryption compatible with RFC2040 and RFC3962.
 *
 * @param [in]  in   Data to encrypt.
 * @param [out] out  Encrypted data.
 * @param [in]  len  Length of data to encrypt.
 * @param [in]  key  Symmetric key.
 * @param [in]  iv   Initialization Vector for encryption mode.
 * @param [in]  cbc  CBC mode encryption function.
 * @return  Length of encrypted data in bytes on success.
 * @return  0 when in, out, cbc, key or iv are NULL.
 * @return  0 when len is less than or equal to 16 bytes.
 */
size_t wolfSSL_CRYPTO_cts128_encrypt(const unsigned char *in,
    unsigned char *out, size_t len, const void *key, unsigned char *iv,
    WOLFSSL_CBC128_CB cbc)
{
    byte lastBlk[WOLFSSL_CTS128_BLOCK_SZ];
    int lastBlkLen = len % WOLFSSL_CTS128_BLOCK_SZ;

    WOLFSSL_ENTER("wolfSSL_CRYPTO_cts128_encrypt");

    /* Validate parameters. */
    if ((in == NULL) || (out == NULL) || (len <= WOLFSSL_CTS128_BLOCK_SZ) ||
            (cbc == NULL) || (key == NULL) || (iv == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        len = 0;
    }

    if (len > 0) {
        /* Must have a last block. */
        if (lastBlkLen == 0) {
            lastBlkLen = WOLFSSL_CTS128_BLOCK_SZ;
        }

        /* Encrypt data up to last block */
        (*cbc)(in, out, len - lastBlkLen, key, iv, AES_ENCRYPTION);

        /* Move to last block */
        in += len - lastBlkLen;
        out += len - lastBlkLen;

        /* RFC2040: Pad Pn with zeros at the end to create P of length BB. */
        XMEMCPY(lastBlk, in, lastBlkLen);
        XMEMSET(lastBlk + lastBlkLen, 0, WOLFSSL_CTS128_BLOCK_SZ - lastBlkLen);
        /* RFC2040: Select the first Ln bytes of En-1 to create Cn */
        XMEMCPY(out, out - WOLFSSL_CTS128_BLOCK_SZ, lastBlkLen);
        /* Encrypt last block. */
        (*cbc)(lastBlk, out - WOLFSSL_CTS128_BLOCK_SZ, WOLFSSL_CTS128_BLOCK_SZ,
                key, iv, AES_ENCRYPTION);
    }

    return len;
}

/* Ciphertext stealing decryption compatible with RFC2040 and RFC3962.
 *
 * @param [in]  in   Data to decrypt.
 * @param [out] out  Decrypted data.
 * @param [in]  len  Length of data to decrypt.
 * @param [in]  key  Symmetric key.
 * @param [in]  iv   Initialization Vector for decryption mode.
 * @param [in]  cbc  CBC mode encryption function.
 * @return  Length of decrypted data in bytes on success.
 * @return  0 when in, out, cbc, key or iv are NULL.
 * @return  0 when len is less than or equal to 16 bytes.
 */
size_t wolfSSL_CRYPTO_cts128_decrypt(const unsigned char *in,
    unsigned char *out, size_t len, const void *key, unsigned char *iv,
    WOLFSSL_CBC128_CB cbc)
{
    byte lastBlk[WOLFSSL_CTS128_BLOCK_SZ];
    byte prevBlk[WOLFSSL_CTS128_BLOCK_SZ];
    int lastBlkLen = len % WOLFSSL_CTS128_BLOCK_SZ;

    WOLFSSL_ENTER("wolfSSL_CRYPTO_cts128_decrypt");

    /* Validate parameters. */
    if ((in == NULL) || (out == NULL) || (len <= WOLFSSL_CTS128_BLOCK_SZ) ||
            (cbc == NULL) || (key == NULL) || (iv == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        len = 0;
    }

    if (len > 0) {
        /* Must have a last block. */
        if (lastBlkLen == 0) {
            lastBlkLen = WOLFSSL_CTS128_BLOCK_SZ;
        }

        if (len - lastBlkLen - WOLFSSL_CTS128_BLOCK_SZ != 0) {
            /* Decrypt up to last two blocks */
            (*cbc)(in, out, len - lastBlkLen - WOLFSSL_CTS128_BLOCK_SZ, key, iv,
                    AES_DECRYPTION);

            /* Move to last two blocks */
            in += len - lastBlkLen - WOLFSSL_CTS128_BLOCK_SZ;
            out += len - lastBlkLen - WOLFSSL_CTS128_BLOCK_SZ;
        }

        /* RFC2040: Decrypt Cn-1 to create Dn.
         * Use 0 buffer as IV to do straight decryption.
         * This places the Cn-1 block at lastBlk */
        XMEMSET(lastBlk, 0, WOLFSSL_CTS128_BLOCK_SZ);
        (*cbc)(in, prevBlk, WOLFSSL_CTS128_BLOCK_SZ, key, lastBlk, AES_DECRYPTION);
        /* RFC2040: Append the tail (BB minus Ln) bytes of Xn to Cn
         *          to create En. */
        XMEMCPY(prevBlk, in + WOLFSSL_CTS128_BLOCK_SZ, lastBlkLen);
        /* Cn and Cn-1 can now be decrypted */
        (*cbc)(prevBlk, out, WOLFSSL_CTS128_BLOCK_SZ, key, iv, AES_DECRYPTION);
        (*cbc)(lastBlk, lastBlk, WOLFSSL_CTS128_BLOCK_SZ, key, iv, AES_DECRYPTION);
        XMEMCPY(out + WOLFSSL_CTS128_BLOCK_SZ, lastBlk, lastBlkLen);
    }

    return len;
}
#endif /* HAVE_CTS */
#endif /* !NO_AES && !WOLFSSL_NO_OPENSSL_AES_LOW_LEVEL_API */
#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF AES API
 ******************************************************************************/

/*******************************************************************************
 * START OF RC4 API
 ******************************************************************************/

#ifdef OPENSSL_EXTRA

#ifndef NO_RC4
/* Set the key state for Arc4 key.
 *
 * @param [out] key   Arc4 key.
 * @param [in]  len   Length of key in buffer.
 * @param [in]  data  Key data buffer.
 */
void wolfSSL_RC4_set_key(WOLFSSL_RC4_KEY* key, int len,
    const unsigned char* data)
{
    wc_static_assert(sizeof(WOLFSSL_RC4_KEY) >= sizeof(Arc4));

    WOLFSSL_ENTER("wolfSSL_RC4_set_key");

    /* Validate parameters. */
    if ((key == NULL) || (len < 0) || (data == NULL)) {
        WOLFSSL_MSG("bad argument passed in");
    }
    else {
        /* Reset wolfCrypt Arc4 object. */
        XMEMSET(key, 0, sizeof(WOLFSSL_RC4_KEY));
        /* Set key into wolfCrypt Arc4 object. */
        wc_Arc4SetKey((Arc4*)key, data, (word32)len);
    }
}


/* Encrypt/decrypt with Arc4 key.
 *
 * @param [in]  len  Length of data to encrypt/decrypt.
 * @param [in]  in   Data to encrypt/decrypt.
 * @param [out] out  Enciphered data.
 */
void wolfSSL_RC4(WOLFSSL_RC4_KEY* key, size_t len, const unsigned char* in,
    unsigned char* out)
{
    WOLFSSL_ENTER("wolfSSL_RC4");

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL) || (out == NULL)) {
        WOLFSSL_MSG("Bad argument passed in");
    }
    else {
        /* Encrypt/decrypt data. */
        wc_Arc4Process((Arc4*)key, out, in, (word32)len);
    }
}
#endif /* NO_RC4 */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF RC4 API
 ******************************************************************************/

#endif /* WOLFSSL_SSL_CRYPTO_INCLUDED */

