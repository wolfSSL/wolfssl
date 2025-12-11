/* test_ossl_dgst.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/openssl/md4.h>
#include <wolfssl/openssl/md5.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/sha3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_dgst.h>

/*******************************************************************************
 * Digest OpenSSL compatibility API Testing
 ******************************************************************************/

int test_wolfSSL_MD4(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_MD4)
    MD4_CTX md4;
    unsigned char out[16]; /* MD4_DIGEST_SIZE */
    const char* msg = "12345678901234567890123456789012345678901234567890123456"
                      "789012345678901234567890";
    const char* test = "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f"
                       "\xcc\x05\x36";
    int msgSz = (int)XSTRLEN(msg);


    XMEMSET(out, 0, sizeof(out));
    MD4_Init(&md4);
    MD4_Update(&md4, (const void*)msg, (word32)msgSz);
    MD4_Final(out, &md4);
    ExpectIntEQ(XMEMCMP(out, test, sizeof(out)), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_MD5(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_MD5)
    byte input1[] = "";
    byte input2[] = "message digest";
    byte hash[WC_MD5_DIGEST_SIZE];
    unsigned char output1[] =
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";
    unsigned char output2[] =
        "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0";
    WOLFSSL_MD5_CTX md5;

    XMEMSET(&md5, 0, sizeof(md5));

    /* Test cases for illegal parameters */
    ExpectIntEQ(MD5_Init(NULL), 0);
    ExpectIntEQ(MD5_Init(&md5), 1);
    ExpectIntEQ(MD5_Update(NULL, input1, 0), 0);
    ExpectIntEQ(MD5_Update(NULL, NULL, 0), 0);
    ExpectIntEQ(MD5_Update(&md5, NULL, 1), 0);
    ExpectIntEQ(MD5_Final(NULL, &md5), 0);
    ExpectIntEQ(MD5_Final(hash, NULL), 0);
    ExpectIntEQ(MD5_Final(NULL, NULL), 0);

    /* Init MD5 CTX */
    ExpectIntEQ(wolfSSL_MD5_Init(&md5), 1);
    ExpectIntEQ(wolfSSL_MD5_Update(&md5, input1, XSTRLEN((const char*)&input1)),
        1);
    ExpectIntEQ(wolfSSL_MD5_Final(hash, &md5), 1);
    ExpectIntEQ(XMEMCMP(&hash, output1, WC_MD5_DIGEST_SIZE), 0);

    /* Init MD5 CTX */
    ExpectIntEQ(wolfSSL_MD5_Init(&md5), 1);
    ExpectIntEQ(wolfSSL_MD5_Update(&md5, input2,
        (int)XSTRLEN((const char*)input2)), 1);
    ExpectIntEQ(wolfSSL_MD5_Final(hash, &md5), 1);
    ExpectIntEQ(XMEMCMP(&hash, output2, WC_MD5_DIGEST_SIZE), 0);
#if !defined(NO_OLD_NAMES) && \
  (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2)))
    ExpectPtrNE(MD5(NULL, 1, (byte*)&hash), &hash);
    ExpectPtrEq(MD5(input1, 0, (byte*)&hash), &hash);
    ExpectPtrNE(MD5(input1, 1, NULL), NULL);
    ExpectPtrNE(MD5(NULL, 0, NULL), NULL);

    ExpectPtrEq(MD5(input1, (int)XSTRLEN((const char*)&input1), (byte*)&hash),
        &hash);
    ExpectIntEQ(XMEMCMP(&hash, output1, WC_MD5_DIGEST_SIZE), 0);

    ExpectPtrEq(MD5(input2, (int)XSTRLEN((const char*)&input2), (byte*)&hash),
        &hash);
    ExpectIntEQ(XMEMCMP(&hash, output2, WC_MD5_DIGEST_SIZE), 0);
    {
        byte data[] = "Data to be hashed.";
        XMEMSET(hash, 0, WC_MD5_DIGEST_SIZE);

        ExpectNotNull(MD5(data, sizeof(data), NULL));
        ExpectNotNull(MD5(data, sizeof(data), hash));
        ExpectNotNull(MD5(NULL, 0, hash));
        ExpectNull(MD5(NULL, sizeof(data), hash));
    }
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_MD5_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_MD5)
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_MD5_BLOCK_SIZE];
    word32 sLen = 0;
#ifdef BIG_ENDIAN_ORDER
    unsigned char output1[] =
        "\x03\x1f\x1d\xac\x6e\xa5\x8e\xd0\x1f\xab\x67\xb7\x74\x31\x77\x91";
    unsigned char output2[] =
        "\xef\xd3\x79\x8d\x67\x17\x25\x90\xa4\x13\x79\xc7\xe3\xa7\x7b\xbc";
#else
    unsigned char output1[] =
        "\xac\x1d\x1f\x03\xd0\x8e\xa5\x6e\xb7\x67\xab\x1f\x91\x77\x31\x74";
    unsigned char output2[] =
        "\x8d\x79\xd3\xef\x90\x25\x17\x67\xc7\x79\x13\xa4\xbc\x7b\xa7\xe3";
#endif

    union {
        wc_Md5 native;
        MD5_CTX compat;
    } md5;

    XMEMSET(&md5.compat, 0, sizeof(md5.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(MD5_Transform(NULL, NULL), 0);
    ExpectIntEQ(MD5_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(MD5_Transform(&md5.compat, NULL), 0);
    ExpectIntEQ(wc_Md5Transform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Md5Transform(NULL, (const byte*)&input1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Md5Transform(&md5.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init MD5 CTX */
    ExpectIntEQ(wolfSSL_MD5_Init(&md5.compat), 1);
    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(MD5_Transform(&md5.compat, (const byte*)&local[0]), 1);

    ExpectIntEQ(XMEMCMP(md5.native.digest, output1, WC_MD5_DIGEST_SIZE), 0);

    /* Init MD5 CTX */
    ExpectIntEQ(MD5_Init(&md5.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_MD5_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(MD5_Transform(&md5.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(md5.native.digest, output2, WC_MD5_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(HAVE_SELFTEST)
    #if !defined(NO_SHA) && defined(NO_OLD_SHA_NAMES) && \
        (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2))
    {
        const unsigned char in[] = "abc";
        unsigned char expected[] = "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E"
                                   "\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D";
        unsigned char out[WC_SHA_DIGEST_SIZE];
        unsigned char* p = NULL;
        WOLFSSL_SHA_CTX sha;

        XMEMSET(out, 0, WC_SHA_DIGEST_SIZE);
        ExpectNotNull(SHA1(in, XSTRLEN((char*)in), out));
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA_DIGEST_SIZE), 0);

        /* SHA interface test */
        XMEMSET(out, 0, WC_SHA_DIGEST_SIZE);

        ExpectNull(SHA(NULL, XSTRLEN((char*)in), out));
        ExpectNotNull(SHA(in, 0, out));
        ExpectNotNull(SHA(in, XSTRLEN((char*)in), NULL));
        ExpectNotNull(SHA(NULL, 0, out));
        ExpectNotNull(SHA(NULL, 0, NULL));

        ExpectNotNull(SHA(in, XSTRLEN((char*)in), out));
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA_DIGEST_SIZE), 0);
        ExpectNotNull(p = SHA(in, XSTRLEN((char*)in), NULL));
        ExpectIntEQ(XMEMCMP(p, expected, WC_SHA_DIGEST_SIZE), 0);

        ExpectIntEQ(wolfSSL_SHA_Init(&sha), 1);
        ExpectIntEQ(wolfSSL_SHA_Update(&sha, in, XSTRLEN((char*)in)), 1);
        ExpectIntEQ(wolfSSL_SHA_Final(out, &sha), 1);
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA_DIGEST_SIZE), 0);

        ExpectIntEQ(wolfSSL_SHA1_Init(&sha), 1);
        ExpectIntEQ(wolfSSL_SHA1_Update(&sha, in, XSTRLEN((char*)in)), 1);
        ExpectIntEQ(wolfSSL_SHA1_Final(out, &sha), 1);
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA_DIGEST_SIZE), 0);
    }
    #endif

    #if !defined(NO_SHA256)
    {
        const unsigned char in[] = "abc";
        unsigned char expected[] =
            "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
            "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
            "\x15\xAD";
        unsigned char out[WC_SHA256_DIGEST_SIZE];
        unsigned char* p = NULL;

        XMEMSET(out, 0, WC_SHA256_DIGEST_SIZE);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(SHA256(in, XSTRLEN((char*)in), out));
#else
        ExpectNotNull(wolfSSL_SHA256(in, XSTRLEN((char*)in), out));
#endif
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA256_DIGEST_SIZE), 0);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(p = SHA256(in, XSTRLEN((char*)in), NULL));
#else
        ExpectNotNull(p = wolfSSL_SHA256(in, XSTRLEN((char*)in), NULL));
#endif
        ExpectIntEQ(XMEMCMP(p, expected, WC_SHA256_DIGEST_SIZE), 0);
    }
    #endif

    #if defined(WOLFSSL_SHA384)
    {
        const unsigned char in[] = "abc";
        unsigned char expected[] =
            "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50"
            "\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff"
            "\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34"
            "\xc8\x25\xa7";
        unsigned char out[WC_SHA384_DIGEST_SIZE];
        unsigned char* p = NULL;

        XMEMSET(out, 0, WC_SHA384_DIGEST_SIZE);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(SHA384(in, XSTRLEN((char*)in), out));
#else
        ExpectNotNull(wolfSSL_SHA384(in, XSTRLEN((char*)in), out));
#endif
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA384_DIGEST_SIZE), 0);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(p = SHA384(in, XSTRLEN((char*)in), NULL));
#else
        ExpectNotNull(p = wolfSSL_SHA384(in, XSTRLEN((char*)in), NULL));
#endif
        ExpectIntEQ(XMEMCMP(p, expected, WC_SHA384_DIGEST_SIZE), 0);
    }
    #endif

    #if defined(WOLFSSL_SHA512)
    {
        const unsigned char in[] = "abc";
        unsigned char expected[] =
            "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
            "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55"
            "\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3"
            "\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f"
            "\xa5\x4c\xa4\x9f";
        unsigned char out[WC_SHA512_DIGEST_SIZE];
        unsigned char* p = NULL;

        XMEMSET(out, 0, WC_SHA512_DIGEST_SIZE);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(SHA512(in, XSTRLEN((char*)in), out));
#else
        ExpectNotNull(wolfSSL_SHA512(in, XSTRLEN((char*)in), out));
#endif
        ExpectIntEQ(XMEMCMP(out, expected, WC_SHA512_DIGEST_SIZE), 0);
#if !defined(NO_OLD_NAMES) && !defined(HAVE_FIPS)
        ExpectNotNull(p = SHA512(in, XSTRLEN((char*)in), NULL));
#else
        ExpectNotNull(p = wolfSSL_SHA512(in, XSTRLEN((char*)in), NULL));
#endif
        ExpectIntEQ(XMEMCMP(p, expected, WC_SHA512_DIGEST_SIZE), 0);
    }
    #endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA)
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_SHA_BLOCK_SIZE];
    word32 sLen = 0;
#ifdef BIG_ENDIAN_ORDER
    unsigned char output1[] =
        "\x92\xb4\x04\xe5\x56\x58\x8c\xed\x6c\x1a\xcd\x4e\xbf\x05\x3f\x68"
        "\x09\xf7\x3a\x93";
    unsigned char output2[] =
        "\x97\xb2\x74\x8b\x4f\x5b\xbc\xca\x5b\xc0\xe6\xea\x2d\x40\xb4\xa0"
        "\x7c\x6e\x08\xb8";
#else
    unsigned char output1[] =
        "\xe5\x04\xb4\x92\xed\x8c\x58\x56\x4e\xcd\x1a\x6c\x68\x3f\x05\xbf"
        "\x93\x3a\xf7\x09";
    unsigned char output2[] =
        "\x8b\x74\xb2\x97\xca\xbc\x5b\x4f\xea\xe6\xc0\x5b\xa0\xb4\x40\x2d"
        "\xb8\x08\x6e\x7c";
#endif

    union {
        wc_Sha native;
        SHA_CTX compat;
    } sha;
    union {
        wc_Sha native;
        SHA_CTX compat;
    } sha1;

    XMEMSET(&sha.compat, 0, sizeof(sha.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(SHA_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA_Transform(&sha.compat, NULL), 0);
    ExpectIntEQ(SHA1_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA1_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA1_Transform(&sha.compat, NULL), 0);
    ExpectIntEQ(wc_ShaTransform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ShaTransform(NULL, (const byte*)&input1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ShaTransform(&sha.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init SHA CTX */
    ExpectIntEQ(SHA_Init(&sha.compat), 1);
    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA_Transform(&sha.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha.native.digest, output1, WC_SHA_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA_Final(local, &sha.compat), 1); /* frees resources */

    /* Init SHA CTX */
    ExpectIntEQ(SHA_Init(&sha.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA_Transform(&sha.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha.native.digest, output2, WC_SHA_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA_Final(local, &sha.compat), 1); /* frees resources */

    /* SHA1 */
    XMEMSET(local, 0, WC_SHA_BLOCK_SIZE);
    /* Init SHA CTX */
    ExpectIntEQ(SHA1_Init(&sha1.compat), 1);
    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA1_Transform(&sha1.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha1.native.digest, output1, WC_SHA_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA1_Final(local, &sha1.compat), 1); /* frees resources */

    /* Init SHA CTX */
    ExpectIntEQ(SHA1_Init(&sha1.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA1_Transform(&sha1.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha1.native.digest, output2, WC_SHA_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA_Final(local, &sha1.compat), 1); /* frees resources */
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA224(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA224) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2))
    unsigned char input[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char output[] =
         "\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01"
         "\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25";
    size_t inLen;
    byte hash[WC_SHA224_DIGEST_SIZE];
    unsigned char* p = NULL;

    inLen  = XSTRLEN((char*)input);

    XMEMSET(hash, 0, WC_SHA224_DIGEST_SIZE);

    ExpectNull(SHA224(NULL, inLen, hash));
    ExpectNotNull(SHA224(input, 0, hash));
    ExpectNotNull(SHA224(input, inLen, NULL));
    ExpectNotNull(SHA224(NULL, 0, hash));
    ExpectNotNull(SHA224(NULL, 0, NULL));

    ExpectNotNull(SHA224(input, inLen, hash));
    ExpectIntEQ(XMEMCMP(hash, output, WC_SHA224_DIGEST_SIZE), 0);
    ExpectNotNull(p = SHA224(input, inLen, NULL));
    ExpectIntEQ(XMEMCMP(p, output, WC_SHA224_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA256(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA256) && \
    defined(NO_OLD_SHA_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    unsigned char input[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char output[] =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
        "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
        "\x06\xC1";
    size_t inLen;
    byte hash[WC_SHA256_DIGEST_SIZE];

    inLen  = XSTRLEN((char*)input);

    XMEMSET(hash, 0, WC_SHA256_DIGEST_SIZE);
    ExpectNotNull(SHA256(input, inLen, hash));
    ExpectIntEQ(XMEMCMP(hash, output, WC_SHA256_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA256_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA256)
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
        !defined(WOLFSSL_DEVCRYPTO_HASH) && !defined(WOLFSSL_AFALG_HASH) && \
        !defined(WOLFSSL_KCAPI_HASH)
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_SHA256_BLOCK_SIZE];
    word32 sLen = 0;
#ifdef BIG_ENDIAN_ORDER
    unsigned char output1[] =
        "\xda\x56\x98\xbe\x17\xb9\xb4\x69\x62\x33\x57\x99\x77\x9f\xbe\xca"
        "\x8c\xe5\xd4\x91\xc0\xd2\x62\x43\xba\xfe\xf9\xea\x18\x37\xa9\xd8";
    unsigned char output2[] =
        "\x1d\x4e\xd4\x67\x67\x7c\x61\x67\x44\x10\x76\x26\x78\x10\xff\xb8"
        "\x40\xc8\x9a\x39\x73\x16\x60\x8c\xa6\x61\xd6\x05\x91\xf2\x8c\x35";
#else
    unsigned char output1[] =
        "\xbe\x98\x56\xda\x69\xb4\xb9\x17\x99\x57\x33\x62\xca\xbe\x9f\x77"
        "\x91\xd4\xe5\x8c\x43\x62\xd2\xc0\xea\xf9\xfe\xba\xd8\xa9\x37\x18";
    unsigned char output2[] =
        "\x67\xd4\x4e\x1d\x67\x61\x7c\x67\x26\x76\x10\x44\xb8\xff\x10\x78"
        "\x39\x9a\xc8\x40\x8c\x60\x16\x73\x05\xd6\x61\xa6\x35\x8c\xf2\x91";
#endif
    union {
        wc_Sha256 native;
        SHA256_CTX compat;
    } sha256;

    XMEMSET(&sha256.compat, 0, sizeof(sha256.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(SHA256_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA256_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA256_Transform(&sha256.compat, NULL), 0);
    ExpectIntEQ(wc_Sha256Transform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Transform(NULL, (const byte*)&input1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Transform(&sha256.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init SHA256 CTX */
    ExpectIntEQ(SHA256_Init(&sha256.compat), 1);
    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA256_Transform(&sha256.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha256.native.digest, output1, WC_SHA256_DIGEST_SIZE),
        0);
    ExpectIntEQ(SHA256_Final(local, &sha256.compat), 1); /* frees resources */

    /* Init SHA256 CTX */
    ExpectIntEQ(SHA256_Init(&sha256.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA256_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA256_Transform(&sha256.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha256.native.digest, output2, WC_SHA256_DIGEST_SIZE),
        0);
    ExpectIntEQ(SHA256_Final(local, &sha256.compat), 1); /* frees resources */
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA512_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA512)
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
        !defined(WOLFSSL_KCAPI_HASH)
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_SHA512_BLOCK_SIZE];
    word32 sLen = 0;
#ifdef BIG_ENDIAN_ORDER
    unsigned char output1[] =
        "\xcf\x78\x81\xd5\x77\x4a\xcb\xe8\x53\x33\x62\xe0\xfb\xc7\x80\x70"
        "\x02\x67\x63\x9d\x87\x46\x0e\xda\x30\x86\xcb\x40\xe8\x59\x31\xb0"
        "\x71\x7d\xc9\x52\x88\xa0\x23\xa3\x96\xba\xb2\xc1\x4c\xe0\xb5\xe0"
        "\x6f\xc4\xfe\x04\xea\xe3\x3e\x0b\x91\xf4\xd8\x0c\xbd\x66\x8b\xee";
   unsigned char output2[] =
        "\x11\x10\x93\x4e\xeb\xa0\xcc\x0d\xfd\x33\x43\x9c\xfb\x04\xc8\x21"
        "\xa9\xb4\x26\x3d\xca\xab\x31\x41\xe2\xc6\xaa\xaf\xe1\x67\xd7\xab"
        "\x31\x8f\x2e\x54\x2c\xba\x4e\x83\xbe\x88\xec\x9d\x8f\x2b\x38\x98"
        "\x14\xd2\x4e\x9d\x53\x8b\x5e\x4d\xde\x68\x6c\x69\xaf\x20\x96\xf0";
#else
    unsigned char output1[] =
        "\xe8\xcb\x4a\x77\xd5\x81\x78\xcf\x70\x80\xc7\xfb\xe0\x62\x33\x53"
        "\xda\x0e\x46\x87\x9d\x63\x67\x02\xb0\x31\x59\xe8\x40\xcb\x86\x30"
        "\xa3\x23\xa0\x88\x52\xc9\x7d\x71\xe0\xb5\xe0\x4c\xc1\xb2\xba\x96"
        "\x0b\x3e\xe3\xea\x04\xfe\xc4\x6f\xee\x8b\x66\xbd\x0c\xd8\xf4\x91";
   unsigned char output2[] =
        "\x0d\xcc\xa0\xeb\x4e\x93\x10\x11\x21\xc8\x04\xfb\x9c\x43\x33\xfd"
        "\x41\x31\xab\xca\x3d\x26\xb4\xa9\xab\xd7\x67\xe1\xaf\xaa\xc6\xe2"
        "\x83\x4e\xba\x2c\x54\x2e\x8f\x31\x98\x38\x2b\x8f\x9d\xec\x88\xbe"
        "\x4d\x5e\x8b\x53\x9d\x4e\xd2\x14\xf0\x96\x20\xaf\x69\x6c\x68\xde";
#endif
    union {
        wc_Sha512 native;
        SHA512_CTX compat;
    } sha512;

    XMEMSET(&sha512.compat, 0, sizeof(sha512.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(SHA512_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA512_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA512_Transform(&sha512.compat, NULL), 0);
    ExpectIntEQ(wc_Sha512Transform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Transform(NULL, (const byte*)&input1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Transform(&sha512.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init SHA512 CTX */
    ExpectIntEQ(wolfSSL_SHA512_Init(&sha512.compat), 1);

    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA512_Transform(&sha512.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output1,
                                                    WC_SHA512_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA512_Final(local, &sha512.compat), 1); /* frees resources */

    /* Init SHA512 CTX */
    ExpectIntEQ(SHA512_Init(&sha512.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA512_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA512_Transform(&sha512.compat, (const byte*)&local[0]), 1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output2,
                                                    WC_SHA512_DIGEST_SIZE), 0);
    ExpectIntEQ(SHA512_Final(local, &sha512.compat), 1); /* frees resources */

    (void)input1;
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA512_224_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA512) && \
    !defined(WOLFSSL_NOSHA512_224)
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
        !defined(WOLFSSL_KCAPI_HASH)
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_SHA512_BLOCK_SIZE];
    word32 sLen = 0;
    unsigned char output1[] =
        "\x94\x24\x66\xd4\x60\x3a\xeb\x23\x1d\xa8\x69\x31\x3c\xd2\xde\x11"
        "\x48\x0f\x4a\x5a\xdf\x3a\x8d\x87\xcf\xcd\xbf\xa5\x03\x21\x50\xf1"
        "\x8a\x0d\x0f\x0d\x3c\x07\xba\x52\xe0\xaa\x3c\xbb\xf1\xd3\x3f\xca"
        "\x12\xa7\x61\xf8\x47\xda\x0d\x1b\x79\xc2\x65\x13\x92\xc1\x9c\xa5";
   unsigned char output2[] =
        "\x51\x28\xe7\x0b\xca\x1e\xbc\x5f\xd7\x34\x0b\x48\x30\xd7\xc2\x75"
        "\x6d\x8d\x48\x2c\x1f\xc7\x9e\x2b\x20\x5e\xbb\x0f\x0e\x4d\xb7\x61"
        "\x31\x76\x33\xa0\xb4\x3d\x5f\x93\xc1\x73\xac\xf7\x21\xff\x69\x17"
        "\xce\x66\xe5\x1e\x31\xe7\xf3\x22\x0f\x0b\x34\xd7\x5a\x57\xeb\xbf";
    union {
        wc_Sha512 native;
        SHA512_CTX compat;
    } sha512;

#ifdef BIG_ENDIAN_ORDER
    ByteReverseWords64((word64*)output1, (word64*)output1, sizeof(output1));
    ByteReverseWords64((word64*)output2, (word64*)output2, sizeof(output2));
#endif

    XMEMSET(&sha512.compat, 0, sizeof(sha512.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(SHA512_224_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA512_224_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA512_224_Transform(&sha512.compat, NULL), 0);
    ExpectIntEQ(wc_Sha512_224Transform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_224Transform(NULL, (const byte*)&input1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_224Transform(&sha512.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init SHA512 CTX */
    ExpectIntEQ(wolfSSL_SHA512_224_Init(&sha512.compat), 1);

    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA512_224_Transform(&sha512.compat, (const byte*)&local[0]),
        1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output1,
        WC_SHA512_DIGEST_SIZE), 0);
    /* frees resources */
    ExpectIntEQ(SHA512_224_Final(local, &sha512.compat), 1);

    /* Init SHA512 CTX */
    ExpectIntEQ(SHA512_224_Init(&sha512.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA512_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA512_224_Transform(&sha512.compat, (const byte*)&local[0]),
        1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output2,
        WC_SHA512_DIGEST_SIZE), 0);
    /* frees resources */
    ExpectIntEQ(SHA512_224_Final(local, &sha512.compat), 1);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SHA512_256_Transform(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA512) && \
    !defined(WOLFSSL_NOSHA512_256)
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))) && \
        !defined(WOLFSSL_KCAPI_HASH)
    byte input1[] = "";
    byte input2[] = "abc";
    byte local[WC_SHA512_BLOCK_SIZE];
    word32 sLen = 0;
    unsigned char output1[] =
        "\xf8\x37\x37\x5a\xd7\x2e\x56\xec\xe2\x51\xa8\x31\x3a\xa0\x63\x2b"
        "\x7e\x7c\x64\xcc\xd9\xff\x2b\x6b\xeb\xc3\xd4\x4d\x7f\x8a\x3a\xb5"
        "\x61\x85\x0b\x37\x30\x9f\x3b\x08\x5e\x7b\xd3\xbc\x6d\x00\x61\xc0"
        "\x65\x9a\xd7\x73\xda\x40\xbe\xc1\xe5\x2f\xc6\x5d\xb7\x9f\xbe\x60";
   unsigned char output2[] =
        "\x22\xad\xc0\x30\xee\xd4\x6a\xef\x13\xee\x5a\x95\x8b\x1f\xb7\xb6"
        "\xb6\xba\xc0\x44\xb8\x18\x3b\xf0\xf6\x4b\x70\x9f\x03\xba\x64\xa1"
        "\xe1\xe3\x45\x15\x91\x7d\xcb\x0b\x9a\xf0\xd2\x8e\x47\x8b\x37\x78"
        "\x91\x41\xa6\xc4\xb0\x29\x8f\x8b\xdd\x78\x5c\xf2\x73\x3f\x21\x31";
    union {
        wc_Sha512 native;
        SHA512_CTX compat;
    } sha512;

#ifdef BIG_ENDIAN_ORDER
    ByteReverseWords64((word64*)output1, (word64*)output1, sizeof(output1));
    ByteReverseWords64((word64*)output2, (word64*)output2, sizeof(output2));
#endif

    XMEMSET(&sha512.compat, 0, sizeof(sha512.compat));
    XMEMSET(&local, 0, sizeof(local));

    /* sanity check */
    ExpectIntEQ(SHA512_256_Transform(NULL, NULL), 0);
    ExpectIntEQ(SHA512_256_Transform(NULL, (const byte*)&input1), 0);
    ExpectIntEQ(SHA512_256_Transform(&sha512.compat, NULL), 0);
    ExpectIntEQ(wc_Sha512_256Transform(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_256Transform(NULL, (const byte*)&input1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_256Transform(&sha512.native, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init SHA512 CTX */
    ExpectIntEQ(wolfSSL_SHA512_256_Init(&sha512.compat), 1);

    /* Do Transform*/
    sLen = (word32)XSTRLEN((char*)input1);
    XMEMCPY(local, input1, sLen);
    ExpectIntEQ(SHA512_256_Transform(&sha512.compat, (const byte*)&local[0]),
        1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output1,
        WC_SHA512_DIGEST_SIZE), 0);
    /* frees resources */
    ExpectIntEQ(SHA512_256_Final(local, &sha512.compat), 1);

    /* Init SHA512 CTX */
    ExpectIntEQ(SHA512_256_Init(&sha512.compat), 1);
    sLen = (word32)XSTRLEN((char*)input2);
    XMEMSET(local, 0, WC_SHA512_BLOCK_SIZE);
    XMEMCPY(local, input2, sLen);
    ExpectIntEQ(SHA512_256_Transform(&sha512.compat, (const byte*)&local[0]),
        1);
    ExpectIntEQ(XMEMCMP(sha512.native.digest, output2,
        WC_SHA512_DIGEST_SIZE), 0);
    /* frees resources */
    ExpectIntEQ(SHA512_256_Final(local, &sha512.compat), 1);
#endif
#endif
    return EXPECT_RESULT();
}

