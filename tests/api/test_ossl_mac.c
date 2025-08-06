/* test_ossl_mac.c
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

#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/cmac.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_mac.h>

/*******************************************************************************
 * MAC OpenSSL compatibility API Testing
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && !defined(NO_HMAC)
/* helper function for test_wolfSSL_HMAC_CTX, digest size is expected to be a
 * buffer of 64 bytes.
 *
 * returns the size of the digest buffer on success and a negative value on
 * failure.
 */
static int test_HMAC_CTX_helper(const EVP_MD* type, unsigned char* digest,
    int* sz)
{
    EXPECT_DECLS;
    HMAC_CTX ctx1;
    HMAC_CTX ctx2;

    unsigned char key[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                          "\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    unsigned char long_key[] =
        "0123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789";

    unsigned char msg[] = "message to hash";
    unsigned int  digestSz = 64;
    int keySz = sizeof(key);
    int long_keySz = sizeof(long_key);
    int msgSz = sizeof(msg);

    unsigned char digest2[64];
    unsigned int digestSz2 = 64;

    HMAC_CTX_init(&ctx1);
    HMAC_CTX_init(&ctx2);

    ExpectIntEQ(HMAC_Init(&ctx1, (const void*)key, keySz, type), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_CTX_copy(&ctx2, &ctx1), SSL_SUCCESS);

    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx1, digest, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx1);

    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx2, digest2, &digestSz2), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx2);

    ExpectIntEQ(digestSz, digestSz2);
    ExpectIntEQ(XMEMCMP(digest, digest2, digestSz), 0);

    /* test HMAC_Init with NULL key */

    /* init after copy */
    HMAC_CTX_init(&ctx1);
    ExpectIntEQ(HMAC_Init(&ctx1, (const void*)key, keySz, type), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_CTX_copy(&ctx2, &ctx1), SSL_SUCCESS);

    ExpectIntEQ(HMAC_Init(&ctx1, NULL, 0, NULL), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx1, digest, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx1);

    ExpectIntEQ(HMAC_Init(&ctx2, NULL, 0, NULL), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx2, digest2, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx2);

    ExpectIntEQ(digestSz, digestSz2);
    ExpectIntEQ(XMEMCMP(digest, digest2, digestSz), 0);

    /* long key */
    HMAC_CTX_init(&ctx1);
    ExpectIntEQ(HMAC_Init(&ctx1, (const void*)long_key, long_keySz, type),
        SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_CTX_copy(&ctx2, &ctx1), SSL_SUCCESS);

    ExpectIntEQ(HMAC_Init(&ctx1, NULL, 0, NULL), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx1, digest, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx1);

    ExpectIntEQ(HMAC_Init(&ctx2, NULL, 0, NULL), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx2, digest2, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx2);

    ExpectIntEQ(digestSz, digestSz2);
    ExpectIntEQ(XMEMCMP(digest, digest2, digestSz), 0);

    /* init before copy */
    HMAC_CTX_init(&ctx1);
    ExpectIntEQ(HMAC_Init(&ctx1, (const void*)key, keySz, type), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Init(&ctx1, NULL, 0, NULL), SSL_SUCCESS);
    ExpectIntEQ(HMAC_CTX_copy(&ctx2, &ctx1), SSL_SUCCESS);

    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx1, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx1, digest, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx1);

    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Update(&ctx2, msg, msgSz), SSL_SUCCESS);
    ExpectIntEQ(HMAC_Final(&ctx2, digest2, &digestSz), SSL_SUCCESS);
    HMAC_CTX_cleanup(&ctx2);

    ExpectIntEQ(digestSz, digestSz2);
    ExpectIntEQ(XMEMCMP(digest, digest2, digestSz), 0);

    *sz = (int)digestSz;
    return EXPECT_RESULT();
}
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_HMAC) */

int test_wolfSSL_HMAC_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_HMAC)
    unsigned char digest[64];
    int digestSz;
    WOLFSSL_HMAC_CTX* hmac_ctx = NULL;
    WOLFSSL_HMAC_CTX ctx1;
    WOLFSSL_HMAC_CTX ctx2;

    ExpectNotNull(hmac_ctx = wolfSSL_HMAC_CTX_new());
    ExpectIntEQ(wolfSSL_HMAC_CTX_Init(NULL), 1);
    ExpectIntEQ(wolfSSL_HMAC_CTX_Init(hmac_ctx), 1);
    wolfSSL_HMAC_CTX_free(NULL);
    wolfSSL_HMAC_CTX_free(hmac_ctx);

    XMEMSET(&ctx2, 0, sizeof(WOLFSSL_HMAC_CTX));
    ExpectIntEQ(HMAC_CTX_init(NULL), 1);
    ExpectIntEQ(HMAC_CTX_init(&ctx2), 1);
    ExpectIntEQ(HMAC_CTX_copy(NULL, NULL), 0);
    ExpectIntEQ(HMAC_CTX_copy(NULL, &ctx2), 0);
    ExpectIntEQ(HMAC_CTX_copy(&ctx2, NULL), 0);
#if defined(HAVE_SELFTEST) || (defined(HAVE_FIPS) && \
    ((! defined(HAVE_FIPS_VERSION)) || \
     defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 2)))
    /* Copy object that hasn't had a digest set - MD5. */
    ExpectIntEQ(HMAC_CTX_copy(&ctx1, &ctx2), 1);
#else
    /* Copy object that hasn't had a digest set. */
    ExpectIntEQ(HMAC_CTX_copy(&ctx1, &ctx2), 0);
#endif
    HMAC_CTX_cleanup(NULL);
    HMAC_CTX_cleanup(&ctx2);

    ExpectNull(HMAC_CTX_get_md(NULL));

    #ifndef NO_SHA
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha1(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 20);
    ExpectIntEQ(XMEMCMP("\xD9\x68\x77\x23\x70\xFB\x53\x70\x53\xBA\x0E\xDC\xDA"
                          "\xBF\x03\x98\x31\x19\xB2\xCC", digest, digestSz), 0);
    #endif /* !NO_SHA */
    #ifdef WOLFSSL_SHA224
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha224(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 28);
    ExpectIntEQ(XMEMCMP("\x57\xFD\xF4\xE1\x2D\xB0\x79\xD7\x4B\x25\x7E\xB1\x95"
                          "\x9C\x11\xAC\x2D\x1E\x78\x94\x4F\x3A\x0F\xED\xF8\xAD"
                          "\x02\x0E", digest, digestSz), 0);
    #endif /* WOLFSSL_SHA224 */
    #ifndef NO_SHA256
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha256(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 32);
    ExpectIntEQ(XMEMCMP("\x13\xAB\x76\x91\x0C\x37\x86\x8D\xB3\x7E\x30\x0C\xFC"
                          "\xB0\x2E\x8E\x4A\xD7\xD4\x25\xCC\x3A\xA9\x0F\xA2\xF2"
                          "\x47\x1E\x62\x6F\x5D\xF2", digest, digestSz), 0);
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha384(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 48);
    ExpectIntEQ(XMEMCMP("\x9E\xCB\x07\x0C\x11\x76\x3F\x23\xC3\x25\x0E\xC4\xB7"
                          "\x28\x77\x95\x99\xD5\x9D\x7A\xBB\x1A\x9F\xB7\xFD\x25"
                          "\xC9\x72\x47\x9F\x8F\x86\x76\xD6\x20\x57\x87\xB7\xE7"
                          "\xCD\xFB\xC2\xCC\x9F\x2B\xC5\x41\xAB",
                          digest, digestSz), 0);
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha512(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 64);
    ExpectIntEQ(XMEMCMP("\xD4\x21\x0C\x8B\x60\x6F\xF4\xBF\x07\x2F\x26\xCC\xAD"
                          "\xBC\x06\x0B\x34\x78\x8B\x4F\xD6\xC0\x42\xF1\x33\x10"
                          "\x6C\x4F\x1E\x55\x59\xDD\x2A\x9F\x15\x88\x62\xF8\x60"
                          "\xA3\x99\x91\xE2\x08\x7B\xF7\x95\x3A\xB0\x92\x48\x60"
                          "\x88\x8B\x5B\xB8\x5F\xE9\xB6\xB1\x96\xE3\xB5\xF0",
                          digest, digestSz), 0);
    #endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha3_224(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 28);
    ExpectIntEQ(XMEMCMP("\xdc\x53\x25\x3f\xc0\x9d\x2b\x0c\x7f\x59\x11\x17\x08"
                        "\x5c\xe8\x43\x31\x01\x5a\xb3\xe3\x08\x37\x71\x26\x0b"
                        "\x29\x0f", digest, digestSz), 0);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha3_256(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 32);
    ExpectIntEQ(XMEMCMP("\x0f\x00\x89\x82\x15\xce\xd6\x45\x01\x83\xce\xc8\x35"
                        "\xab\x71\x07\xc9\xfe\x61\x22\x38\xf9\x09\xad\x35\x65"
                        "\x43\x77\x24\xd4\x1e\xf4", digest, digestSz), 0);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha3_384(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 48);
    ExpectIntEQ(XMEMCMP("\x0f\x6a\xc0\xfb\xc3\xf2\x80\xb1\xb4\x04\xb6\xc8\x45"
                        "\x23\x3b\xb4\xbe\xc6\xea\x85\x07\xca\x8c\x71\xbb\x6e"
                        "\x79\xf6\xf9\x2b\x98\xf5\xef\x11\x39\xd4\x5d\xd3\xca"
                        "\xc0\xe6\x81\xf7\x73\xf9\x85\x5d\x4f",
                          digest, digestSz), 0);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_sha3_512(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 64);
    ExpectIntEQ(XMEMCMP("\x3e\x77\xe3\x59\x42\x89\xed\xc3\xa4\x26\x3d\xa4\x75"
                        "\xd2\x84\x8c\xb2\xf3\x25\x04\x47\x61\xce\x1c\x42\x86"
                        "\xcd\xf4\x56\xaa\x2f\x84\xb1\x3b\x18\xed\xe6\xd6\x48"
                        "\x15\xb0\x29\xc5\x9d\x32\xef\xdd\x3e\x09\xf6\xed\x9e"
                        "\x70\xbc\x1c\x63\xf7\x3b\x3e\xe1\xdc\x84\x9c\x1c",
                          digest, digestSz), 0);
    #endif
#endif

    #if !defined(NO_MD5) && (!defined(HAVE_FIPS_VERSION) || \
        HAVE_FIPS_VERSION <= 2)
    ExpectIntEQ((test_HMAC_CTX_helper(EVP_md5(), digest, &digestSz)),
        TEST_SUCCESS);
    ExpectIntEQ(digestSz, 16);
    ExpectIntEQ(XMEMCMP("\xB7\x27\xC4\x41\xE5\x2E\x62\xBA\x54\xED\x72\x70\x9F"
                          "\xE4\x98\xDD", digest, digestSz), 0);
    #endif /* !NO_MD5 */
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && (!defined(NO_SHA256) || \
    defined(WOLFSSL_SHA224) || defined(WOLFSSL_SHA384) || \
    defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA3))
static int test_openssl_hmac(const WOLFSSL_EVP_MD* md, int md_len)
{
    EXPECT_DECLS;
    static const unsigned char key[] = "simple test key";
    HMAC_CTX* hmac = NULL;
    ENGINE* e = NULL;
    unsigned char hash[WC_MAX_DIGEST_SIZE];
    unsigned int len;

    ExpectNotNull(hmac = HMAC_CTX_new());
    HMAC_CTX_init(hmac);
#if defined(HAVE_SELFTEST) || (defined(HAVE_FIPS) && \
    ((! defined(HAVE_FIPS_VERSION)) || \
     defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 2)))
    /* Get size on object that hasn't had a digest set - MD5. */
    ExpectIntEQ(HMAC_size(hmac), 16);
    ExpectIntEQ(HMAC_Init(hmac, NULL, 0, NULL), 1);
    ExpectIntEQ(HMAC_Init(hmac, (void*)key, (int)sizeof(key), NULL), 1);
    ExpectIntEQ(HMAC_Init(hmac, NULL, 0, md), 1);
#else
    ExpectIntEQ(HMAC_size(hmac), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(HMAC_Init(hmac, NULL, 0, NULL), 0);
    ExpectIntEQ(HMAC_Init(hmac, (void*)key, (int)sizeof(key), NULL), 0);
    ExpectIntEQ(HMAC_Init(hmac, NULL, 0, md), 0);
#endif
    ExpectIntEQ(HMAC_Init_ex(NULL, (void*)key, (int)sizeof(key), md, e), 0);
    ExpectIntEQ(HMAC_Init_ex(hmac, (void*)key, (int)sizeof(key), md, e), 1);

    /* reusing test key as data to hash */
    ExpectIntEQ(HMAC_Update(NULL, key, (int)sizeof(key)), 0);
    ExpectIntEQ(HMAC_Update(hmac, key, (int)sizeof(key)), 1);
    ExpectIntEQ(HMAC_Update(hmac, key, 0), 1);
    ExpectIntEQ(HMAC_Update(hmac, NULL, 0), 1);
    ExpectIntEQ(HMAC_Update(hmac, NULL, (int)sizeof(key)), 1);
    ExpectIntEQ(HMAC_Final(NULL, NULL, &len), 0);
    ExpectIntEQ(HMAC_Final(hmac, NULL, &len), 0);
    ExpectIntEQ(HMAC_Final(NULL, hash, &len), 0);
    ExpectIntEQ(HMAC_Final(hmac, hash, &len), 1);
    ExpectIntEQ(HMAC_Final(hmac, hash, NULL), 1);
    ExpectIntEQ(len, md_len);
    ExpectIntEQ(HMAC_size(NULL), 0);
    ExpectIntEQ(HMAC_size(hmac), md_len);
    ExpectStrEQ(HMAC_CTX_get_md(hmac), md);

    HMAC_cleanup(NULL);
    HMAC_cleanup(hmac);
    HMAC_CTX_free(hmac);

    len = 0;
    ExpectNull(HMAC(NULL, key, (int)sizeof(key), NULL, 0, hash, &len));
    ExpectNull(HMAC(md, NULL, (int)sizeof(key), NULL, 0, hash, &len));
    ExpectNull(HMAC(md, key, (int)sizeof(key), NULL, 0, NULL, &len));
    ExpectNotNull(HMAC(md, key, (int)sizeof(key), NULL, 0, hash, &len));
    ExpectIntEQ(len, md_len);
    ExpectNotNull(HMAC(md, key, (int)sizeof(key), NULL, 0, hash, NULL));
    /* With data. */
    ExpectNotNull(HMAC(md, key, (int)sizeof(key), key, (int)sizeof(key), hash,
        &len));
    /* With NULL data. */
    ExpectNull(HMAC(md, key, (int)sizeof(key), NULL, (int)sizeof(key), hash,
        &len));
    /* With zero length data. */
    ExpectNotNull(HMAC(md, key, (int)sizeof(key), key, 0, hash, &len));

    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_HMAC(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && (!defined(NO_SHA256) || \
    defined(WOLFSSL_SHA224) || defined(WOLFSSL_SHA384) || \
    defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA3))
#ifndef NO_SHA256
    ExpectIntEQ(test_openssl_hmac(EVP_sha256(), (int)WC_SHA256_DIGEST_SIZE),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA224
    ExpectIntEQ(test_openssl_hmac(EVP_sha224(), (int)WC_SHA224_DIGEST_SIZE),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA384
    ExpectIntEQ(test_openssl_hmac(EVP_sha384(), (int)WC_SHA384_DIGEST_SIZE),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA512
    ExpectIntEQ(test_openssl_hmac(EVP_sha512(), (int)WC_SHA512_DIGEST_SIZE),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        ExpectIntEQ(test_openssl_hmac(EVP_sha3_224(),
             (int)WC_SHA3_224_DIGEST_SIZE), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        ExpectIntEQ(test_openssl_hmac(EVP_sha3_256(),
             (int)WC_SHA3_256_DIGEST_SIZE), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        ExpectIntEQ(test_openssl_hmac(EVP_sha3_384(),
             (int)WC_SHA3_384_DIGEST_SIZE), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        ExpectIntEQ(test_openssl_hmac(EVP_sha3_512(),
             (int)WC_SHA3_512_DIGEST_SIZE), TEST_SUCCESS);
    #endif
#endif
#ifndef NO_SHA
    ExpectIntEQ(test_openssl_hmac(EVP_sha1(), (int)WC_SHA_DIGEST_SIZE),
        TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CMAC(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_CMAC) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_AES_DIRECT)
    int i;
    byte key[AES_256_KEY_SIZE];
    CMAC_CTX* cmacCtx = NULL;
    byte out[AES_BLOCK_SIZE];
    size_t outLen = AES_BLOCK_SIZE;

    for (i=0; i < AES_256_KEY_SIZE; ++i) {
        key[i] = i;
    }
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    /* Check CMAC_CTX_get0_cipher_ctx; return value not used. */
    ExpectNotNull(CMAC_CTX_get0_cipher_ctx(cmacCtx));
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_128_KEY_SIZE, EVP_aes_128_cbc(),
        NULL), 1);
    /* reusing test key as data to hash */
    ExpectIntEQ(CMAC_Update(cmacCtx, key, AES_128_KEY_SIZE), 1);
    ExpectIntEQ(CMAC_Update(cmacCtx, NULL, 0), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, out, &outLen), 1);
    ExpectIntEQ(outLen, AES_BLOCK_SIZE);

    /* No Update works. */
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_128_KEY_SIZE, EVP_aes_128_cbc(),
        NULL), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, out, NULL), 1);

    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_128_KEY_SIZE, EVP_aes_128_cbc(),
        NULL), 1);
    /* Test parameters with CMAC_Update. */
    ExpectIntEQ(CMAC_Update(NULL, NULL, 0), 0);
    ExpectIntEQ(CMAC_Update(NULL, key, 0), 0);
    ExpectIntEQ(CMAC_Update(NULL, NULL, AES_128_KEY_SIZE), 0);
    ExpectIntEQ(CMAC_Update(NULL, key, AES_128_KEY_SIZE), 0);
    ExpectIntEQ(CMAC_Update(cmacCtx, key, 0), 1);
    ExpectIntEQ(CMAC_Update(cmacCtx, NULL, 0), 1);
    ExpectIntEQ(CMAC_Update(cmacCtx, NULL, AES_128_KEY_SIZE), 1);
    /* Test parameters with CMAC_Final. */
    ExpectIntEQ(CMAC_Final(NULL, NULL, NULL), 0);
    ExpectIntEQ(CMAC_Final(NULL, out, NULL), 0);
    ExpectIntEQ(CMAC_Final(NULL, NULL, &outLen), 0);
    ExpectIntEQ(CMAC_Final(NULL, out, &outLen), 0);
    ExpectIntEQ(CMAC_Final(cmacCtx, NULL, NULL), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, NULL, &outLen), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, out, NULL), 1);
    CMAC_CTX_free(cmacCtx);

    /* Test parameters with CMAC Init. */
    cmacCtx = NULL;
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    ExpectNotNull(CMAC_CTX_get0_cipher_ctx(cmacCtx));
    ExpectIntEQ(CMAC_Init(NULL, NULL, 0, NULL, NULL), 0);
    #ifdef WOLFSSL_AES_192
    ExpectIntEQ(CMAC_Init(NULL, key, AES_192_KEY_SIZE, EVP_aes_192_cbc(),
        NULL), 0);
    ExpectIntEQ(CMAC_Init(cmacCtx, NULL, AES_192_KEY_SIZE, EVP_aes_192_cbc(),
        NULL), 0);
    /* give a key too small for the cipher, verify we get failure */
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_128_KEY_SIZE, EVP_aes_192_cbc(),
        NULL), 0);
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_192_KEY_SIZE, NULL, NULL), 0);
    #endif
    #if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_128)
    /* Only AES-CBC supported. */
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_128_KEY_SIZE, EVP_aes_128_gcm(),
        NULL), 0);
    #endif
    CMAC_CTX_free(cmacCtx);

    ExpectNull(CMAC_CTX_get0_cipher_ctx(NULL));
    cmacCtx = NULL;
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    /* No Init. */
    ExpectIntEQ(CMAC_Final(cmacCtx, out, &outLen), 0);
    CMAC_CTX_free(cmacCtx);

    /* Test AES-256-CBC */
#ifdef WOLFSSL_AES_256
    cmacCtx = NULL;
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_256_KEY_SIZE, EVP_aes_256_cbc(),
        NULL), 1);
    ExpectIntEQ(CMAC_Update(cmacCtx, key, AES_128_KEY_SIZE), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, out, NULL), 1);
    CMAC_CTX_free(cmacCtx);
#endif

    /* Test AES-192-CBC */
#ifdef WOLFSSL_AES_192
    cmacCtx = NULL;
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    ExpectIntEQ(CMAC_Init(cmacCtx, key, AES_192_KEY_SIZE, EVP_aes_192_cbc(),
        NULL), 1);
    ExpectIntEQ(CMAC_Update(cmacCtx, key, AES_128_KEY_SIZE), 1);
    ExpectIntEQ(CMAC_Final(cmacCtx, out, NULL), 1);
    CMAC_CTX_free(cmacCtx);
#endif

    cmacCtx = NULL;
    ExpectNotNull(cmacCtx = CMAC_CTX_new());
    CMAC_CTX_free(cmacCtx);
#endif /* WOLFSSL_CMAC && OPENSSL_EXTRA && WOLFSSL_AES_DIRECT */
    return EXPECT_RESULT();
}

