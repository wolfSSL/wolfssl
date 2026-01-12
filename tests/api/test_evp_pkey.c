/* test_evp_pkey.c
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

#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/kdf.h>
#include <tests/api/api.h>
#include <tests/api/test_evp_pkey.h>


int test_wolfSSL_EVP_PKEY_CTX_new_id(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_ENGINE* e = NULL;
    int id = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ExpectNotNull(ctx = wolfSSL_EVP_PKEY_CTX_new_id(id, e));

    EVP_PKEY_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_PKEY*   pkey = NULL;
    EVP_PKEY_CTX*       ctx = NULL;
    int                 bits = 2048;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));

    ExpectIntEQ(wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits),
        WOLFSSL_SUCCESS);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_QT_EVP_PKEY_CTX_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(OPENSSL_ALL)
    EVP_PKEY*     pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* void */
    EVP_PKEY_CTX_free(ctx);
#else
    /* int */
    ExpectIntEQ(EVP_PKEY_CTX_free(ctx), WOLFSSL_SUCCESS);
#endif

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_up_ref(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL)
    EVP_PKEY* pkey;

    pkey = EVP_PKEY_new();
    ExpectNotNull(pkey);
    ExpectIntEQ(EVP_PKEY_up_ref(NULL), 0);
    ExpectIntEQ(EVP_PKEY_up_ref(pkey), 1);
    EVP_PKEY_free(pkey);
    ExpectIntEQ(EVP_PKEY_up_ref(pkey), 1);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_base_id(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    ExpectIntEQ(wolfSSL_EVP_PKEY_base_id(NULL), NID_undef);

    ExpectIntEQ(wolfSSL_EVP_PKEY_base_id(pkey), EVP_PKEY_RSA);

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_PKEY_id(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    ExpectIntEQ(wolfSSL_EVP_PKEY_id(NULL), 0);

    ExpectIntEQ(wolfSSL_EVP_PKEY_id(pkey), EVP_PKEY_RSA);

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_MD_pkey_type(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    const WOLFSSL_EVP_MD* md;

#ifndef NO_MD5
    ExpectNotNull(md = EVP_md5());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_md5WithRSAEncryption);
#endif
#ifndef NO_SHA
    ExpectNotNull(md = EVP_sha1());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_sha1WithRSAEncryption);
#endif
#ifdef WOLFSSL_SHA224
    ExpectNotNull(md = EVP_sha224());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_sha224WithRSAEncryption);
#endif
    ExpectNotNull(md = EVP_sha256());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_sha256WithRSAEncryption);
#ifdef WOLFSSL_SHA384
    ExpectNotNull(md = EVP_sha384());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_sha384WithRSAEncryption);
#endif
#ifdef WOLFSSL_SHA512
    ExpectNotNull(md = EVP_sha512());
    ExpectIntEQ(EVP_MD_pkey_type(md), NID_sha512WithRSAEncryption);
#endif
#endif
    return EXPECT_RESULT();
}

#ifdef OPENSSL_EXTRA
static int test_hmac_signing(const WOLFSSL_EVP_MD *type, const byte* testKey,
        size_t testKeySz, const char* testData, size_t testDataSz,
        const byte* testResult, size_t testResultSz)
{
    EXPECT_DECLS;
    unsigned char check[WC_MAX_DIGEST_SIZE];
    size_t checkSz = 0;
    WOLFSSL_EVP_PKEY* key = NULL;
    WOLFSSL_EVP_MD_CTX mdCtx;

    ExpectNotNull(key = wolfSSL_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
                                                      testKey, (int)testKeySz));
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, type, NULL, key), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData,
                                                  (unsigned int)testDataSz), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    ExpectIntEQ((int)checkSz, (int)testResultSz);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz,(int)testResultSz);
    ExpectIntEQ(XMEMCMP(testResult, check, testResultSz), 0);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, type, NULL, key), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData,
                                                  (unsigned int)testDataSz), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, testResult, checkSz), 1);

    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, type, NULL, key), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData, 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    ExpectIntEQ((int)checkSz, (int)testResultSz);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz,(int)testResultSz);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData + 4,
                                              (unsigned int)testDataSz - 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz,(int)testResultSz);
    ExpectIntEQ(XMEMCMP(testResult, check, testResultSz), 0);

    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, type, NULL, key), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData, 4), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData + 4,
                                              (unsigned int)testDataSz - 4), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, testResult, checkSz), 1);

    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

    wolfSSL_EVP_PKEY_free(key);

    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_EVP_MD_hmac_signing(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    static const unsigned char testKey[] =
    {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    static const char testData[] = "Hi There";
#ifdef WOLFSSL_SHA224
    static const unsigned char testResultSha224[] =
    {
        0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19,
        0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
        0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f,
        0x53, 0x68, 0x4b, 0x22
    };
#endif
#ifndef NO_SHA256
    static const unsigned char testResultSha256[] =
    {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
#endif
#ifdef WOLFSSL_SHA384
    static const unsigned char testResultSha384[] =
    {
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
        0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
        0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
        0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
        0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
        0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
    };
#endif
#ifdef WOLFSSL_SHA512
    static const unsigned char testResultSha512[] =
    {
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
        0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
        0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
        0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
        0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
        0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
    };
#endif
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    static const unsigned char testResultSha3_224[] =
    {
        0x3b, 0x16, 0x54, 0x6b, 0xbc, 0x7b, 0xe2, 0x70,
        0x6a, 0x03, 0x1d, 0xca, 0xfd, 0x56, 0x37, 0x3d,
        0x98, 0x84, 0x36, 0x76, 0x41, 0xd8, 0xc5, 0x9a,
        0xf3, 0xc8, 0x60, 0xf7
    };
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    static const unsigned char testResultSha3_256[] =
    {
        0xba, 0x85, 0x19, 0x23, 0x10, 0xdf, 0xfa, 0x96,
        0xe2, 0xa3, 0xa4, 0x0e, 0x69, 0x77, 0x43, 0x51,
        0x14, 0x0b, 0xb7, 0x18, 0x5e, 0x12, 0x02, 0xcd,
        0xcc, 0x91, 0x75, 0x89, 0xf9, 0x5e, 0x16, 0xbb
    };
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    static const unsigned char testResultSha3_384[] =
    {
        0x68, 0xd2, 0xdc, 0xf7, 0xfd, 0x4d, 0xdd, 0x0a,
        0x22, 0x40, 0xc8, 0xa4, 0x37, 0x30, 0x5f, 0x61,
        0xfb, 0x73, 0x34, 0xcf, 0xb5, 0xd0, 0x22, 0x6e,
        0x1b, 0xc2, 0x7d, 0xc1, 0x0a, 0x2e, 0x72, 0x3a,
        0x20, 0xd3, 0x70, 0xb4, 0x77, 0x43, 0x13, 0x0e,
        0x26, 0xac, 0x7e, 0x3d, 0x53, 0x28, 0x86, 0xbd
    };
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    static const unsigned char testResultSha3_512[] =
    {
        0xeb, 0x3f, 0xbd, 0x4b, 0x2e, 0xaa, 0xb8, 0xf5,
        0xc5, 0x04, 0xbd, 0x3a, 0x41, 0x46, 0x5a, 0xac,
        0xec, 0x15, 0x77, 0x0a, 0x7c, 0xab, 0xac, 0x53,
        0x1e, 0x48, 0x2f, 0x86, 0x0b, 0x5e, 0xc7, 0xba,
        0x47, 0xcc, 0xb2, 0xc6, 0xf2, 0xaf, 0xce, 0x8f,
        0x88, 0xd2, 0x2b, 0x6d, 0xc6, 0x13, 0x80, 0xf2,
        0x3a, 0x66, 0x8f, 0xd3, 0x88, 0x8b, 0xb8, 0x05,
        0x37, 0xc0, 0xa0, 0xb8, 0x64, 0x07, 0x68, 0x9e
    };
    #endif
#endif

#ifndef NO_SHA256
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha256(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha256,
        sizeof(testResultSha256)), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA224
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha224(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha224,
        sizeof(testResultSha224)), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA384
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha384(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha384,
        sizeof(testResultSha384)), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA512
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha512(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha512,
        sizeof(testResultSha512)), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha3_224(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha3_224,
        sizeof(testResultSha3_224)), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha3_256(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha3_256,
        sizeof(testResultSha3_256)), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha3_384(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha3_384,
        sizeof(testResultSha3_384)), TEST_SUCCESS);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    ExpectIntEQ(test_hmac_signing(wolfSSL_EVP_sha3_512(), testKey,
        sizeof(testKey), testData, XSTRLEN(testData), testResultSha3_512,
        sizeof(testResultSha3_512)), TEST_SUCCESS);
    #endif
#endif
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_new_mac_key(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    static const unsigned char pw[] = "password";
    static const int pwSz = sizeof(pw) - 1;
    size_t checkPwSz = 0;
    const unsigned char* checkPw = NULL;
    WOLFSSL_EVP_PKEY* key = NULL;

    ExpectNull(key = wolfSSL_EVP_PKEY_new_mac_key(0, NULL, pw, pwSz));
    ExpectNull(key = wolfSSL_EVP_PKEY_new_mac_key(0, NULL, NULL, pwSz));

    ExpectNotNull(key = wolfSSL_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pw,
        pwSz));
    if (key != NULL) {
        ExpectIntEQ(key->type, EVP_PKEY_HMAC);
        ExpectIntEQ(key->save_type, EVP_PKEY_HMAC);
        ExpectIntEQ(key->pkey_sz, pwSz);
        ExpectIntEQ(XMEMCMP(key->pkey.ptr, pw, pwSz), 0);
    }
    ExpectNotNull(checkPw = wolfSSL_EVP_PKEY_get0_hmac(key, &checkPwSz));
    ExpectIntEQ((int)checkPwSz, pwSz);
    ExpectIntEQ(XMEMCMP(checkPw, pw, pwSz), 0);
    wolfSSL_EVP_PKEY_free(key);
    key = NULL;

    ExpectNotNull(key = wolfSSL_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pw,
        0));
    ExpectIntEQ(key->pkey_sz, 0);
    if (EXPECT_SUCCESS()) {
        /* Allocation for key->pkey.ptr may fail - OK key len is 0 */
        checkPw = wolfSSL_EVP_PKEY_get0_hmac(key, &checkPwSz);
    }
    ExpectTrue((checkPwSz == 0) || (checkPw != NULL));
    ExpectIntEQ((int)checkPwSz, 0);
    wolfSSL_EVP_PKEY_free(key);
    key = NULL;

    ExpectNotNull(key = wolfSSL_EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, NULL,
        0));
    ExpectIntEQ(key->pkey_sz, 0);
    if (EXPECT_SUCCESS()) {
        /* Allocation for key->pkey.ptr may fail - OK key len is 0 */
        checkPw = wolfSSL_EVP_PKEY_get0_hmac(key, &checkPwSz);
    }
    ExpectTrue((checkPwSz == 0) || (checkPw != NULL));
    ExpectIntEQ((int)checkPwSz, 0);
    wolfSSL_EVP_PKEY_free(key);
    key = NULL;
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_hkdf(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_HKDF)
    EVP_PKEY_CTX* ctx = NULL;
    byte salt[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    byte key[]   = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    byte info[]  = {0X01, 0x02, 0x03, 0x04, 0x05};
    byte info2[] = {0X06, 0x07, 0x08, 0x09, 0x0A};
    byte outKey[34];
    size_t outKeySz = sizeof(outKey);
    /* These expected outputs were gathered by running the same test below using
     * OpenSSL. */
    const byte extractAndExpand[] = {
        0x8B, 0xEB, 0x90, 0xA9, 0x04, 0xFF, 0x05, 0x10, 0xE4, 0xB5, 0xB1, 0x10,
        0x31, 0x34, 0xFF, 0x07, 0x5B, 0xE3, 0xC6, 0x93, 0xD4, 0xF8, 0xC7, 0xEE,
        0x96, 0xDA, 0x78, 0x7A, 0xE2, 0x9A, 0x2D, 0x05, 0x4B, 0xF6
    };
    const byte extractOnly[] = {
        0xE7, 0x6B, 0x9E, 0x0F, 0xE4, 0x02, 0x1D, 0x62, 0xEA, 0x97, 0x74, 0x5E,
        0xF4, 0x3C, 0x65, 0x4D, 0xC1, 0x46, 0x98, 0xAA, 0x79, 0x9A, 0xCB, 0x9C,
        0xCC, 0x3E, 0x7F, 0x2A, 0x2B, 0x41, 0xA1, 0x9E
    };
    const byte expandOnly[] = {
        0xFF, 0x29, 0x29, 0x56, 0x9E, 0xA7, 0x66, 0x02, 0xDB, 0x4F, 0xDB, 0x53,
        0x7D, 0x21, 0x67, 0x52, 0xC3, 0x0E, 0xF3, 0xFC, 0x71, 0xCE, 0x67, 0x2B,
        0xEA, 0x3B, 0xE9, 0xFC, 0xDD, 0xC8, 0xCC, 0xB7, 0x42, 0x74
    };
    const byte extractAndExpandAddInfo[] = {
        0x5A, 0x74, 0x79, 0x83, 0xA3, 0xA4, 0x2E, 0xB7, 0xD4, 0x08, 0xC2, 0x6A,
        0x2F, 0xA5, 0xE3, 0x4E, 0xF1, 0xF4, 0x87, 0x3E, 0xA6, 0xC7, 0x88, 0x45,
        0xD7, 0xE2, 0x15, 0xBC, 0xB8, 0x10, 0xEF, 0x6C, 0x4D, 0x7A
    };

    ExpectNotNull((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(NULL, EVP_sha256()),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL md. */
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(ctx, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()), WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(NULL, salt, sizeof(salt)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL salt is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, NULL, sizeof(salt)),
                WOLFSSL_SUCCESS);
    /* Salt length <= 0. */
    /* Length 0 salt is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, -1),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(NULL, key, sizeof(key)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL key. */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, NULL, sizeof(key)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Key length <= 0 */
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, 0),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, -1),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, sizeof(key)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(NULL, info, sizeof(info)),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* NULL info is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, NULL, sizeof(info)),
                WOLFSSL_SUCCESS);
    /* Info length <= 0 */
    /* Length 0 info is ok. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, -1),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)),
                WOLFSSL_SUCCESS);
    /* NULL ctx. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(NULL, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Extract and expand (default). */
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractAndExpand));
    ExpectIntEQ(XMEMCMP(outKey, extractAndExpand, outKeySz), 0);
    /* Extract only. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractOnly));
    ExpectIntEQ(XMEMCMP(outKey, extractOnly, outKeySz), 0);
    outKeySz = sizeof(outKey);
    /* Expand only. */
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(expandOnly));
    ExpectIntEQ(XMEMCMP(outKey, expandOnly, outKeySz), 0);
    outKeySz = sizeof(outKey);
    /* Extract and expand with appended additional info. */
    ExpectIntEQ(EVP_PKEY_CTX_add1_hkdf_info(ctx, info2, sizeof(info2)),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_hkdf_mode(ctx,
                EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_derive(ctx, outKey, &outKeySz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outKeySz, sizeof(extractAndExpandAddInfo));
    ExpectIntEQ(XMEMCMP(outKey, extractAndExpandAddInfo, outKeySz), 0);

    EVP_PKEY_CTX_free(ctx);
#endif /* OPENSSL_EXTRA && HAVE_HKDF */
    return EXPECT_RESULT();
}


int test_wolfSSL_EVP_PBE_scrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_SCRYPT) && defined(HAVE_PBKDF2) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 5))
#if !defined(NO_PWDBASED) &&  !defined(NO_SHA256)
    int ret;

    const char  pwd[]    = {'p','a','s','s','w','o','r','d'};
    int         pwdlen   = sizeof(pwd);
    const byte  salt[]   = {'N','a','C','l'};
    int         saltlen  = sizeof(salt);
    byte        key[80];
    word64      numOvr32 = (word64)INT32_MAX + 1;

    /* expected derived key for N:16, r:1, p:1 */
    const byte expectedKey[] = {
        0xAE, 0xC6, 0xB7, 0x48, 0x3E, 0xD2, 0x6E, 0x08, 0x80, 0x2B,
        0x41, 0xF4, 0x03, 0x20, 0x86, 0xA0, 0xE8, 0x86, 0xBE, 0x7A,
        0xC4, 0x8F, 0xCF, 0xD9, 0x2F, 0xF0, 0xCE, 0xF8, 0x10, 0x97,
        0x52, 0xF4, 0xAC, 0x74, 0xB0, 0x77, 0x26, 0x32, 0x56, 0xA6,
        0x5A, 0x99, 0x70, 0x1B, 0x7A, 0x30, 0x4D, 0x46, 0x61, 0x1C,
        0x8A, 0xA3, 0x91, 0xE7, 0x99, 0xCE, 0x10, 0xA2, 0x77, 0x53,
        0xE7, 0xE9, 0xC0, 0x9A};

    /*                                               N  r  p  mx key keylen */
    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 0, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* N must be greater than 1 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 3, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* N must be power of 2 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 0, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* r must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 0, 0, key, 64);
    ExpectIntEQ(ret, 0); /* p must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, key, 0);
    ExpectIntEQ(ret, 0); /* keylen must be greater than 0 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 9, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* r must be smaller than 9 */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, NULL, 64);
    ExpectIntEQ(ret, 1); /* should succeed if key is NULL  */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, numOvr32, 1, 0,
                                                                    key, 64);
    ExpectIntEQ(ret, 0); /* should fail since r is greater than INT32_MAC */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 2, 1, numOvr32, 0,
                                                                    key, 64);
    ExpectIntEQ(ret, 0); /* should fail since p is greater than INT32_MAC */

    ret = EVP_PBE_scrypt(pwd, pwdlen, NULL, 0, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed even if salt is NULL */

    ret = EVP_PBE_scrypt(pwd, pwdlen, NULL, 4, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* if salt is NULL, saltlen must be 0, otherwise fail*/

    ret = EVP_PBE_scrypt(NULL, 0, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed if pwd is NULL and pwdlen is 0*/

    ret = EVP_PBE_scrypt(NULL, 4, salt, saltlen, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 0); /* if pwd is NULL, pwdlen must be 0 */

    ret = EVP_PBE_scrypt(NULL, 0, NULL, 0, 2, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1); /* should succeed even both pwd and salt are NULL */

    ret = EVP_PBE_scrypt(pwd, pwdlen, salt, saltlen, 16, 1, 1, 0, key, 64);
    ExpectIntEQ(ret, 1);

    ret = XMEMCMP(expectedKey, key, sizeof(expectedKey));
    ExpectIntEQ(ret, 0); /* derived key must be the same as expected-key */
#endif /* !NO_PWDBASED && !NO_SHA256 */
#endif /* OPENSSL_EXTRA && HAVE_SCRYPT && HAVE_PBKDF2 */
    return EXPECT_RESULT();
}

int test_EVP_PKEY_cmp(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    EVP_PKEY *a = NULL;
    EVP_PKEY *b = NULL;
    const unsigned char *in;

#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
    in = client_key_der_2048;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));
    in = client_key_der_2048;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));

    /* Test success case RSA */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 1);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */

    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    in = ecc_clikey_der_256;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));
    in = ecc_clikey_der_256;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));

    /* Test success case ECC */
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 1);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */

    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

    /* Test failure cases */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048) && \
     defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)

    in = client_key_der_2048;
    ExpectNotNull(a = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
        &in, (long)sizeof_client_key_der_2048));
    in = ecc_clikey_der_256;
    ExpectNotNull(b = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL,
        &in, (long)sizeof_ecc_clikey_der_256));

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(a, b), -1);
#else
    ExpectIntNE(EVP_PKEY_cmp(a, b), 0);
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */
    EVP_PKEY_free(b);
    b = NULL;
    EVP_PKEY_free(a);
    a = NULL;
#endif

    /* invalid or empty failure cases */
    a = EVP_PKEY_new();
    b = EVP_PKEY_new();
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(EVP_PKEY_cmp(NULL, NULL), 0);
    ExpectIntEQ(EVP_PKEY_cmp(a, NULL), 0);
    ExpectIntEQ(EVP_PKEY_cmp(NULL, b), 0);
#ifdef NO_RSA
    /* Type check will fail since RSA is the default EVP key type */
    ExpectIntEQ(EVP_PKEY_cmp(a, b), -2);
#else
    ExpectIntEQ(EVP_PKEY_cmp(a, b), 0);
#endif
#else
    ExpectIntNE(EVP_PKEY_cmp(NULL, NULL), 0);
    ExpectIntNE(EVP_PKEY_cmp(a, NULL), 0);
    ExpectIntNE(EVP_PKEY_cmp(NULL, b), 0);
    ExpectIntNE(EVP_PKEY_cmp(a, b), 0);
#endif
    EVP_PKEY_free(b);
    EVP_PKEY_free(a);

    (void)in;
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_set1_get1_DSA(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined (NO_DSA) && !defined(HAVE_SELFTEST) && \
    defined(WOLFSSL_KEY_GEN)
    DSA       *dsa  = NULL;
    DSA       *setDsa  = NULL;
    EVP_PKEY  *pkey = NULL;
    EVP_PKEY  *set1Pkey = NULL;

    SHA_CTX sha;
    byte    signature[DSA_SIG_SIZE];
    byte    hash[WC_SHA_DIGEST_SIZE];
    word32  bytes;
    int     answer;
#ifdef USE_CERT_BUFFERS_1024
    const unsigned char* dsaKeyDer = dsa_key_der_1024;
    int dsaKeySz  = sizeof_dsa_key_der_1024;
    byte    tmp[ONEK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsaKeyDer , dsaKeySz);
    bytes = dsaKeySz;
#elif defined(USE_CERT_BUFFERS_2048)
    const unsigned char* dsaKeyDer = dsa_key_der_2048;
    int dsaKeySz  = sizeof_dsa_key_der_2048;
    byte    tmp[TWOK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsaKeyDer , dsaKeySz);
    bytes = (word32)dsaKeySz;
#else
    byte    tmp[TWOK_BUF];
    const unsigned char* dsaKeyDer = (const unsigned char*)tmp;
    int dsaKeySz;
    XFILE fp = XBADFILE;

    XMEMSET(tmp, 0, sizeof(tmp));
    ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb")) != XBADFILE);
    ExpectIntGT(dsaKeySz = bytes = (word32) XFREAD(tmp, 1, sizeof(tmp), fp), 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif /* END USE_CERT_BUFFERS_1024 */

    /* Create hash to later Sign and Verify */
    ExpectIntEQ(SHA1_Init(&sha), WOLFSSL_SUCCESS);
    ExpectIntEQ(SHA1_Update(&sha, tmp, bytes), WOLFSSL_SUCCESS);
    ExpectIntEQ(SHA1_Final(hash,&sha), WOLFSSL_SUCCESS);

    /* Initialize pkey with der format dsa key */
    ExpectNotNull(d2i_PrivateKey(EVP_PKEY_DSA, &pkey, &dsaKeyDer,
        (long)dsaKeySz));

    /* Test wolfSSL_EVP_PKEY_get1_DSA */
    /* Should Fail: NULL argument */
    ExpectNull(dsa = EVP_PKEY_get0_DSA(NULL));
    ExpectNull(dsa = EVP_PKEY_get1_DSA(NULL));
    /* Should Pass: Initialized pkey argument */
    ExpectNotNull(dsa = EVP_PKEY_get0_DSA(pkey));
    ExpectNotNull(dsa = EVP_PKEY_get1_DSA(pkey));

#ifdef USE_CERT_BUFFERS_1024
    ExpectIntEQ(DSA_bits(dsa), 1024);
#else
    ExpectIntEQ(DSA_bits(dsa), 2048);
#endif

    /* Sign */
    ExpectIntEQ(wolfSSL_DSA_do_sign(hash, signature, dsa), WOLFSSL_SUCCESS);
    /* Verify. */
    ExpectIntEQ(wolfSSL_DSA_do_verify(hash, signature, dsa, &answer),
                WOLFSSL_SUCCESS);

    /* Test wolfSSL_EVP_PKEY_set1_DSA */
    /* Should Fail: set1Pkey not initialized */
    ExpectIntNE(EVP_PKEY_set1_DSA(set1Pkey, dsa), WOLFSSL_SUCCESS);

    /* Initialize set1Pkey */
    set1Pkey = EVP_PKEY_new();

    /* Should Fail Verify: setDsa not initialized from set1Pkey */
    ExpectIntNE(wolfSSL_DSA_do_verify(hash,signature,setDsa,&answer),
                WOLFSSL_SUCCESS);

    /* Should Pass: set dsa into set1Pkey */
    ExpectIntEQ(EVP_PKEY_set1_DSA(set1Pkey, dsa), WOLFSSL_SUCCESS);

    DSA_free(dsa);
    DSA_free(setDsa);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(set1Pkey);
#endif /* OPENSSL_ALL && !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();
} /* END test_EVP_PKEY_set1_get1_DSA */

int test_wolfSSL_EVP_PKEY_set1_get1_EC_KEY(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(OPENSSL_ALL)
    WOLFSSL_EC_KEY* ecKey  = NULL;
    WOLFSSL_EC_KEY* ecGet1  = NULL;
    EVP_PKEY* pkey = NULL;

    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    /* Test wolfSSL_EVP_PKEY_set1_EC_KEY */
    ExpectIntEQ(wolfSSL_EVP_PKEY_set1_EC_KEY(NULL, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_set1_EC_KEY(pkey, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Should fail since ecKey is empty */
    ExpectIntEQ(wolfSSL_EVP_PKEY_set1_EC_KEY(pkey, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    ExpectIntEQ(wolfSSL_EVP_PKEY_set1_EC_KEY(pkey, ecKey), WOLFSSL_SUCCESS);

    /* Test wolfSSL_EVP_PKEY_get1_EC_KEY */
    ExpectNull(wolfSSL_EVP_PKEY_get1_EC_KEY(NULL));
    ExpectNotNull(ecGet1 = wolfSSL_EVP_PKEY_get1_EC_KEY(pkey));

    wolfSSL_EC_KEY_free(ecKey);
    wolfSSL_EC_KEY_free(ecGet1);
    EVP_PKEY_free(pkey);
#endif /* HAVE_ECC && OPENSSL_ALL */
    return EXPECT_RESULT();
} /* END test_EVP_PKEY_set1_get1_EC_KEY */

int test_wolfSSL_EVP_PKEY_get0_EC_KEY(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ECC) && defined(OPENSSL_ALL)
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNull(EVP_PKEY_get0_EC_KEY(NULL));

    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectNull(EVP_PKEY_get0_EC_KEY(pkey));
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_set1_get1_DH(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
    DH       *dh    = NULL;
    DH       *setDh = NULL;
    EVP_PKEY *pkey  = NULL;

    XFILE f = XBADFILE;
    unsigned char buf[4096];
    const unsigned char* pt = buf;
    const char* dh2048 = "./certs/dh2048.der";
    long len = 0;
    int code = -1;

    XMEMSET(buf, 0, sizeof(buf));

    ExpectTrue((f = XFOPEN(dh2048, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Load dh2048.der into DH with internal format */
    ExpectNotNull(setDh = wolfSSL_d2i_DHparams(NULL, &pt, len));

    ExpectIntEQ(wolfSSL_DH_check(setDh, &code), WOLFSSL_SUCCESS);
    ExpectIntEQ(code, 0);
    code = -1;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    /* Set DH into PKEY */
    ExpectIntEQ(wolfSSL_EVP_PKEY_set1_DH(pkey, setDh), WOLFSSL_SUCCESS);

    /* Get DH from PKEY */
    ExpectNotNull(dh = wolfSSL_EVP_PKEY_get1_DH(pkey));

    ExpectIntEQ(wolfSSL_DH_check(dh, &code), WOLFSSL_SUCCESS);
    ExpectIntEQ(code, 0);

    EVP_PKEY_free(pkey);
    DH_free(setDh);
    setDh = NULL;
    DH_free(dh);
    dh = NULL;
#endif /* !NO_DH && WOLFSSL_DH_EXTRA && !NO_FILESYSTEM */
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* OPENSSL_ALL || WOLFSSL_QT || WOLFSSL_OPENSSH */
    return EXPECT_RESULT();
} /* END test_EVP_PKEY_set1_get1_DH */

int test_wolfSSL_EVP_PKEY_assign(void)
{
    EXPECT_DECLS;
#if (!defined(NO_RSA) || !defined(NO_DSA) || defined(HAVE_ECC)) && \
    defined(OPENSSL_ALL)
    int type;
    WOLFSSL_EVP_PKEY* pkey = NULL;
#ifndef NO_RSA
    WOLFSSL_RSA* rsa = NULL;
#endif
#ifndef NO_DSA
    WOLFSSL_DSA* dsa = NULL;
#endif
#ifdef HAVE_ECC
    WOLFSSL_EC_KEY* ecKey = NULL;
#endif

#ifndef NO_RSA
    type = EVP_PKEY_RSA;
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(rsa = wolfSSL_RSA_new());
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(NULL, type, rsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, -1, rsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, rsa),  WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_RSA_free(rsa);
    }
    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
#endif /* NO_RSA */

#ifndef NO_DSA
    type = EVP_PKEY_DSA;
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(dsa = wolfSSL_DSA_new());
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(NULL, type, dsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, -1, dsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, dsa),  WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_DSA_free(dsa);
    }
    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
#endif /* NO_DSA */

#ifdef HAVE_ECC
    type = EVP_PKEY_EC;
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(NULL, type, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, -1, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, type, ecKey), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_EC_KEY_free(ecKey);
    }
    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
#endif /* HAVE_ECC */
#endif /* (!NO_RSA || !NO_DSA || HAVE_ECC) && OPENSSL_ALL */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_assign_DH(void)
{
    EXPECT_DECLS;
#if !defined(NO_DH) && defined(OPENSSL_ALL) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    XFILE                   f = XBADFILE;
    unsigned char           buf[4096];
    const unsigned char*    pt = buf;
    const char*             params1 = "./certs/dh2048.der";
    long                    len = 0;
    WOLFSSL_DH*             dh = NULL;
    WOLFSSL_EVP_PKEY*       pkey = NULL;
    XMEMSET(buf, 0, sizeof(buf));

    /* Load DH parameters DER. */
    ExpectTrue((f = XFOPEN(params1, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNotNull(dh = wolfSSL_d2i_DHparams(NULL, &pt, len));
    ExpectIntEQ(DH_generate_key(dh), WOLFSSL_SUCCESS);

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    /* Bad cases */
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign_DH(NULL, dh),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign_DH(pkey, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign_DH(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Good case */
    ExpectIntEQ(wolfSSL_EVP_PKEY_assign_DH(pkey, dh), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_DH_free(dh);
    }

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_EVP_PKEY_rsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA)
    WOLFSSL_RSA* rsa = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(rsa = wolfSSL_RSA_new());
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_RSA(NULL, rsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_RSA_free(rsa);
    }
    ExpectPtrEq(EVP_PKEY_get0_RSA(pkey), rsa);
    wolfSSL_EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_EVP_PKEY_ec(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_EC_KEY* ecKey = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(ecKey = wolfSSL_EC_KEY_new());
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(NULL, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Should fail since ecKey is empty */
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, ecKey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ecKey), 1);
    ExpectIntEQ(EVP_PKEY_assign_EC_KEY(pkey, ecKey), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        wolfSSL_EC_KEY_free(ecKey);
    }
    wolfSSL_EVP_PKEY_free(pkey);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_missing_parameters(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_WOLFSSL_STUB)
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());

    ExpectIntEQ(wolfSSL_EVP_PKEY_missing_parameters(pkey), 0);
    ExpectIntEQ(wolfSSL_EVP_PKEY_missing_parameters(NULL), 0);

    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_copy_parameters(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_DH) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST) && defined(WOLFSSL_DH_EXTRA) && \
     (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && !defined(NO_FILESYSTEM)
    WOLFSSL_EVP_PKEY* params = NULL;
    WOLFSSL_EVP_PKEY* copy = NULL;
    DH* dh = NULL;
    BIGNUM* p1;
    BIGNUM* g1;
    BIGNUM* q1;
    BIGNUM* p2;
    BIGNUM* g2;
    BIGNUM* q2;

    /* create DH with DH_get_2048_256 params */
    ExpectNotNull(params = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(dh = DH_get_2048_256());
    ExpectIntEQ(EVP_PKEY_set1_DH(params, dh), WOLFSSL_SUCCESS);
    DH_get0_pqg(dh, (const BIGNUM**)&p1,
                    (const BIGNUM**)&q1,
                    (const BIGNUM**)&g1);
    DH_free(dh);
    dh = NULL;

    /* create DH with random generated DH params */
    ExpectNotNull(copy = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(dh = DH_generate_parameters(2048, 2, NULL, NULL));
    ExpectIntEQ(EVP_PKEY_set1_DH(copy, dh), WOLFSSL_SUCCESS);
    DH_free(dh);
    dh = NULL;

    ExpectIntEQ(EVP_PKEY_copy_parameters(copy, params), WOLFSSL_SUCCESS);
    ExpectNotNull(dh = EVP_PKEY_get1_DH(copy));
    ExpectNotNull(dh->p);
    ExpectNotNull(dh->g);
    ExpectNotNull(dh->q);
    DH_get0_pqg(dh, (const BIGNUM**)&p2,
                    (const BIGNUM**)&q2,
                    (const BIGNUM**)&g2);

    ExpectIntEQ(BN_cmp(p1, p2), 0);
    ExpectIntEQ(BN_cmp(q1, q2), 0);
    ExpectIntEQ(BN_cmp(g1, g2), 0);

    DH_free(dh);
    dh = NULL;
    EVP_PKEY_free(copy);
    EVP_PKEY_free(params);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_paramgen(void)
{
    EXPECT_DECLS;
    /* ECC check taken from ecc.c. It is the condition that defines ECC256 */
#if defined(OPENSSL_ALL) && !defined(NO_ECC_SECP) && \
    ((!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && \
            ECC_MIN_KEY_SZ <= 256)
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY*     pkey = NULL;

    /* Test error conditions. */
    ExpectIntEQ(EVP_PKEY_paramgen(NULL, &pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    ExpectIntEQ(EVP_PKEY_paramgen(ctx, NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

#ifndef NO_RSA
    EVP_PKEY_CTX_free(ctx);
    /* Parameter generation for RSA not supported yet. */
    ExpectNotNull(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    ExpectIntEQ(EVP_PKEY_paramgen(ctx, &pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif

#ifdef HAVE_ECC
    EVP_PKEY_CTX_free(ctx);
    ExpectNotNull(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    ExpectIntEQ(EVP_PKEY_paramgen_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
        NID_X9_62_prime256v1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_paramgen(ctx, &pkey), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_keygen_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_keygen(ctx, &pkey), WOLFSSL_SUCCESS);
#endif

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_param_check(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)

    DH       *dh    = NULL;
    DH       *setDh = NULL;
    EVP_PKEY *pkey  = NULL;
    EVP_PKEY_CTX*   ctx = NULL;

    FILE* f = NULL;
    unsigned char buf[512];
    const unsigned char* pt = buf;
    const char* dh2048 = "./certs/dh2048.der";
    long len = 0;
    int code = -1;

    XMEMSET(buf, 0, sizeof(buf));

    ExpectTrue((f = XFOPEN(dh2048, "rb")) != XBADFILE);
    ExpectTrue((len = (long)XFREAD(buf, 1, sizeof(buf), f)) > 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Load dh2048.der into DH with internal format */
    ExpectNotNull(setDh = d2i_DHparams(NULL, &pt, len));
    ExpectIntEQ(DH_check(setDh, &code), WOLFSSL_SUCCESS);
    ExpectIntEQ(code, 0);
    code = -1;

    pkey = wolfSSL_EVP_PKEY_new();
    /* Set DH into PKEY */
    ExpectIntEQ(EVP_PKEY_set1_DH(pkey, setDh), WOLFSSL_SUCCESS);
    /* create ctx from pkey */
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_param_check(ctx), 1/* valid */);

    /* TODO: more invalid cases */
    ExpectIntEQ(EVP_PKEY_param_check(NULL), 0);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    DH_free(setDh);
    setDh = NULL;
    DH_free(dh);
    dh = NULL;
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_keygen_init(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_PKEY*   pkey = NULL;
    EVP_PKEY_CTX        *ctx = NULL;

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));

    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen_init(NULL), WOLFSSL_SUCCESS);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_keygen(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX*     ctx = NULL;
#if !defined(NO_DH) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    WOLFSSL_EVP_PKEY* params = NULL;
    DH* dh = NULL;
    const BIGNUM* pubkey = NULL;
    const BIGNUM* privkey = NULL;
    ASN1_INTEGER* asn1int = NULL;
    unsigned int length = 0;
    byte* derBuffer = NULL;
#endif

    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));

    /* Bad cases */
    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen(NULL, &pkey), 0);
    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen(ctx, NULL), 0);
    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen(NULL, NULL), 0);

    /* Good case */
    ExpectIntEQ(wolfSSL_EVP_PKEY_keygen(ctx, &pkey), 0);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    EVP_PKEY_free(pkey);
    pkey = NULL;

#if !defined(NO_DH) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    /* Test DH keygen */
    {
        ExpectNotNull(params = wolfSSL_EVP_PKEY_new());
        ExpectNotNull(dh = DH_get_2048_256());
        ExpectIntEQ(EVP_PKEY_set1_DH(params, dh), WOLFSSL_SUCCESS);
        ExpectNotNull(ctx = EVP_PKEY_CTX_new(params, NULL));
        ExpectIntEQ(EVP_PKEY_keygen_init(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_keygen(ctx, &pkey), WOLFSSL_SUCCESS);

        DH_free(dh);
        dh = NULL;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(params);

        /* try exporting generated key to DER, to verify */
        ExpectNotNull(dh = EVP_PKEY_get1_DH(pkey));
        DH_get0_key(dh, &pubkey, &privkey);
        ExpectNotNull(pubkey);
        ExpectNotNull(privkey);
        ExpectNotNull(asn1int = BN_to_ASN1_INTEGER(pubkey, NULL));
        ExpectIntGT((length = i2d_ASN1_INTEGER(asn1int, &derBuffer)), 0);

        ASN1_INTEGER_free(asn1int);
        DH_free(dh);
        dh = NULL;
        XFREE(derBuffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        EVP_PKEY_free(pkey);
    }
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_SignInit_ex(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_EVP_MD_CTX mdCtx;
    WOLFSSL_ENGINE*    e = 0;
    const EVP_MD*      md = EVP_sha256();

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_SignInit_ex(&mdCtx, md, e), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif
#if defined(OPENSSL_EXTRA)
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    #ifndef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
        #define TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
    #endif
#endif
#endif

#ifdef TEST_WOLFSSL_EVP_PKEY_SIGN_VERIFY
static int test_wolfSSL_EVP_PKEY_sign_verify(int keyType)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_RSA* rsa = NULL;
#endif
#endif
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    WOLFSSL_DSA* dsa = NULL;
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    WOLFSSL_EC_KEY* ecKey = NULL;
#endif
#endif
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx_verify = NULL;
    const char* in = "What is easy to do is easy not to do.";
    size_t inlen = XSTRLEN(in);
    byte hash[SHA256_DIGEST_LENGTH] = {0};
    byte zero[SHA256_DIGEST_LENGTH] = {0};
    SHA256_CTX c;
    byte*  sig = NULL;
    byte*  sigVerify = NULL;
    size_t siglen;
    size_t siglenOnlyLen;
    size_t keySz = 2048/8;  /* Bytes */

    ExpectNotNull(sig =
        (byte*)XMALLOC(keySz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(sigVerify =
        (byte*)XMALLOC(keySz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));

    siglen = keySz;
    ExpectNotNull(XMEMSET(sig, 0, keySz));
    ExpectNotNull(XMEMSET(sigVerify, 0, keySz));

    /* Generate hash */
    SHA256_Init(&c);
    SHA256_Update(&c, in, inlen);
    SHA256_Final(hash, &c);
#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* workaround for small stack cache case */
    wc_Sha256Free((wc_Sha256*)&c);
#endif

    /* Generate key */
    ExpectNotNull(pkey = EVP_PKEY_new());
    switch (keyType) {
        case EVP_PKEY_RSA:
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        {
            ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
            ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
        }
#endif
#endif
            break;
        case EVP_PKEY_DSA:
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
            ExpectNotNull(dsa = DSA_new());
            ExpectIntEQ(DSA_generate_parameters_ex(dsa, 2048,
                NULL, 0, NULL, NULL, NULL), 1);
            ExpectIntEQ(DSA_generate_key(dsa), 1);
            ExpectIntEQ(EVP_PKEY_set1_DSA(pkey, dsa), WOLFSSL_SUCCESS);
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
            break;
        case EVP_PKEY_EC:
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        {
            ExpectNotNull(ecKey = EC_KEY_new());
            ExpectIntEQ(EC_KEY_generate_key(ecKey), 1);
            ExpectIntEQ(
                EVP_PKEY_assign_EC_KEY(pkey, ecKey), WOLFSSL_SUCCESS);
            if (EXPECT_FAIL()) {
                EC_KEY_free(ecKey);
            }
        }
#endif
#endif
            break;
    }
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA)
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
                    WOLFSSL_SUCCESS);
#endif
#endif

    /* Check returning only length */
    ExpectIntEQ(EVP_PKEY_sign(ctx, NULL, &siglenOnlyLen, hash,
        SHA256_DIGEST_LENGTH), WOLFSSL_SUCCESS);
    ExpectIntGT(siglenOnlyLen, 0);
    /* Sign data */
    ExpectIntEQ(EVP_PKEY_sign(ctx, sig, &siglen, hash,
        SHA256_DIGEST_LENGTH), WOLFSSL_SUCCESS);
    ExpectIntGE(siglenOnlyLen, siglen);

    /* Verify signature */
    ExpectNotNull(ctx_verify = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA)
        ExpectIntEQ(
            EVP_PKEY_CTX_set_rsa_padding(ctx_verify, RSA_PKCS1_PADDING),
            WOLFSSL_SUCCESS);
#endif
#endif
    ExpectIntEQ(EVP_PKEY_verify(
        ctx_verify, sig, siglen, hash, SHA256_DIGEST_LENGTH),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_verify(
        ctx_verify, sig, siglen, zero, SHA256_DIGEST_LENGTH),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    if (keyType == EVP_PKEY_RSA) {
    #if defined(WC_RSA_NO_PADDING) || defined(WC_RSA_DIRECT)
        /* Try RSA sign/verify with no padding. */
        ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_sign(ctx, sigVerify, &siglen, sig,
            siglen), WOLFSSL_SUCCESS);
        ExpectIntGE(siglenOnlyLen, siglen);
        ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_NO_PADDING), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_verify(ctx_verify, sigVerify, siglen, sig,
            siglen), WOLFSSL_SUCCESS);
   #endif

        /* Wrong padding schemes. */
        ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx,
            RSA_PKCS1_OAEP_PADDING), WOLFSSL_SUCCESS);
        ExpectIntNE(EVP_PKEY_sign(ctx, sigVerify, &siglen, sig,
            siglen), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_verify_init(ctx_verify), WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_PKCS1_OAEP_PADDING), WOLFSSL_SUCCESS);
        ExpectIntNE(EVP_PKEY_verify(ctx_verify, sigVerify, siglen, sig,
            siglen), WOLFSSL_SUCCESS);

        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx_verify,
            RSA_PKCS1_PADDING), WOLFSSL_SUCCESS);
    }
#endif
#endif

    /* error cases */
    siglen = keySz; /* Reset because sig size may vary slightly */
    ExpectIntNE(EVP_PKEY_sign_init(NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntNE(EVP_PKEY_sign(NULL, sig, &siglen, (byte*)in, inlen),
                              WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_sign(ctx, sig, &siglen, (byte*)in, inlen),
                              WOLFSSL_SUCCESS);

    EVP_PKEY_free(pkey);
    pkey = NULL;
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    DSA_free(dsa);
    dsa = NULL;
#endif /* !NO_DSA && !HAVE_SELFTEST && WOLFSSL_KEY_GEN */
    EVP_PKEY_CTX_free(ctx_verify);
    ctx_verify = NULL;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sigVerify, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_EVP_PKEY_sign_verify_rsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_SELFTEST)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_RSA), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_PKEY_sign_verify_dsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
#if !defined (NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN)
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_DSA), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_EVP_PKEY_sign_verify_ec(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
    ExpectIntEQ(test_wolfSSL_EVP_PKEY_sign_verify(EVP_PKEY_EC), TEST_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_EVP_MD_rsa_signing(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
    WOLFSSL_EVP_PKEY* privKey = NULL;
    WOLFSSL_EVP_PKEY* pubKey = NULL;
    WOLFSSL_EVP_PKEY_CTX* keyCtx = NULL;
    const char testData[] = "Hi There";
    WOLFSSL_EVP_MD_CTX mdCtx;
    WOLFSSL_EVP_MD_CTX mdCtxCopy;
    int ret;
    size_t checkSz = -1;
    int sz = 2048 / 8;
    const unsigned char* cp;
    const unsigned char* p;
    unsigned char check[2048/8];
    size_t i;
    int paddings[] = {
            RSA_PKCS1_PADDING,
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && defined(WC_RSA_PSS)
            RSA_PKCS1_PSS_PADDING,
#endif
    };


    cp = client_key_der_2048;
    ExpectNotNull((privKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &cp,
                                                  sizeof_client_key_der_2048)));
    p = client_keypub_der_2048;
    ExpectNotNull((pubKey = wolfSSL_d2i_PUBKEY(NULL, &p,
                                               sizeof_client_keypub_der_2048)));

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    wolfSSL_EVP_MD_CTX_init(&mdCtxCopy);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                             NULL, privKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData,
                                          (unsigned int)XSTRLEN(testData)), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    ExpectIntEQ((int)checkSz, sz);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz,sz);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_copy_ex(&mdCtxCopy, &mdCtx), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_copy_ex(&mdCtxCopy, &mdCtx), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtxCopy);
    ExpectIntEQ(ret, 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                              NULL, pubKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData,
                                               (unsigned int)XSTRLEN(testData)),
                1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, check, checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                             NULL, privKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData, 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    ExpectIntEQ((int)checkSz, sz);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz, sz);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData + 4,
                                      (unsigned int)XSTRLEN(testData) - 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ((int)checkSz, sz);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                              NULL, pubKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData, 4), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData + 4,
                                           (unsigned int)XSTRLEN(testData) - 4),
                1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, check, checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    /* Check all signing padding types */
    for (i = 0; i < sizeof(paddings)/sizeof(int); i++) {
        wolfSSL_EVP_MD_CTX_init(&mdCtx);
        ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, &keyCtx,
                wolfSSL_EVP_sha256(), NULL, privKey), 1);
        ExpectIntEQ(wolfSSL_EVP_PKEY_CTX_set_rsa_padding(keyCtx,
                paddings[i]), 1);
        ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData,
                (unsigned int)XSTRLEN(testData)), 1);
        checkSz = sizeof(check);
        ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
        ExpectIntEQ((int)checkSz, sz);
        checkSz = sizeof(check);
        ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
        ExpectIntEQ((int)checkSz,sz);
        ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
        ExpectIntEQ(ret, 1);

        wolfSSL_EVP_MD_CTX_init(&mdCtx);
        ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, &keyCtx,
                wolfSSL_EVP_sha256(), NULL, pubKey), 1);
        ExpectIntEQ(wolfSSL_EVP_PKEY_CTX_set_rsa_padding(keyCtx,
                paddings[i]), 1);
        ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData,
                (unsigned int)XSTRLEN(testData)), 1);
        ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, check, checkSz), 1);
        ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
        ExpectIntEQ(ret, 1);
    }

    wolfSSL_EVP_PKEY_free(pubKey);
    wolfSSL_EVP_PKEY_free(privKey);
#endif
    return EXPECT_RESULT();
}

/* Test RSA-PSS digital signature creation and verification */
int test_wc_RsaPSS_DigitalSignVerify(void)
{
    EXPECT_DECLS;

    /* Early FIPS did not support PSS. */
#if (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))) && \
    (!defined(HAVE_SELFTEST) || (defined(HAVE_SELFTEST_VERSION) && \
    (HAVE_SELFTEST_VERSION > 2))) && \
    !defined(NO_RSA) && defined(WC_RSA_PSS) && defined(OPENSSL_EXTRA) && \
    defined(WOLFSSL_KEY_GEN) && defined(WC_RSA_NO_PADDING) && \
    !defined(NO_SHA256)

    /* Test digest */
    const unsigned char test_digest[32] = {
        0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
    };
    const unsigned int digest_len = sizeof(test_digest);

    /* Variables for RSA key generation and signature operations */
    EVP_PKEY_CTX *pkctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sign_ctx = NULL;
    EVP_PKEY_CTX *verify_ctx = NULL;
    unsigned char signature[256+MAX_DER_DIGEST_ASN_SZ] = {0};
    size_t signature_len = sizeof(signature);
    int modulus_bits = 2048;

    /* Generate RSA key pair to avoid file dependencies */
    ExpectNotNull(pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    ExpectIntEQ(EVP_PKEY_keygen_init(pkctx), 1);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_keygen_bits(pkctx, modulus_bits), 1);
    ExpectIntEQ(EVP_PKEY_keygen(pkctx, &pkey), 1);

    /* Create signing context */
    ExpectNotNull(sign_ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_sign_init(sign_ctx), 1);

    /* Configure RSA-PSS parameters for signing. */
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PSS_PADDING),
        1);
    /* Default salt length matched hash so use 32 for SHA256 */
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(sign_ctx, 32), 1);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_mgf1_md(sign_ctx, EVP_sha256()), 1);
    ExpectIntEQ(EVP_PKEY_CTX_set_signature_md(sign_ctx, EVP_sha256()), 1);

    /* Create the digital signature */
    ExpectIntEQ(EVP_PKEY_sign(sign_ctx, signature, &signature_len, test_digest,
                              digest_len), 1);
    ExpectIntGT((int)signature_len, 0);

    /* Create verification context */
    ExpectNotNull(verify_ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_verify_init(verify_ctx), 1);

    /* Configure RSA-PSS parameters for verification */
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PSS_PADDING),
        1);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_ctx, 32), 1);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_mgf1_md(verify_ctx, EVP_sha256()), 1);
    ExpectIntEQ(EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256()), 1);

    /* Verify the digital signature */
    ExpectIntEQ(EVP_PKEY_verify(verify_ctx, signature, signature_len,
                                test_digest, digest_len), 1);

    /* Test with wrong digest to ensure verification fails (negative test) */
    {
        const unsigned char wrong_digest[32] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02
        };
        ExpectIntNE(EVP_PKEY_verify(verify_ctx, signature, signature_len,
                    wrong_digest, digest_len), 1);
    }

    /* Clean up */
    if (verify_ctx)
        EVP_PKEY_CTX_free(verify_ctx);
    if (sign_ctx)
        EVP_PKEY_CTX_free(sign_ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pkctx)
        EVP_PKEY_CTX_free(pkctx);

#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_MD_ecc_signing(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
    WOLFSSL_EVP_PKEY* privKey = NULL;
    WOLFSSL_EVP_PKEY* pubKey = NULL;
    const char testData[] = "Hi There";
    WOLFSSL_EVP_MD_CTX mdCtx;
    int ret;
    const unsigned char* cp;
    const unsigned char* p;
    unsigned char check[2048/8];
    size_t checkSz = sizeof(check);

    XMEMSET(check, 0, sizeof(check));

    cp = ecc_clikey_der_256;
    ExpectNotNull(privKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, NULL, &cp,
                                                   sizeof_ecc_clikey_der_256));
    p = ecc_clikeypub_der_256;
    ExpectNotNull((pubKey = wolfSSL_d2i_PUBKEY(NULL, &p,
                                                sizeof_ecc_clikeypub_der_256)));

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                             NULL, privKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData,
                                          (unsigned int)XSTRLEN(testData)), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                              NULL, pubKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData,
                                               (unsigned int)XSTRLEN(testData)),
                1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, check, checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestSignInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                             NULL, privKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData, 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, NULL, &checkSz), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestSignUpdate(&mdCtx, testData + 4,
                                      (unsigned int)XSTRLEN(testData) - 4), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(wolfSSL_EVP_DigestSignFinal(&mdCtx, check, &checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyInit(&mdCtx, NULL, wolfSSL_EVP_sha256(),
                                                              NULL, pubKey), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData, 4), 1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyUpdate(&mdCtx, testData + 4,
                                           (unsigned int)XSTRLEN(testData) - 4),
                1);
    ExpectIntEQ(wolfSSL_EVP_DigestVerifyFinal(&mdCtx, check, checkSz), 1);
    ret = wolfSSL_EVP_MD_CTX_cleanup(&mdCtx);
    ExpectIntEQ(ret, 1);

    wolfSSL_EVP_PKEY_free(pubKey);
    wolfSSL_EVP_PKEY_free(privKey);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_EVP_PKEY_encrypt(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    WOLFSSL_RSA* rsa = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
    const char* in = "What is easy to do is easy not to do.";
    size_t inlen = XSTRLEN(in);
    size_t outEncLen = 0;
    byte*  outEnc = NULL;
    byte*  outDec = NULL;
    size_t outDecLen = 0;
    size_t rsaKeySz = 2048/8;  /* Bytes */
#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    byte*  inTmp = NULL;
    byte*  outEncTmp = NULL;
    byte*  outDecTmp = NULL;
#endif

    ExpectNotNull(outEnc = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outEnc != NULL) {
        XMEMSET(outEnc, 0, rsaKeySz);
    }
    ExpectNotNull(outDec = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outDec != NULL) {
        XMEMSET(outDec, 0, rsaKeySz);
    }

    ExpectNotNull(rsa = RSA_generate_key(2048, 3, NULL, NULL));
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    ExpectIntEQ(EVP_PKEY_assign_RSA(pkey, rsa), WOLFSSL_SUCCESS);
    if (EXPECT_FAIL()) {
        RSA_free(rsa);
    }
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_encrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING),
        WOLFSSL_SUCCESS);

    /* Test pkey references count is decremented. pkey shouldn't be destroyed
     since ctx uses it.*/
    ExpectIntEQ(pkey->ref.count, 2);
    EVP_PKEY_free(pkey);
    ExpectIntEQ(pkey->ref.count, 1);

    /* Encrypt data */
    /* Check that we can get the required output buffer length by passing in a
     * NULL output buffer. */
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, NULL, &outEncLen,
                            (const unsigned char*)in, inlen), WOLFSSL_SUCCESS);
    ExpectIntEQ(rsaKeySz, outEncLen);
    /* Now do the actual encryption. */
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, outEnc, &outEncLen,
                            (const unsigned char*)in, inlen), WOLFSSL_SUCCESS);

    /* Decrypt data */
    ExpectIntEQ(EVP_PKEY_decrypt_init(ctx), WOLFSSL_SUCCESS);
    /* Check that we can get the required output buffer length by passing in a
     * NULL output buffer. */
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, NULL, &outDecLen, outEnc, outEncLen),
                                 WOLFSSL_SUCCESS);
    ExpectIntEQ(rsaKeySz, outDecLen);
    /* Now do the actual decryption. */
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, outDec, &outDecLen, outEnc, outEncLen),
                                 WOLFSSL_SUCCESS);

    ExpectIntEQ(XMEMCMP(in, outDec, outDecLen), 0);

#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    /* The input length must be the same size as the RSA key.*/
    ExpectNotNull(inTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (inTmp != NULL) {
        XMEMSET(inTmp, 9, rsaKeySz);
    }
    ExpectNotNull(outEncTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outEncTmp != NULL) {
        XMEMSET(outEncTmp, 0, rsaKeySz);
   }
    ExpectNotNull(outDecTmp = (byte*)XMALLOC(rsaKeySz, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (outDecTmp != NULL) {
        XMEMSET(outDecTmp, 0, rsaKeySz);
    }
    ExpectIntEQ(EVP_PKEY_encrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_encrypt(ctx, outEncTmp, &outEncLen, inTmp, rsaKeySz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_decrypt_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_decrypt(ctx, outDecTmp, &outDecLen, outEncTmp,
        outEncLen), WOLFSSL_SUCCESS);
    ExpectIntEQ(XMEMCMP(inTmp, outDecTmp, outDecLen), 0);
#endif
    EVP_PKEY_CTX_free(ctx);
    XFREE(outEnc, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outDec, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#if !defined(HAVE_FIPS) && defined(WC_RSA_NO_PADDING)
    XFREE(inTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outEncTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outDecTmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_derive(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT) || defined(WOLFSSL_OPENSSH)
#if (!defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)) || defined(HAVE_ECC)
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *skey = NULL;
    size_t skeylen;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peerkey = NULL;
    const unsigned char* key;

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    /* DH */
    key = dh_key_der_2048;
    ExpectNotNull((pkey = d2i_PrivateKey(EVP_PKEY_DH, NULL, &key,
        sizeof_dh_key_der_2048)));
    ExpectIntEQ(DH_generate_key(EVP_PKEY_get0_DH(pkey)), 1);
    key = dh_key_der_2048;
    ExpectNotNull((peerkey = d2i_PrivateKey(EVP_PKEY_DH, NULL, &key,
        sizeof_dh_key_der_2048)));
    ExpectIntEQ(DH_generate_key(EVP_PKEY_get0_DH(peerkey)), 1);
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), 1);
    ExpectIntEQ(EVP_PKEY_derive_set_peer(ctx, peerkey), 1);
    ExpectIntEQ(EVP_PKEY_derive(ctx, NULL, &skeylen), 1);
    ExpectNotNull(skey = (unsigned char*)XMALLOC(skeylen, NULL,
        DYNAMIC_TYPE_OPENSSL));
    ExpectIntEQ(EVP_PKEY_derive(ctx, skey, &skeylen), 1);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    EVP_PKEY_free(peerkey);
    peerkey = NULL;
    EVP_PKEY_free(pkey);
    pkey = NULL;
    XFREE(skey, NULL, DYNAMIC_TYPE_OPENSSL);
    skey = NULL;
#endif

#ifdef HAVE_ECC
    /* ECDH */
    key = ecc_clikey_der_256;
    ExpectNotNull((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key,
        sizeof_ecc_clikey_der_256)));
    key = ecc_clikeypub_der_256;
    ExpectNotNull((peerkey = d2i_PUBKEY(NULL, &key,
        sizeof_ecc_clikeypub_der_256)));
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_derive_init(ctx), 1);
    ExpectIntEQ(EVP_PKEY_derive_set_peer(ctx, peerkey), 1);
    ExpectIntEQ(EVP_PKEY_derive(ctx, NULL, &skeylen), 1);
    ExpectNotNull(skey = (unsigned char*)XMALLOC(skeylen, NULL,
        DYNAMIC_TYPE_OPENSSL));
    ExpectIntEQ(EVP_PKEY_derive(ctx, skey, &skeylen), 1);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    XFREE(skey, NULL, DYNAMIC_TYPE_OPENSSL);
#endif /* HAVE_ECC */
#endif /* (!NO_DH && WOLFSSL_DH_EXTRA) || HAVE_ECC */
#endif /* OPENSSL_ALL || WOLFSSL_QT || WOLFSSL_OPENSSH */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_PKEY_print_public(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    WOLFSSL_BIO* rbio = NULL;
    WOLFSSL_BIO* wbio = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    char line[256] = { 0 };
    char line1[256] = { 0 };
    int i = 0;

    /* test error cases */
    ExpectIntEQ( EVP_PKEY_print_public(NULL,NULL,0,NULL),0L);

    /*
     *  test RSA public key print
     *  in this test, pass '3' for indent
     */
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_1024)

    ExpectNotNull(rbio = BIO_new_mem_buf( client_keypub_der_1024,
        sizeof_client_keypub_der_1024));

    ExpectNotNull(wolfSSL_d2i_PUBKEY_bio(rbio, &pkey));

    ExpectNotNull(wbio = BIO_new(BIO_s_mem()));

    ExpectIntEQ(EVP_PKEY_print_public(wbio, pkey,3,NULL),1);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "   RSA Public-Key: (1024 bit)\n");
    ExpectIntEQ(XSTRNCMP(line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "   Modulus:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "       00:bc:73:0e:a8:49:f3:74:a2:a9:ef:18:a5:da:55:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of modulus element*/
    for (i = 0; i < 8 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "   Exponent: 65537 (0x010001)\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);


    /* should reach EOF */
    ExpectIntLE(BIO_gets(wbio, line, sizeof(line)), 0);

    EVP_PKEY_free(pkey);
    pkey = NULL;
    BIO_free(rbio);
    BIO_free(wbio);
    rbio = NULL;
    wbio = NULL;

#endif  /* !NO_RSA && USE_CERT_BUFFERS_1024*/

    /*
     *  test DSA public key print
     */
#if !defined(NO_DSA) && defined(USE_CERT_BUFFERS_2048)
    ExpectNotNull(rbio = BIO_new_mem_buf( dsa_pub_key_der_2048,
        sizeof_dsa_pub_key_der_2048));

    ExpectNotNull(wolfSSL_d2i_PUBKEY_bio(rbio, &pkey));

    ExpectNotNull(wbio = BIO_new(BIO_s_mem()));

    ExpectIntEQ(EVP_PKEY_print_public(wbio, pkey,0,NULL),1);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "DSA Public-Key: (2048 bit)\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "pub:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1,
        "    00:C2:35:2D:EC:83:83:6C:73:13:9E:52:7C:74:C8:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of pub element*/
    for (i = 0; i < 17 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "P:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of P element*/
    for (i = 0; i < 18 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "Q:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of Q element*/
    for (i = 0; i < 3 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }
    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "G:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of G element*/
    for (i = 0; i < 18 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }
    /* should reach EOF */
    ExpectIntLE(BIO_gets(wbio, line, sizeof(line)), 0);

    EVP_PKEY_free(pkey);
    pkey = NULL;
    BIO_free(rbio);
    BIO_free(wbio);
    rbio = NULL;
    wbio = NULL;

#endif /* !NO_DSA && USE_CERT_BUFFERS_2048 */

    /*
     *  test ECC public key print
     */
#if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)

    ExpectNotNull(rbio = BIO_new_mem_buf( ecc_clikeypub_der_256,
        sizeof_ecc_clikeypub_der_256));

    ExpectNotNull(wolfSSL_d2i_PUBKEY_bio(rbio, &pkey));

    ExpectNotNull(wbio = BIO_new(BIO_s_mem()));

    ExpectIntEQ(EVP_PKEY_print_public(wbio, pkey,0,NULL),1);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    ExpectStrEQ(line, "Public-Key: (256 bit)\n");

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "pub:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1,
            "    04:55:BF:F4:0F:44:50:9A:3D:CE:9B:B7:F0:C5:4D:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of pub element*/
    for (i = 0; i < 4 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "ASN1 OID: prime256v1\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "NIST CURVE: P-256\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);


    /* should reach EOF */
    ExpectIntLE(BIO_gets(wbio, line, sizeof(line)), 0);

    EVP_PKEY_free(pkey);
    pkey = NULL;
    BIO_free(rbio);
    BIO_free(wbio);
    rbio = NULL;
    wbio = NULL;

#endif /* HAVE_ECC && USE_CERT_BUFFERS_256 */

    /*
     *  test DH public key print
     */
#if defined(WOLFSSL_DH_EXTRA) && defined(USE_CERT_BUFFERS_2048)

    ExpectNotNull(rbio = BIO_new_mem_buf( dh_pub_key_der_2048,
        sizeof_dh_pub_key_der_2048));

    ExpectNotNull(wolfSSL_d2i_PUBKEY_bio(rbio, &pkey));

    ExpectNotNull(wbio = BIO_new(BIO_s_mem()));

    ExpectIntEQ(EVP_PKEY_print_public(wbio, pkey,0,NULL), 1);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "DH Public-Key: (2048 bit)\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "public-key:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1,
        "    34:41:BF:E9:F2:11:BF:05:DB:B2:72:A8:29:CC:BD:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of public-key element*/
    for (i = 0; i < 17 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "prime:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1,
        "    00:D3:B2:99:84:5C:0A:4C:E7:37:CC:FC:18:37:01:\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* skip to the end of prime element*/
    for (i = 0; i < 17 ;i++) {
        ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    }

    ExpectIntGT(BIO_gets(wbio, line, sizeof(line)), 0);
    strcpy(line1, "generator: 2 (0x02)\n");
    ExpectIntEQ(XSTRNCMP( line, line1, XSTRLEN(line1)), 0);

    /* should reach EOF */
    ExpectIntLE(BIO_gets(wbio, line, sizeof(line)), 0);

    EVP_PKEY_free(pkey);
    pkey = NULL;
    BIO_free(rbio);
    BIO_free(wbio);
    rbio = NULL;
    wbio = NULL;

#endif /* WOLFSSL_DH_EXTRA && USE_CERT_BUFFERS_2048 */

    /* to prevent "unused variable" warning */
    (void)pkey;
    (void)wbio;
    (void)rbio;
    (void)line;
    (void)line1;
    (void)i;
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

