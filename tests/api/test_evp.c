/* test_evp.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <tests/unit.h>
#include <wolfssl/openssl/evp.h>
#include <tests/api/test_evp.h>

#ifdef OPENSSL_EXTRA

/* Test for NULL_CIPHER_TYPE in wolfSSL_EVP_CipherUpdate() */
static int TestNullCipherUpdate(void);
/* Test for NULL_CIPHER_TYPE with empty data */
static int TestNullCipherUpdateEmptyData(void);
/* Test for NULL_CIPHER_TYPE with large data */
static int TestNullCipherUpdateLargeData(void);
/* Test for NULL_CIPHER_TYPE with multiple updates */
static int TestNullCipherUpdateMultiple(void);

/* Test for NULL_CIPHER_TYPE in wolfSSL_EVP_CipherUpdate() */
static int TestNullCipherUpdate(void)
{
    EXPECT_DECLS;
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    const char* testData = "Test NULL cipher data";
    unsigned char output[100];
    int outputLen = 0;
    int testDataLen = (int)XSTRLEN(testData);

    /* Create and initialize the cipher context */
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);

    /* Initialize with NULL cipher */
    ExpectIntEQ(wolfSSL_EVP_CipherInit_ex(ctx, wolfSSL_EVP_enc_null(), 
                                         NULL, NULL, NULL, 1), WOLFSSL_SUCCESS);

    /* Test encryption (which should just copy the data) */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output, &outputLen, 
                                        (const unsigned char*)testData, 
                                        testDataLen), WOLFSSL_SUCCESS);
    
    /* Verify output length matches input length */
    ExpectIntEQ(outputLen, testDataLen);
    
    /* Verify output data matches input data (no encryption occurred) */
    ExpectIntEQ(XMEMCMP(output, testData, testDataLen), 0);

    /* Clean up */
    wolfSSL_EVP_CIPHER_CTX_free(ctx);

    return EXPECT_RESULT();
}

/* Test for NULL_CIPHER_TYPE with empty data */
static int TestNullCipherUpdateEmptyData(void)
{
    EXPECT_DECLS;
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    unsigned char output[100];
    int outputLen = 0;

    /* Create and initialize the cipher context */
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);

    /* Initialize with NULL cipher */
    ExpectIntEQ(wolfSSL_EVP_CipherInit_ex(ctx, wolfSSL_EVP_enc_null(), 
                                         NULL, NULL, NULL, 1), WOLFSSL_SUCCESS);

    /* Test with empty data */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output, &outputLen, 
                                        NULL, 0), WOLFSSL_SUCCESS);
    
    /* Verify output length is 0 */
    ExpectIntEQ(outputLen, 0);

    /* Clean up */
    wolfSSL_EVP_CIPHER_CTX_free(ctx);

    return EXPECT_RESULT();
}

/* Test for NULL_CIPHER_TYPE with large data */
static int TestNullCipherUpdateLargeData(void)
{
    EXPECT_DECLS;
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    unsigned char largeData[1024];
    unsigned char output[1024];
    int outputLen = 0;
    int i;

    /* Fill large data buffer with pattern */
    for (i = 0; i < 1024; i++) {
        largeData[i] = (unsigned char)(i & 0xFF);
    }

    /* Create and initialize the cipher context */
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);

    /* Initialize with NULL cipher */
    ExpectIntEQ(wolfSSL_EVP_CipherInit_ex(ctx, wolfSSL_EVP_enc_null(), 
                                         NULL, NULL, NULL, 1), WOLFSSL_SUCCESS);

    /* Test with large data */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output, &outputLen, 
                                        largeData, 1024), WOLFSSL_SUCCESS);
    
    /* Verify output length matches input length */
    ExpectIntEQ(outputLen, 1024);
    
    /* Verify output data matches input data */
    ExpectIntEQ(XMEMCMP(output, largeData, 1024), 0);

    /* Clean up */
    wolfSSL_EVP_CIPHER_CTX_free(ctx);

    return EXPECT_RESULT();
}

/* Test for NULL_CIPHER_TYPE with multiple updates */
static int TestNullCipherUpdateMultiple(void)
{
    EXPECT_DECLS;
    WOLFSSL_EVP_CIPHER_CTX* ctx;
    const char* testData1 = "First part of data";
    const char* testData2 = "Second part of data";
    unsigned char output1[100];
    unsigned char output2[100];
    int outputLen1 = 0;
    int outputLen2 = 0;
    int testData1Len = (int)XSTRLEN(testData1);
    int testData2Len = (int)XSTRLEN(testData2);

    /* Create and initialize the cipher context */
    ctx = wolfSSL_EVP_CIPHER_CTX_new();
    ExpectNotNull(ctx);

    /* Initialize with NULL cipher */
    ExpectIntEQ(wolfSSL_EVP_CipherInit_ex(ctx, wolfSSL_EVP_enc_null(), 
                                         NULL, NULL, NULL, 1), WOLFSSL_SUCCESS);

    /* First update */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output1, &outputLen1, 
                                        (const unsigned char*)testData1, 
                                        testData1Len), WOLFSSL_SUCCESS);
    
    /* Verify first output */
    ExpectIntEQ(outputLen1, testData1Len);
    ExpectIntEQ(XMEMCMP(output1, testData1, testData1Len), 0);

    /* Second update */
    ExpectIntEQ(wolfSSL_EVP_CipherUpdate(ctx, output2, &outputLen2, 
                                        (const unsigned char*)testData2, 
                                        testData2Len), WOLFSSL_SUCCESS);
    
    /* Verify second output */
    ExpectIntEQ(outputLen2, testData2Len);
    ExpectIntEQ(XMEMCMP(output2, testData2, testData2Len), 0);

    /* Clean up */
    wolfSSL_EVP_CIPHER_CTX_free(ctx);

    return EXPECT_RESULT();
}

/* Function to register all EVP tests */
int TestEvpAll(void)
{
    int ret = 0;

    ret |= TestNullCipherUpdate();
    ret |= TestNullCipherUpdateEmptyData();
    ret |= TestNullCipherUpdateLargeData();
    ret |= TestNullCipherUpdateMultiple();

    return ret;
}

#endif /* OPENSSL_EXTRA */
