/* test_evp.c
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

#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/openssl/evp.h>
#include <tests/api/test_evp.h>

/* Test for NULL_CIPHER_TYPE in wolfSSL_EVP_CipherUpdate() */
int test_wolfSSL_EVP_CipherUpdate_Null(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
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
#endif /* OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

/* Test for wolfSSL_EVP_CIPHER_type_string() */
int test_wolfSSL_EVP_CIPHER_type_string(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    const char* cipherStr;

    /* Test with valid cipher types */
#ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_AES_128_CBC_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "AES-128-CBC");
    #endif
#endif

#ifndef NO_DES3
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_DES_CBC_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "DES-CBC");
#endif

    /* Test with NULL cipher type */
    cipherStr = wolfSSL_EVP_CIPHER_type_string(WC_NULL_CIPHER_TYPE);
    ExpectNotNull(cipherStr);
    ExpectStrEQ(cipherStr, "NULL");

    /* Test with invalid cipher type */
    cipherStr = wolfSSL_EVP_CIPHER_type_string(0xFFFF);
    ExpectNull(cipherStr);
#endif /* OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

