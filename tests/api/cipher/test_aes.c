/* test_aes.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_aes.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * AES Tests
 ******************************************************************************/

int test_wc_AesInit(void)
{
#ifndef NO_AES
    byte key[32];
    byte iv[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE];
    byte cipher[AES_BLOCK_SIZE];
    
    return TEST_CRYPTO_OPERATION("AES",
        wc_AesInit,
        wc_AesSetKey,
        wc_AesCbcEncrypt,
        wc_AesFree,
        plain, sizeof(plain), cipher);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_AesSetKey(void)
{
    EXPECT_DECLS;
#ifndef NO_AES
    Aes aes;
    byte key[32];
    byte iv[AES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION), 0);

    /* Test error cases */
    ExpectIntEQ(wc_AesSetKey(NULL, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_AesSetKey(&aes, NULL, AES_BLOCK_SIZE, iv, AES_ENCRYPTION),
        BAD_FUNC_ARG);

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

int test_wc_AesCbcEncrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_AES
    Aes aes;
    byte key[32];
    byte iv[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE];
    byte cipher[AES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION), 0);
    ExpectIntEQ(wc_AesCbcEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_AesCbcEncrypt(NULL, cipher, plain, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_AesCbcEncrypt(&aes, NULL, plain, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_AesCbcEncrypt(&aes, cipher, NULL, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

int test_wc_AesCbcDecrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_AES
    Aes aes;
    byte key[32];
    byte iv[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE];
    byte cipher[AES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION), 0);
    ExpectIntEQ(wc_AesCbcDecrypt(&aes, plain, cipher, AES_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_AesCbcDecrypt(NULL, plain, cipher, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_AesCbcDecrypt(&aes, NULL, cipher, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_AesCbcDecrypt(&aes, plain, NULL, AES_BLOCK_SIZE),
        BAD_FUNC_ARG);

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

int test_wc_AesFree(void)
{
    EXPECT_DECLS;
#ifndef NO_AES
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesFree(&aes);
    wc_AesFree(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
