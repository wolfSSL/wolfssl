/* test_camellia.c
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
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_camellia.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * Camellia Tests
 ******************************************************************************/

int test_wc_CamelliaInit(void)
{
#ifdef HAVE_CAMELLIA
    byte key[32];
    byte iv[CAMELLIA_BLOCK_SIZE];
    byte plain[CAMELLIA_BLOCK_SIZE];
    byte cipher[CAMELLIA_BLOCK_SIZE];
    
    return TEST_CRYPTO_OPERATION("CAMELLIA",
        wc_CamelliaInit,
        wc_CamelliaSetKey,
        wc_CamelliaCbcEncrypt,
        wc_CamelliaFree,
        plain, sizeof(plain), cipher);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_CamelliaSetKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    Camellia camellia;
    byte key[32];
    byte iv[CAMELLIA_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_CamelliaInit(&camellia, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, 16, iv), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, 24, iv), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, 32, iv), 0);

    /* Test error cases */
    ExpectIntEQ(wc_CamelliaSetKey(NULL, key, 16, iv), BAD_FUNC_ARG);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, NULL, 16, iv), BAD_FUNC_ARG);

    wc_CamelliaFree(&camellia);
#endif
    return EXPECT_RESULT();
}

int test_wc_CamelliaCbcEncrypt(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    Camellia camellia;
    byte key[32];
    byte iv[CAMELLIA_BLOCK_SIZE];
    byte plain[CAMELLIA_BLOCK_SIZE];
    byte cipher[CAMELLIA_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_CamelliaInit(&camellia, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, 16, iv), 0);
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, cipher, plain,
        CAMELLIA_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_CamelliaCbcEncrypt(NULL, cipher, plain,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, NULL, plain,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);
    ExpectIntEQ(wc_CamelliaCbcEncrypt(&camellia, cipher, NULL,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);

    wc_CamelliaFree(&camellia);
#endif
    return EXPECT_RESULT();
}

int test_wc_CamelliaCbcDecrypt(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    Camellia camellia;
    byte key[32];
    byte iv[CAMELLIA_BLOCK_SIZE];
    byte plain[CAMELLIA_BLOCK_SIZE];
    byte cipher[CAMELLIA_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_CamelliaInit(&camellia, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_CamelliaSetKey(&camellia, key, 16, iv), 0);
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, plain, cipher,
        CAMELLIA_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_CamelliaCbcDecrypt(NULL, plain, cipher,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, NULL, cipher,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);
    ExpectIntEQ(wc_CamelliaCbcDecrypt(&camellia, plain, NULL,
        CAMELLIA_BLOCK_SIZE), BAD_FUNC_ARG);

    wc_CamelliaFree(&camellia);
#endif
    return EXPECT_RESULT();
}

int test_wc_CamelliaFree(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CAMELLIA
    Camellia camellia;
    wc_CamelliaInit(&camellia, NULL, INVALID_DEVID);
    wc_CamelliaFree(&camellia);
    wc_CamelliaFree(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
