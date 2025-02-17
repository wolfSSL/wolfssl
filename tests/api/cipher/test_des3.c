/* test_des3.c
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
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_des3.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * DES3 Tests
 ******************************************************************************/

int test_wc_Des3Init(void)
{
#ifndef NO_DES3
    byte key[24];
    byte iv[DES_BLOCK_SIZE];
    byte plain[DES_BLOCK_SIZE];
    byte cipher[DES_BLOCK_SIZE];
    
    return TEST_CRYPTO_OPERATION("DES3",
        wc_Des3Init,
        wc_Des3SetKey,
        wc_Des3CbcEncrypt,
        wc_Des3Free,
        plain, sizeof(plain), cipher);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_Des3SetKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des3;
    byte key[24];
    byte iv[DES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_Des3Init(&des3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3SetKey(&des3, key, iv, DES_ENCRYPTION), 0);
    ExpectIntEQ(wc_Des3SetKey(&des3, key, iv, DES_DECRYPTION), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Des3SetKey(NULL, key, iv, DES_ENCRYPTION), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Des3SetKey(&des3, NULL, iv, DES_ENCRYPTION), BAD_FUNC_ARG);

    wc_Des3Free(&des3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Des3CbcEncrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des3;
    byte key[24];
    byte iv[DES_BLOCK_SIZE];
    byte plain[DES_BLOCK_SIZE];
    byte cipher[DES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_Des3Init(&des3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3SetKey(&des3, key, iv, DES_ENCRYPTION), 0);
    ExpectIntEQ(wc_Des3CbcEncrypt(&des3, cipher, plain, DES_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Des3CbcEncrypt(NULL, cipher, plain, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_Des3CbcEncrypt(&des3, NULL, plain, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_Des3CbcEncrypt(&des3, cipher, NULL, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);

    wc_Des3Free(&des3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Des3CbcDecrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des3;
    byte key[24];
    byte iv[DES_BLOCK_SIZE];
    byte plain[DES_BLOCK_SIZE];
    byte cipher[DES_BLOCK_SIZE];

    /* Test normal operation */
    ExpectIntEQ(wc_Des3Init(&des3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Des3SetKey(&des3, key, iv, DES_DECRYPTION), 0);
    ExpectIntEQ(wc_Des3CbcDecrypt(&des3, plain, cipher, DES_BLOCK_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Des3CbcDecrypt(NULL, plain, cipher, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_Des3CbcDecrypt(&des3, NULL, cipher, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_Des3CbcDecrypt(&des3, plain, NULL, DES_BLOCK_SIZE),
        BAD_FUNC_ARG);

    wc_Des3Free(&des3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Des3Free(void)
{
    EXPECT_DECLS;
#ifndef NO_DES3
    Des3 des3;
    wc_Des3Init(&des3, NULL, INVALID_DEVID);
    wc_Des3Free(&des3);
    wc_Des3Free(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
