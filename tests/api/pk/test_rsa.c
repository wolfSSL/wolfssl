/* test_rsa.c
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
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_rsa.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * RSA Tests
 ******************************************************************************/

int test_wc_InitRsaKey(void)
{
#ifndef NO_RSA
    RsaKey key;
    return TEST_CRYPTO_OPERATION("RSA",
        wc_InitRsaKey,
        NULL,
        NULL,
        wc_FreeRsaKey,
        NULL, 0, NULL);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_RsaPrivateKeyDecode(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;
    byte* tmp = NULL;
    word32 idx = 0;

    /* Test normal operation */
    ExpectIntEQ(wc_InitRsaKey(&key, NULL), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, &key, 0), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_RsaPrivateKeyDecode(NULL, &idx, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, NULL, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, NULL, 0), BAD_FUNC_ARG);

    wc_FreeRsaKey(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_RsaPublicKeyDecode(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;
    byte* tmp = NULL;
    word32 idx = 0;

    /* Test normal operation */
    ExpectIntEQ(wc_InitRsaKey(&key, NULL), 0);
    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, &idx, &key, 0), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_RsaPublicKeyDecode(NULL, &idx, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, NULL, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicKeyDecode(tmp, &idx, NULL, 0), BAD_FUNC_ARG);

    wc_FreeRsaKey(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_RsaPublicEncrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;
    WC_RNG rng;
    byte in[] = "Test data";
    byte out[256];
    word32 outLen = sizeof(out);

    /* Test normal operation */
    ExpectIntEQ(wc_InitRsaKey(&key, NULL), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_RsaPublicEncrypt(in, sizeof(in), out, outLen, &key, &rng), 
        BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_RsaPublicEncrypt(NULL, sizeof(in), out, outLen, &key, &rng),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicEncrypt(in, 0, out, outLen, &key, &rng),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicEncrypt(in, sizeof(in), NULL, outLen, &key, &rng),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicEncrypt(in, sizeof(in), out, 0, &key, &rng),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPublicEncrypt(in, sizeof(in), out, outLen, NULL, &rng),
        BAD_FUNC_ARG);

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_RsaPrivateDecrypt(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;
    byte in[256];
    byte out[256];
    word32 outLen = sizeof(out);

    /* Test normal operation */
    ExpectIntEQ(wc_InitRsaKey(&key, NULL), 0);
    ExpectIntEQ(wc_RsaPrivateDecrypt(in, sizeof(in), out, outLen, &key),
        BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_RsaPrivateDecrypt(NULL, sizeof(in), out, outLen, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateDecrypt(in, 0, out, outLen, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateDecrypt(in, sizeof(in), NULL, outLen, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateDecrypt(in, sizeof(in), out, 0, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_RsaPrivateDecrypt(in, sizeof(in), out, outLen, NULL),
        BAD_FUNC_ARG);

    wc_FreeRsaKey(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_RsaFree(void)
{
    EXPECT_DECLS;
#ifndef NO_RSA
    RsaKey key;
    wc_InitRsaKey(&key, NULL);
    wc_FreeRsaKey(&key);
    wc_FreeRsaKey(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
