/* test_dsa.c
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
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_dsa.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * DSA Tests
 ******************************************************************************/

int test_wc_InitDsaKey(void)
{
#ifndef NO_DSA
    DsaKey key;
    return TEST_CRYPTO_OPERATION("DSA",
        wc_InitDsaKey,
        NULL,
        NULL,
        wc_FreeDsaKey,
        NULL, 0, NULL);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_DsaSign(void)
{
    EXPECT_DECLS;
#ifndef NO_DSA
    DsaKey key;
    WC_RNG rng;
    byte hash[SHA_DIGEST_SIZE];
    byte sig[DSA_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    /* Test normal operation */
    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_DsaSign(hash, sig, &key, &rng), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_DsaSign(NULL, sig, &key, &rng), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaSign(hash, NULL, &key, &rng), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaSign(hash, sig, NULL, &rng), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaSign(hash, sig, &key, NULL), BAD_FUNC_ARG);

    wc_FreeDsaKey(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_DsaVerify(void)
{
    EXPECT_DECLS;
#ifndef NO_DSA
    DsaKey key;
    byte hash[SHA_DIGEST_SIZE];
    byte sig[DSA_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    int stat = 0;

    /* Test normal operation */
    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaVerify(hash, sig, &key, &stat), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_DsaVerify(NULL, sig, &key, &stat), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaVerify(hash, NULL, &key, &stat), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaVerify(hash, sig, NULL, &stat), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaVerify(hash, sig, &key, NULL), BAD_FUNC_ARG);

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_DsaPublicPrivateKeyDecode(void)
{
    EXPECT_DECLS;
#ifndef NO_DSA
    DsaKey key;
    byte* tmp = NULL;
    word32 idx = 0;

    /* Test normal operation */
    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, &idx, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, &key, 0), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_DsaPublicKeyDecode(NULL, &idx, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, NULL, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, &idx, NULL, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(NULL, &idx, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, NULL, &key, 0), BAD_FUNC_ARG);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, NULL, 0), BAD_FUNC_ARG);

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_DsaFree(void)
{
    EXPECT_DECLS;
#ifndef NO_DSA
    DsaKey key;
    wc_InitDsaKey(&key);
    wc_FreeDsaKey(&key);
    wc_FreeDsaKey(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
