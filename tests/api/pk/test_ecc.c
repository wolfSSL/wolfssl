/* test_ecc.c
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/test_ecc.h>
#include "../core/test_utils.h"

/*******************************************************************************
 * ECC Tests
 ******************************************************************************/

int test_wc_ecc_init(void)
{
#ifdef HAVE_ECC
    ecc_key key;
    return TEST_CRYPTO_OPERATION("ECC",
        wc_ecc_init,
        NULL,
        NULL,
        wc_ecc_free,
        NULL, 0, NULL);
#else
    return EXPECT_RESULT();
#endif
}

int test_wc_ecc_sign_hash(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    ecc_key key;
    WC_RNG rng;
    byte hash[32];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);

    /* Test normal operation */
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, &rng, &key),
        BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_ecc_sign_hash(NULL, sizeof(hash), sig, &sigLen, &rng, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_sign_hash(hash, 0, sig, &sigLen, &rng, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_sign_hash(hash, sizeof(hash), NULL, &sigLen, &rng, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_sign_hash(hash, sizeof(hash), sig, NULL, &rng, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, NULL, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, &rng, NULL),
        BAD_FUNC_ARG);

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_ecc_verify_hash(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    ecc_key key;
    byte hash[32];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    int stat = 0;

    /* Test normal operation */
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &stat, &key),
        BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_ecc_verify_hash(NULL, sigLen, hash, sizeof(hash), &stat, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_verify_hash(sig, 0, hash, sizeof(hash), &stat, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_verify_hash(sig, sigLen, NULL, sizeof(hash), &stat, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_verify_hash(sig, sigLen, hash, 0, &stat, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), NULL, &key),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &stat, NULL),
        BAD_FUNC_ARG);

    wc_ecc_free(&key);
#endif
    return EXPECT_RESULT();
}

int test_wc_ecc_make_key(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    WC_RNG rng;
    ecc_key key;
    int size = 32;

    /* Test normal operation */
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, size, &key), BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_ecc_make_key(NULL, size, &key), BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_make_key(&rng, 0, &key), BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_make_key(&rng, size, NULL), BAD_FUNC_ARG);

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_wc_ecc_shared_secret(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    ecc_key key1, key2;
    byte secret[ECC_MAXSIZE];
    word32 secretLen = sizeof(secret);

    /* Test normal operation */
    ExpectIntEQ(wc_ecc_init(&key1), 0);
    ExpectIntEQ(wc_ecc_init(&key2), 0);
    ExpectIntEQ(wc_ecc_shared_secret(&key1, &key2, secret, &secretLen),
        BAD_FUNC_ARG);

    /* Test error cases */
    ExpectIntEQ(wc_ecc_shared_secret(NULL, &key2, secret, &secretLen),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_shared_secret(&key1, NULL, secret, &secretLen),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_shared_secret(&key1, &key2, NULL, &secretLen),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_ecc_shared_secret(&key1, &key2, secret, NULL),
        BAD_FUNC_ARG);

    wc_ecc_free(&key1);
    wc_ecc_free(&key2);
#endif
    return EXPECT_RESULT();
}

int test_wc_ecc_free(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ECC
    ecc_key key;
    wc_ecc_init(&key);
    wc_ecc_free(&key);
    wc_ecc_free(NULL); /* Test NULL case */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
}
