/* test_slhdsa.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef WOLFSSL_HAVE_SLHDSA
    #include <wolfssl/wolfcrypt/wc_slhdsa.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_slhdsa.h>


/*
 * Test basic init/free and NULL parameter handling for SLH-DSA key operations.
 */
int test_wc_slhdsa(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;

    /* Test NULL parameter handling for init. */
    ExpectIntEQ(wc_SlhDsaKey_Init(NULL, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test wc_SlhDsaKey_Free with NULL - should not crash. */
    wc_SlhDsaKey_Free(NULL);

    /* Test valid init for each supported parameter set. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test size functions for SLH-DSA.
 */
int test_wc_slhdsa_sizes(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;

    /* Test NULL parameter handling for size functions. */
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SigSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test sizes for each parameter set. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE128S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE128F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE192S_PUB_LEN);
    /* Verify signature size is positive. */
    ExpectIntGT(wc_SlhDsaKey_SigSize(&key), 0);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PUB_LEN);
    /* Verify SigSizeFromParam returns positive value. */
    ExpectIntGT(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE192S), 0);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE192F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE256S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE256F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_SIG_LEN);
#endif

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test key generation for SLH-DSA.
 */
int test_wc_slhdsa_make_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

    /* Test MakeKeyWithRandom. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    {
        byte sk_seed[WC_SLHDSA_SHAKE128S_SEED_LEN];
        byte sk_prf[WC_SLHDSA_SHAKE128S_SEED_LEN];
        byte pk_seed[WC_SLHDSA_SHAKE128S_SEED_LEN];

        XMEMSET(sk_seed, 0x01, sizeof(sk_seed));
        XMEMSET(sk_prf, 0x02, sizeof(sk_prf));
        XMEMSET(pk_seed, 0x03, sizeof(pk_seed));

        /* Test NULL parameter handling. */
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(NULL, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, NULL, sizeof(sk_seed),
            sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), NULL, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), NULL, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Test wrong size. */
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed, 8,
            sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            0);
        wc_SlhDsaKey_Free(&key);
    }
#endif

    wc_FreeRng(&rng);
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */
    return EXPECT_RESULT();
}

/*
 * Test signing for SLH-DSA.
 */
int test_wc_slhdsa_sign(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    word32 expSigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(NULL, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256F_SIG_LEN;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), NULL, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        NULL, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test buffer too small. */
    sigLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful signing. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, expSigLen);

    /* Test signing with NULL context (allowed). */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    wc_SlhDsaKey_Free(&key);

    /* Test SignDeterministic. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignDeterministic(NULL, ctx, sizeof(ctx),
        msg, sizeof(msg), sig, &sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignDeterministic(&key, ctx, sizeof(ctx),
        msg, sizeof(msg), sig, &sigLen), 0);
    ExpectIntEQ(sigLen, expSigLen);

    wc_SlhDsaKey_Free(&key);

    /* Test SignWithRandom. */
    {
        byte addRnd[WC_SLHDSA_MAX_SEED];
        XMEMSET(addRnd, 0x55, sizeof(addRnd));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL,
            INVALID_DEVID), 0);
#endif
        ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(NULL, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, addRnd),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(&key, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(&key, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, addRnd), 0);
        ExpectIntEQ(sigLen, expSigLen);

        wc_SlhDsaKey_Free(&key);
    }

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */
    return EXPECT_RESULT();
}

/*
 * Test verification for SLH-DSA.
 */
int test_wc_slhdsa_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Generate a signature. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(NULL, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), NULL, sizeof(msg),
        sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        NULL, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test successful verification. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    /* Test verification with wrong message. */
    msg[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    msg[0] ^= 0xFF;

    /* Test verification with wrong context. */
    ctx[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    ctx[0] ^= 0xFF;

    /* Test verification with corrupted signature. */
    sig[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    sig[0] ^= 0xFF;

    /* Test verification with NULL context (allowed, but must match signing). */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, NULL, 0, msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test combined sign and verify for all parameter sets.
 */
int test_wc_slhdsa_sign_vfy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE128S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE128F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, (word32)wc_SlhDsaKey_SigSize(&key));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE192F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE256S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE256F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test hash signing and verification for SLH-DSA.
 */
int test_wc_slhdsa_sign_hash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte hash[64];
    byte* sig = NULL;
    word32 sigLen;
    word32 expSigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(hash, 0xBB, sizeof(hash));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256F_SIG_LEN;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test SignHash NULL parameter handling. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHash(NULL, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), NULL,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, NULL, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test SignHash with SHA-256. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, expSigLen);
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);

    /* Test VerifyHash NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(NULL, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), NULL, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, NULL, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test VerifyHash with wrong hash. */
    hash[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);
    hash[0] ^= 0xFF;

    /* Test SignHashDeterministic. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHashDeterministic(NULL, ctx, sizeof(ctx),
        hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHashDeterministic(&key, ctx, sizeof(ctx),
        hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);

    /* Test SignHashWithRandom. */
    {
        byte addRnd[WC_SLHDSA_MAX_SEED];
        XMEMSET(addRnd, 0x55, sizeof(addRnd));

        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(NULL, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, addRnd),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(&key, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(&key, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, addRnd), 0);
        ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
            WC_HASH_TYPE_SHA256, sig, sigLen), 0);
    }

    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test export and import for SLH-DSA keys.
 */
int test_wc_slhdsa_export_import(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    SlhDsaKey key2;
    WC_RNG rng;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen;
    word32 expPrivKeyLen;
    word32 pubKeyLen;
    word32 expPubKeyLen;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    privKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PRIV_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(privKey);
    pubKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PUB_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);
    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling for export functions. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(NULL, privKey, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(NULL, pubKey, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test NULL parameter handling for import functions. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(NULL, privKey, privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(NULL, pubKey, pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 16;
    expPubKeyLen = 2 * 16;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 16;
    expPubKeyLen = 2 * 16;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 24;
    expPubKeyLen = 2 * 24;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 24;
    expPubKeyLen = 2 * 24;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 32;
    expPubKeyLen = 2 * 32;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 32;
    expPubKeyLen = 2 * 32;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test export with NULL buffer. */
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, NULL, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, NULL, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test export with buffer too small. */
    privKeyLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    pubKeyLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful export. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen), 0);
    ExpectIntEQ(privKeyLen, expPrivKeyLen);

    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen), 0);
    ExpectIntEQ(pubKeyLen, expPubKeyLen);

    /* Sign with original key. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    /* Test import into new key and verify. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif

    /* Test import with NULL data. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, NULL, privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, NULL, pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test import with wrong size. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, privKey, 10),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, pubKey, 10),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful import of public key only. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, pubKey, pubKeyLen), 0);
    /* Verify with imported public key. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key2, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key2);

    /* Test import of private key. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, privKey, privKeyLen), 0);
    /* Sign with imported key. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key2, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    /* Verify with original key. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key2);
    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test key check for SLH-DSA.
 */
int test_wc_slhdsa_check_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen;
    word32 pubKeyLen;

    privKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PRIV_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(privKey);
    pubKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PUB_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test check of valid key. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);

    /* Export keys. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen), 0);
    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen), 0);

    wc_SlhDsaKey_Free(&key);

    /* Test check with only public key imported - requires private key. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    /* CheckKey requires a private key to validate. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), WC_NO_ERR_TRACE(MISSING_KEY));
    wc_SlhDsaKey_Free(&key);

    /* Test check with only private key imported. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    /* Test check with both keys imported.
     * Note: ImportPublic overwrites flags, so import Public first then Private.
     */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}
