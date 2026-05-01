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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <tests/api/api.h>
#include <tests/api/test_slhdsa.h>


#ifdef WOLFSSL_HAVE_SLHDSA
/* Pick the first available parameter set so tests that just need any one valid
 * SLH-DSA configuration compile and run in SHAKE-only, SHA-2-only, or mixed
 * builds. Preference order: SHAKE 128s/f, 192s/f, 256s/f, then the SHA-2
 * variants in the same order. */
#if defined(WOLFSSL_SLHDSA_PARAM_128S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE128S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE128S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE128S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE128S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE128S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE128F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE128F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE128F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE128F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE128F_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE192S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE192S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE192S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE192S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE192S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE192F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE192F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE192F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE192F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE192F_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE256S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE256S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE256S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE256S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE256S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHAKE256F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHAKE256F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHAKE256F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHAKE256F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHAKE256F_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_128S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_128S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_128S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_128S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_128S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_128S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_128F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_128F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_128F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_128F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_128F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_128F_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_192S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_192S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_192S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_192S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_192S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_192S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_192F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_192F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_192F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_192F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_192F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_192F_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_256S)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_256S
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_256S_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_256S_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_256S_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_256S_SEED_LEN
#elif defined(WOLFSSL_SLHDSA_PARAM_SHA2_256F)
    #define TEST_SLHDSA_DEFAULT_PARAM     SLHDSA_SHA2_256F
    #define TEST_SLHDSA_DEFAULT_SIG_LEN   WC_SLHDSA_SHA2_256F_SIG_LEN
    #define TEST_SLHDSA_DEFAULT_PRIV_LEN  WC_SLHDSA_SHA2_256F_PRIV_LEN
    #define TEST_SLHDSA_DEFAULT_PUB_LEN   WC_SLHDSA_SHA2_256F_PUB_LEN
    #define TEST_SLHDSA_DEFAULT_SEED_LEN  WC_SLHDSA_SHA2_256F_SEED_LEN
#endif
#endif /* WOLFSSL_HAVE_SLHDSA */


/*
 * Test basic init/free and NULL parameter handling for SLH-DSA key operations.
 */
int test_wc_slhdsa(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    /* `key` is only used by the per-variant Init/Free blocks below, so
     * gate its declaration on the same precondition (at least one
     * parameter set compiled in) to avoid -Wunused-variable when SLH-DSA
     * is enabled but no params are. */
#ifdef TEST_SLHDSA_DEFAULT_PARAM
    SlhDsaKey key;

    /* Test NULL parameter handling for init. Use whichever variant the
     * build actually has so a SHA-2-only build doesn't pass a SHAKE param
     * id and conflate BAD_FUNC_ARG (NULL key) with NOT_COMPILED_IN
     * (variant disabled). */
    ExpectIntEQ(wc_SlhDsaKey_Init(NULL, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* Test wc_SlhDsaKey_Free with NULL - should not crash. */
    wc_SlhDsaKey_Free(NULL);

    /* Test valid init for each supported parameter set. Each block zeros
     * `key` first so a future regression where wc_SlhDsaKey_Free leaves
     * a residual field set cannot be papered over by the next Init's
     * partial reinitialisation. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

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
    /* See test_wc_slhdsa() for the rationale on this guard. */
#ifdef TEST_SLHDSA_DEFAULT_PARAM
    SlhDsaKey key;
#endif

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
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE192S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_SIG_LEN);
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

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_128S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_128F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_192S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_192F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_256S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_256F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_SIG_LEN);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

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

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

    /* Test MakeKeyWithRandom. */
#ifdef TEST_SLHDSA_DEFAULT_PARAM
    {
        byte sk_seed[TEST_SLHDSA_DEFAULT_SEED_LEN];
        byte sk_prf[TEST_SLHDSA_DEFAULT_SEED_LEN];
        byte pk_seed[TEST_SLHDSA_DEFAULT_SEED_LEN];

        XMEMSET(sk_seed, 0x01, sizeof(sk_seed));
        XMEMSET(sk_prf, 0x02, sizeof(sk_prf));
        XMEMSET(pk_seed, 0x03, sizeof(pk_seed));

        /* Test NULL parameter handling. */
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(NULL, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
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

    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    expSigLen = TEST_SLHDSA_DEFAULT_SIG_LEN;
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
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
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

        ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
            INVALID_DEVID), 0);
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

    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
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

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_128S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_128F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_192S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_192F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_256S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_256F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

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

    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    expSigLen = TEST_SLHDSA_DEFAULT_SIG_LEN;
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

    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    expPrivKeyLen = TEST_SLHDSA_DEFAULT_PRIV_LEN;
    expPubKeyLen = TEST_SLHDSA_DEFAULT_PUB_LEN;
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
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);

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
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
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

    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
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
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    /* CheckKey requires a private key to validate. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), WC_NO_ERR_TRACE(MISSING_KEY));
    wc_SlhDsaKey_Free(&key);

    /* Test check with only private key imported. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    /* Test check with both keys imported. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    /* Regression: Private-then-Public order. ImportPrivate sets
     * flags = WC_SLHDSA_FLAG_BOTH_KEYS; if ImportPublic clobbered flags
     * with `=` instead of `|=`, the FLAG_PRIVATE bit would be dropped and
     * CheckKey would return MISSING_KEY. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, TEST_SLHDSA_DEFAULT_PARAM, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
/* Round-trip a single SLH-DSA parameter set through the DER codec:
 * generate -> KeyToDer -> PrivateKeyDecode -> sign/verify round-trip.
 * Also tests PublicKeyToDer -> PublicKeyDecode, and that the decode
 * correctly auto-detects the parameter set from the OID. */
static int slhdsa_der_roundtrip_one(enum SlhDsaParam param)
{
    EXPECT_DECLS;
    SlhDsaKey keyGen;
    SlhDsaKey keyPriv;
    SlhDsaKey keyPub;
    WC_RNG rng;
    byte* derBuf = NULL;
    byte* sig = NULL;
    const word32 derBufSz = 16 * 1024;
    word32 derLen;
    word32 idx;
    word32 sigLen;
    enum SlhDsaParam placeholder = param;
    static const byte msg[] = "SLH-DSA DER round-trip";
    static const enum SlhDsaParam candidates[] = {
        SLHDSA_SHAKE256S, SLHDSA_SHAKE128F, SLHDSA_SHAKE192S,
        SLHDSA_SHAKE192F, SLHDSA_SHAKE256F, SLHDSA_SHAKE128S,
    #ifdef WOLFSSL_SLHDSA_SHA2
        SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S,
        SLHDSA_SHA2_192F, SLHDSA_SHA2_256S, SLHDSA_SHA2_256F,
    #endif
    };
    size_t cIdx;

    /* Pick a placeholder different from the encoded param so a regression
     * that disables OID auto-detection would fail the post-decode equality
     * check. Walk the candidate list and probe each via wc_SlhDsaKey_Init;
     * the first one that initialises successfully (i.e. is compiled in) is
     * used. Falls back to the encoded param if no other variant is
     * available, in which case the test reduces to a smoke check. */
    for (cIdx = 0; cIdx < sizeof(candidates)/sizeof(candidates[0]); cIdx++) {
        SlhDsaKey probe;
        if (candidates[cIdx] == param) {
            continue;
        }
        XMEMSET(&probe, 0, sizeof(probe));
        if (wc_SlhDsaKey_Init(&probe, candidates[cIdx], NULL,
                              INVALID_DEVID) == 0) {
            placeholder = candidates[cIdx];
            wc_SlhDsaKey_Free(&probe);
            break;
        }
    }

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&keyGen, 0, sizeof(keyGen));
    XMEMSET(&keyPriv, 0, sizeof(keyPriv));
    XMEMSET(&keyPub, 0, sizeof(keyPub));

    derBuf = (byte*)XMALLOC(derBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(derBuf);
    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&keyGen, param, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&keyGen, &rng), 0);

    /* Size-query contract: passing output=NULL returns the encoded size
     * without touching the buffer. The real encode below must produce
     * exactly this many bytes -- a size-query regression (e.g. forgetting
     * to add verSz) would surface here as a mismatch. */
    {
        int querySize;
        ExpectIntGT(querySize = wc_SlhDsaKey_KeyToDer(&keyGen, NULL, 0), 0);
        ExpectIntGT(derLen = (word32)wc_SlhDsaKey_KeyToDer(&keyGen, derBuf,
            derBufSz), 0);
        ExpectIntEQ((int)derLen, querySize);

        /* BUFFER_E contract: too-small buffer is rejected without writing
         * anything past the limit. Pass inLen = querySize - 1 so the
         * length check fails for any encoding. */
        ExpectIntEQ(wc_SlhDsaKey_KeyToDer(&keyGen, derBuf,
            (word32)(querySize - 1)), WC_NO_ERR_TRACE(BUFFER_E));

        /* PrivateKeyToDer is an RFC 9909 alias of KeyToDer; sizes must
         * match and BUFFER_E must propagate. */
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(&keyGen, NULL, 0), querySize);
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(&keyGen, derBuf,
            (word32)(querySize - 1)), WC_NO_ERR_TRACE(BUFFER_E));
    }

    /* Decode into a fresh key.  The decode must auto-detect the real
     * parameter set from the OID embedded in the DER encoding. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&keyPriv, placeholder, NULL, INVALID_DEVID),
        0);
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idx, &keyPriv, derLen),
        0);
    /* Verify the decoded key reports the ORIGINAL parameter set. */
    if (keyPriv.params != NULL) {
        ExpectIntEQ((int)keyPriv.params->param, (int)param);
    }
    /* Byte-level equivalence check: re-encode the decoded private key
     * and compare against the original DER. This catches a regression
     * even in single-variant builds where placeholder == param made the
     * params equality test above tautological -- if the decoder ignored
     * the OID and kept stale state, the bytes won't match. */
    {
        byte* roundBuf = (byte*)XMALLOC(derBufSz, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        word32 roundLen;
        ExpectNotNull(roundBuf);
        ExpectIntGT(roundLen = (word32)wc_SlhDsaKey_KeyToDer(&keyPriv,
            roundBuf, derBufSz), 0);
        ExpectIntEQ((int)roundLen, (int)derLen);
        if (roundBuf != NULL) {
            ExpectIntEQ(XMEMCMP(roundBuf, derBuf, roundLen), 0);
        }
        XFREE(roundBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    /* Sign with the decoded private key and verify with the originally
     * generated key. This proves the decoded key material is correct. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&keyPriv, NULL, 0, msg, (word32)sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&keyGen, NULL, 0, msg, (word32)sizeof(msg),
        sig, sigLen), 0);

    /* Also test PrivateKeyToDer -> PrivateKeyDecode round-trip. */
    {
        SlhDsaKey keyPriv2;
        word32 derLen2;
        word32 idx2 = 0;
        XMEMSET(&keyPriv2, 0, sizeof(keyPriv2));
        ExpectIntGT(derLen2 = (word32)wc_SlhDsaKey_PrivateKeyToDer(&keyGen,
            derBuf, derBufSz), 0);
        ExpectIntEQ(wc_SlhDsaKey_Init(&keyPriv2, placeholder, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idx2, &keyPriv2,
            derLen2), 0);
        /* Verify the PrivateKeyToDer output matches KeyToDer. */
        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_Sign(&keyPriv2, NULL, 0, msg,
            (word32)sizeof(msg), sig, &sigLen, &rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Verify(&keyGen, NULL, 0, msg,
            (word32)sizeof(msg), sig, sigLen), 0);
        wc_SlhDsaKey_Free(&keyPriv2);
    }

    /* PKCS#8 v2 (RFC 5958) acceptance: the decoder explicitly allows
     * version=0 or version=1. The encoder only ever writes version=0,
     * so without a targeted check the v=1 branch would never fire and a
     * regression that rejected v2 wrappers (legal RFC 5958 OneAsymmetricKey
     * input from external tools) would slip through. Walk past the outer
     * SEQUENCE header (which uses short or long-form length depending on
     * the parameter set's encoded size) to land on the INTEGER version
     * field, then flip its value from 0 to 1. */
    {
        SlhDsaKey keyPrivV2;
        word32 idxV2 = 0;
        word32 verPos;
        byte saved;

        XMEMSET(&keyPrivV2, 0, sizeof(keyPrivV2));
        ExpectIntGT((int)derLen, 5);
        ExpectIntEQ((int)derBuf[0], 0x30); /* outer SEQUENCE tag */
        if ((derBuf[1] & 0x80) == 0) {
            verPos = 2;                       /* short-form length */
        }
        else {
            verPos = 2 + (derBuf[1] & 0x7F);  /* long-form length */
        }
        ExpectIntLT((int)verPos + 3, (int)derLen);
        ExpectIntEQ((int)derBuf[verPos], 0x02);     /* INTEGER tag */
        ExpectIntEQ((int)derBuf[verPos + 1], 0x01); /* INTEGER length */
        ExpectIntEQ((int)derBuf[verPos + 2], 0x00); /* v0 baseline */
        saved = derBuf[verPos + 2];
        derBuf[verPos + 2] = 0x01;

        ExpectIntEQ(wc_SlhDsaKey_Init(&keyPrivV2, placeholder, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idxV2, &keyPrivV2,
            derLen), 0);
        if (keyPrivV2.params != NULL) {
            ExpectIntEQ((int)keyPrivV2.params->param, (int)param);
        }
        /* Confirm the v2-decoded private material is functionally
         * identical: a signature it produces verifies under keyGen. */
        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_Sign(&keyPrivV2, NULL, 0, msg,
            (word32)sizeof(msg), sig, &sigLen, &rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Verify(&keyGen, NULL, 0, msg,
            (word32)sizeof(msg), sig, sigLen), 0);
        derBuf[verPos + 2] = saved;
        wc_SlhDsaKey_Free(&keyPrivV2);
    }

    /* Now round-trip the public key alone, with size-query and BUFFER_E
     * contract checks for both withAlg modes. */
    {
        int querySpki, queryRaw;
        byte rawPub[WC_SLHDSA_MAX_PUB_LEN];
        word32 rawPubLen = (word32)sizeof(rawPub);

        /* withAlg=1: full SubjectPublicKeyInfo (used by certificate code). */
        ExpectIntGT(querySpki = wc_SlhDsaKey_PublicKeyToDer(&keyGen, NULL, 0,
            1), 0);
        ExpectIntGT(derLen = (word32)wc_SlhDsaKey_PublicKeyToDer(&keyGen,
            derBuf, derBufSz, 1), 0);
        ExpectIntEQ((int)derLen, querySpki);
        ExpectIntEQ(wc_SlhDsaKey_PublicKeyToDer(&keyGen, derBuf,
            (word32)(querySpki - 1), 1), WC_NO_ERR_TRACE(BUFFER_E));

        /* withAlg=0: raw 2*n public-key bytes only -- this is the path
         * SetKeyIdFromPublicKey in asn.c walks when computing SKID/AKID
         * for SLH-DSA certificates. Verify the bytes match what
         * ExportPublic produces so a regression in this branch (e.g.
         * accidentally emitting the SPKI envelope, or returning the
         * wrong length) breaks the test rather than silently corrupting
         * key identifiers in issued certs. */
        ExpectIntGT(queryRaw = wc_SlhDsaKey_PublicKeyToDer(&keyGen, NULL, 0,
            0), 0);
        ExpectIntEQ(queryRaw, (int)(2 * keyGen.params->n));
        ExpectIntGT(wc_SlhDsaKey_PublicKeyToDer(&keyGen, derBuf, derBufSz, 0),
            0);
        ExpectIntEQ(wc_SlhDsaKey_PublicKeyToDer(&keyGen, derBuf,
            (word32)(queryRaw - 1), 0), WC_NO_ERR_TRACE(BUFFER_E));

        ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&keyGen, rawPub, &rawPubLen), 0);
        ExpectIntEQ((int)rawPubLen, queryRaw);
        ExpectIntEQ(XMEMCMP(derBuf, rawPub, rawPubLen), 0);

        /* Re-encode the SPKI so the decode test below sees the
         * withAlg=1 buffer (raw output above is not decodable as SPKI). */
        ExpectIntGT(derLen = (word32)wc_SlhDsaKey_PublicKeyToDer(&keyGen,
            derBuf, derBufSz, 1), 0);
    }

    ExpectIntEQ(wc_SlhDsaKey_Init(&keyPub, placeholder, NULL, INVALID_DEVID),
        0);
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(derBuf, &idx, &keyPub, derLen), 0);
    if (keyPub.params != NULL) {
        ExpectIntEQ((int)keyPub.params->param, (int)param);
    }
    /* The decoded public key should verify the signature we just produced. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&keyPub, NULL, 0, msg, (word32)sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&keyPub);
    wc_SlhDsaKey_Free(&keyPriv);
    wc_SlhDsaKey_Free(&keyGen);
    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#endif

/*
 * DER codec round-trip test: encode each compiled-in SLH-DSA parameter set
 * to DER, decode it (without telling the decoder which parameter set it is),
 * confirm auto-detect produces the right parameter, and verify a signature
 * produced with the decoded key. This test would fail if PrivateKeyDecode
 * / PublicKeyDecode did not auto-detect the parameter set from the OID.
 */
int test_wc_slhdsa_der_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE256F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_256F), TEST_SUCCESS);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif /* WOLFSSL_HAVE_SLHDSA && !VERIFY_ONLY && WC_ENABLE_ASYM_KEY_EXPORT */
    return EXPECT_RESULT();
}

/*
 * Negative / error-path tests for the DER encode/decode functions.
 */
int test_wc_slhdsa_der_negative(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;
    word32 idx;
    byte buf[16];

    XMEMSET(&key, 0, sizeof(key));

    /* PrivateKeyDecode: NULL parameters */
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* PrivateKeyDecode: truncated data */
    idx = 0;
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntNE(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, &key, sizeof(buf)), 0);
#endif

    /* PublicKeyDecode: NULL parameters */
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    /* KeyToDer / PrivateKeyToDer: NULL key */
    ExpectIntEQ(wc_SlhDsaKey_KeyToDer(NULL, buf, sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(NULL, buf, sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* KeyToDer: public-only key should return MISSING_KEY. Build the
     * public-only state through the public API (generate a key, export
     * the public part, import it into a fresh key) rather than poking
     * key->flags directly. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    {
        SlhDsaKey srcKey;
        SlhDsaKey pubOnly;
        WC_RNG rng;
        byte pub[WC_SLHDSA_MAX_PUB_LEN];
        word32 pubLen = (word32)sizeof(pub);

        XMEMSET(&srcKey, 0, sizeof(srcKey));
        XMEMSET(&pubOnly, 0, sizeof(pubOnly));
        XMEMSET(&rng, 0, sizeof(rng));

        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Init(&srcKey, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_MakeKey(&srcKey, &rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&srcKey, pub, &pubLen), 0);

        ExpectIntEQ(wc_SlhDsaKey_Init(&pubOnly, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&pubOnly, pub, pubLen), 0);
        ExpectIntEQ(wc_SlhDsaKey_KeyToDer(&pubOnly, NULL, 0),
            WC_NO_ERR_TRACE(MISSING_KEY));
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(&pubOnly, NULL, 0),
            WC_NO_ERR_TRACE(MISSING_KEY));
        wc_SlhDsaKey_Free(&pubOnly);
        wc_SlhDsaKey_Free(&srcKey);
        wc_FreeRng(&rng);
    }
#endif
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && !VERIFY_ONLY */

    /* PublicKeyToDer: NULL key */
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyToDer(NULL, buf, sizeof(buf), 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* RFC 5958 OneAsymmetricKey trailing-field validation:
     *   [0] IMPLICIT Attributes  OPTIONAL  -- at most once
     *   [1] IMPLICIT PublicKey   OPTIONAL  -- at most once, after [0]
     * The decoder must reject duplicates, out-of-order tags, and
     * unrecognised tags. Build a valid SHAKE128S DER then mutate it. */
#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WOLFSSL_SLHDSA_PARAM_128S)
    {
        SlhDsaKey srcKey;
        WC_RNG rng;
        byte goodDer[256];
        int goodLen = 0;
        size_t i;
        struct {
            const byte* trailing;
            word32      trailingLen;
            int         expectAccept; /* 0 = expect ASN_PARSE_E */
            const char* desc;
        } cases[5];
        const byte tDupAttr[]   = { 0xA0, 0x00, 0xA0, 0x00 };
        const byte tDupPub[]    = { 0xA1, 0x00, 0xA1, 0x00 };
        const byte tOutOfOrder[]= { 0xA1, 0x00, 0xA0, 0x00 };
        const byte tUnknown[]   = { 0xA2, 0x00 };
        const byte tValidAttr[] = { 0xA0, 0x00 };

        cases[0].trailing = tDupAttr;
        cases[0].trailingLen = (word32)sizeof(tDupAttr);
        cases[0].expectAccept = 0;
        cases[0].desc = "duplicate [0] attributes";
        cases[1].trailing = tDupPub;
        cases[1].trailingLen = (word32)sizeof(tDupPub);
        cases[1].expectAccept = 0;
        cases[1].desc = "duplicate [1] publicKey";
        cases[2].trailing = tOutOfOrder;
        cases[2].trailingLen = (word32)sizeof(tOutOfOrder);
        cases[2].expectAccept = 0;
        cases[2].desc = "[1] before [0]";
        cases[3].trailing = tUnknown;
        cases[3].trailingLen = (word32)sizeof(tUnknown);
        cases[3].expectAccept = 0;
        cases[3].desc = "unknown context tag [2]";
        /* Sanity: a single [0] is permitted -- if this rejects, the
         * tightening above is overzealous and the four rejection cases
         * are testing nothing useful. */
        cases[4].trailing = tValidAttr;
        cases[4].trailingLen = (word32)sizeof(tValidAttr);
        cases[4].expectAccept = 1;
        cases[4].desc = "single [0] attributes (accepted)";

        XMEMSET(&srcKey, 0, sizeof(srcKey));
        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Init(&srcKey, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_MakeKey(&srcKey, &rng), 0);
        ExpectIntGT(goodLen = wc_SlhDsaKey_KeyToDer(&srcKey, goodDer,
            sizeof(goodDer)), 0);

        /* The mutator below tweaks goodDer[1] (length byte) in place,
         * which only works if the encoder used short-form SEQUENCE
         * length. SHAKE128S body is ~82 bytes so this holds, but assert
         * it so a future encoder change surfaces here rather than
         * silently producing buffers that decode despite the mutation. */
        ExpectIntEQ((int)goodDer[0], 0x30);
        ExpectIntLT((int)goodDer[1], 0x80);
        ExpectIntLT((int)goodDer[1] + 4, 0x80);

        for (i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
            byte mut[260];
            word32 mutLen;
            word32 idx2 = 0;
            SlhDsaKey k;
            int decRet;
            XMEMSET(&k, 0, sizeof(k));
            XMEMCPY(mut, goodDer, (size_t)goodLen);
            XMEMCPY(mut + goodLen, cases[i].trailing, cases[i].trailingLen);
            mutLen = (word32)goodLen + cases[i].trailingLen;
            mut[1] = (byte)(goodDer[1] + cases[i].trailingLen);
            ExpectIntEQ(wc_SlhDsaKey_Init(&k, SLHDSA_SHAKE128S, NULL,
                INVALID_DEVID), 0);
            decRet = wc_SlhDsaKey_PrivateKeyDecode(mut, &idx2, &k, mutLen);
            if (cases[i].expectAccept) {
                ExpectIntEQ(decRet, 0);
            }
            else {
                ExpectIntEQ(decRet, WC_NO_ERR_TRACE(ASN_PARSE_E));
            }
            (void)cases[i].desc;
            wc_SlhDsaKey_Free(&k);
        }

        wc_SlhDsaKey_Free(&srcKey);
        wc_FreeRng(&rng);
    }
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && !VERIFY_ONLY && PARAM_128S */

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    !defined(NO_FILESYSTEM)
/* Load an RFC 9909 compliant DER file from disk and confirm that
 * wc_SlhDsaKey_PrivateKeyDecode accepts it, auto-detects the parameter
 * set from the OID, and produces a usable signing key. This test
 * exercises the on-disk certs/slhdsa/ fixtures - any future file-format
 * drift (nested wrapper, seed-only, wrong length) will be caught here. */
/* doSign=0 skips the sign/verify smoke check; the 192s and 256s parameter
 * sets are slow enough (multi-second per Sign) that running them on every
 * make-check would balloon test time. The decoder is still exercised. */
static int slhdsa_decode_file_one(const char *path, enum SlhDsaParam expected,
    int doSign)
{
    EXPECT_DECLS;
    XFILE f = XBADFILE;
    byte der[256];
    int derSz = 0;
    SlhDsaKey key;
    WC_RNG rng;
    word32 idx = 0;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigLen = (word32)sizeof(sig);
    static const byte msg[] = "slhdsa decode-file test";

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectTrue((f = XFOPEN(path, "rb")) != XBADFILE);
    if (f != XBADFILE) {
        ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), f), 0);
        XFCLOSE(f);
    }

    /* Pick a seed param different from `expected` when more than one
     * variant is built. The decoder always overwrites this from the OID
     * in the DER, so a different placeholder actually tests the auto-
     * detect contract on disk-loaded fixtures (mirroring the helper
     * logic in slhdsa_der_roundtrip_one). Falls back to `expected` when
     * no alternative variant is available. */
    {
        static const enum SlhDsaParam candidates[] = {
            SLHDSA_SHAKE128S, SLHDSA_SHAKE128F, SLHDSA_SHAKE192S,
            SLHDSA_SHAKE192F, SLHDSA_SHAKE256S, SLHDSA_SHAKE256F,
        #ifdef WOLFSSL_SLHDSA_SHA2
            SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S,
            SLHDSA_SHA2_192F, SLHDSA_SHA2_256S, SLHDSA_SHA2_256F,
        #endif
        };
        enum SlhDsaParam placeholder = expected;
        size_t cIdx;
        for (cIdx = 0; cIdx < sizeof(candidates)/sizeof(candidates[0]);
             cIdx++) {
            SlhDsaKey probe;
            if (candidates[cIdx] == expected) continue;
            XMEMSET(&probe, 0, sizeof(probe));
            if (wc_SlhDsaKey_Init(&probe, candidates[cIdx], NULL,
                                  INVALID_DEVID) == 0) {
                placeholder = candidates[cIdx];
                wc_SlhDsaKey_Free(&probe);
                break;
            }
        }
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, placeholder, NULL, INVALID_DEVID),
            0);
    }

    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &key, (word32)derSz),
        0);
    ExpectNotNull(key.params);
    if (key.params != NULL) {
        ExpectIntEQ((int)key.params->param, (int)expected);
    }

    if (doSign) {
        /* Sanity: signing works with the decoded key. */
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, (word32)sizeof(msg),
            sig, &sigLen, &rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Verify(&key, NULL, 0, msg,
            (word32)sizeof(msg), sig, sigLen), 0);
        wc_FreeRng(&rng);
    }
    else {
        /* Cheap structural validation when the full sign/verify is
         * skipped (slow 192s/256s variants): catches an uninitialised SK
         * half or a botched SHA-2 precompute without paying the
         * multi-second cost of an actual Sign. */
        ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    }

    wc_SlhDsaKey_Free(&key);
    return EXPECT_RESULT();
}
#endif

/* Load each checked-in bench_slhdsa_shake*_key.der fixture and confirm it
 * decodes via wc_SlhDsaKey_PrivateKeyDecode with correct auto-detection.
 * These fixtures are RFC 9909 compliant (bare OCTET STRING, 4*n bytes) -
 * this test would fail if the files drift to a non-compliant encoding
 * (e.g. nested OCTET STRING, seed-only). */
int test_wc_slhdsa_der_decode_files(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    !defined(NO_FILESYSTEM)
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake128s_key.der", SLHDSA_SHAKE128S, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake128f_key.der", SLHDSA_SHAKE128F, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake192s_key.der", SLHDSA_SHAKE192S, 0),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake192f_key.der", SLHDSA_SHAKE192F, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake256s_key.der", SLHDSA_SHAKE256S, 0),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake256f_key.der", SLHDSA_SHAKE256F, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_128s_key.der", SLHDSA_SHA2_128S, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_128f_key.der", SLHDSA_SHA2_128F, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_192s_key.der", SLHDSA_SHA2_192S, 0),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_192f_key.der", SLHDSA_SHA2_192F, 1),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_256s_key.der", SLHDSA_SHA2_256S, 0),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_256f_key.der", SLHDSA_SHA2_256F, 1),
        TEST_SUCCESS);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
/* Regression: wolfssl_x509_make_der and ConfirmSignature both pass the
 * raw 2*n public-key bytes (the BIT STRING contents stashed by StoreKey
 * into cert->publicKey) to wc_SlhDsaKey_PublicKeyDecode. Before the
 * raw-first fast path landed, that call returned ASN_PARSE_E because
 * DecodeAsymKeyPublic_Assign requires an SPKI SEQUENCE. This test pins
 * the new contract: when key->params is already set, raw bytes decode
 * directly, mirroring wc_Falcon_PublicKeyDecode and
 * wc_Dilithium_PublicKeyDecode. */
static int slhdsa_raw_public_decode_one(enum SlhDsaParam param)
{
    EXPECT_DECLS;
    SlhDsaKey src;
    SlhDsaKey dst;
    byte pub[WC_SLHDSA_MAX_PUB_LEN];
    word32 pubLen = (word32)sizeof(pub);
    word32 idx = 0;
    WC_RNG rng;

    XMEMSET(&src, 0, sizeof(src));
    XMEMSET(&dst, 0, sizeof(dst));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&src, param, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&src, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&src, pub, &pubLen), 0);

    /* Decode the raw public-key bytes via PublicKeyDecode. The fast
     * path triggers because key->params is set by Init. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&dst, param, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(pub, &idx, &dst, pubLen), 0);
    ExpectIntEQ((int)idx, (int)pubLen);
    ExpectNotNull(dst.params);
    if (dst.params != NULL) {
        ExpectIntEQ((int)dst.params->param, (int)param);
    }

    wc_SlhDsaKey_Free(&dst);
    wc_SlhDsaKey_Free(&src);
    wc_FreeRng(&rng);
    return EXPECT_RESULT();
}
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */

int test_wc_slhdsa_x509_i2d_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    /* Exercise the raw public-key fast path for every compiled-in variant
     * so a regression in n-dependent buffer math (32/48/64-byte keys)
     * fails the test even in restricted builds where SHAKE128S /
     * SHA2_128S happen to be excluded. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHAKE256F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_128S), TEST_SUCCESS);
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_128F), TEST_SUCCESS);
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_192S), TEST_SUCCESS);
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_192F), TEST_SUCCESS);
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_256S), TEST_SUCCESS);
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_raw_public_decode_one(SLHDSA_SHA2_256F), TEST_SUCCESS);
    #endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
/* Build a DER blob using an enabled SLH-DSA variant and patch the
 * AlgorithmIdentifier OID's trailing byte to point at a *disabled*
 * variant, then push it through the decoders. The contract being
 * pinned is that wc_SlhDsaKey_PrivateKeyDecode / PublicKeyDecode pass
 * the wc_SlhDsaOidToParam NOT_COMPILED_IN result through verbatim
 * rather than collapsing it to ASN_PARSE_E -- if that breaks, x509 /
 * TLS lose the precise "variant unavailable" diagnostic and silently
 * report malformed-DER instead.
 *
 * All SLH-DSA OIDs share the prefix 2.16.840.1.101.3.4.3.X with X<128,
 * so DER encoding lengths match exactly and the trailing byte is the
 * sole discriminator -- patching it in place produces a structurally
 * valid SPKI/PKCS#8 buffer that only fails at the OID-lookup step.
 *
 * @param src             Enabled parameter set used to generate real DER.
 * @param targetOidByte   Trailing OID byte of the disabled variant.
 */
/* Marked WC_MAYBE_UNUSED because every call site below is gated on a
 * per-variant disable macro -- builds that leave every variant enabled
 * (e.g. --enable-fips=ready) preprocess all callers away. */
static WC_MAYBE_UNUSED int slhdsa_decode_disabled_oid_one(enum SlhDsaParam src,
    byte targetOidByte)
{
    EXPECT_DECLS;
    /* OID prefix common to every SLH-DSA variant. */
    static const byte oidPrefix[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03
    };
    SlhDsaKey srcKey;
    SlhDsaKey dstKey;
    WC_RNG rng;
    byte* derBuf = NULL;
    const word32 derBufSz = 16 * 1024;
    int derLen = 0;
    word32 idx;
    word32 j;
    int patched;

    XMEMSET(&srcKey, 0, sizeof(srcKey));
    XMEMSET(&dstKey, 0, sizeof(dstKey));
    XMEMSET(&rng, 0, sizeof(rng));

    derBuf = (byte*)XMALLOC(derBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(derBuf);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&srcKey, src, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&srcKey, &rng), 0);

    /* Public-key path: build SPKI, patch the variant byte, decode. */
    ExpectIntGT(derLen = wc_SlhDsaKey_PublicKeyToDer(&srcKey, derBuf, derBufSz,
        1), 0);
    patched = 0;
    for (j = 0; derLen > (int)sizeof(oidPrefix) &&
            j + sizeof(oidPrefix) < (word32)derLen; j++) {
        if (XMEMCMP(derBuf + j, oidPrefix, sizeof(oidPrefix)) == 0) {
            derBuf[j + sizeof(oidPrefix)] = targetOidByte;
            patched = 1;
            break;
        }
    }
    ExpectIntEQ(patched, 1);
    /* dstKey is zeroed (no params) so the raw fast path is skipped and
     * SPKI parsing surfaces the OID-lookup result. */
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(derBuf, &idx, &dstKey,
        (word32)derLen), WC_NO_ERR_TRACE(NOT_COMPILED_IN));

    /* Private-key path: same scheme using the PKCS#8 wrapper. */
    ExpectIntGT(derLen = wc_SlhDsaKey_KeyToDer(&srcKey, derBuf, derBufSz), 0);
    patched = 0;
    for (j = 0; derLen > (int)sizeof(oidPrefix) &&
            j + sizeof(oidPrefix) < (word32)derLen; j++) {
        if (XMEMCMP(derBuf + j, oidPrefix, sizeof(oidPrefix)) == 0) {
            derBuf[j + sizeof(oidPrefix)] = targetOidByte;
            patched = 1;
            break;
        }
    }
    ExpectIntEQ(patched, 1);
    /* Free any state PublicKeyDecode may have established before the
     * second decode call reuses the key slot. */
    wc_SlhDsaKey_Free(&dstKey);
    XMEMSET(&dstKey, 0, sizeof(dstKey));
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idx, &dstKey,
        (word32)derLen), WC_NO_ERR_TRACE(NOT_COMPILED_IN));

    wc_SlhDsaKey_Free(&dstKey);
    wc_SlhDsaKey_Free(&srcKey);
    wc_FreeRng(&rng);
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}

/* Round-trip variant: same patcher path but the targetOidByte must equal
 * the source's own OID byte, so the decode is expected to succeed. Used
 * as an unconditional smoke check so test_wc_slhdsa_decoder_disabled_oid
 * exercises the patcher infrastructure even on builds with no per-variant
 * disable, where every disabled-branch in the caller is #if'd out. */
static int slhdsa_decode_disabled_oid_one_roundtrip(enum SlhDsaParam src,
    byte targetOidByte)
{
    EXPECT_DECLS;
    static const byte oidPrefix[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03
    };
    SlhDsaKey srcKey;
    SlhDsaKey dstKey;
    WC_RNG rng;
    byte* derBuf = NULL;
    const word32 derBufSz = 16 * 1024;
    int derLen = 0;
    word32 idx;
    word32 j;
    int patched;

    XMEMSET(&srcKey, 0, sizeof(srcKey));
    XMEMSET(&dstKey, 0, sizeof(dstKey));
    XMEMSET(&rng, 0, sizeof(rng));

    derBuf = (byte*)XMALLOC(derBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(derBuf);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&srcKey, src, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&srcKey, &rng), 0);

    ExpectIntGT(derLen = wc_SlhDsaKey_PublicKeyToDer(&srcKey, derBuf, derBufSz,
        1), 0);
    patched = 0;
    for (j = 0; derLen > (int)sizeof(oidPrefix) &&
            j + sizeof(oidPrefix) < (word32)derLen; j++) {
        if (XMEMCMP(derBuf + j, oidPrefix, sizeof(oidPrefix)) == 0) {
            derBuf[j + sizeof(oidPrefix)] = targetOidByte;
            patched = 1;
            break;
        }
    }
    ExpectIntEQ(patched, 1);
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(derBuf, &idx, &dstKey,
        (word32)derLen), 0);

    wc_SlhDsaKey_Free(&dstKey);
    wc_SlhDsaKey_Free(&srcKey);
    wc_FreeRng(&rng);
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}

/* Probe candidate parameter sets in priority order and return the first
 * one whose backend is built in. Used to source a real DER buffer for
 * slhdsa_decode_disabled_oid_one regardless of which variants the
 * current build excluded. Returns 1 on success, 0 if no variant is
 * available (which the build's #error guard makes impossible in
 * practice but the test handles defensively). */
static int slhdsa_pick_enabled_param(enum SlhDsaParam* out)
{
    static const enum SlhDsaParam candidates[] = {
        SLHDSA_SHAKE128S, SLHDSA_SHAKE128F, SLHDSA_SHAKE192S,
        SLHDSA_SHAKE192F, SLHDSA_SHAKE256S, SLHDSA_SHAKE256F,
    #ifdef WOLFSSL_SLHDSA_SHA2
        SLHDSA_SHA2_128S, SLHDSA_SHA2_128F, SLHDSA_SHA2_192S,
        SLHDSA_SHA2_192F, SLHDSA_SHA2_256S, SLHDSA_SHA2_256F,
    #endif
    };
    size_t i;

    for (i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        SlhDsaKey probe;
        XMEMSET(&probe, 0, sizeof(probe));
        if (wc_SlhDsaKey_Init(&probe, candidates[i], NULL,
                              INVALID_DEVID) == 0) {
            wc_SlhDsaKey_Free(&probe);
            *out = candidates[i];
            return 1;
        }
    }
    return 0;
}
#endif /* WOLFSSL_HAVE_SLHDSA && !VERIFY_ONLY && WC_ENABLE_ASYM_KEY_EXPORT */

/* Pin the per-variant disable contract: every parameter set whose enum
 * value is visible (so the test compiles) but whose backend is excluded
 * by a WOLFSSL_SLHDSA_PARAM_NO_* / WOLFSSL_SLHDSA_NO_* macro must surface
 * NOT_COMPILED_IN from wc_SlhDsaKey_Init instead of silently succeeding
 * or returning a generic error.
 *
 * This is the only API-level test for the granular disable surface and
 * also locks in the contract that wc_SlhDsaOidToParam/CertType in asn.c
 * piggyback on -- if Init drifts away from NOT_COMPILED_IN here, the
 * mapping helpers will likewise diverge and certificate handling will
 * lose its "variant unavailable" diagnostic. */
int test_wc_slhdsa_param_disabled(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;
    enum SlhDsaParam enabledProbe = SLHDSA_SHAKE128S;
    int haveEnabled;

    XMEMSET(&key, 0, sizeof(key));

    /* Positive smoke check: at least one variant must initialise. Without
     * this the disabled-variant branches below can all be #if'd out and
     * the test would silently pass on default builds, defeating its
     * documented purpose. The probe also validates the contract from the
     * other side -- Init must succeed for an enabled param. */
    haveEnabled = 0;
#if defined(WOLFSSL_SLHDSA_PARAM_128S)
    enabledProbe = SLHDSA_SHAKE128S; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    enabledProbe = SLHDSA_SHAKE128F; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    enabledProbe = SLHDSA_SHAKE192S; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    enabledProbe = SLHDSA_SHAKE192F; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    enabledProbe = SLHDSA_SHAKE256S; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    enabledProbe = SLHDSA_SHAKE256F; haveEnabled = 1;
#elif defined(WOLFSSL_SLHDSA_SHA2) && defined(WOLFSSL_SLHDSA_PARAM_SHA2_128S)
    enabledProbe = SLHDSA_SHA2_128S; haveEnabled = 1;
#endif
    ExpectIntEQ(haveEnabled, 1);
    if (haveEnabled) {
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, enabledProbe, NULL,
            INVALID_DEVID), 0);
        wc_SlhDsaKey_Free(&key);
        XMEMSET(&key, 0, sizeof(key));
    }

#if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) || \
    defined(WOLFSSL_SLHDSA_NO_128) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) || \
    defined(WOLFSSL_SLHDSA_NO_128) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) || \
    defined(WOLFSSL_SLHDSA_NO_192) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_192F) || \
    defined(WOLFSSL_SLHDSA_NO_192) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) || \
    defined(WOLFSSL_SLHDSA_NO_256) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#if defined(WOLFSSL_SLHDSA_PARAM_NO_256F) || \
    defined(WOLFSSL_SLHDSA_NO_256) || \
    defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif

#ifdef WOLFSSL_SLHDSA_SHA2
    /* SHA-2 enum values are only declared when WOLFSSL_SLHDSA_SHA2 is set;
     * each per-variant disable below is checked under that gate. */
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
    #ifdef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    #endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

    (void)key;
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/* Decoder-level companion to test_wc_slhdsa_param_disabled: feed DER for
 * each disabled SLH-DSA OID into PrivateKeyDecode/PublicKeyDecode and
 * confirm they pass NOT_COMPILED_IN through verbatim. The Init-level
 * test above proves the mapping helper is correct; this one proves the
 * decoders honour it instead of collapsing the result to ASN_PARSE_E. */
int test_wc_slhdsa_decoder_disabled_oid(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
    enum SlhDsaParam src = SLHDSA_SHAKE128S;
    int haveSrc = slhdsa_pick_enabled_param(&src);
    ExpectIntEQ(haveSrc, 1);

    if (haveSrc) {
        /* Positive smoke check: feed src's own OID through the patcher
         * (round-trip) and expect a clean decode, so the decoder path
         * actually exercises here even when no per-variant disable is
         * active. The trailing OID byte for SHAKE128S is 0x1A; we look
         * up the byte for `src` from a small table because src may not
         * be SHAKE128S in restricted builds. */
        {
            byte srcOidByte = 0;
            switch (src) {
                case SLHDSA_SHAKE128S: srcOidByte = 0x1A; break;
                case SLHDSA_SHAKE128F: srcOidByte = 0x1B; break;
                case SLHDSA_SHAKE192S: srcOidByte = 0x1C; break;
                case SLHDSA_SHAKE192F: srcOidByte = 0x1D; break;
                case SLHDSA_SHAKE256S: srcOidByte = 0x1E; break;
                case SLHDSA_SHAKE256F: srcOidByte = 0x1F; break;
            #ifdef WOLFSSL_SLHDSA_SHA2
                case SLHDSA_SHA2_128S: srcOidByte = 0x14; break;
                case SLHDSA_SHA2_128F: srcOidByte = 0x15; break;
                case SLHDSA_SHA2_192S: srcOidByte = 0x16; break;
                case SLHDSA_SHA2_192F: srcOidByte = 0x17; break;
                case SLHDSA_SHA2_256S: srcOidByte = 0x18; break;
                case SLHDSA_SHA2_256F: srcOidByte = 0x19; break;
            #endif
                default: break;
            }
            ExpectIntGT((int)srcOidByte, 0);
            /* Round-trip: patching src's OID to itself must still decode
             * successfully -- this fires unconditionally and validates
             * the patcher infrastructure even when no disable branch
             * below applies. */
            ExpectIntEQ(slhdsa_decode_disabled_oid_one_roundtrip(src,
                srcOidByte), TEST_SUCCESS);
        }

        /* SHAKE family: trailing OID byte = 0x1A..0x1F. */
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_128S) || \
            defined(WOLFSSL_SLHDSA_NO_128) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1A), TEST_SUCCESS);
        #endif
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_128F) || \
            defined(WOLFSSL_SLHDSA_NO_128) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1B), TEST_SUCCESS);
        #endif
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_192S) || \
            defined(WOLFSSL_SLHDSA_NO_192) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1C), TEST_SUCCESS);
        #endif
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_192F) || \
            defined(WOLFSSL_SLHDSA_NO_192) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1D), TEST_SUCCESS);
        #endif
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_256S) || \
            defined(WOLFSSL_SLHDSA_NO_256) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SMALL)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1E), TEST_SUCCESS);
        #endif
        #if defined(WOLFSSL_SLHDSA_PARAM_NO_256F) || \
            defined(WOLFSSL_SLHDSA_NO_256) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_FAST)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x1F), TEST_SUCCESS);
        #endif

        /* SHA-2 family: trailing OID byte = 0x14..0x19. The whole
         * family is also disabled when WOLFSSL_SLHDSA_SHA2 is unset. */
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x14), TEST_SUCCESS);
        #endif
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x15), TEST_SUCCESS);
        #endif
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x16), TEST_SUCCESS);
        #endif
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x17), TEST_SUCCESS);
        #endif
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x18), TEST_SUCCESS);
        #endif
        #if !defined(WOLFSSL_SLHDSA_SHA2) || \
            defined(WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F)
        ExpectIntEQ(slhdsa_decode_disabled_oid_one(src, 0x19), TEST_SUCCESS);
        #endif
    }
#endif
    return EXPECT_RESULT();
}

#ifdef TEST_SLHDSA_DEFAULT_PARAM
    #undef TEST_SLHDSA_DEFAULT_PARAM
    #undef TEST_SLHDSA_DEFAULT_SIG_LEN
    #undef TEST_SLHDSA_DEFAULT_PRIV_LEN
    #undef TEST_SLHDSA_DEFAULT_PUB_LEN
    #undef TEST_SLHDSA_DEFAULT_SEED_LEN
#endif
