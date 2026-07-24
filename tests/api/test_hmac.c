/* test_cmac.c
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

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/internal.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_hmac.h>

/*
 * Test function for wc_HmacSetKey
 */
int test_wc_Md5HmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_MD5)
    Hmac hmac;
    int ret, times, itr;

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
#ifndef HAVE_FIPS
        "Jefe", /* smaller than minimum FIPS key size */
#endif
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    };
    times = sizeof(keys) / sizeof(char*);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);

    for (itr = 0; itr < times; itr++) {
        ret = wc_HmacSetKey(&hmac, WC_MD5, (byte*)keys[itr],
            (word32)XSTRLEN(keys[itr]));
#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5)
        wc_HmacFree(&hmac);
        ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
        ExpectIntEQ(ret, 0);
#endif
    }

    /* Bad args. */
    ExpectIntEQ(wc_HmacSetKey(NULL, WC_MD5, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_MD5, NULL, (word32)XSTRLEN(keys[0])),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, 21, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ret = wc_HmacSetKey(&hmac, WC_MD5, (byte*)keys[0], 0);
#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#elif defined(HAVE_FIPS)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E));
#else
    ExpectIntEQ(ret, 0);
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Md5HmacSetKey */

/*
 * testing wc_HmacSetKey() on wc_Sha hash.
 */
int test_wc_ShaHmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA)
    Hmac hmac;
    int ret, times, itr;

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
#ifndef HAVE_FIPS
        "Jefe", /* smaller than minimum FIPS key size */
#endif
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };

    times = sizeof(keys) / sizeof(char*);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);

    for (itr = 0; itr < times; itr++) {
        ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA, (byte*)keys[itr],
            (word32)XSTRLEN(keys[itr])), 0);
    }

    /* Bad args. */
    ExpectIntEQ(wc_HmacSetKey(NULL, WC_SHA, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA, NULL, (word32)XSTRLEN(keys[0])),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, 21, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ret = wc_HmacSetKey(&hmac, WC_SHA, (byte*)keys[0], 0);
#ifdef HAVE_FIPS
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E));
#else
    ExpectIntEQ(ret, 0);
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaHmacSetKey() */

/*
 * testing wc_HmacSetKey() on Sha224 hash.
 */
int test_wc_Sha224HmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA224)
    Hmac hmac;
    int ret, times, itr;

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
#ifndef HAVE_FIPS
        "Jefe", /* smaller than minimum FIPS key size */
#endif
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };
    times = sizeof(keys) / sizeof(char*);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);

    for (itr = 0; itr < times; itr++) {
        ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA224, (byte*)keys[itr],
            (word32)XSTRLEN(keys[itr])), 0);
    }

    /* Bad args. */
    ExpectIntEQ(wc_HmacSetKey(NULL, WC_SHA224, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA224, NULL, (word32)XSTRLEN(keys[0])),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, 21, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ret = wc_HmacSetKey(&hmac, WC_SHA224, (byte*)keys[0], 0);
#ifdef HAVE_FIPS
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E));
#else
    ExpectIntEQ(ret, 0);
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224HmacSetKey() */

 /*
  * testing wc_HmacSetKey() on Sha256 hash
  */
int test_wc_Sha256HmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    Hmac hmac;
    int ret, times, itr;

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
#ifndef HAVE_FIPS
        "Jefe", /* smaller than minimum FIPS key size */
#endif
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };
    times = sizeof(keys) / sizeof(char*);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);

    for (itr = 0; itr < times; itr++) {
        ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256, (byte*)keys[itr],
            (word32)XSTRLEN(keys[itr])), 0);
    }

    /* Bad args. */
    ExpectIntEQ(wc_HmacSetKey(NULL, WC_SHA256, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256, NULL, (word32)XSTRLEN(keys[0])),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, 21, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ret = wc_HmacSetKey(&hmac, WC_SHA256, (byte*)keys[0], 0);
#ifdef HAVE_FIPS
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E));
#else
    ExpectIntEQ(ret, 0);
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256HmacSetKey() */

/*
 * testing wc_HmacSetKey on Sha384 hash.
 */
int test_wc_Sha384HmacSetKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
    Hmac hmac;
    int ret, times, itr;

    const char* keys[]=
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b",
#ifndef HAVE_FIPS
        "Jefe", /* smaller than minimum FIPS key size */
#endif
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
                                                                "\xAA\xAA\xAA"
    };
    times = sizeof(keys) / sizeof(char*);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);

    for (itr = 0; itr < times; itr++) {
        ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA384, (byte*)keys[itr],
            (word32)XSTRLEN(keys[itr])), 0);
    }

    /* Bad args. */
    ExpectIntEQ(wc_HmacSetKey(NULL, WC_SHA384, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA384, NULL, (word32)XSTRLEN(keys[0])),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacSetKey(&hmac, 21, (byte*)keys[0],
        (word32)XSTRLEN(keys[0])), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ret = wc_HmacSetKey(&hmac, WC_SHA384, (byte*)keys[0], 0);
#ifdef HAVE_FIPS
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(HMAC_MIN_KEYLEN_E));
#else
    ExpectIntEQ(ret, 0);
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384HmacSetKey() */

/*
 * testing wc_HmacUpdate on wc_Md5 hash.
 */
int test_wc_Md5HmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_MD5) && !(defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION >= 5))
    Hmac hmac;
    testVector a, b;
#ifdef HAVE_FIPS
    const char* keys =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
#else
    const char* keys = "Jefe";
#endif

    a.input = "what do ya want for nothing?";
    a.inLen  = XSTRLEN(a.input);
    b.input = "Hi There";
    b.inLen = XSTRLEN(b.input);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    #if !defined(WOLFSSL_KCAPI_HMAC) && !defined(HAVE_SELFTEST) && \
       (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* update before setkey results in err. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif /* !WOLFSSL_KCAPI_HMAC && !HAVE_SELFTEST && \
              (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_MD5, (byte*)keys,
        (word32)XSTRLEN(keys)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen), 0);
    /* Update Hmac. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_HmacUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacUpdate(&hmac, NULL, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, 0), 0);

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Md5HmacUpdate */

/*
 * testing wc_HmacUpdate on SHA hash.
 */
int test_wc_ShaHmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA)
    Hmac hmac;
    testVector a, b;
#ifdef HAVE_FIPS
    const char* keys =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
#else
    const char* keys = "Jefe";
#endif

    a.input = "what do ya want for nothing?";
    a.inLen  = XSTRLEN(a.input);
    b.input = "Hi There";
    b.inLen = XSTRLEN(b.input);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* update before setkey results in err. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA, (byte*)keys,
        (word32)XSTRLEN(keys)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen), 0);
    /* Update Hmac. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_HmacUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacUpdate(&hmac, NULL, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, 0), 0);

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaHmacUpdate */

/*
 * testing wc_HmacUpdate on SHA224 hash.
 */
int test_wc_Sha224HmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA224)
    Hmac hmac;
    testVector a, b;
#ifdef HAVE_FIPS
    const char* keys =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
#else
    const char* keys = "Jefe";
#endif

    a.input = "what do ya want for nothing?";
    a.inLen  = XSTRLEN(a.input);
    b.input = "Hi There";
    b.inLen = XSTRLEN(b.input);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* update before setkey results in err. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA224, (byte*)keys,
        (word32)XSTRLEN(keys)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen), 0);
    /* Update Hmac. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_HmacUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacUpdate(&hmac, NULL, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, 0), 0);

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224HmacUpdate */

/*
 * testing wc_HmacUpdate on SHA256 hash.
 */
int test_wc_Sha256HmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    Hmac hmac;
    testVector a, b;
#ifdef HAVE_FIPS
    const char* keys =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
#else
    const char* keys = "Jefe";
#endif

    a.input = "what do ya want for nothing?";
    a.inLen  = XSTRLEN(a.input);
    b.input = "Hi There";
    b.inLen = XSTRLEN(b.input);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* update before setkey results in err. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256, (byte*)keys,
        (word32)XSTRLEN(keys)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen), 0);
    /* Update Hmac. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_HmacUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacUpdate(&hmac, NULL, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, 0), 0);

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256HmacUpdate */

/*
 * testing wc_HmacUpdate on SHA384  hash.
 */
int test_wc_Sha384HmacUpdate(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
    Hmac hmac;
    testVector a, b;
#ifdef HAVE_FIPS
    const char* keys =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
#else
    const char* keys = "Jefe";
#endif

    a.input = "what do ya want for nothing?";
    a.inLen  = XSTRLEN(a.input);
    b.input = "Hi There";
    b.inLen = XSTRLEN(b.input);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* update before setkey results in err. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    #endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS_VERSION3_GE(7,0,0)) */
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA384, (byte*)keys,
        (word32)XSTRLEN(keys)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)b.input, (word32)b.inLen), 0);
    /* Update Hmac. */
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_HmacUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacUpdate(&hmac, NULL, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, 0), 0);

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384HmacUpdate */

/*
 * Testing wc_HmacFinal() with MD5
 */

int test_wc_Md5HmacFinal(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_MD5) && !(defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION >= 5))
    Hmac hmac;
    byte hash[WC_MD5_DIGEST_SIZE];
    testVector a;
    const char* key;

    key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    a.input = "Hi There";
    a.output = "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc"
               "\x9d";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_MD5, (byte*)key, (word32)XSTRLEN(key)),
        0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_MD5_DIGEST_SIZE), 0);

    /* Try bad parameters. */
    ExpectIntEQ(wc_HmacFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_HmacFinal(&hmac, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Md5HmacFinal */

/*
 * Testing wc_HmacFinal() with SHA
 */
int test_wc_ShaHmacFinal(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA)
    Hmac hmac;
    byte hash[WC_SHA_DIGEST_SIZE];
    testVector a;
    const char* key;

    key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b";
    a.input = "Hi There";
    a.output = "\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c"
               "\x8e\xf1\x46\xbe\x00";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA, (byte*)key, (word32)XSTRLEN(key)),
        0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA_DIGEST_SIZE), 0);

    /* Try bad parameters. */
    ExpectIntEQ(wc_HmacFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_HmacFinal(&hmac, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaHmacFinal */

/*
 * Testing wc_HmacFinal() with SHA224
 */
int test_wc_Sha224HmacFinal(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA224)
    Hmac hmac;
    byte hash[WC_SHA224_DIGEST_SIZE];
    testVector a;
    const char* key;

    key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b";
    a.input = "Hi There";
    a.output = "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3"
               "\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA224, (byte*)key,
        (word32)XSTRLEN(key)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA224_DIGEST_SIZE), 0);

    /* Try bad parameters. */
    ExpectIntEQ(wc_HmacFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_HmacFinal(&hmac, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224HmacFinal */

/*
 * Testing wc_HmacFinal() with SHA256
 */
int test_wc_Sha256HmacFinal(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA256)
    Hmac hmac;
    byte hash[WC_SHA256_DIGEST_SIZE];
    testVector a;
    const char* key;

    key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b";
    a.input = "Hi There";
    a.output = "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1"
               "\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32"
               "\xcf\xf7";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256, (byte*)key,
        (word32)XSTRLEN(key)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA256_DIGEST_SIZE), 0);

    /* Try bad parameters. */
    ExpectIntEQ(wc_HmacFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_HmacFinal(&hmac, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256HmacFinal */

/*
 * Testing wc_HmacFinal() with SHA384
 */
int test_wc_Sha384HmacFinal(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
    Hmac hmac;
    byte hash[WC_SHA384_DIGEST_SIZE];
    testVector a;
    const char* key;

    key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                                                                "\x0b\x0b\x0b";
    a.input = "Hi There";
    a.output = "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90"
               "\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb"
               "\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2"
               "\xfa\x9c\xb6";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA384, (byte*)key,
        (word32)XSTRLEN(key)), 0);
    ExpectIntEQ(wc_HmacUpdate(&hmac, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_HmacFinal(&hmac, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA384_DIGEST_SIZE), 0);

    /* Try bad parameters. */
    ExpectIntEQ(wc_HmacFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_HmacFinal(&hmac, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384HmacFinal */

/* Test for integer overflow in TLS_hmac size calculation (ZD #21240).
 *
 * TLS_hmac() computes sz + hashSz + padSz + 1 and passes the result to
 * Hmac_UpdateFinal / Hmac_UpdateFinal_CT. When sz (word32) is near
 * UINT32_MAX, the addition overflows and wraps to a small value, causing
 * the HMAC routines to operate on an undersized length. The fix adds
 * WC_SAFE_SUM_WORD32 overflow checks and returns BUFFER_E on overflow.
 *
 * This test calls through ssl->hmac (which points to TLS_hmac) with
 * values that trigger the overflow condition and verifies the function
 * correctly rejects them.
 */
int test_tls_hmac_size_overflow(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_TLS) && \
    defined(NO_OLD_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    byte         digest[WC_MAX_DIGEST_SIZE];
    byte         dummy_in[64];

    XMEMSET(dummy_in, 0xAA, sizeof(dummy_in));
    XMEMSET(digest, 0, sizeof(digest));

    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    ExpectNotNull(ctx);
    ssl = wolfSSL_new(ctx);
    ExpectNotNull(ssl);

    if (EXPECT_SUCCESS()) {
        ExpectNotNull(ssl->hmac);

        /* Set a hash size so the verify path in TLS_hmac is exercised. */
        ssl->specs.hash_size = WC_SHA256_DIGEST_SIZE;

        /* Overflow case 1: sz near UINT32_MAX, padSz pushes sum past limit.
         *   (UINT32_MAX - 300) + 32 + 500 + 1 = UINT32_MAX + 233 -> wraps to 232
         */
        ExpectIntEQ(ssl->hmac(ssl, digest, dummy_in,
                              (word32)(WOLFSSL_MAX_32BIT - 300),
                              500,   /* padSz */
                              application_data, 1, PEER_ORDER),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Overflow case 2: padSz = 0, hashSz alone causes overflow.
         *   (UINT32_MAX - 10) + 32 + 0 + 1 = UINT32_MAX + 23 -> wraps to 22
         */
        ExpectIntEQ(ssl->hmac(ssl, digest, dummy_in,
                              (word32)(WOLFSSL_MAX_32BIT - 10),
                              0,     /* padSz */
                              application_data, 1, PEER_ORDER),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Normal case: should NOT return BUFFER_E.
         * May fail for other reasons (no keys configured) but the overflow
         * check must not fire for small legitimate values.
         */
        ExpectIntNE(ssl->hmac(ssl, digest, dummy_in,
                              100,
                              10,    /* padSz */
                              application_data, 1, PEER_ORDER),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* !NO_HMAC && !WOLFSSL_AEAD_ONLY && !NO_TLS && NO_OLD_TLS &&
        * !NO_WOLFSSL_CLIENT */
    return EXPECT_RESULT();
} /* END test_tls_hmac_size_overflow */

/*
 * MC/DC: wc_HmacSizeByType() has its own physical copy of the "which hash
 * type" compound guard (a second, separately-tracked copy of the same-
 * looking condition in wc_HmacSetKey_ex, at a different source location).
 * Exercise every hash type this build enables directly, plus one invalid
 * type for the all-operands-false side.
 */
int test_wc_HmacSizeByType(void)
{
    EXPECT_DECLS;
/* The FIPS/self-test hmac's wc_HmacSizeByType returns HMAC_KAT_FIPS_E for any
 * type it doesn't accept (e.g. MD5 is not a FIPS HMAC type), and BAD_FUNC_ARG
 * differs too, so the size/invalid-type assertions here only hold on the open
 * builds the campaign actually measures. Exclude the frozen modules whole. */
#if !defined(NO_HMAC) && !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
#ifndef NO_MD5
    ExpectIntEQ(wc_HmacSizeByType(WC_MD5), WC_MD5_DIGEST_SIZE);
#endif
#ifndef NO_SHA
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA), WC_SHA_DIGEST_SIZE);
#endif
#ifdef WOLFSSL_SHA224
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA224), WC_SHA224_DIGEST_SIZE);
#endif
#ifndef NO_SHA256
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA256), WC_SHA256_DIGEST_SIZE);
#endif
#ifdef WOLFSSL_SHA384
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA384), WC_SHA384_DIGEST_SIZE);
#endif
#ifdef WOLFSSL_SHA512
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA512), WC_SHA512_DIGEST_SIZE);
#ifndef WOLFSSL_NOSHA512_224
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA512_224), WC_SHA512_224_DIGEST_SIZE);
#endif
#ifndef WOLFSSL_NOSHA512_256
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA512_256), WC_SHA512_256_DIGEST_SIZE);
#endif
#endif /* WOLFSSL_SHA512 */
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA3_224), WC_SHA3_224_DIGEST_SIZE);
#endif
#ifndef WOLFSSL_NOSHA3_256
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA3_256), WC_SHA3_256_DIGEST_SIZE);
#endif
#ifndef WOLFSSL_NOSHA3_384
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA3_384), WC_SHA3_384_DIGEST_SIZE);
#endif
#ifndef WOLFSSL_NOSHA3_512
    ExpectIntEQ(wc_HmacSizeByType(WC_SHA3_512), WC_SHA3_512_DIGEST_SIZE);
#endif
#endif /* WOLFSSL_SHA3 */
#ifdef WOLFSSL_SM3
    ExpectIntEQ(wc_HmacSizeByType(WC_SM3), WC_SM3_DIGEST_SIZE);
#endif
    /* Invalid type: every operand false. */
    ExpectIntEQ(wc_HmacSizeByType(9999), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* !NO_HMAC && !HAVE_SELFTEST && !HAVE_FIPS */
    return EXPECT_RESULT();
} /* END test_wc_HmacSizeByType */

/*
 * MC/DC: wc_HmacCopy()'s (src == NULL) || (dst == NULL) guard.
 */
int test_wc_HmacCopy(void)
{
    EXPECT_DECLS;
/* wc_HmacCopy() is newer than the frozen FIPS/selftest wolfcrypt modules
 * (absent from the v4.1.0-stable hmac.h that cavp-selftest-v2 pins, and from
 * every frozen FIPS bundle), so skip it there to keep those builds warning-
 * clean; the campaign measures MC/DC on non-FIPS variants regardless. */
#if !defined(NO_HMAC) && !defined(NO_SHA256) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    Hmac src;
    Hmac dst;
    const byte key[] = "0123456789abcdef";
    const byte data[] = "wolfSSL wc_HmacCopy test";

    ExpectIntEQ(wc_HmacInit(&src, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&src, WC_SHA256, key,
        (word32)XSTRLEN((const char*)key)), 0);
    ExpectIntEQ(wc_HmacUpdate(&src, data, (word32)XSTRLEN((const char*)data)),
        0);

    /* Independence pairs for (src == NULL) || (dst == NULL). */
    ExpectIntEQ(wc_HmacCopy(NULL, &dst), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HmacCopy(&src, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Both conditions false: a real deep copy. */
    ExpectIntEQ(wc_HmacCopy(&src, &dst), 0);
    if (EXPECT_SUCCESS()) {
        byte hSrc[WC_SHA256_DIGEST_SIZE];
        byte hDst[WC_SHA256_DIGEST_SIZE];
        ExpectIntEQ(wc_HmacFinal(&src, hSrc), 0);
        ExpectIntEQ(wc_HmacFinal(&dst, hDst), 0);
        ExpectIntEQ(XMEMCMP(hSrc, hDst, WC_SHA256_DIGEST_SIZE), 0);
    }
    wc_HmacFree(&src);
    wc_HmacFree(&dst);
#endif
    return EXPECT_RESULT();
} /* END test_wc_HmacCopy */

/*
 * MC/DC: wc_HmacInit_Id()'s two guards -- (ret == 0 && (len < 0 ||
 * len > HMAC_MAX_ID_LEN)) and (ret == 0 && id != NULL && len != 0).
 * Compiled out entirely unless WOLF_PRIVATE_KEY_ID is defined.
 */
int test_wc_HmacInit_Id(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLF_PRIVATE_KEY_ID) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    Hmac hmac;
    byte id[HMAC_MAX_ID_LEN];
    int i;

    for (i = 0; i < (int)sizeof(id); i++) {
        id[i] = (byte)i;
    }

    /* hmac == NULL forces ret != 0 before the len guard, masking it. */
    ExpectIntEQ(wc_HmacInit_Id(NULL, id, 16, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* len < 0. */
    ExpectIntEQ(wc_HmacInit_Id(&hmac, id, -1, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* len > HMAC_MAX_ID_LEN. */
    ExpectIntEQ(wc_HmacInit_Id(&hmac, id, HMAC_MAX_ID_LEN + 1, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

    /* id == NULL, len valid: skips the copy, still succeeds. */
    ExpectIntEQ(wc_HmacInit_Id(&hmac, NULL, 16, NULL, INVALID_DEVID), 0);
    wc_HmacFree(&hmac);

    /* len == 0, id != NULL: skips the copy (len != 0 false), succeeds. */
    ExpectIntEQ(wc_HmacInit_Id(&hmac, id, 0, NULL, INVALID_DEVID), 0);
    wc_HmacFree(&hmac);

    /* Baseline: valid id and len, every guard false, copy performed. */
    ExpectIntEQ(wc_HmacInit_Id(&hmac, id, 16, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(hmac.idLen, 16);
    ExpectIntEQ(XMEMCMP(hmac.id, id, 16), 0);
    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_HmacInit_Id */

/*
 * MC/DC: wc_HmacInit_Label()'s two guards -- (hmac == NULL || label ==
 * NULL) and (labelLen == 0 || labelLen > HMAC_MAX_LABEL_LEN). Compiled out
 * entirely unless WOLF_PRIVATE_KEY_ID is defined.
 */
int test_wc_HmacInit_Label(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && defined(WOLF_PRIVATE_KEY_ID) && !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    Hmac hmac;
    char longLabel[HMAC_MAX_LABEL_LEN + 2];
    int i;

    for (i = 0; i < (int)sizeof(longLabel) - 1; i++) {
        longLabel[i] = 'a';
    }
    longLabel[sizeof(longLabel) - 1] = '\0';

    /* hmac == NULL. */
    ExpectIntEQ(wc_HmacInit_Label(NULL, "label", NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* label == NULL. */
    ExpectIntEQ(wc_HmacInit_Label(&hmac, NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* labelLen == 0 (empty string). */
    ExpectIntEQ(wc_HmacInit_Label(&hmac, "", NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* labelLen > HMAC_MAX_LABEL_LEN. */
    ExpectIntEQ(wc_HmacInit_Label(&hmac, longLabel, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Baseline: valid label, every guard false. */
    ExpectIntEQ(wc_HmacInit_Label(&hmac, "test-label", NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(hmac.labelLen, (int)XSTRLEN("test-label"));
    wc_HmacFree(&hmac);
#endif
    return EXPECT_RESULT();
} /* END test_wc_HmacInit_Label */

#ifdef WOLF_CRYPTO_CB
#define TEST_HMAC_CRYPTOCB_DEVID 0x484d4143 /* "HMAC" */

static int test_hmac_cryptocb_fallback_cb(int cbDevId, wc_CryptoInfo* info,
    void* ctx)
{
    (void)cbDevId;
    (void)info;
    (void)ctx;
    /* Always decline: exercises the CRYPTOCB_UNAVAILABLE software
     * fall-through without needing real hardware. */
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLF_CRYPTO_CB */

/*
 * MC/DC: wc_HmacFree()'s (hmac->devId != INVALID_DEVID && hmac->devCtx !=
 * NULL) cleanup guard. devCtx is a public struct field that no software
 * path ever sets non-NULL on its own, so the true side is simulated the
 * way a device driver would set it (stashing a handle there).
 */
int test_wc_HmacFree_CryptoCb(void)
{
    EXPECT_DECLS;
#if !defined(NO_HMAC) && !defined(NO_SHA256) && defined(WOLF_CRYPTO_CB)
    Hmac hmac;

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_HMAC_CRYPTOCB_DEVID,
        test_hmac_cryptocb_fallback_cb, NULL), 0);

    /* True side: devId != INVALID_DEVID && devCtx != NULL. */
    ExpectIntEQ(wc_HmacInit(&hmac, NULL, TEST_HMAC_CRYPTOCB_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256,
        (const byte*)"0123456789abcdef", 16), 0);
    hmac.devCtx = (void*)&hmac; /* placeholder non-NULL value */
    wc_HmacFree(&hmac);

    /* False side: default INVALID_DEVID / NULL devCtx. */
    ExpectIntEQ(wc_HmacInit(&hmac, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_HmacSetKey(&hmac, WC_SHA256,
        (const byte*)"0123456789abcdef", 16), 0);
    wc_HmacFree(&hmac);

    wc_CryptoCb_UnRegisterDevice(TEST_HMAC_CRYPTOCB_DEVID);
#endif
    return EXPECT_RESULT();
} /* END test_wc_HmacFree_CryptoCb */

/*
 * MC/DC: wc_HKDF_Extract_ex()/wc_HKDF_Expand_ex() share the guard shape
 * (out == NULL || (inKey == NULL && inKeySz > 0)) at two physical
 * locations; existing HKDF coverage (wolfcrypt/test/test.c hkdf_test)
 * never passes a NULL inKey, so the inKeySz > 0 operand's independence was
 * never shown at either location.
 */
int test_wc_HKDF_NullKeyEdgeCases(void)
{
    EXPECT_DECLS;
/* The wc_HKDF_*_ex() heap/devId variants are newer than the frozen FIPS/
 * selftest wolfcrypt modules (absent from the v4.1.0-stable hmac.h that
 * cavp-selftest-v2 pins, and from every frozen FIPS bundle), so skip there. */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_SHA) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
    byte prk[WC_SHA_DIGEST_SIZE];
    byte okm[WC_SHA_DIGEST_SIZE];

    /* wc_HKDF_Extract_ex: inKey == NULL && inKeySz > 0 -> BAD_FUNC_ARG. */
    ExpectIntEQ(wc_HKDF_Extract_ex(WC_SHA, NULL, 0, NULL, 5, prk, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* inKey == NULL && inKeySz == 0 -> valid zero-length IKM. */
    ExpectIntEQ(wc_HKDF_Extract_ex(WC_SHA, NULL, 0, NULL, 0, prk, NULL,
        INVALID_DEVID), 0);

    /* wc_HKDF_Expand_ex: same operand shape, different physical decision.
     */
    ExpectIntEQ(wc_HKDF_Expand_ex(WC_SHA, NULL, 5, NULL, 0, okm,
        WC_SHA_DIGEST_SIZE, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_HKDF_Expand_ex(WC_SHA, NULL, 0, NULL, 0, okm,
        WC_SHA_DIGEST_SIZE, NULL, INVALID_DEVID), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_HKDF_NullKeyEdgeCases */

/* The callback below declines so the software path still derives the PRK, which
 * WOLF_CRYPTO_CB_ONLY_SHA256 builds have no fallback for. */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_KDF) && \
    !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && \
    defined(WOLF_CRYPTO_CB) && !defined(WOLF_CRYPTO_CB_ONLY_SHA256)
#define TEST_KDF_EXTRACT_CRYPTOCB
#define TEST_KDF_CRYPTOCB_DEVID 0x4b444658 /* "KDFX" */

typedef struct {
    int    called;
    int    inKeyNull;
    int    inKeyZeroed;
    word32 inKeySz;
} TestKdfExtractCbCtx;

/* Records the IKM handed to a callback, then declines. */
static int test_kdf_cryptocb_extract_cb(int cbDevId, wc_CryptoInfo* info,
    void* ctx)
{
    TestKdfExtractCbCtx* cbCtx = (TestKdfExtractCbCtx*)ctx;
    word32 j;

    (void)cbDevId;
    if (info->algo_type == WC_ALGO_TYPE_KDF &&
            info->kdf.type == WC_KDF_TYPE_HKDF_EXTRACT) {
        cbCtx->called++;
        cbCtx->inKeySz = info->kdf.hkdf_extract.inKeySz;
        cbCtx->inKeyNull = (info->kdf.hkdf_extract.inKey == NULL);
        cbCtx->inKeyZeroed = 1;
        for (j = 0; !cbCtx->inKeyNull && j < info->kdf.hkdf_extract.inKeySz;
                j++) {
            if (info->kdf.hkdf_extract.inKey[j] != 0) {
                cbCtx->inKeyZeroed = 0;
            }
        }
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif

/* A zero length IKM must not write into the caller's ikm buffer, whose
 * required size is not implied by the length the caller passes in. */
int test_wc_Tls13_HKDF_Extract_ZeroLenIkm(void)
{
    EXPECT_DECLS;
/* kdf.c sits inside the FIPS module boundary, so selftest and older FIPS builds
 * use a frozen copy that still writes into the caller's ikm buffer; skip there.
 * FIPS v7 would carry this fix, so it runs. */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_KDF) && \
    !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    static const int digests[] = {
        WC_SHA256,
    #ifdef WOLFSSL_SHA384
        WC_SHA384,
    #endif
    #ifdef WOLFSSL_TLS13_SHA512
        WC_SHA512,
    #endif
    #ifdef WOLFSSL_SM3
        WC_SM3,
    #endif
    };
    byte prkNull[WC_MAX_DIGEST_SIZE];
    byte prkOther[WC_MAX_DIGEST_SIZE];
    byte zeros[WC_MAX_DIGEST_SIZE];
    byte sentinel[WC_MAX_DIGEST_SIZE];
    byte filled[WC_MAX_DIGEST_SIZE];
    byte small[4];
    word32 i;
    int len = 0;
#ifdef TEST_KDF_EXTRACT_CRYPTOCB
    TestKdfExtractCbCtx cbCtx;
#endif

    XMEMSET(zeros, 0, sizeof(zeros));
    XMEMSET(filled, 0xA5, sizeof(filled));

    /* Every digest the switch accepts, up to the WC_MAX_DIGEST_SIZE the scratch
     * buffer is sized against. */
    for (i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) {
        ExpectIntGT(len = wc_HmacSizeByType(digests[i]), 0);

        /* ikmLen 0 feeds a digest length zeroed IKM rather than an empty one,
         * so a NULL ikm must derive the same PRK as passing those zeros. */
        ExpectIntEQ(wc_Tls13_HKDF_Extract(prkNull, NULL, 0, NULL, 0,
            digests[i]), 0);
        ExpectIntEQ(wc_Tls13_HKDF_Extract(prkOther, NULL, 0, zeros,
            (word32)len, digests[i]), 0);
        ExpectBufEQ(prkNull, prkOther, (word32)len);

        /* The caller's buffer must come back untouched, through the _ex entry
         * point that TLS 1.3 itself calls. */
        XMEMSET(sentinel, 0xA5, sizeof(sentinel));
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prkOther, NULL, 0, sentinel, 0,
            digests[i], NULL, INVALID_DEVID), 0);
        ExpectBufEQ(sentinel, filled, (word32)len);
        ExpectBufEQ(prkNull, prkOther, (word32)len);

        XMEMSET(sentinel, 0xA5, sizeof(sentinel));
        ExpectIntEQ(wc_Tls13_HKDF_Extract(prkOther, NULL, 0, sentinel, 0,
            digests[i]), 0);
        ExpectBufEQ(sentinel, filled, (word32)len);
        ExpectBufEQ(prkNull, prkOther, (word32)len);

        /* A NULL salt stays valid whatever saltLen says. */
        ExpectIntEQ(wc_Tls13_HKDF_Extract(prkOther, NULL, 5, NULL, 0,
            digests[i]), 0);
        ExpectBufEQ(prkNull, prkOther, (word32)len);
    }

    /* ASan tripwire: a revert overruns this and may abort the binary under a
     * stack protector. The sentinel above is what fails cleanly. */
    XMEMSET(small, 0xA5, sizeof(small));
    ExpectIntEQ(wc_Tls13_HKDF_Extract(prkNull, NULL, 0, small, 0, WC_SHA256), 0);
    ExpectIntEQ(small[0], 0xA5);
    ExpectIntEQ(small[3], 0xA5);

    ExpectIntEQ(wc_Tls13_HKDF_Extract(NULL, NULL, 0, zeros,
        WC_SHA256_DIGEST_SIZE, WC_SHA256), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Tls13_HKDF_Extract(prkNull, NULL, 0, NULL, 5, WC_SHA256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(NULL, NULL, 0, zeros,
        WC_SHA256_DIGEST_SIZE, WC_SHA256, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prkNull, NULL, 0, NULL, 5, WC_SHA256,
        NULL, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef TEST_KDF_EXTRACT_CRYPTOCB
    /* A callback dispatches before the software path, so it must receive the
     * substituted zeroed IKM rather than the caller's untouched buffer. */
    XMEMSET(&cbCtx, 0, sizeof(cbCtx));
    XMEMSET(sentinel, 0xA5, sizeof(sentinel));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_KDF_CRYPTOCB_DEVID,
        test_kdf_cryptocb_extract_cb, &cbCtx), 0);
    ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prkOther, NULL, 0, sentinel, 0,
        WC_SHA256, NULL, TEST_KDF_CRYPTOCB_DEVID), 0);
    ExpectIntEQ(cbCtx.called, 1);
    ExpectIntEQ(cbCtx.inKeyNull, 0);
    ExpectIntEQ(cbCtx.inKeyZeroed, 1);
    ExpectIntEQ(cbCtx.inKeySz, WC_SHA256_DIGEST_SIZE);
    ExpectBufEQ(sentinel, filled, WC_SHA256_DIGEST_SIZE);
    wc_CryptoCb_UnRegisterDevice(TEST_KDF_CRYPTOCB_DEVID);
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_Tls13_HKDF_Extract_ZeroLenIkm */
