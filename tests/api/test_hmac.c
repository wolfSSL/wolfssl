/* test_cmac.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/types.h>
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

