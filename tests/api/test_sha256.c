/* test_sha256.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_sha256.h>

/*******************************************************************************
 * SHA-256
 ******************************************************************************/

/*
 * Unit test for wc_InitSha256()
 */
int test_wc_InitSha256(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256 sha256;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha256(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha256 */

/*
 * Unit test for wc_Sha256Update()
 */
int test_wc_Sha256Update(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256 sha256;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte hash_unaligned[WC_SHA256_DIGEST_SIZE+1];
    testVector a, b, c;

    ExpectIntEQ(wc_InitSha256(&sha256), 0);

    /*  Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha256Update(&sha256, NULL, 0), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha256Final(&sha256, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
               "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
               "\x15\xAD";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha256Final(&sha256, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA256_DIGEST_SIZE), 0);

    /* Unaligned check. */
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)a.input+1, (word32)a.inLen-1),
        0);
    ExpectIntEQ(wc_Sha256Final(&sha256, hash_unaligned + 1), 0);

    /* Try passing in bad values */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_SHA256_DIGEST_SIZE;
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Update */

/*
 * Unit test function for wc_Sha256Final()
 */
int test_wc_Sha256Final(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256 sha256;
    byte* hash_test[3];
    byte hash1[WC_SHA256_DIGEST_SIZE];
    byte hash2[2*WC_SHA256_DIGEST_SIZE];
    byte hash3[5*WC_SHA256_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_Sha256Final(&sha256, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha256Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Final(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Final(&sha256, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Final */

/*
 * Unit test function for wc_Sha256FinalRaw()
 */
int test_wc_Sha256FinalRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    wc_Sha256 sha256;
    byte* hash_test[3];
    byte hash1[WC_SHA256_DIGEST_SIZE];
    byte hash2[2*WC_SHA256_DIGEST_SIZE];
    byte hash3[5*WC_SHA256_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_Sha256FinalRaw(&sha256, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha256FinalRaw(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256FinalRaw(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256FinalRaw(&sha256, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha256FinalRaw */

/*
 * Unit test function for wc_Sha256GetFlags()
 */
int test_wc_Sha256GetFlags(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha256 sha256;
    word32 flags = 0;

    /* Initialize */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);

    ExpectIntEQ(wc_Sha256GetFlags(&sha256, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha256GetFlags */

/*
 * Unit test function for wc_Sha256Free()
 */
int test_wc_Sha256Free(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Free */
/*
 * Unit test function for wc_Sha256GetHash()
 */
int test_wc_Sha256GetHash(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256 sha256;
    byte hash1[WC_SHA256_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);

    ExpectIntEQ(wc_Sha256GetHash(&sha256, hash1), 0);

    /* test bad arguments*/
    ExpectIntEQ(wc_Sha256GetHash(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256GetHash(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256GetHash(&sha256, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256GetHash */

/*
 * Unit test function for wc_Sha256Copy()
 */
int test_wc_Sha256Copy(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    wc_Sha256 sha256;
    wc_Sha256 temp;

    XMEMSET(&sha256, 0, sizeof(sha256));
    XMEMSET(&temp, 0, sizeof(temp));

    /* Initialize */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_InitSha256(&temp), 0);

    ExpectIntEQ(wc_Sha256Copy(&sha256, &temp), 0);

    /* test bad arguments*/
    ExpectIntEQ(wc_Sha256Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Copy(&sha256, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha256Free(&sha256);
    wc_Sha256Free(&temp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Copy */


/*******************************************************************************
 * SHA-224
 ******************************************************************************/

/*
 * Testing wc_InitSha224();
 */
int test_wc_InitSha224(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha224(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha224 */

/*
 * Unit test on wc_Sha224Update
 */
int test_wc_Sha224Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;
    byte hash[WC_SHA224_DIGEST_SIZE];
    testVector a, b, c;

    ExpectIntEQ(wc_InitSha224(&sha224), 0);

    /* Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha224Update(&sha224, NULL, 0), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha224Final(&sha224, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2"
               "\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha224Final(&sha224, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA224_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_SHA224_DIGEST_SIZE;
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)c.input, (word32)c.inLen),
       WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Update(NULL, (byte*)a.input, (word32)a.inLen),
       WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Update */

/*
 * Unit test for wc_Sha224Final();
 */
int test_wc_Sha224Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;
    byte* hash_test[3];
    byte hash1[WC_SHA224_DIGEST_SIZE];
    byte hash2[2*WC_SHA224_DIGEST_SIZE];
    byte hash3[5*WC_SHA224_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    /* Good test args. */
    /* Testing oversized buffers. */
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_Sha224Final(&sha224, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha224Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Final(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Final(&sha224, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Final */

/*
 * Unit test function for wc_Sha224SetFlags()
 */
int test_wc_Sha224SetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA224) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha224 sha224;
    word32 flags = WC_HASH_FLAG_WILLCOPY;

    /* Initialize */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);

    ExpectIntEQ(wc_Sha224SetFlags(&sha224, flags), 0);
    flags = 0;
    ExpectIntEQ(wc_Sha224GetFlags(&sha224, &flags), 0);
    ExpectTrue(flags == WC_HASH_FLAG_WILLCOPY);

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224SetFlags */

/*
 * Unit test function for wc_Sha224GetFlags()
 */
int test_wc_Sha224GetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA224) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha224 sha224;
    word32 flags = 0;

    /* Initialize */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);

    ExpectIntEQ(wc_Sha224GetFlags(&sha224, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224GetFlags */
/*
 * Unit test function for wc_Sha224Free()
 */
int test_wc_Sha224Free(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha224Free */

/*
 * Unit test function for wc_Sha224GetHash()
 */
int test_wc_Sha224GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;
    byte hash1[WC_SHA224_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);

    ExpectIntEQ(wc_Sha224GetHash(&sha224, hash1), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha224GetHash(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224GetHash(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224GetHash(&sha224, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224GetHash */

/*
 * Unit test function for wc_Sha224Copy()
 */
int test_wc_Sha224Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;
    wc_Sha224 temp;

    XMEMSET(&sha224, 0, sizeof(wc_Sha224));
    XMEMSET(&temp, 0, sizeof(wc_Sha224));

    /* Initialize */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_InitSha224(&temp), 0);

    ExpectIntEQ(wc_Sha224Copy(&sha224, &temp), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha224Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Copy(&sha224, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
    wc_Sha224Free(&temp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Copy */

