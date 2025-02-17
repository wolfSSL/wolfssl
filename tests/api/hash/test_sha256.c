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
#include "../core/test_utils.h"

/*******************************************************************************
 * SHA-256
 ******************************************************************************/

/*
 * Unit test for wc_InitSha256()
 */
int test_wc_InitSha256(void)
{
#ifndef NO_SHA256
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte data[] = "test data";
    return TEST_CRYPTO_OPERATION("SHA256",
        wc_InitSha256,
        wc_Sha256Update,
        wc_Sha256Final,
        wc_Sha256Free,
        data, sizeof(data), hash);
#else
    return EXPECT_RESULT();
#endif
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
    const char* test_input = "abc";
    const byte expected[] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha256Final(&sha256, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, expected, WC_SHA256_DIGEST_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha256Update(NULL, (byte*)test_input, XSTRLEN(test_input)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256Update(&sha256, NULL, WC_SHA256_DIGEST_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test edge cases */
    ExpectIntEQ(wc_Sha256Update(&sha256, NULL, 0), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, 0), 0);

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
    byte hash[WC_SHA256_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha256Final(&sha256, hash), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha256Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    byte hash[WC_SHA256_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha256FinalRaw(&sha256, hash), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha256FinalRaw(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256FinalRaw(&sha256, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

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

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_Sha256GetFlags(&sha256, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha256GetFlags(NULL, &flags), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha256GetFlags(&sha256, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

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
    byte hash[WC_SHA256_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha256GetHash(&sha256, hash), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha256GetHash(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    wc_Sha256 sha256, temp;
    byte hash1[WC_SHA256_DIGEST_SIZE], hash2[WC_SHA256_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    XMEMSET(&sha256, 0, sizeof(sha256));
    XMEMSET(&temp, 0, sizeof(temp));
    
    ExpectIntEQ(wc_InitSha256(&sha256), 0);
    ExpectIntEQ(wc_InitSha256(&temp), 0);
    ExpectIntEQ(wc_Sha256Update(&sha256, (byte*)test_input, XSTRLEN(test_input)), 0);
    
    /* Test copy operation */
    ExpectIntEQ(wc_Sha256Copy(&sha256, &temp), 0);
    
    /* Verify both generate same hash */
    ExpectIntEQ(wc_Sha256Final(&sha256, hash1), 0);
    ExpectIntEQ(wc_Sha256Final(&temp, hash2), 0);
    ExpectIntEQ(XMEMCMP(hash1, hash2, WC_SHA256_DIGEST_SIZE), 0);

    /* Test error cases */
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
#ifdef WOLFSSL_SHA224
    byte hash[WC_SHA224_DIGEST_SIZE];
    byte data[] = "test data";
    return TEST_CRYPTO_OPERATION("SHA224",
        wc_InitSha224,
        wc_Sha224Update,
        wc_Sha224Final,
        wc_Sha224Free,
        data, sizeof(data), hash);
#else
    return EXPECT_RESULT();
#endif
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
    const char* test_input = "abc";
    const byte expected[] = {
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
        0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
        0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
        0xe3, 0x6c, 0x9d, 0xa7
    };

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha224Final(&sha224, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, expected, WC_SHA224_DIGEST_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha224Update(NULL, (byte*)test_input, XSTRLEN(test_input)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Update(&sha224, NULL, WC_SHA224_DIGEST_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test edge cases */
    ExpectIntEQ(wc_Sha224Update(&sha224, NULL, 0), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)test_input, 0), 0);

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
    byte hash[WC_SHA224_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha224Final(&sha224, hash), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha224Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_Sha224SetFlags(&sha224, flags), 0);

    /* Verify flags were set */
    flags = 0;
    ExpectIntEQ(wc_Sha224GetFlags(&sha224, &flags), 0);
    ExpectTrue(flags == WC_HASH_FLAG_WILLCOPY);

    /* Test error cases */
    ExpectIntEQ(wc_Sha224SetFlags(NULL, flags), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

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
    byte hash[WC_SHA224_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)test_input, XSTRLEN(test_input)), 0);
    ExpectIntEQ(wc_Sha224GetHash(&sha224, hash), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha224GetHash(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    wc_Sha224 sha224, temp;
    byte hash1[WC_SHA224_DIGEST_SIZE], hash2[WC_SHA224_DIGEST_SIZE];
    const char* test_input = "test";

    /* Test normal operation */
    XMEMSET(&sha224, 0, sizeof(sha224));
    XMEMSET(&temp, 0, sizeof(temp));
    
    ExpectIntEQ(wc_InitSha224(&sha224), 0);
    ExpectIntEQ(wc_InitSha224(&temp), 0);
    ExpectIntEQ(wc_Sha224Update(&sha224, (byte*)test_input, XSTRLEN(test_input)), 0);
    
    /* Test copy operation */
    ExpectIntEQ(wc_Sha224Copy(&sha224, &temp), 0);
    
    /* Verify both generate same hash */
    ExpectIntEQ(wc_Sha224Final(&sha224, hash1), 0);
    ExpectIntEQ(wc_Sha224Final(&temp, hash2), 0);
    ExpectIntEQ(XMEMCMP(hash1, hash2, WC_SHA224_DIGEST_SIZE), 0);

    /* Test error cases */
    ExpectIntEQ(wc_Sha224Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha224Copy(&sha224, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha224Free(&sha224);
    wc_Sha224Free(&temp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Copy */

