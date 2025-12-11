/* test_sha.c
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

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sha.h>
#include <tests/api/test_digest.h>

/*
 * Unit test for the wc_InitSha()
 */
int test_wc_InitSha(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha, Sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha */

/*
 *  Tesing wc_ShaUpdate()
 */
int test_wc_ShaUpdate(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_UPDATE_TEST(wc_Sha, Sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaUpdate() */

/*
 * Unit test on wc_ShaFinal
 */
int test_wc_ShaFinal(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_FINAL_TEST(wc_Sha, Sha, SHA);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaFinal */

/*
 * Unit test on wc_ShaFinalRaw
 */
int test_wc_ShaFinalRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha, Sha, SHA,
        "\x67\x45\x23\x01\xef\xcd\xab\x89"
        "\x98\xba\xdc\xfe\x10\x32\x54\x76"
        "\xc3\xd2\xe1\xf0");
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaFinal */

#define SHA_KAT_CNT     7
int test_wc_Sha_KATs(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_KATS_TEST_VARS(wc_Sha, SHA);

    DIGEST_KATS_ADD("", 0,
        "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d"
        "\x32\x55\xbf\xef\x95\x60\x18\x90"
        "\xaf\xd8\x07\x09");
    DIGEST_KATS_ADD("a", 1,
        "\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc"
        "\xe1\x5d\x1d\xdc\xb9\xea\xea\xea"
        "\x37\x76\x67\xb8");
    DIGEST_KATS_ADD("abc", 3,
        "\xa9\x99\x3e\x36\x47\x06\x81\x6a"
        "\xba\x3e\x25\x71\x78\x50\xc2\x6c"
        "\x9c\xd0\xd8\x9d");
    DIGEST_KATS_ADD("message digest", 14,
        "\xc1\x22\x52\xce\xda\x8b\xe8\x99"
        "\x4d\x5f\xa0\x29\x0a\x47\x23\x1c"
        "\x1d\x16\xaa\xe3");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x32\xd1\x0c\x7b\x8c\xf9\x65\x70"
        "\xca\x04\xce\x37\xf2\xa1\x9d\x84"
        "\x24\x0d\x3a\x89");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x76\x1c\x45\x7b\xf7\x3b\x14\xd2"
        "\x7e\x9e\x92\x65\xc4\x6f\x4b\x4d"
        "\xda\x11\xf9\x40");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x50\xab\xf5\x70\x6a\x15\x09\x90"
        "\xa0\x8b\x2c\x5e\xa4\x0f\xa0\xe5"
        "\x85\x55\x47\x32");

    DIGEST_KATS_TEST(Sha, SHA);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaFinal */

int test_wc_Sha_other(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_OTHER_TEST(wc_Sha, Sha, SHA,
        "\xf0\xc2\x3f\xeb\xe0\xb0\xd9\x8c"
        "\x01\x23\x6c\x4c\x3b\x72\x7b\x01"
        "\xc7\x0d\x2b\x60");
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaFinal */

int test_wc_ShaCopy(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_COPY_TEST(wc_Sha, Sha, SHA,
        "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d"
        "\x32\x55\xbf\xef\x95\x60\x18\x90"
        "\xaf\xd8\x07\x09",
        "\xa9\x99\x3e\x36\x47\x06\x81\x6a"
        "\xba\x3e\x25\x71\x78\x50\xc2\x6c"
        "\x9c\xd0\xd8\x9d");
#endif
    return EXPECT_RESULT();
}

int test_wc_ShaGetHash(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    DIGEST_GET_HASH_TEST(wc_Sha, Sha, SHA,
        "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d"
        "\x32\x55\xbf\xef\x95\x60\x18\x90"
        "\xaf\xd8\x07\x09",
        "\xa9\x99\x3e\x36\x47\x06\x81\x6a"
        "\xba\x3e\x25\x71\x78\x50\xc2\x6c"
        "\x9c\xd0\xd8\x9d");
#endif
    return EXPECT_RESULT();
}

int test_wc_ShaTransform(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA) && (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3)))
    DIGEST_TRANSFORM_FINAL_RAW_TEST(wc_Sha, Sha, SHA,
        "\x80\x63\x62\x61\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x18\x00\x00\x00",
        "\xa9\x99\x3e\x36\x47\x06\x81\x6a"
        "\xba\x3e\x25\x71\x78\x50\xc2\x6c"
        "\x9c\xd0\xd8\x9d");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha_Flags(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA) && defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Sha, Sha);
#endif
    return EXPECT_RESULT();
}

