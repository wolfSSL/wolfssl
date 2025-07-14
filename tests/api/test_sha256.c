/* test_sha256.c
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

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sha256.h>
#include <tests/api/test_digest.h>

/*******************************************************************************
 * SHA-256
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha256()
 */
int test_wc_InitSha256(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha256, Sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha256 */

/*
 *  Tesing wc_Sha256Update()
 */
int test_wc_Sha256Update(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_UPDATE_TEST(wc_Sha256, Sha256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Update() */

/*
 * Unit test on wc_Sha256Final
 */
int test_wc_Sha256Final(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_FINAL_TEST(wc_Sha256, Sha256, SHA256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Final */

/*
 * Unit test on wc_Sha256FinalRaw
 */
int test_wc_Sha256FinalRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha256, Sha256, SHA256,
        "\x6a\x09\xe6\x67\xbb\x67\xae\x85"
        "\x3c\x6e\xf3\x72\xa5\x4f\xf5\x3a"
        "\x51\x0e\x52\x7f\x9b\x05\x68\x8c"
        "\x1f\x83\xd9\xab\x5b\xe0\xcd\x19");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Final */

#define SHA256_KAT_CNT     7
int test_wc_Sha256_KATs(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_KATS_TEST_VARS(wc_Sha256, SHA256);

    DIGEST_KATS_ADD("", 0,
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14"
        "\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c"
        "\xa4\x95\x99\x1b\x78\x52\xb8\x55");
    DIGEST_KATS_ADD("a", 1,
        "\xca\x97\x81\x12\xca\x1b\xbd\xca"
        "\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d"
        "\xa7\x86\xef\xf8\x14\x7c\x4e\x72"
        "\xb9\x80\x77\x85\xaf\xee\x48\xbb");
    DIGEST_KATS_ADD("abc", 3,
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea"
        "\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c"
        "\xb4\x10\xff\x61\xf2\x00\x15\xad");
    DIGEST_KATS_ADD("message digest", 14,
        "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e"
        "\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
        "\x5b\x50\x9e\x33\x48\xfb\xc4\xef"
        "\xa3\xa1\x41\x3d\x39\x3c\xb6\x50");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x71\xc4\x80\xdf\x93\xd6\xae\x2f"
        "\x1e\xfa\xd1\x44\x7c\x66\xc9\x52"
        "\x5e\x31\x62\x18\xcf\x51\xfc\x8d"
        "\x9e\xd8\x32\xf2\xda\xf1\x8b\x73");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85"
        "\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80"
        "\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe"
        "\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xf3\x71\xbc\x4a\x31\x1f\x2b\x00"
        "\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e"
        "\x2b\x60\x02\x6c\x8e\x93\x55\x92"
        "\xd0\xf9\xc3\x08\x45\x3c\x81\x3e");

    DIGEST_KATS_TEST(Sha256, SHA256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Final */

int test_wc_Sha256_other(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_OTHER_TEST(wc_Sha256, Sha256, SHA256,
        "\x2c\x41\xa1\xdd\x58\x4e\x37\x73"
        "\xb9\x56\x74\x84\x1b\x68\x5f\x36"
        "\xc7\x6b\x48\xec\x4d\xb7\x58\x63"
        "\x37\x2c\x2f\xd6\xe1\x9a\x61\xce");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha256Final */

int test_wc_Sha256Copy(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_COPY_TEST(wc_Sha256, Sha256, SHA256,
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14"
        "\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c"
        "\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea"
        "\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c"
        "\xb4\x10\xff\x61\xf2\x00\x15\xad");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha256GetHash(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA256
    DIGEST_GET_HASH_TEST(wc_Sha256, Sha256, SHA256,
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14"
        "\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c"
        "\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea"
        "\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c"
        "\xb4\x10\xff\x61\xf2\x00\x15\xad");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha256Transform(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(WOLFSSL_KCAPI_HASH) && !defined(WOLFSSL_AFALG_HASH) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3)))
    DIGEST_TRANSFORM_FINAL_RAW_TEST(wc_Sha256, Sha256, SHA256,
        "\x80\x63\x62\x61\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x18\x00\x00\x00",
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea"
        "\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c"
        "\xb4\x10\xff\x61\xf2\x00\x15\xad");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha256_Flags(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && defined(WOLFSSL_HASH_FLAGS) && \
    (!defined(WOLFSSL_ARMASM) || !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    DIGEST_FLAGS_TEST(wc_Sha256, Sha256);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-224
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha224()
 */
int test_wc_InitSha224(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha224, Sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha224 */

/*
 *  Tesing wc_Sha224Update()
 */
int test_wc_Sha224Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_UPDATE_TEST(wc_Sha224, Sha224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Update() */

/*
 * Unit test on wc_Sha224Final
 */
int test_wc_Sha224Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_FINAL_TEST(wc_Sha224, Sha224, SHA224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Final */

#define SHA224_KAT_CNT     7
int test_wc_Sha224_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_KATS_TEST_VARS(wc_Sha224, SHA224);

    DIGEST_KATS_ADD("", 0,
        "\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9"
        "\x47\x61\x02\xbb\x28\x82\x34\xc4"
        "\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a"
        "\xc5\xb3\xe4\x2f");
    DIGEST_KATS_ADD("a", 1,
        "\xab\xd3\x75\x34\xc7\xd9\xa2\xef"
        "\xb9\x46\x5d\xe9\x31\xcd\x70\x55"
        "\xff\xdb\x88\x79\x56\x3a\xe9\x80"
        "\x78\xd6\xd6\xd5");
    DIGEST_KATS_ADD("abc", 3,
        "\x23\x09\x7d\x22\x34\x05\xd8\x22"
        "\x86\x42\xa4\x77\xbd\xa2\x55\xb3"
        "\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7"
        "\xe3\x6c\x9d\xa7");
    DIGEST_KATS_ADD("message digest", 14,
        "\x2c\xb2\x1c\x83\xae\x2f\x00\x4d"
        "\xe7\xe8\x1c\x3c\x70\x19\xcb\xcb"
        "\x65\xb7\x1a\xb6\x56\xb2\x2d\x6d"
        "\x0c\x39\xb8\xeb");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x45\xa5\xf7\x2c\x39\xc5\xcf\xf2"
        "\x52\x2e\xb3\x42\x97\x99\xe4\x9e"
        "\x5f\x44\xb3\x56\xef\x92\x6b\xcf"
        "\x39\x0d\xcc\xc2");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xbf\xf7\x2b\x4f\xcb\x7d\x75\xe5"
        "\x63\x29\x00\xac\x5f\x90\xd2\x19"
        "\xe0\x5e\x97\xa7\xbd\xe7\x2e\x74"
        "\x0d\xb3\x93\xd9");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xb5\x0a\xec\xbe\x4e\x9b\xb0\xb5"
        "\x7b\xc5\xf3\xae\x76\x0a\x8e\x01"
        "\xdb\x24\xf2\x03\xfb\x3c\xdc\xd1"
        "\x31\x48\x04\x6e");

    DIGEST_KATS_TEST(Sha224, SHA224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Final */

int test_wc_Sha224_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_OTHER_TEST(wc_Sha224, Sha224, SHA224,
        "\x60\x81\xdf\x2f\xae\xe2\x25\xe9"
        "\x87\x61\x2a\x8e\x25\x19\x16\x39"
        "\x80\xfb\x77\xfa\x28\x74\x17\x4d"
        "\xf3\x15\x52\x2b");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha224Final */

int test_wc_Sha224Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_COPY_TEST(wc_Sha224, Sha224, SHA224,
        "\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9"
        "\x47\x61\x02\xbb\x28\x82\x34\xc4"
        "\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a"
        "\xc5\xb3\xe4\x2f",
        "\x23\x09\x7d\x22\x34\x05\xd8\x22"
        "\x86\x42\xa4\x77\xbd\xa2\x55\xb3"
        "\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7"
        "\xe3\x6c\x9d\xa7");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha224GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA224
    DIGEST_GET_HASH_TEST(wc_Sha224, Sha224, SHA224,
        "\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9"
        "\x47\x61\x02\xbb\x28\x82\x34\xc4"
        "\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a"
        "\xc5\xb3\xe4\x2f",
        "\x23\x09\x7d\x22\x34\x05\xd8\x22"
        "\x86\x42\xa4\x77\xbd\xa2\x55\xb3"
        "\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7"
        "\xe3\x6c\x9d\xa7");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha224_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA224) && defined(WOLFSSL_HASH_FLAGS) && \
    (!defined(WOLFSSL_ARMASM) || !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    DIGEST_FLAGS_TEST(wc_Sha224, Sha224);
#endif
    return EXPECT_RESULT();
}

