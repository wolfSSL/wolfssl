/* test_sha512.c
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

#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sha512.h>
#include <tests/api/test_digest.h>

/*******************************************************************************
 * SHA-512
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha512()
 */
int test_wc_InitSha512(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha512, Sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha512 */

/*
 *  Tesing wc_Sha512Update()
 */
int test_wc_Sha512Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_UPDATE_TEST(wc_Sha512, Sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Update() */

/*
 * Unit test on wc_Sha512Final
 */
int test_wc_Sha512Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_FINAL_TEST(wc_Sha512, Sha512, SHA512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Final */

/*
 * Unit test on wc_Sha512FinalRaw
 */
int test_wc_Sha512FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha512, Sha512, SHA512,
        "\x6a\x09\xe6\x67\xf3\xbc\xc9\x08"
        "\xbb\x67\xae\x85\x84\xca\xa7\x3b"
        "\x3c\x6e\xf3\x72\xfe\x94\xf8\x2b"
        "\xa5\x4f\xf5\x3a\x5f\x1d\x36\xf1"
        "\x51\x0e\x52\x7f\xad\xe6\x82\xd1"
        "\x9b\x05\x68\x8c\x2b\x3e\x6c\x1f"
        "\x1f\x83\xd9\xab\xfb\x41\xbd\x6b"
        "\x5b\xe0\xcd\x19\x13\x7e\x21\x79");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Final */

#define SHA512_KAT_CNT     7
int test_wc_Sha512_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_KATS_TEST_VARS(wc_Sha512, SHA512);

    DIGEST_KATS_ADD("", 0,
        "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd"
        "\xf1\x54\x28\x50\xd6\x6d\x80\x07"
        "\xd6\x20\xe4\x05\x0b\x57\x15\xdc"
        "\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
        "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0"
        "\xff\x83\x18\xd2\x87\x7e\xec\x2f"
        "\x63\xb9\x31\xbd\x47\x41\x7a\x81"
        "\xa5\x38\x32\x7a\xf9\x27\xda\x3e");
    DIGEST_KATS_ADD("a", 1,
        "\x1f\x40\xfc\x92\xda\x24\x16\x94"
        "\x75\x09\x79\xee\x6c\xf5\x82\xf2"
        "\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0"
        "\x5a\xbc\x54\xd0\x56\x0e\x0f\x53"
        "\x02\x86\x0c\x65\x2b\xf0\x8d\x56"
        "\x02\x52\xaa\x5e\x74\x21\x05\x46"
        "\xf3\x69\xfb\xbb\xce\x8c\x12\xcf"
        "\xc7\x95\x7b\x26\x52\xfe\x9a\x75");
    DIGEST_KATS_ADD("abc", 3,
        "\xdd\xaf\x35\xa1\x93\x61\x7a\xba"
        "\xcc\x41\x73\x49\xae\x20\x41\x31"
        "\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2"
        "\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
        "\x21\x92\x99\x2a\x27\x4f\xc1\xa8"
        "\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
        "\x45\x4d\x44\x23\x64\x3c\xe8\x0e"
        "\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f");
    DIGEST_KATS_ADD("message digest", 14,
        "\x10\x7d\xbf\x38\x9d\x9e\x9f\x71"
        "\xa3\xa9\x5f\x6c\x05\x5b\x92\x51"
        "\xbc\x52\x68\xc2\xbe\x16\xd6\xc1"
        "\x34\x92\xea\x45\xb0\x19\x9f\x33"
        "\x09\xe1\x64\x55\xab\x1e\x96\x11"
        "\x8e\x8a\x90\x5d\x55\x97\xb7\x20"
        "\x38\xdd\xb3\x72\xa8\x98\x26\x04"
        "\x6d\xe6\x66\x87\xbb\x42\x0e\x7c");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x4d\xbf\xf8\x6c\xc2\xca\x1b\xae"
        "\x1e\x16\x46\x8a\x05\xcb\x98\x81"
        "\xc9\x7f\x17\x53\xbc\xe3\x61\x90"
        "\x34\x89\x8f\xaa\x1a\xab\xe4\x29"
        "\x95\x5a\x1b\xf8\xec\x48\x3d\x74"
        "\x21\xfe\x3c\x16\x46\x61\x3a\x59"
        "\xed\x54\x41\xfb\x0f\x32\x13\x89"
        "\xf7\x7f\x48\xa8\x79\xc7\xb1\xf1");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x1e\x07\xbe\x23\xc2\x6a\x86\xea"
        "\x37\xea\x81\x0c\x8e\xc7\x80\x93"
        "\x52\x51\x5a\x97\x0e\x92\x53\xc2"
        "\x6f\x53\x6c\xfc\x7a\x99\x96\xc4"
        "\x5c\x83\x70\x58\x3e\x0a\x78\xfa"
        "\x4a\x90\x04\x1d\x71\xa4\xce\xab"
        "\x74\x23\xf1\x9c\x71\xb9\xd5\xa3"
        "\xe0\x12\x49\xf0\xbe\xbd\x58\x94");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x72\xec\x1e\xf1\x12\x4a\x45\xb0"
        "\x47\xe8\xb7\xc7\x5a\x93\x21\x95"
        "\x13\x5b\xb6\x1d\xe2\x4e\xc0\xd1"
        "\x91\x40\x42\x24\x6e\x0a\xec\x3a"
        "\x23\x54\xe0\x93\xd7\x6f\x30\x48"
        "\xb4\x56\x76\x43\x46\x90\x0c\xb1"
        "\x30\xd2\xa4\xfd\x5d\xd1\x6a\xbb"
        "\x5e\x30\xbc\xb8\x50\xde\xe8\x43");

    DIGEST_KATS_TEST(Sha512, SHA512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Final */

int test_wc_Sha512_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_OTHER_TEST(wc_Sha512, Sha512, SHA512,
        "\xf2\x7d\xa3\xe0\x25\x71\x51\x3f"
        "\x75\xf4\xdc\xea\xdc\xf7\x7f\xf1"
        "\xad\x5a\x51\x32\x07\x73\x1d\xf8"
        "\xdd\xaa\xf1\x15\x3e\xa3\x3c\xc5"
        "\x00\x76\x6e\x1d\xa5\xa2\x4a\x44"
        "\x99\x3e\x2d\xaa\xa8\x05\xc8\x49"
        "\xf0\x83\x34\x02\x07\x43\x8b\xac"
        "\xfb\xe6\x02\x40\x6b\x48\x54\x8e");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Final */

int test_wc_Sha512Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_COPY_TEST(wc_Sha512, Sha512, SHA512,
        "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd"
        "\xf1\x54\x28\x50\xd6\x6d\x80\x07"
        "\xd6\x20\xe4\x05\x0b\x57\x15\xdc"
        "\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
        "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0"
        "\xff\x83\x18\xd2\x87\x7e\xec\x2f"
        "\x63\xb9\x31\xbd\x47\x41\x7a\x81"
        "\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
        "\xdd\xaf\x35\xa1\x93\x61\x7a\xba"
        "\xcc\x41\x73\x49\xae\x20\x41\x31"
        "\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2"
        "\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
        "\x21\x92\x99\x2a\x27\x4f\xc1\xa8"
        "\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
        "\x45\x4d\x44\x23\x64\x3c\xe8\x0e"
        "\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    DIGEST_GET_HASH_TEST(wc_Sha512, Sha512, SHA512,
        "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd"
        "\xf1\x54\x28\x50\xd6\x6d\x80\x07"
        "\xd6\x20\xe4\x05\x0b\x57\x15\xdc"
        "\x83\xf4\xa9\x21\xd3\x6c\xe9\xce"
        "\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0"
        "\xff\x83\x18\xd2\x87\x7e\xec\x2f"
        "\x63\xb9\x31\xbd\x47\x41\x7a\x81"
        "\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
        "\xdd\xaf\x35\xa1\x93\x61\x7a\xba"
        "\xcc\x41\x73\x49\xae\x20\x41\x31"
        "\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2"
        "\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
        "\x21\x92\x99\x2a\x27\x4f\xc1\xa8"
        "\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
        "\x45\x4d\x44\x23\x64\x3c\xe8\x0e"
        "\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512Transform(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && \
    (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3)))
    DIGEST_TRANSFORM_FINAL_RAW_ALL_TEST(wc_Sha512, Sha512, SHA512,
        "\x80\x63\x62\x61\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x18\x00\x00\x00",
        "\x54\x52\xb6\x73\x58\x3e\x6f\x12"
        "\xcb\x0b\xf3\x61\x38\xb9\x76\xe8"
        "\x2e\x46\x13\xd9\x4a\x67\xe3\x7c"
        "\x5c\xd7\xa5\xe6\x43\x55\x16\xa2"
        "\x83\x06\x9a\x32\x69\x55\x63\x95"
        "\x68\x75\xde\x70\x09\x4d\xcd\xfe"
        "\xbe\x11\x20\xd6\xe7\x7c\x49\xd3"
        "\x5b\xd7\x07\x75\x19\xc9\x8a\xfa");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Sha512, Sha512);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-512-224
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha512_224()
 */
int test_wc_InitSha512_224(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha512, Sha512_224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha512_224 */

/*
 *  Tesing wc_Sha512_224Update()
 */
int test_wc_Sha512_224Update(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_UPDATE_TEST(wc_Sha512, Sha512_224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_224Update() */

/*
 * Unit test on wc_Sha512_224Final
 */
int test_wc_Sha512_224Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_FINAL_TEST(wc_Sha512, Sha512_224, SHA512_224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_224Final */

/*
 * Unit test on wc_Sha512_224FinalRaw
 */
int test_wc_Sha512_224FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_DEVCRYPTO) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION >= 3))) && !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha512, Sha512_224, SHA512_224,
        "\x8c\x3d\x37\xc8\x19\x54\x4d\xa2"
        "\x73\xe1\x99\x66\x89\xdc\xd4\xd6"
        "\x1d\xfa\xb7\xae\x32\xff\x9c\x82"
        "\x67\x9d\xd5\x14");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_224Final */

#define SHA512_224_KAT_CNT     7
int test_wc_Sha512_224_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_KATS_TEST_VARS(wc_Sha512, SHA512_224);

    DIGEST_KATS_ADD("", 0,
        "\x6e\xd0\xdd\x02\x80\x6f\xa8\x9e"
        "\x25\xde\x06\x0c\x19\xd3\xac\x86"
        "\xca\xbb\x87\xd6\xa0\xdd\xd0\x5c"
        "\x33\x3b\x84\xf4");
    DIGEST_KATS_ADD("a", 1,
        "\xd5\xcd\xb9\xcc\xc7\x69\xa5\x12"
        "\x1d\x41\x75\xf2\xbf\xdd\x13\xd6"
        "\x31\x0e\x0d\x3d\x36\x1e\xa7\x5d"
        "\x82\x10\x83\x27");
    DIGEST_KATS_ADD("abc", 3,
        "\x46\x34\x27\x0f\x70\x7b\x6a\x54"
        "\xda\xae\x75\x30\x46\x08\x42\xe2"
        "\x0e\x37\xed\x26\x5c\xee\xe9\xa4"
        "\x3e\x89\x24\xaa");
    DIGEST_KATS_ADD("message digest", 14,
        "\xad\x1a\x4d\xb1\x88\xfe\x57\x06"
        "\x4f\x4f\x24\x60\x9d\x2a\x83\xcd"
        "\x0a\xfb\x9b\x39\x8e\xb2\xfc\xae"
        "\xaa\xe2\xc5\x64");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xff\x83\x14\x8a\xa0\x7e\xc3\x06"
        "\x55\xc1\xb4\x0a\xff\x86\x14\x1c"
        "\x02\x15\xfe\x2a\x54\xf7\x67\xd3"
        "\xf3\x87\x43\xd8");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xa8\xb4\xb9\x17\x4b\x99\xff\xc6"
        "\x7d\x6f\x49\xbe\x99\x81\x58\x7b"
        "\x96\x44\x10\x51\xe1\x6e\x6d\xd0"
        "\x36\xb1\x40\xd3");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xae\x98\x8f\xaa\xa4\x7e\x40\x1a"
        "\x45\xf7\x04\xd1\x27\x2d\x99\x70"
        "\x24\x58\xfe\xa2\xdd\xc6\x58\x28"
        "\x27\x55\x6d\xd2");

    DIGEST_KATS_TEST(Sha512_224, SHA512_224);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_224Final */

int test_wc_Sha512_224_other(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_OTHER_TEST(wc_Sha512, Sha512_224, SHA512_224,
        "\xbe\xbb\x85\xa0\x14\x9f\xd7\xae"
        "\xc4\xbe\xa4\x8f\xa3\xeb\xac\xc0"
        "\x88\x02\x6b\xa0\xe8\x22\x5c\xb3"
        "\x12\x11\xa0\x48");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_224Final */

int test_wc_Sha512_224Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_COPY_TEST(wc_Sha512, Sha512_224, SHA512_224,
        "\x6e\xd0\xdd\x02\x80\x6f\xa8\x9e"
        "\x25\xde\x06\x0c\x19\xd3\xac\x86"
        "\xca\xbb\x87\xd6\xa0\xdd\xd0\x5c"
        "\x33\x3b\x84\xf4",
        "\x46\x34\x27\x0f\x70\x7b\x6a\x54"
        "\xda\xae\x75\x30\x46\x08\x42\xe2"
        "\x0e\x37\xed\x26\x5c\xee\xe9\xa4"
        "\x3e\x89\x24\xaa");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_224GetHash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    DIGEST_GET_HASH_TEST(wc_Sha512, Sha512_224, SHA512_224,
        "\x6e\xd0\xdd\x02\x80\x6f\xa8\x9e"
        "\x25\xde\x06\x0c\x19\xd3\xac\x86"
        "\xca\xbb\x87\xd6\xa0\xdd\xd0\x5c"
        "\x33\x3b\x84\xf4",
        "\x46\x34\x27\x0f\x70\x7b\x6a\x54"
        "\xda\xae\x75\x30\x46\x08\x42\xe2"
        "\x0e\x37\xed\x26\x5c\xee\xe9\xa4"
        "\x3e\x89\x24\xaa");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_224Transform(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
    (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3)))
    DIGEST_TRANSFORM_FINAL_RAW_ALL_TEST(wc_Sha512, Sha512_224, SHA512_224,
        "\x61\x62\x63\x80\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x18",
        "\x46\x34\x27\x0f\x70\x7b\x6a\x54"
        "\xda\xae\x75\x30\x46\x08\x42\xe2"
        "\x0e\x37\xed\x26\x5c\xee\xe9\xa4"
        "\x3e\x89\x24\xaa");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_224_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
    defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Sha512, Sha512_224);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-512-256
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha512_256()
 */
int test_wc_InitSha512_256(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha512, Sha512_256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha512_256 */

/*
 *  Tesing wc_Sha512_256Update()
 */
int test_wc_Sha512_256Update(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_UPDATE_TEST(wc_Sha512, Sha512_256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_256Update() */

/*
 * Unit test on wc_Sha512_256Final
 */
int test_wc_Sha512_256Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_FINAL_TEST(wc_Sha512, Sha512_256, SHA512_256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_256Final */

/*
 * Unit test on wc_Sha512_256FinalRaw
 */
int test_wc_Sha512_256FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_DEVCRYPTO) && \
    (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION >= 3))) && !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha512, Sha512_256, SHA512_256,
        "\x22\x31\x21\x94\xfc\x2b\xf7\x2c"
        "\x9f\x55\x5f\xa3\xc8\x4c\x64\xc2"
        "\x23\x93\xb8\x6b\x6f\x53\xb1\x51"
        "\x96\x38\x77\x19\x59\x40\xea\xbd");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_256Final */

#define SHA512_256_KAT_CNT     7
int test_wc_Sha512_256_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_KATS_TEST_VARS(wc_Sha512, SHA512_256);

    DIGEST_KATS_ADD("", 0,
        "\xc6\x72\xb8\xd1\xef\x56\xed\x28"
        "\xab\x87\xc3\x62\x2c\x51\x14\x06"
        "\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74"
        "\x98\xd0\xc0\x1e\xce\xf0\x96\x7a");
    DIGEST_KATS_ADD("a", 1,
        "\x45\x5e\x51\x88\x24\xbc\x06\x01"
        "\xf9\xfb\x85\x8f\xf5\xc3\x7d\x41"
        "\x7d\x67\xc2\xf8\xe0\xdf\x2b\xab"
        "\xe4\x80\x88\x58\xae\xa8\x30\xf8");
    DIGEST_KATS_ADD("abc", 3,
        "\x53\x04\x8e\x26\x81\x94\x1e\xf9"
        "\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab"
        "\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46"
        "\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");
    DIGEST_KATS_ADD("message digest", 14,
        "\x0c\xf4\x71\xfd\x17\xed\x69\xd9"
        "\x90\xda\xf3\x43\x3c\x89\xb1\x6d"
        "\x63\xde\xc1\xbb\x9c\xb4\x2a\x60"
        "\x94\x60\x4e\xe5\xd7\xb4\xe9\xfb");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xfc\x31\x89\x44\x3f\x9c\x26\x8f"
        "\x62\x6a\xea\x08\xa7\x56\xab\xe7"
        "\xb7\x26\xb0\x5f\x70\x1c\xb0\x82"
        "\x22\x31\x2c\xcf\xd6\x71\x0a\x26");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xcd\xf1\xcc\x0e\xff\xe2\x6e\xcc"
        "\x0c\x13\x75\x8f\x7b\x4a\x48\xe0"
        "\x00\x61\x5d\xf2\x41\x28\x41\x85"
        "\xc3\x9e\xb0\x5d\x35\x5b\xb9\xc8");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x2c\x9f\xdb\xc0\xc9\x0b\xdd\x87"
        "\x61\x2e\xe8\x45\x54\x74\xf9\x04"
        "\x48\x50\x24\x1d\xc1\x05\xb1\xe8"
        "\xb9\x4b\x8d\xdf\x5f\xac\x91\x48");

    DIGEST_KATS_TEST(Sha512_256, SHA512_256);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_256Final */

int test_wc_Sha512_256_other(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_OTHER_TEST(wc_Sha512, Sha512_256, SHA512_256,
        "\x0c\x80\x73\xf5\xf4\xc8\xc7\x13"
        "\x4a\xc4\x8a\xda\x04\xfc\x77\x74"
        "\xea\xa0\x85\xa9\x29\xb3\x54\xa4"
        "\x08\xef\x2a\x87\x61\x1f\x8c\xb8");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512_256Final */

int test_wc_Sha512_256Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_COPY_TEST(wc_Sha512, Sha512_256, SHA512_256,
        "\xc6\x72\xb8\xd1\xef\x56\xed\x28"
        "\xab\x87\xc3\x62\x2c\x51\x14\x06"
        "\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74"
        "\x98\xd0\xc0\x1e\xce\xf0\x96\x7a",
        "\x53\x04\x8e\x26\x81\x94\x1e\xf9"
        "\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab"
        "\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46"
        "\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_256GetHash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    DIGEST_GET_HASH_TEST(wc_Sha512, Sha512_256, SHA512_256,
        "\xc6\x72\xb8\xd1\xef\x56\xed\x28"
        "\xab\x87\xc3\x62\x2c\x51\x14\x06"
        "\x9b\xdd\x3a\xd7\xb8\xf9\x73\x74"
        "\x98\xd0\xc0\x1e\xce\xf0\x96\x7a",
        "\x53\x04\x8e\x26\x81\x94\x1e\xf9"
        "\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab"
        "\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46"
        "\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_256Transform(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
    (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3)))
    DIGEST_TRANSFORM_FINAL_RAW_ALL_TEST(wc_Sha512, Sha512_256, SHA512_256,
        "\x61\x62\x63\x80\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x18",
        "\x53\x04\x8e\x26\x81\x94\x1e\xf9"
        "\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab"
        "\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46"
        "\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_256_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
    defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Sha512, Sha512_256);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-384
 ******************************************************************************/

/*
 * Unit test for the wc_InitSha384()
 */
int test_wc_InitSha384(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Sha384, Sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha384 */

/*
 *  Tesing wc_Sha384Update()
 */
int test_wc_Sha384Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_UPDATE_TEST(wc_Sha384, Sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Update() */

/*
 * Unit test on wc_Sha384Final
 */
int test_wc_Sha384Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_FINAL_TEST(wc_Sha384, Sha384, SHA384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Final */

/*
 * Unit test on wc_Sha384FinalRaw
 */
int test_wc_Sha384FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA384) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    DIGEST_FINAL_RAW_TEST(wc_Sha384, Sha384, SHA384,
        "\xcb\xbb\x9d\x5d\xc1\x05\x9e\xd8"
        "\x62\x9a\x29\x2a\x36\x7c\xd5\x07"
        "\x91\x59\x01\x5a\x30\x70\xdd\x17"
        "\x15\x2f\xec\xd8\xf7\x0e\x59\x39"
        "\x67\x33\x26\x67\xff\xc0\x0b\x31"
        "\x8e\xb4\x4a\x87\x68\x58\x15\x11");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384 */

#define SHA384_KAT_CNT     7
int test_wc_Sha384_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_KATS_TEST_VARS(wc_Sha384, SHA384);

    DIGEST_KATS_ADD("", 0,
        "\x38\xb0\x60\xa7\x51\xac\x96\x38"
        "\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a"
        "\x21\xfd\xb7\x11\x14\xbe\x07\x43"
        "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda"
        "\x27\x4e\xde\xbf\xe7\x6f\x65\xfb"
        "\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b");
    DIGEST_KATS_ADD("a", 1,
        "\x54\xa5\x9b\x9f\x22\xb0\xb8\x08"
        "\x80\xd8\x42\x7e\x54\x8b\x7c\x23"
        "\xab\xd8\x73\x48\x6e\x1f\x03\x5d"
        "\xce\x9c\xd6\x97\xe8\x51\x75\x03"
        "\x3c\xaa\x88\xe6\xd5\x7b\xc3\x5e"
        "\xfa\xe0\xb5\xaf\xd3\x14\x5f\x31");
    DIGEST_KATS_ADD("abc", 3,
        "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b"
        "\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
        "\x27\x2c\x32\xab\x0e\xde\xd1\x63"
        "\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
        "\x80\x86\x07\x2b\xa1\xe7\xcc\x23"
        "\x58\xba\xec\xa1\x34\xc8\x25\xa7");
    DIGEST_KATS_ADD("message digest", 14,
        "\x47\x3e\xd3\x51\x67\xec\x1f\x5d"
        "\x8e\x55\x03\x68\xa3\xdb\x39\xbe"
        "\x54\x63\x9f\x82\x88\x68\xe9\x45"
        "\x4c\x23\x9f\xc8\xb5\x2e\x3c\x61"
        "\xdb\xd0\xd8\xb4\xde\x13\x90\xc2"
        "\x56\xdc\xbb\x5d\x5f\xd9\x9c\xd5");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xfe\xb6\x73\x49\xdf\x3d\xb6\xf5"
        "\x92\x48\x15\xd6\xc3\xdc\x13\x3f"
        "\x09\x18\x09\x21\x37\x31\xfe\x5c"
        "\x7b\x5f\x49\x99\xe4\x63\x47\x9f"
        "\xf2\x87\x7f\x5f\x29\x36\xfa\x63"
        "\xbb\x43\x78\x4b\x12\xf3\xeb\xb4");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x17\x61\x33\x6e\x3f\x7c\xbf\xe5"
        "\x1d\xeb\x13\x7f\x02\x6f\x89\xe0"
        "\x1a\x44\x8e\x3b\x1f\xaf\xa6\x40"
        "\x39\xc1\x46\x4e\xe8\x73\x2f\x11"
        "\xa5\x34\x1a\x6f\x41\xe0\xc2\x02"
        "\x29\x47\x36\xed\x64\xdb\x1a\x84");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xb1\x29\x32\xb0\x62\x7d\x1c\x06"
        "\x09\x42\xf5\x44\x77\x64\x15\x56"
        "\x55\xbd\x4d\xa0\xc9\xaf\xa6\xdd"
        "\x9b\x9e\xf5\x31\x29\xaf\x1b\x8f"
        "\xb0\x19\x59\x96\xd2\xde\x9c\xa0"
        "\xdf\x9d\x82\x1f\xfe\xe6\x70\x26");

    DIGEST_KATS_TEST(Sha384, SHA384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Final */

int test_wc_Sha384_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_OTHER_TEST(wc_Sha384, Sha384, SHA384,
        "\xbe\x28\x56\x36\xd3\xae\x1c\x63"
        "\x94\x7a\xc0\x7f\xb1\x71\x5c\x19"
        "\x45\xfd\x81\x7b\x46\xfb\x03\xc2"
        "\x46\x2c\x80\x8d\xd2\xc0\x16\x91"
        "\x23\x51\x6b\xa5\x0d\x71\x6f\x8b"
        "\x2f\x52\x74\x86\x0d\x05\xa5\x95");
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Final */

int test_wc_Sha384Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_COPY_TEST(wc_Sha384, Sha384, SHA384,
        "\x38\xb0\x60\xa7\x51\xac\x96\x38"
        "\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a"
        "\x21\xfd\xb7\x11\x14\xbe\x07\x43"
        "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda"
        "\x27\x4e\xde\xbf\xe7\x6f\x65\xfb"
        "\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b",
        "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b"
        "\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
        "\x27\x2c\x32\xab\x0e\xde\xd1\x63"
        "\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
        "\x80\x86\x07\x2b\xa1\xe7\xcc\x23"
        "\x58\xba\xec\xa1\x34\xc8\x25\xa7");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha384GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    DIGEST_GET_HASH_TEST(wc_Sha384, Sha384, SHA384,
        "\x38\xb0\x60\xa7\x51\xac\x96\x38"
        "\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a"
        "\x21\xfd\xb7\x11\x14\xbe\x07\x43"
        "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda"
        "\x27\x4e\xde\xbf\xe7\x6f\x65\xfb"
        "\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b",
        "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b"
        "\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
        "\x27\x2c\x32\xab\x0e\xde\xd1\x63"
        "\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
        "\x80\x86\x07\x2b\xa1\xe7\xcc\x23"
        "\x58\xba\xec\xa1\x34\xc8\x25\xa7");
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha384_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Sha384, Sha384);
#endif
    return EXPECT_RESULT();
}

