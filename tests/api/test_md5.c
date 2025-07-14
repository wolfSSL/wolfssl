/* test_md5.c
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

#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_md5.h>
#include <tests/api/test_digest.h>

/* Unit test for wc_InitMd5() and wc_InitMd5_ex() */
int test_wc_InitMd5(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_UpdateMd5() */
int test_wc_Md5Update(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_UPDATE_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_Md5Final() */
int test_wc_Md5Final(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_FINAL_TEST(wc_Md5, Md5, MD5);
#endif
    return EXPECT_RESULT();
}

#define MD5_KAT_CNT     7

int test_wc_Md5_KATs(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_KATS_TEST_VARS(wc_Md5, MD5);

    /* From RFC 1321. */
    DIGEST_KATS_ADD("", 0,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e");
    DIGEST_KATS_ADD("a", 1,
        "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8"
        "\x31\xc3\x99\xe2\x69\x77\x26\x61");
    DIGEST_KATS_ADD("abc", 3,
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
    DIGEST_KATS_ADD("message digest", 14,
        "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d"
        "\x52\x5a\x2f\x31\xaa\xf1\x61\xd0");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00"
        "\x7d\xfb\x49\x6c\xca\x67\xe1\x3b");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xd1\x74\xab\x98\xd2\x77\xd9\xf5"
        "\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55"
        "\xac\x49\xda\x2e\x21\x07\xb6\x7a");

    DIGEST_KATS_TEST(Md5, MD5);
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5_other(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_OTHER_TEST(wc_Md5, Md5, MD5,
        "\xd9\xa6\xc2\x1f\xf4\x05\xab\x62"
        "\xd6\xad\xa8\xcd\x0c\xb9\x49\x14");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5Copy(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_COPY_TEST(wc_Md5, Md5, MD5,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5GetHash(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_GET_HASH_TEST(wc_Md5, Md5, MD5,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5Transform(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD5) && (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_MD5_CUST_API)
    DIGEST_TRANSFORM_TEST(wc_Md5, Md5, MD5,
        "\x61\x62\x63\x80\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x18\x00\x00\x00\x00\x00\x00\x00",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5_Flags(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD5) && defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

