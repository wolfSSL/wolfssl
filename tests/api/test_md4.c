/* test_md4.c
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

#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_md4.h>
#include <tests/api/test_digest.h>

/* Unit test for wc_InitMd4() and wc_InitMd4_ex() */
int test_wc_InitMd4(void)
{
    EXPECT_SUCCESS_DECLS;
#ifndef NO_MD4
    DIGEST_INIT_ONLY_TEST(wc_Md4, Md4);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_UpdateMd4() */
int test_wc_Md4Update(void)
{
    EXPECT_SUCCESS_DECLS;
#ifndef NO_MD4
    DIGEST_UPDATE_ONLY_TEST(wc_Md4, Md4);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_Md4Final() */
int test_wc_Md4Final(void)
{
    EXPECT_SUCCESS_DECLS;
#ifndef NO_MD4
    DIGEST_FINAL_ONLY_TEST(wc_Md4, Md4, MD4);
#endif
    return EXPECT_RESULT();
}

#define MD4_KAT_CNT     7

int test_wc_Md4_KATs(void)
{
    EXPECT_DECLS;
#ifndef NO_MD4
    DIGEST_KATS_TEST_VARS(wc_Md4, MD4);

    /* From RFC 1321. */
    DIGEST_KATS_ADD("", 0,
        "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31"
        "\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0");
    DIGEST_KATS_ADD("a", 1,
        "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46"
        "\x24\x5e\x05\xfb\xdb\xd6\xfb\x24");
    DIGEST_KATS_ADD("abc", 3,
        "\xa4\x48\x01\x7a\xaf\x21\xd8\x52"
        "\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d");
    DIGEST_KATS_ADD("message digest", 14,
        "\xd9\x13\x0a\x81\x64\x54\x9f\xe8"
        "\x18\x87\x48\x06\xe1\xc7\x01\x4b");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd"
        "\xee\xa8\xed\x63\xdf\x41\x2d\xa9");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x04\x3f\x85\x82\xf2\x41\xdb\x35"
        "\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19"
        "\x9c\x3e\x7b\x16\x4f\xcc\x05\x36");

    DIGEST_KATS_ONLY_TEST(Md4, MD4);
#endif
    return EXPECT_RESULT();
}

int test_wc_Md4_other(void)
{
    EXPECT_DECLS;
#ifndef NO_MD4
    DIGEST_OTHER_ONLY_TEST(wc_Md4, Md4, MD4,
        "\x1b\x60\x7d\x08\x57\x0c\xf1\x52"
        "\xbb\x44\x55\x97\x73\x26\x95\x6d");
#endif
    return EXPECT_RESULT();
}

