/* test_md2.c
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

#include <wolfssl/wolfcrypt/md2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_md2.h>
#include <tests/api/test_digest.h>

/* Unit test for wc_InitMd2() and wc_InitMd2_ex() */
int test_wc_InitMd2(void)
{
    EXPECT_SUCCESS_DECLS;
#ifdef WOLFSSL_MD2
    DIGEST_INIT_ONLY_TEST(wc_Md2, Md2);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_UpdateMd2() */
int test_wc_Md2Update(void)
{
    EXPECT_SUCCESS_DECLS;
#ifdef WOLFSSL_MD2
    DIGEST_UPDATE_ONLY_TEST(wc_Md2, Md2);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_Md2Final() */
int test_wc_Md2Final(void)
{
    EXPECT_SUCCESS_DECLS;
#ifdef WOLFSSL_MD2
    DIGEST_FINAL_ONLY_TEST(wc_Md2, Md2, MD2);
#endif
    return EXPECT_RESULT();
}

#define MD2_KAT_CNT     7

int test_wc_Md2_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_MD2
    DIGEST_KATS_TEST_VARS(wc_Md2, MD2);

    /* From RFC 1321. */
    DIGEST_KATS_ADD("", 0,
        "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d"
        "\xf2\x27\x5c\x9f\x80\x69\x27\x73" );
    DIGEST_KATS_ADD("a", 1,
        "\x32\xec\x01\xec\x4a\x6d\xac\x72"
        "\xc0\xab\x96\xfb\x34\xc0\xb5\xd1");
    DIGEST_KATS_ADD("abc", 3,
        "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b"
        "\x30\x28\x3a\x69\xe6\xde\xd6\xbb");
    DIGEST_KATS_ADD("message digest", 14,
        "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b"
        "\x21\x9f\xf3\x30\x31\xfe\x06\xb0");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x4e\x8d\xdf\xf3\x65\x02\x92\xab"
        "\x5a\x41\x08\xc3\xaa\x47\x94\x0b");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xda\x33\xde\xf2\xa4\x2d\xf1\x39"
        "\x75\x35\x28\x46\xc3\x03\x38\xcd");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d"
        "\xc9\x80\x6c\x3c\x66\xf3\xef\xd8");

    DIGEST_KATS_ONLY_TEST(Md2, MD2);
#endif
    return EXPECT_RESULT();
}

int test_wc_Md2_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_MD2
    DIGEST_OTHER_ONLY_TEST(wc_Md2, Md2, MD2,
        "\xa3\x0c\xa1\xdd\xfa\xd0\x7c\x97"
        "\x58\xfd\xe2\x53\xf0\xa1\xb0\x6d");
#endif
    return EXPECT_RESULT();
}

/*
 *  Testing wc_Md2Hash()
 */
int test_wc_Md2Hash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_MD2)
    DIGEST_HASH_ONLY_TEST(Md2, MD2);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Hash */

