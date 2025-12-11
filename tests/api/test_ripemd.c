/* test_ripemd.c
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

#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ripemd.h>
#include <tests/api/test_digest.h>

/*
 * Testing wc_InitRipeMd()
 */
int test_wc_InitRipeMd(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;

    /* Test bad arg. */
    ExpectIntEQ(wc_InitRipeMd(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);
#endif
    return EXPECT_RESULT();

} /* END test_wc_InitRipeMd */

/*
 * Testing wc_RipeMdUpdate()
 */
int test_wc_RipeMdUpdate(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;

    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);

    /* Test bad arg. */
    ExpectIntEQ(wc_RipeMdUpdate(NULL   , NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdUpdate(NULL   , NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, NULL, 0), 0);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)"a", 1), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RipeMdUdpate */

/*
 * Unit test function for wc_RipeMdFinal()
 */
int test_wc_RipeMdFinal(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;
    byte hash[RIPEMD_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_RipeMdFinal(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdFinal(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);
#endif
    return EXPECT_RESULT();
} /* END test_wc_RipeMdFinal */

#define RIPEMD_KAT_CNT  7
int test_wc_RipeMd_KATs( void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;
    testVector ripemd_kat[RIPEMD_KAT_CNT];
    byte hash[RIPEMD_DIGEST_SIZE];
    int i = 0;

    ripemd_kat[i].input = "";
    ripemd_kat[i].inLen = 0;
    ripemd_kat[i].output =
        "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54"
        "\x61\x28\x08\x97\x7e\xe8\xf5\x48"
        "\xb2\x25\x8d\x31";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input = "a";
    ripemd_kat[i].inLen = 1;
    ripemd_kat[i].output =
        "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9"
        "\xda\xae\x34\x7b\xe6\xf4\xdc\x83"
        "\x5a\x46\x7f\xfe";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input = "abc";
    ripemd_kat[i].inLen = 3;
    ripemd_kat[i].output =
        "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a"
        "\x9b\x04\x4a\x8e\x98\xc6\xb0\x87"
        "\xf1\x5a\x0b\xfc";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input = "message digest";
    ripemd_kat[i].inLen = 14;
    ripemd_kat[i].output =
        "\x5d\x06\x89\xef\x49\xd2\xfa\xe5"
        "\x72\xb8\x81\xb1\x23\xa8\x5f\xfa"
        "\x21\x59\x5f\x36";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input = "abcdefghijklmnopqrstuvwxyz";
    ripemd_kat[i].inLen = 26;
    ripemd_kat[i].output =
        "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b"
        "\x56\xbb\xdc\xeb\x5b\x9d\x28\x65"
        "\xb3\x70\x8d\xbc";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789";
    ripemd_kat[i].inLen = 62;
    ripemd_kat[i].output =
        "\xb0\xe2\x0b\x6e\x31\x16\x64\x02"
        "\x86\xed\x3a\x87\xa5\x71\x30\x79"
        "\xb2\x1f\x51\x89";
    ripemd_kat[i].outLen = 0;
    i++;
    ripemd_kat[i].input = "1234567890123456789012345678901234567890"
                           "1234567890123456789012345678901234567890";
    ripemd_kat[i].inLen = 80;
    ripemd_kat[i].output =
        "\x9b\x75\x2e\x45\x57\x3d\x4b\x39"
        "\xf4\xdb\xd3\x32\x3c\xab\x82\xbf"
        "\x63\x32\x6b\xfb";
    ripemd_kat[i].outLen = 0;

    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);
    for (i = 0; i < RIPEMD_KAT_CNT; i++) {
        /* Do KAT. */
        ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)ripemd_kat[i].input,
            (word32)ripemd_kat[i].inLen), 0);
        ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);
        ExpectBufEQ(hash, (byte*)ripemd_kat[i].output, RIPEMD_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_RipeMd_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;
    byte hash[RIPEMD_DIGEST_SIZE + 1];
    byte data[RIPEMD_DIGEST_SIZE * 8 + 1];
    int dataLen = RIPEMD_DIGEST_SIZE * 8;
    const char* expHash =
        "\x11\x8f\x4f\x23\xa9\xc2\xcb\x04"
        "\x10\x10\xbb\x44\x5a\x1d\xfb\x17"
        "\x6b\x68\x09\xb4";
    int i;
    int j;

    XMEMSET(data, 0xa5, sizeof(data));

    /* Initialize */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);

    /* Unaligned input and output buffer. */
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, data + 1, dataLen), 0);
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash + 1), 0);
    ExpectBufEQ(hash + 1, (byte*)expHash, RIPEMD_DIGEST_SIZE);

    /* Test that empty updates work. */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, NULL, 0), 0);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)"", 0), 0);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, data, dataLen), 0);
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);
    ExpectBufEQ(hash, (byte*)expHash, RIPEMD_DIGEST_SIZE);

    /* Ensure chunking works. */
    for (i = 1; i < dataLen; i++) {
        ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);
        for (j = 0; j < dataLen; j += i) {
             int len = dataLen - j;
             if (i < len)
                 len = i;
             ExpectIntEQ(wc_RipeMdUpdate(&ripemd, data + j, len), 0);
        }
        ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);
        ExpectBufEQ(hash, (byte*)expHash, RIPEMD_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

