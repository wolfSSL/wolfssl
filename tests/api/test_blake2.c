/* test_blake2.c
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

#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_blake2.h>

/*******************************************************************************
 * BLAKE2b
 ******************************************************************************/

int test_wc_InitBlake2b(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;

    /* Test bad arg. */
    ExpectIntEQ(wc_InitBlake2b(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(NULL, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(&blake, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(&blake, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(NULL, WC_BLAKE2B_DIGEST_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_InitBlake2b_WithKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b     blake;
    word32      digestSz = BLAKE2B_KEYBYTES;
    byte        key[BLAKE2B_KEYBYTES];
    word32      keylen = BLAKE2B_KEYBYTES;

    XMEMSET(key, 0, sizeof(key));

    /* Test bad args. */
    ExpectIntEQ(wc_InitBlake2b_WithKey(NULL, digestSz, NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(NULL, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(NULL, digestSz, NULL, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(NULL, digestSz, key, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, NULL, keylen), 0);
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, key, keylen), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2bUpdate(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;

    ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    ExpectIntEQ(wc_Blake2bUpdate(NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2bUpdate(&blake, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2bUpdate(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Blake2bUpdate(&blake, NULL, 0), 0);
    ExpectIntEQ(wc_Blake2bUpdate(&blake, (byte*)"a", 1), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2bFinal(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;
    byte hash[WC_BLAKE2B_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Blake2bFinal(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2bFinal(&blake, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2bFinal(NULL, hash, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Blake2bFinal(&blake, hash, WC_BLAKE2B_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

#define BLAKE2B_KAT_CNT     7
int test_wc_Blake2b_KATs(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;

    testVector blake2b_kat[BLAKE2B_KAT_CNT];
    byte hash[WC_BLAKE2B_DIGEST_SIZE];
    int i = 0;

    blake2b_kat[i].input = "";
    blake2b_kat[i].inLen = 0;
    blake2b_kat[i].output =
        "\x78\x6a\x02\xf7\x42\x01\x59\x03"
        "\xc6\xc6\xfd\x85\x25\x52\xd2\x72"
        "\x91\x2f\x47\x40\xe1\x58\x47\x61"
        "\x8a\x86\xe2\x17\xf7\x1f\x54\x19"
        "\xd2\x5e\x10\x31\xaf\xee\x58\x53"
        "\x13\x89\x64\x44\x93\x4e\xb0\x4b"
        "\x90\x3a\x68\x5b\x14\x48\xb7\x55"
        "\xd5\x6f\x70\x1a\xfe\x9b\xe2\xce";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input = "a";
    blake2b_kat[i].inLen = 1;
    blake2b_kat[i].output =
        "\x33\x3f\xcb\x4e\xe1\xaa\x7c\x11"
        "\x53\x55\xec\x66\xce\xac\x91\x7c"
        "\x8b\xfd\x81\x5b\xf7\x58\x7d\x32"
        "\x5a\xec\x18\x64\xed\xd2\x4e\x34"
        "\xd5\xab\xe2\xc6\xb1\xb5\xee\x3f"
        "\xac\xe6\x2f\xed\x78\xdb\xef\x80"
        "\x2f\x2a\x85\xcb\x91\xd4\x55\xa8"
        "\xf5\x24\x9d\x33\x08\x53\xcb\x3c";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input = "abc";
    blake2b_kat[i].inLen = 3;
    blake2b_kat[i].output =
        "\xba\x80\xa5\x3f\x98\x1c\x4d\x0d"
        "\x6a\x27\x97\xb6\x9f\x12\xf6\xe9"
        "\x4c\x21\x2f\x14\x68\x5a\xc4\xb7"
        "\x4b\x12\xbb\x6f\xdb\xff\xa2\xd1"
        "\x7d\x87\xc5\x39\x2a\xab\x79\x2d"
        "\xc2\x52\xd5\xde\x45\x33\xcc\x95"
        "\x18\xd3\x8a\xa8\xdb\xf1\x92\x5a"
        "\xb9\x23\x86\xed\xd4\x00\x99\x23";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input = "message digest";
    blake2b_kat[i].inLen = 14;
    blake2b_kat[i].output =
        "\x3c\x26\xce\x48\x7b\x1c\x0f\x06"
        "\x23\x63\xaf\xa3\xc6\x75\xeb\xdb"
        "\xf5\xf4\xef\x9b\xdc\x02\x2c\xfb"
        "\xef\x91\xe3\x11\x1c\xdc\x28\x38"
        "\x40\xd8\x33\x1f\xc3\x0a\x8a\x09"
        "\x06\xcf\xf4\xbc\xdb\xcd\x23\x0c"
        "\x61\xaa\xec\x60\xfd\xfa\xd4\x57"
        "\xed\x96\xb7\x09\xa3\x82\x35\x9a";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input = "abcdefghijklmnopqrstuvwxyz";
    blake2b_kat[i].inLen = 26;
    blake2b_kat[i].output =
        "\xc6\x8e\xde\x14\x3e\x41\x6e\xb7"
        "\xb4\xaa\xae\x0d\x8e\x48\xe5\x5d"
        "\xd5\x29\xea\xfe\xd1\x0b\x1d\xf1"
        "\xa6\x14\x16\x95\x3a\x2b\x0a\x56"
        "\x66\xc7\x61\xe7\xd4\x12\xe6\x70"
        "\x9e\x31\xff\xe2\x21\xb7\xa7\xa7"
        "\x39\x08\xcb\x95\xa4\xd1\x20\xb8"
        "\xb0\x90\xa8\x7d\x1f\xbe\xdb\x4c";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789";
    blake2b_kat[i].inLen = 62;
    blake2b_kat[i].output =
        "\x99\x96\x48\x02\xe5\xc2\x5e\x70"
        "\x37\x22\x90\x5d\x3f\xb8\x00\x46"
        "\xb6\xbc\xa6\x98\xca\x9e\x2c\xc7"
        "\xe4\x9b\x4f\xe1\xfa\x08\x7c\x2e"
        "\xdf\x03\x12\xdf\xbb\x27\x5c\xf2"
        "\x50\xa1\xe5\x42\xfd\x5d\xc2\xed"
        "\xd3\x13\xf9\xc4\x91\x12\x7c\x2e"
        "\x8c\x0c\x9b\x24\x16\x8e\x2d\x50";
    blake2b_kat[i].outLen = 0;
    i++;
    blake2b_kat[i].input = "1234567890123456789012345678901234567890"
                           "1234567890123456789012345678901234567890";
    blake2b_kat[i].inLen = 80;
    blake2b_kat[i].output =
        "\x68\x6f\x41\xec\x5a\xff\xf6\xe8"
        "\x7e\x1f\x07\x6f\x54\x2a\xa4\x66"
        "\x46\x6f\xf5\xfb\xde\x16\x2c\x48"
        "\x48\x1b\xa4\x8a\x74\x8d\x84\x27"
        "\x99\xf5\xb3\x0f\x5b\x67\xfc\x68"
        "\x47\x71\xb3\x3b\x99\x42\x06\xd0"
        "\x5c\xc3\x10\xf3\x19\x14\xed\xd7"
        "\xb9\x7e\x41\x86\x0d\x77\xd2\x82";
    blake2b_kat[i].outLen = 0;

    for (i = 0; i < BLAKE2B_KAT_CNT; i++) {
        /* Do KAT. */
        ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);
        ExpectIntEQ(wc_Blake2bUpdate(&blake, (byte*)blake2b_kat[i].input,
            (word32)blake2b_kat[i].inLen), 0);
        ExpectIntEQ(wc_Blake2bFinal(&blake, hash, WC_BLAKE2B_DIGEST_SIZE), 0);
        ExpectBufEQ(hash, (byte*)blake2b_kat[i].output, WC_BLAKE2B_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2b_other(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;
    byte hash[WC_BLAKE2B_DIGEST_SIZE + 1];
    byte data[WC_BLAKE2B_DIGEST_SIZE * 8 + 1];
    int dataLen = WC_BLAKE2B_DIGEST_SIZE * 8;
    const char* expHash =
        "\xfb\xea\x44\x32\x0b\x4a\x40\x44"
        "\xa0\xad\x54\x0c\x39\x62\xa6\x4d"
        "\x2a\xc2\x08\x3f\xce\xb4\x1d\x71"
        "\x77\x04\xa6\xfc\x38\xe5\xd9\x99"
        "\xe6\x92\xf1\x9f\xe7\x21\x10\x94"
        "\xe6\x08\xc1\x9c\x1d\xdf\x87\x11"
        "\xfa\xf4\xe6\x7b\xf1\xe5\xc8\x12"
        "\x55\x90\x05\x00\xfa\x0d\x61\x3d";
    int i;
    int j;

    XMEMSET(data, 0xa5, sizeof(data));

    /* Initialize */
    ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);

    /* Unaligned input and output buffer. */
    ExpectIntEQ(wc_Blake2bUpdate(&blake, data + 1, dataLen), 0);
    ExpectIntEQ(wc_Blake2bFinal(&blake, hash + 1, WC_BLAKE2B_DIGEST_SIZE), 0);
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_BLAKE2B_DIGEST_SIZE);

    /* Test that empty updates work. */
    ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);
    ExpectIntEQ(wc_Blake2bUpdate(&blake, NULL, 0), 0);
    ExpectIntEQ(wc_Blake2bUpdate(&blake, (byte*)"", 0), 0);
    ExpectIntEQ(wc_Blake2bUpdate(&blake, data, dataLen), 0);
    ExpectIntEQ(wc_Blake2bFinal(&blake, hash, WC_BLAKE2B_DIGEST_SIZE), 0);
    ExpectBufEQ(hash, (byte*)expHash, WC_BLAKE2B_DIGEST_SIZE);

    /* Ensure chunking works. */
    for (i = 1; i < dataLen; i++) {
        ExpectIntEQ(wc_InitBlake2b(&blake, WC_BLAKE2B_DIGEST_SIZE), 0);
        for (j = 0; j < dataLen; j += i) {
             int len = dataLen - j;
             if (i < len)
                 len = i;
             ExpectIntEQ(wc_Blake2bUpdate(&blake, data + j, len), 0);
        }
        ExpectIntEQ(wc_Blake2bFinal(&blake, hash, WC_BLAKE2B_DIGEST_SIZE), 0);
        ExpectBufEQ(hash, (byte*)expHash, WC_BLAKE2B_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * BLAKE2s
 ******************************************************************************/

int test_wc_InitBlake2s(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s blake;

    /* Test bad arg. */
    ExpectIntEQ(wc_InitBlake2s(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s(NULL, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s(&blake, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s(&blake, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s(NULL, WC_BLAKE2S_DIGEST_SIZE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_InitBlake2s_WithKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s     blake;
    word32      digestSz = BLAKE2S_KEYBYTES;
    byte        *key = (byte*)"01234567890123456789012345678901";
    word32      keylen = BLAKE2S_KEYBYTES;

    /* Test bad args. */
    ExpectIntEQ(wc_InitBlake2s_WithKey(NULL, digestSz, NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, NULL, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(NULL, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(NULL, digestSz, NULL, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(NULL, digestSz, key, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, NULL, keylen), 0);
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, key, keylen), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2sUpdate(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s blake;

    ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    ExpectIntEQ(wc_Blake2sUpdate(NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2sUpdate(&blake, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2sUpdate(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Blake2sUpdate(&blake, NULL, 0), 0);
    ExpectIntEQ(wc_Blake2sUpdate(&blake, (byte*)"a", 1), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2sFinal(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s blake;
    byte hash[WC_BLAKE2S_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Blake2sFinal(NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2sFinal(&blake, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Blake2sFinal(NULL, hash, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Blake2sFinal(&blake, hash, WC_BLAKE2S_DIGEST_SIZE), 0);
#endif
    return EXPECT_RESULT();
}

#define BLAKE2S_KAT_CNT     7
int test_wc_Blake2s_KATs(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s blake;

    testVector blake2s_kat[BLAKE2S_KAT_CNT];
    byte hash[WC_BLAKE2S_DIGEST_SIZE];
    int i = 0;

    blake2s_kat[i].input = "";
    blake2s_kat[i].inLen = 0;
    blake2s_kat[i].output =
        "\x69\x21\x7a\x30\x79\x90\x80\x94"
        "\xe1\x11\x21\xd0\x42\x35\x4a\x7c"
        "\x1f\x55\xb6\x48\x2c\xa1\xa5\x1e"
        "\x1b\x25\x0d\xfd\x1e\xd0\xee\xf9";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input = "a";
    blake2s_kat[i].inLen = 1;
    blake2s_kat[i].output =
        "\x4a\x0d\x12\x98\x73\x40\x30\x37"
        "\xc2\xcd\x9b\x90\x48\x20\x36\x87"
        "\xf6\x23\x3f\xb6\x73\x89\x56\xe0"
        "\x34\x9b\xd4\x32\x0f\xec\x3e\x90";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input = "abc";
    blake2s_kat[i].inLen = 3;
    blake2s_kat[i].output =
        "\x50\x8c\x5e\x8c\x32\x7c\x14\xe2"
        "\xe1\xa7\x2b\xa3\x4e\xeb\x45\x2f"
        "\x37\x45\x8b\x20\x9e\xd6\x3a\x29"
        "\x4d\x99\x9b\x4c\x86\x67\x59\x82";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input = "message digest";
    blake2s_kat[i].inLen = 14;
    blake2s_kat[i].output =
        "\xfa\x10\xab\x77\x5a\xcf\x89\xb7"
        "\xd3\xc8\xa6\xe8\x23\xd5\x86\xf6"
        "\xb6\x7b\xdb\xac\x4c\xe2\x07\xfe"
        "\x14\x5b\x7d\x3a\xc2\x5c\xd2\x8c";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input = "abcdefghijklmnopqrstuvwxyz";
    blake2s_kat[i].inLen = 26;
    blake2s_kat[i].output =
        "\xbd\xf8\x8e\xb1\xf8\x6a\x0c\xdf"
        "\x0e\x84\x0b\xa8\x8f\xa1\x18\x50"
        "\x83\x69\xdf\x18\x6c\x73\x55\xb4"
        "\xb1\x6c\xf7\x9f\xa2\x71\x0a\x12";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789";
    blake2s_kat[i].inLen = 62;
    blake2s_kat[i].output =
        "\xc7\x54\x39\xea\x17\xe1\xde\x6f"
        "\xa4\x51\x0c\x33\x5d\xc3\xd3\xf3"
        "\x43\xe6\xf9\xe1\xce\x27\x73\xe2"
        "\x5b\x41\x74\xf1\xdf\x8b\x11\x9b";
    blake2s_kat[i].outLen = 0;
    i++;
    blake2s_kat[i].input = "1234567890123456789012345678901234567890"
                           "1234567890123456789012345678901234567890";
    blake2s_kat[i].inLen = 80;
    blake2s_kat[i].output =
        "\xfd\xae\xdb\x29\x0a\x0d\x5a\xf9"
        "\x87\x08\x64\xfe\xc2\xe0\x90\x20"
        "\x09\x89\xdc\x9c\xd5\x3a\x3c\x09"
        "\x21\x29\xe8\x53\x5e\x8b\x4f\x66";
    blake2s_kat[i].outLen = 0;

    for (i = 0; i < BLAKE2S_KAT_CNT; i++) {
        /* Do KAT. */
        ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);
        ExpectIntEQ(wc_Blake2sUpdate(&blake, (byte*)blake2s_kat[i].input,
            (word32)blake2s_kat[i].inLen), 0);
        ExpectIntEQ(wc_Blake2sFinal(&blake, hash, WC_BLAKE2S_DIGEST_SIZE), 0);
        ExpectBufEQ(hash, (byte*)blake2s_kat[i].output, WC_BLAKE2S_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

int test_wc_Blake2s_other(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s blake;
    byte hash[WC_BLAKE2S_DIGEST_SIZE + 1];
    byte data[WC_BLAKE2S_DIGEST_SIZE * 8 + 1];
    int dataLen = WC_BLAKE2S_DIGEST_SIZE * 8;
    const char* expHash =
        "\x30\x1c\x41\x93\xd0\x63\x99\xeb"
        "\x17\x68\x7a\xfb\xba\x58\x47\x33"
        "\xad\x62\xea\x91\x77\x20\xf0\x72"
        "\x11\xe3\x9e\x29\xe9\xc8\x24\x59";
    int i;
    int j;

    XMEMSET(data, 0xa5, sizeof(data));

    /* Initialize */
    ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);

    /* Unaligned input and output buffer. */
    ExpectIntEQ(wc_Blake2sUpdate(&blake, data + 1, dataLen), 0);
    ExpectIntEQ(wc_Blake2sFinal(&blake, hash + 1, WC_BLAKE2S_DIGEST_SIZE), 0);
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_BLAKE2S_DIGEST_SIZE);

    /* Test that empty updates work. */
    ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);
    ExpectIntEQ(wc_Blake2sUpdate(&blake, NULL, 0), 0);
    ExpectIntEQ(wc_Blake2sUpdate(&blake, (byte*)"", 0), 0);
    ExpectIntEQ(wc_Blake2sUpdate(&blake, data, dataLen), 0);
    ExpectIntEQ(wc_Blake2sFinal(&blake, hash, WC_BLAKE2S_DIGEST_SIZE), 0);
    ExpectBufEQ(hash, (byte*)expHash, WC_BLAKE2S_DIGEST_SIZE);

    /* Ensure chunking works. */
    for (i = 1; i < dataLen; i++) {
        ExpectIntEQ(wc_InitBlake2s(&blake, WC_BLAKE2S_DIGEST_SIZE), 0);
        for (j = 0; j < dataLen; j += i) {
             int len = dataLen - j;
             if (i < len)
                 len = i;
             ExpectIntEQ(wc_Blake2sUpdate(&blake, data + j, len), 0);
        }
        ExpectIntEQ(wc_Blake2sFinal(&blake, hash, WC_BLAKE2S_DIGEST_SIZE), 0);
        ExpectBufEQ(hash, (byte*)expHash, WC_BLAKE2S_DIGEST_SIZE);
    }
#endif
    return EXPECT_RESULT();
}

