/* test_sm3.c
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

#include <wolfssl/wolfcrypt/sm3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sm3.h>
#include <tests/api/test_digest.h>


int test_wc_InitSm3(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;

    /* Test bad arg. */
    ExpectIntEQ(wc_InitSm3(NULL, HEAP_HINT, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good arg. */
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);
    wc_Sm3Free(&sm3);

    wc_Sm3Free(NULL);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;

    /* Initialize */
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    /* Pass in bad values. */
    ExpectIntEQ(wc_Sm3Update(NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Update(&sm3, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Update(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Sm3Update(&sm3, NULL, 0), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, (byte*)"a", 1), 0);

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;
    byte hash[WC_SM3_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sm3Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Final(&sm3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    wc_Sm3 sm3;
    byte hash[WC_SM3_DIGEST_SIZE];
    const char* expHash =
        "\x73\x80\x16\x6f\x49\x14\xb2\xb9"
        "\x17\x24\x42\xd7\xda\x8a\x06\x00"
        "\xa9\x6f\x30\xbc\x16\x31\x38\xaa"
        "\xe3\x8d\xee\x4d\xb0\xfb\x0e\x4e";

    /* Initialize */
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sm3FinalRaw(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3FinalRaw(&sm3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3FinalRaw(NULL, hash),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test good args. */
    ExpectIntEQ(wc_Sm3FinalRaw(&sm3, hash), 0);
    ExpectBufEQ(hash, expHash, WC_SM3_DIGEST_SIZE);

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

#define SM3_KAT_CNT     7
int test_wc_Sm3_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;

    testVector sm3_kat[SM3_KAT_CNT];
    byte hash[WC_SM3_DIGEST_SIZE];
    int i = 0;

    sm3_kat[i].input = "";
    sm3_kat[i].inLen = 0;
    sm3_kat[i].output =
        "\x1a\xb2\x1d\x83\x55\xcf\xa1\x7f"
        "\x8e\x61\x19\x48\x31\xe8\x1a\x8f"
        "\x22\xbe\xc8\xc7\x28\xfe\xfb\x74"
        "\x7e\xd0\x35\xeb\x50\x82\xaa\x2b";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input = "a";
    sm3_kat[i].inLen = 1;
    sm3_kat[i].output =
        "\x62\x34\x76\xac\x18\xf6\x5a\x29"
        "\x09\xe4\x3c\x7f\xec\x61\xb4\x9c"
        "\x7e\x76\x4a\x91\xa1\x8c\xcb\x82"
        "\xf1\x91\x7a\x29\xc8\x6c\x5e\x88";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input = "abc";
    sm3_kat[i].inLen = 3;
    sm3_kat[i].output =
        "\x66\xc7\xf0\xf4\x62\xee\xed\xd9"
        "\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
        "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2"
        "\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input = "message digest";
    sm3_kat[i].inLen = 14;
    sm3_kat[i].output =
        "\xc5\x22\xa9\x42\xe8\x9b\xd8\x0d"
        "\x97\xdd\x66\x6e\x7a\x55\x31\xb3"
        "\x61\x88\xc9\x81\x71\x49\xe9\xb2"
        "\x58\xdf\xe5\x1e\xce\x98\xed\x77";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input = "abcdefghijklmnopqrstuvwxyz";
    sm3_kat[i].inLen = 26;
    sm3_kat[i].output =
        "\xb8\x0f\xe9\x7a\x4d\xa2\x4a\xfc"
        "\x27\x75\x64\xf6\x6a\x35\x9e\xf4"
        "\x40\x46\x2a\xd2\x8d\xcc\x6d\x63"
        "\xad\xb2\x4d\x5c\x20\xa6\x15\x95";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789";
    sm3_kat[i].inLen = 62;
    sm3_kat[i].output =
        "\x29\x71\xd1\x0c\x88\x42\xb7\x0c"
        "\x97\x9e\x55\x06\x34\x80\xc5\x0b"
        "\xac\xff\xd9\x0e\x98\xe2\xe6\x0d"
        "\x25\x12\xab\x8a\xbf\xdf\xce\xc5";
    sm3_kat[i].outLen = 0;
    i++;
    sm3_kat[i].input = "1234567890123456789012345678901234567890"
                           "1234567890123456789012345678901234567890";
    sm3_kat[i].inLen = 80;
    sm3_kat[i].output =
        "\xad\x81\x80\x53\x21\xf3\xe6\x9d"
        "\x25\x12\x35\xbf\x88\x6a\x56\x48"
        "\x44\x87\x3b\x56\xdd\x7d\xde\x40"
        "\x0f\x05\x5b\x7d\xde\x39\x30\x7a";
    sm3_kat[i].outLen = 0;

    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    for (i = 0; i < SM3_KAT_CNT; i++) {
        /* Do KAT. */
        ExpectIntEQ(wc_Sm3Update(&sm3, (byte*)sm3_kat[i].input,
            (word32)sm3_kat[i].inLen), 0);
        ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
        ExpectBufEQ(hash, (byte*)sm3_kat[i].output, WC_SM3_DIGEST_SIZE);
    }

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;
    byte hash[WC_SM3_DIGEST_SIZE + 1];
    byte data[WC_SM3_DIGEST_SIZE * 8 + 1];
    int dataLen = WC_SM3_DIGEST_SIZE * 8;
    const char* expHash =
        "\x76\x6e\x30\x64\x3f\x02\x26\x7f"
        "\xb1\x94\x26\xd4\x41\xd1\xed\x87"
        "\x40\x5a\x58\xa5\xaa\x65\xd6\x61"
        "\xe9\x95\xcc\x5d\xdd\xe8\x49\x34";
    int i;
    int j;

    XMEMSET(data, 0xa5, sizeof(data));

    /* Initialize */
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    /* Unaligned input and output buffer. */
    ExpectIntEQ(wc_Sm3Update(&sm3, data + 1, dataLen), 0);
    ExpectIntEQ(wc_Sm3Final(&sm3, hash + 1), 0);
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_SM3_DIGEST_SIZE);

    /* Test that empty updates work. */
    ExpectIntEQ(wc_Sm3Update(&sm3, NULL, 0), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, (byte*)"", 0), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, dataLen), 0);
    ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
    ExpectBufEQ(hash, (byte*)expHash, WC_SM3_DIGEST_SIZE);

    /* Ensure chunking works. */
    for (i = 1; i < dataLen; i++) {
        for (j = 0; j < dataLen; j += i) {
             int len = dataLen - j;
             if (i < len)
                 len = i;
             ExpectIntEQ(wc_Sm3Update(&sm3, data + j, len), 0);
        }
        ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
        ExpectBufEQ(hash, (byte*)expHash, WC_SM3_DIGEST_SIZE);
    }

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 src;
    wc_Sm3 dst;
    byte hashSrc[WC_SM3_DIGEST_SIZE];
    byte hashDst[WC_SM3_DIGEST_SIZE];
    const char* emptyHash =
        "\x1a\xb2\x1d\x83\x55\xcf\xa1\x7f"
        "\x8e\x61\x19\x48\x31\xe8\x1a\x8f"
        "\x22\xbe\xc8\xc7\x28\xfe\xfb\x74"
        "\x7e\xd0\x35\xeb\x50\x82\xaa\x2b";
    const char* abcHash =
        "\x66\xc7\xf0\xf4\x62\xee\xed\xd9"
        "\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
        "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2"
        "\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0";
    byte data[WC_SM3_BLOCK_SIZE];

    XMEMSET(data, 0xa5, sizeof(data));

    ExpectIntEQ(wc_InitSm3(&src, HEAP_HINT, INVALID_DEVID), 0);
    XMEMSET(&dst, 0, sizeof(dst));

    ExpectIntEQ(wc_Sm3Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Copy(&src, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Copy(NULL, &dst), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test copy works. */
    ExpectIntEQ(wc_Sm3Copy(&src, &dst), 0);
    ExpectIntEQ(wc_Sm3Final(&src, hashSrc), 0);
    ExpectIntEQ(wc_Sm3Final(&dst, hashDst), 0);
    ExpectBufEQ(hashSrc, emptyHash, WC_SM3_DIGEST_SIZE);
    ExpectBufEQ(hashDst, emptyHash, WC_SM3_DIGEST_SIZE);
    wc_Sm3Free(&dst);

    /* Test buffered data is copied. */
    ExpectIntEQ(wc_Sm3Update(&src, (byte*)"abc", 3), 0);
    ExpectIntEQ(wc_Sm3Copy(&src, &dst), 0);
    ExpectIntEQ(wc_Sm3Final(&src, hashSrc), 0);
    ExpectIntEQ(wc_Sm3Final(&dst, hashDst), 0);
    ExpectBufEQ(hashSrc, abcHash, WC_SM3_DIGEST_SIZE);
    ExpectBufEQ(hashDst, abcHash, WC_SM3_DIGEST_SIZE);
    wc_Sm3Free(&dst);

    /* Test count of length is copied. */
    ExpectIntEQ(wc_Sm3Update(&src, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Sm3Copy(&src, &dst), 0);
    ExpectIntEQ(wc_Sm3Final(&src, hashSrc), 0);
    ExpectIntEQ(wc_Sm3Final(&dst, hashDst), 0);
    ExpectBufEQ(hashSrc, hashDst, WC_SM3_DIGEST_SIZE);
    wc_Sm3Free(&dst);

    wc_Sm3Free(&src);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sm3GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;
    byte hash[WC_SM3_DIGEST_SIZE];
    const char* emptyHash =
        "\x1a\xb2\x1d\x83\x55\xcf\xa1\x7f"
        "\x8e\x61\x19\x48\x31\xe8\x1a\x8f"
        "\x22\xbe\xc8\xc7\x28\xfe\xfb\x74"
        "\x7e\xd0\x35\xeb\x50\x82\xaa\x2b";
    const char* abcHash =
        "\x66\xc7\xf0\xf4\x62\xee\xed\xd9"
        "\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
        "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2"
        "\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0";

    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    ExpectIntEQ(wc_Sm3GetHash(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3GetHash(&sm3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3GetHash(NULL, hash),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Sm3GetHash(&sm3, hash), 0);
    ExpectBufEQ(hash, emptyHash, WC_SM3_DIGEST_SIZE);
    /* Test that the hash state hasn't been modified. */
    ExpectIntEQ(wc_Sm3Update(&sm3, (byte*)"abc", 3), 0);
    ExpectIntEQ(wc_Sm3GetHash(&sm3, hash), 0);
    ExpectBufEQ(hash, abcHash, WC_SM3_DIGEST_SIZE);

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}


int test_wc_Sm3_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sm3 sm3;
    wc_Sm3 sm3_copy;
    word32 flags;

    XMEMSET(&sm3_copy, 0, sizeof(sm3_copy));
    ExpectIntEQ(wc_InitSm3(&sm3, HEAP_HINT, INVALID_DEVID), 0);

    /* Do nothing. */
    ExpectIntEQ(wc_Sm3GetFlags(NULL, NULL), 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3, NULL), 0);
    ExpectIntEQ(wc_Sm3GetFlags(NULL, &flags), 0);
    ExpectIntEQ(wc_Sm3SetFlags(NULL, 1), 0);

    ExpectIntEQ(wc_Sm3GetFlags(&sm3, &flags), 0);
    ExpectIntEQ(flags, 0);

    ExpectIntEQ(wc_Sm3Copy(&sm3, &sm3_copy), 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3, &flags), 0);
    ExpectIntEQ(flags, 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3_copy, &flags), 0);
    ExpectIntEQ(flags, WC_HASH_FLAG_ISCOPY);

    ExpectIntEQ(wc_Sm3SetFlags(&sm3, WC_HASH_FLAG_WILLCOPY), 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3, &flags), 0);
    ExpectIntEQ(flags, WC_HASH_FLAG_WILLCOPY);
    ExpectIntEQ(wc_Sm3SetFlags(&sm3, 0), 0);

    wc_Sm3Free(&sm3_copy);
    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}

