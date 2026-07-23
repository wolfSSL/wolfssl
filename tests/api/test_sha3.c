/* test_sha3.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sha3.h>
#include <tests/api/test_digest.h>

#if defined(HAVE_SELFTEST) || (defined(HAVE_FIPS) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 3)))
    #define WC_SHA3_128_BLOCK_SIZE  168
    #define WC_SHA3_224_BLOCK_SIZE  144
    #define WC_SHA3_256_BLOCK_SIZE  136
    #define WC_SHA3_384_BLOCK_SIZE  104
    #define WC_SHA3_512_BLOCK_SIZE  72
#endif

/*******************************************************************************
 * SHA-3
 ******************************************************************************/

#define SHA3_KATS_TEST(name, upper)                                            \
    (void)i;                                                                   \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    for (i = 0; i < upper##_KAT_CNT; i++) {                                    \
        /* Do KAT. */                                                          \
        ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)dgst_kat[i].input,        \
            (word32)dgst_kat[i].inLen), 0);                                    \
        ExpectIntEQ(wc_##name##_Final(&dgst, hash), 0);                        \
        ExpectBufEQ(hash, (byte*)dgst_kat[i].output,                           \
            WC_##upper##_DIGEST_SIZE);                                         \
    }                                                                          \
                                                                               \
    wc_##name##_Free(&dgst)

#define SHA3_GET_HASH_TEST(name, upper, emptyHashStr, abcHashStr)              \
do {                                                                           \
    wc_Sha3 dgst;                                                              \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
    const char* emptyHash = emptyHashStr;                                      \
    const char* abcHash = abcHashStr;                                          \
                                                                               \
    XMEMSET(&dgst, 0, sizeof(dgst));                                           \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    ExpectIntEQ(wc_##name##_GetHash(NULL, NULL),                               \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_GetHash(&dgst, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_GetHash(NULL, hash),                               \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##_GetHash(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, emptyHash, WC_##upper##_DIGEST_SIZE);                    \
    /* Test that the hash state hasn't been modified. */                       \
    ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)"abc", 3), 0);                \
    ExpectIntEQ(wc_##name##_GetHash(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, abcHash, WC_##upper##_DIGEST_SIZE);                      \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)


int test_wc_InitSha3(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    DIGEST_INIT_TEST(wc_Sha3, Sha3_224);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    DIGEST_INIT_TEST(wc_Sha3, Sha3_256);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    DIGEST_INIT_TEST(wc_Sha3, Sha3_384);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    DIGEST_INIT_TEST(wc_Sha3, Sha3_512);
    #endif
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    DIGEST_ALT_UPDATE_TEST(wc_Sha3, Sha3_224);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    DIGEST_ALT_UPDATE_TEST(wc_Sha3, Sha3_256);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    DIGEST_ALT_UPDATE_TEST(wc_Sha3, Sha3_384);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    DIGEST_ALT_UPDATE_TEST(wc_Sha3, Sha3_512);
    #endif
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
    DIGEST_ALT_FINAL_TEST(wc_Sha3, Sha3_224, SHA3_224);
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    DIGEST_ALT_FINAL_TEST(wc_Sha3, Sha3_256, SHA3_256);
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    DIGEST_ALT_FINAL_TEST(wc_Sha3, Sha3_384, SHA3_384);
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    DIGEST_ALT_FINAL_TEST(wc_Sha3, Sha3_512, SHA3_512);
    #endif
#endif
    return EXPECT_RESULT();
}

#define SHA3_224_KAT_CNT    7
int test_wc_Sha3_224_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_224)
    DIGEST_KATS_TEST_VARS(wc_Sha3, SHA3_224);

    DIGEST_KATS_ADD("", 0,
        "\x6b\x4e\x03\x42\x36\x67\xdb\xb7"
        "\x3b\x6e\x15\x45\x4f\x0e\xb1\xab"
        "\xd4\x59\x7f\x9a\x1b\x07\x8e\x3f"
        "\x5b\x5a\x6b\xc7");
    DIGEST_KATS_ADD("a", 1,
        "\x9e\x86\xff\x69\x55\x7c\xa9\x5f"
        "\x40\x5f\x08\x12\x69\x68\x5b\x38"
        "\xe3\xa8\x19\xb3\x09\xee\x94\x2f"
        "\x48\x2b\x6a\x8b");
    DIGEST_KATS_ADD("abc", 3,
        "\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a"
        "\xd0\x92\x34\xee\x7d\x3c\x76\x6f"
        "\xc9\xa3\xa5\x16\x8d\x0c\x94\xad"
        "\x73\xb4\x6f\xdf");
    DIGEST_KATS_ADD("message digest", 14,
        "\x18\x76\x8b\xb4\xc4\x8e\xb7\xfc"
        "\x88\xe5\xdd\xb1\x7e\xfc\xf2\x96"
        "\x4a\xbd\x77\x98\xa3\x9d\x86\xa4"
        "\xb4\xa1\xe4\xc8");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x5c\xde\xca\x81\xe1\x23\xf8\x7c"
        "\xad\x96\xb9\xcb\xa9\x99\xf1\x6f"
        "\x6d\x41\x54\x96\x08\xd4\xe0\xf4"
        "\x68\x1b\x82\x39");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xa6\x7c\x28\x9b\x82\x50\xa6\xf4"
        "\x37\xa2\x01\x37\x98\x5d\x60\x55"
        "\x89\xa8\xc1\x63\xd4\x52\x61\xb1"
        "\x54\x19\x55\x6e");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x05\x26\x89\x8e\x18\x58\x69\xf9"
        "\x1b\x3e\x2a\x76\xdd\x72\xa1\x5d"
        "\xc6\x94\x0a\x67\xc8\x16\x4a\x04"
        "\x4c\xd2\x5c\xc8");

    SHA3_KATS_TEST(Sha3_224, SHA3_224);
#endif
    return EXPECT_RESULT();
}

#define SHA3_256_KAT_CNT    7
int test_wc_Sha3_256_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    DIGEST_KATS_TEST_VARS(wc_Sha3, SHA3_256);

    DIGEST_KATS_ADD("", 0,
        "\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66"
        "\x51\xc1\x47\x56\xa0\x61\xd6\x62"
        "\xf5\x80\xff\x4d\xe4\x3b\x49\xfa"
        "\x82\xd8\x0a\x4b\x80\xf8\x43\x4a");
    DIGEST_KATS_ADD("a", 1,
        "\x80\x08\x4b\xf2\xfb\xa0\x24\x75"
        "\x72\x6f\xeb\x2c\xab\x2d\x82\x15"
        "\xea\xb1\x4b\xc6\xbd\xd8\xbf\xb2"
        "\xc8\x15\x12\x57\x03\x2e\xcd\x8b");
    DIGEST_KATS_ADD("abc", 3,
        "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2"
        "\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
        "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b"
        "\x46\xbf\xe2\x45\x11\x43\x15\x32");
    DIGEST_KATS_ADD("message digest", 14,
        "\xed\xcd\xb2\x06\x93\x66\xe7\x52"
        "\x43\x86\x0c\x18\xc3\xa1\x14\x65"
        "\xec\xa3\x4b\xce\x61\x43\xd3\x0c"
        "\x86\x65\xce\xfc\xfd\x32\xbf\xfd");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x7c\xab\x2d\xc7\x65\xe2\x1b\x24"
        "\x1d\xbc\x1c\x25\x5c\xe6\x20\xb2"
        "\x9f\x52\x7c\x6d\x5e\x7f\x5f\x84"
        "\x3e\x56\x28\x8f\x0d\x70\x75\x21");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xa7\x9d\x6a\x9d\xa4\x7f\x04\xa3"
        "\xb9\xa9\x32\x3e\xc9\x99\x1f\x21"
        "\x05\xd4\xc7\x8a\x7b\xc7\xbe\xeb"
        "\x10\x38\x55\xa7\xa1\x1d\xfb\x9f");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x29\x3e\x5c\xe4\xce\x54\xee\x71"
        "\x99\x0a\xb0\x6e\x51\x1b\x7c\xcd"
        "\x62\x72\x2b\x1b\xeb\x41\x4f\x5f"
        "\xf6\x5c\x82\x74\xe0\xf5\xbe\x1d");

    SHA3_KATS_TEST(Sha3_256, SHA3_256);
#endif
    return EXPECT_RESULT();
}

#define SHA3_384_KAT_CNT    7
int test_wc_Sha3_384_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_384)
    DIGEST_KATS_TEST_VARS(wc_Sha3, SHA3_384);

    DIGEST_KATS_ADD("", 0,
        "\x0c\x63\xa7\x5b\x84\x5e\x4f\x7d"
        "\x01\x10\x7d\x85\x2e\x4c\x24\x85"
        "\xc5\x1a\x50\xaa\xaa\x94\xfc\x61"
        "\x99\x5e\x71\xbb\xee\x98\x3a\x2a"
        "\xc3\x71\x38\x31\x26\x4a\xdb\x47"
        "\xfb\x6b\xd1\xe0\x58\xd5\xf0\x04");
    DIGEST_KATS_ADD("a", 1,
        "\x18\x15\xf7\x74\xf3\x20\x49\x1b"
        "\x48\x56\x9e\xfe\xc7\x94\xd2\x49"
        "\xee\xb5\x9a\xae\x46\xd2\x2b\xf7"
        "\x7d\xaf\xe2\x5c\x5e\xdc\x28\xd7"
        "\xea\x44\xf9\x3e\xe1\x23\x4a\xa8"
        "\x8f\x61\xc9\x19\x12\xa4\xcc\xd9");
    DIGEST_KATS_ADD("abc", 3,
        "\xec\x01\x49\x82\x88\x51\x6f\xc9"
        "\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
        "\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25"
        "\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
        "\x98\xd8\x8c\xea\x92\x7a\xc7\xf5"
        "\x39\xf1\xed\xf2\x28\x37\x6d\x25");
    DIGEST_KATS_ADD("message digest", 14,
        "\xd9\x51\x97\x09\xf4\x4a\xf7\x3e"
        "\x2c\x8e\x29\x11\x09\xa9\x79\xde"
        "\x3d\x61\xdc\x02\xbf\x69\xde\xf7"
        "\xfb\xff\xdf\xff\xe6\x62\x75\x15"
        "\x13\xf1\x9a\xd5\x7e\x17\xd4\xb9"
        "\x3b\xa1\xe4\x84\xfc\x19\x80\xd5");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xfe\xd3\x99\xd2\x21\x7a\xaf\x4c"
        "\x71\x7a\xd0\xc5\x10\x2c\x15\x58"
        "\x9e\x1c\x99\x0c\xc2\xb9\xa5\x02"
        "\x90\x56\xa7\xf7\x48\x58\x88\xd6"
        "\xab\x65\xdb\x23\x70\x07\x7a\x5c"
        "\xad\xb5\x3f\xc9\x28\x0d\x27\x8f");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xd5\xb9\x72\x30\x2f\x50\x80\xd0"
        "\x83\x0e\x0d\xe7\xb6\xb2\xcf\x38"
        "\x36\x65\xa0\x08\xf4\xc4\xf3\x86"
        "\xa6\x11\x12\x65\x2c\x74\x2d\x20"
        "\xcb\x45\xaa\x51\xbd\x4f\x54\x2f"
        "\xc7\x33\xe2\x71\x9e\x99\x92\x91");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x3c\x21\x3a\x17\xf5\x14\x63\x8a"
        "\xcb\x3b\xf1\x7f\x10\x9f\x3e\x24"
        "\xc1\x6f\x9f\x14\xf0\x85\xb5\x2a"
        "\x2f\x2b\x81\xad\xc0\xdb\x83\xdf"
        "\x1a\x58\xdb\x2c\xe0\x13\x19\x1b"
        "\x8b\xa7\x2d\x8f\xae\x7e\x2a\x5e");

    SHA3_KATS_TEST(Sha3_384, SHA3_384);
#endif
    return EXPECT_RESULT();
}

#define SHA3_512_KAT_CNT    7
int test_wc_Sha3_512_KATs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_512)
    DIGEST_KATS_TEST_VARS(wc_Sha3, SHA3_512);

    DIGEST_KATS_ADD("", 0,
        "\xa6\x9f\x73\xcc\xa2\x3a\x9a\xc5"
        "\xc8\xb5\x67\xdc\x18\x5a\x75\x6e"
        "\x97\xc9\x82\x16\x4f\xe2\x58\x59"
        "\xe0\xd1\xdc\xc1\x47\x5c\x80\xa6"
        "\x15\xb2\x12\x3a\xf1\xf5\xf9\x4c"
        "\x11\xe3\xe9\x40\x2c\x3a\xc5\x58"
        "\xf5\x00\x19\x9d\x95\xb6\xd3\xe3"
        "\x01\x75\x85\x86\x28\x1d\xcd\x26");
    DIGEST_KATS_ADD("a", 1,
        "\x69\x7f\x2d\x85\x61\x72\xcb\x83"
        "\x09\xd6\xb8\xb9\x7d\xac\x4d\xe3"
        "\x44\xb5\x49\xd4\xde\xe6\x1e\xdf"
        "\xb4\x96\x2d\x86\x98\xb7\xfa\x80"
        "\x3f\x4f\x93\xff\x24\x39\x35\x86"
        "\xe2\x8b\x5b\x95\x7a\xc3\xd1\xd3"
        "\x69\x42\x0c\xe5\x33\x32\x71\x2f"
        "\x99\x7b\xd3\x36\xd0\x9a\xb0\x2a");
    DIGEST_KATS_ADD("abc", 3,
        "\xb7\x51\x85\x0b\x1a\x57\x16\x8a"
        "\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
        "\x08\xf6\x21\x82\x74\x44\xf7\x0d"
        "\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
        "\x10\xe1\x16\xe9\x19\x2a\xf3\xc9"
        "\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
        "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5"
        "\x65\x92\xf8\x27\x4e\xec\x53\xf0");
    DIGEST_KATS_ADD("message digest", 14,
        "\x34\x44\xe1\x55\x88\x1f\xa1\x55"
        "\x11\xf5\x77\x26\xc7\xd7\xcf\xe8"
        "\x03\x02\xa7\x43\x30\x67\xb2\x9d"
        "\x59\xa7\x14\x15\xca\x9d\xd1\x41"
        "\xac\x89\x2d\x31\x0b\xc4\xd7\x81"
        "\x28\xc9\x8f\xda\x83\x9d\x18\xd7"
        "\xf0\x55\x6f\x2f\xe7\xac\xb3\xc0"
        "\xcd\xa4\xbf\xf3\xa2\x5f\x5f\x59");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xaf\x32\x8d\x17\xfa\x28\x75\x3a"
        "\x3c\x9f\x5c\xb7\x2e\x37\x6b\x90"
        "\x44\x0b\x96\xf0\x28\x9e\x57\x03"
        "\xb7\x29\x32\x4a\x97\x5a\xb3\x84"
        "\xed\xa5\x65\xfc\x92\xaa\xde\xd1"
        "\x43\x66\x99\x00\xd7\x61\x86\x16"
        "\x87\xac\xdc\x0a\x5f\xfa\x35\x8b"
        "\xd0\x57\x1a\xaa\xd8\x0a\xca\x68");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xd1\xdb\x17\xb4\x74\x5b\x25\x5e"
        "\x5e\xb1\x59\xf6\x65\x93\xcc\x9c"
        "\x14\x38\x50\x97\x9f\xc7\xa3\x95"
        "\x17\x96\xab\xa8\x01\x65\xaa\xb5"
        "\x36\xb4\x61\x74\xce\x19\xe3\xf7"
        "\x07\xf0\xe5\xc6\x48\x7f\x5f\x03"
        "\x08\x4b\xc0\xec\x94\x61\x69\x1e"
        "\xf2\x01\x13\xe4\x2a\xd2\x81\x63");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x95\x24\xb9\xa5\x53\x6b\x91\x06"
        "\x95\x26\xb4\xf6\x19\x6b\x7e\x94"
        "\x75\xb4\xda\x69\xe0\x1f\x0c\x85"
        "\x57\x97\xf2\x24\xcd\x73\x35\xdd"
        "\xb2\x86\xfd\x99\xb9\xb3\x2f\xfe"
        "\x33\xb5\x9a\xd4\x24\xcc\x17\x44"
        "\xf6\xeb\x59\x13\x7f\x5f\xb8\x60"
        "\x19\x32\xe8\xa8\xaf\x0a\xe9\x30");

    SHA3_KATS_TEST(Sha3_512, SHA3_512);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    DIGEST_ALT_OTHER_TEST(wc_Sha3, Sha3_224, SHA3_224,
        "\xbb\x4e\xb3\xf7\xfb\x7b\x50\xff"
        "\x3b\xf8\xb0\x53\x8c\x13\x40\xce"
        "\x0c\x43\x5f\xff\x6a\x08\x43\x87"
        "\x34\x9f\x7a\x4c");
#endif
#ifndef WOLFSSL_NOSHA3_256
    DIGEST_ALT_OTHER_TEST(wc_Sha3, Sha3_256, SHA3_256,
        "\x78\xc4\x14\xa4\x5d\x85\x07\xf4"
        "\x48\x64\xe0\x5f\x73\x2c\x3b\x78"
        "\xce\x5a\x78\x45\x97\x0b\x29\xa8"
        "\xb4\x53\xed\x38\x19\xd2\x4e\xa9");
#endif
#ifndef WOLFSSL_NOSHA3_384
    DIGEST_ALT_OTHER_TEST(wc_Sha3, Sha3_384, SHA3_384,
        "\x22\x29\x8c\x46\xa7\xf0\xf9\xc7"
        "\xa7\xaf\x66\x5d\x58\x88\xb3\x6c"
        "\xc2\x02\x43\x83\x71\x5f\xce\x12"
        "\x65\x1b\x11\xba\x1c\xde\x52\xdc"
        "\x6f\xde\x26\x43\xf1\x9f\xbe\xea"
        "\x5f\xd6\x25\x06\x7c\xad\x16\xed");
#endif
#ifndef WOLFSSL_NOSHA3_512
    DIGEST_ALT_OTHER_TEST(wc_Sha3, Sha3_512, SHA3_512,
        "\xc3\xaf\x62\x06\x69\x92\xa1\x2f"
        "\xa5\x66\xcc\xcd\xec\x80\xdd\x27"
        "\x93\xbd\x11\xb0\xb7\xba\x6a\x5e"
        "\x36\xcf\x23\x4c\x1a\xf4\x8d\x37"
        "\xb9\xb6\x7f\xb1\xb4\x9a\x04\x23"
        "\x23\x42\x51\x5d\x8f\x07\x0d\x42"
        "\x04\x68\x84\xc4\x56\x24\x14\x65"
        "\x84\x28\xa9\x2f\x10\x35\x7b\x6d");
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    DIGEST_ALT_COPY_TEST(wc_Sha3, Sha3_224, SHA3_224,
        "\x6b\x4e\x03\x42\x36\x67\xdb\xb7"
        "\x3b\x6e\x15\x45\x4f\x0e\xb1\xab"
        "\xd4\x59\x7f\x9a\x1b\x07\x8e\x3f"
        "\x5b\x5a\x6b\xc7",
        "\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a"
        "\xd0\x92\x34\xee\x7d\x3c\x76\x6f"
        "\xc9\xa3\xa5\x16\x8d\x0c\x94\xad"
        "\x73\xb4\x6f\xdf");
#endif
#ifndef WOLFSSL_NOSHA3_256
    DIGEST_ALT_COPY_TEST(wc_Sha3, Sha3_256, SHA3_256,
        "\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66"
        "\x51\xc1\x47\x56\xa0\x61\xd6\x62"
        "\xf5\x80\xff\x4d\xe4\x3b\x49\xfa"
        "\x82\xd8\x0a\x4b\x80\xf8\x43\x4a",
        "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2"
        "\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
        "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b"
        "\x46\xbf\xe2\x45\x11\x43\x15\x32");
#endif
#ifndef WOLFSSL_NOSHA3_384
    DIGEST_ALT_COPY_TEST(wc_Sha3, Sha3_384, SHA3_384,
        "\x0c\x63\xa7\x5b\x84\x5e\x4f\x7d"
        "\x01\x10\x7d\x85\x2e\x4c\x24\x85"
        "\xc5\x1a\x50\xaa\xaa\x94\xfc\x61"
        "\x99\x5e\x71\xbb\xee\x98\x3a\x2a"
        "\xc3\x71\x38\x31\x26\x4a\xdb\x47"
        "\xfb\x6b\xd1\xe0\x58\xd5\xf0\x04",
        "\xec\x01\x49\x82\x88\x51\x6f\xc9"
        "\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
        "\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25"
        "\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
        "\x98\xd8\x8c\xea\x92\x7a\xc7\xf5"
        "\x39\xf1\xed\xf2\x28\x37\x6d\x25");
#endif
#ifndef WOLFSSL_NOSHA3_512
    DIGEST_ALT_COPY_TEST(wc_Sha3, Sha3_512, SHA3_512,
        "\xa6\x9f\x73\xcc\xa2\x3a\x9a\xc5"
        "\xc8\xb5\x67\xdc\x18\x5a\x75\x6e"
        "\x97\xc9\x82\x16\x4f\xe2\x58\x59"
        "\xe0\xd1\xdc\xc1\x47\x5c\x80\xa6"
        "\x15\xb2\x12\x3a\xf1\xf5\xf9\x4c"
        "\x11\xe3\xe9\x40\x2c\x3a\xc5\x58"
        "\xf5\x00\x19\x9d\x95\xb6\xd3\xe3"
        "\x01\x75\x85\x86\x28\x1d\xcd\x26",
        "\xb7\x51\x85\x0b\x1a\x57\x16\x8a"
        "\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
        "\x08\xf6\x21\x82\x74\x44\xf7\x0d"
        "\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
        "\x10\xe1\x16\xe9\x19\x2a\xf3\xc9"
        "\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
        "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5"
        "\x65\x92\xf8\x27\x4e\xec\x53\xf0");
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    SHA3_GET_HASH_TEST(Sha3_224, SHA3_224,
        "\x6b\x4e\x03\x42\x36\x67\xdb\xb7"
        "\x3b\x6e\x15\x45\x4f\x0e\xb1\xab"
        "\xd4\x59\x7f\x9a\x1b\x07\x8e\x3f"
        "\x5b\x5a\x6b\xc7",
        "\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a"
        "\xd0\x92\x34\xee\x7d\x3c\x76\x6f"
        "\xc9\xa3\xa5\x16\x8d\x0c\x94\xad"
        "\x73\xb4\x6f\xdf");
#endif
#ifndef WOLFSSL_NOSHA3_256
    SHA3_GET_HASH_TEST(Sha3_256, SHA3_256,
        "\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66"
        "\x51\xc1\x47\x56\xa0\x61\xd6\x62"
        "\xf5\x80\xff\x4d\xe4\x3b\x49\xfa"
        "\x82\xd8\x0a\x4b\x80\xf8\x43\x4a",
        "\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2"
        "\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
        "\x85\x5f\x08\x6e\x3e\x9d\x52\x5b"
        "\x46\xbf\xe2\x45\x11\x43\x15\x32");
#endif
#ifndef WOLFSSL_NOSHA3_384
    SHA3_GET_HASH_TEST(Sha3_384, SHA3_384,
        "\x0c\x63\xa7\x5b\x84\x5e\x4f\x7d"
        "\x01\x10\x7d\x85\x2e\x4c\x24\x85"
        "\xc5\x1a\x50\xaa\xaa\x94\xfc\x61"
        "\x99\x5e\x71\xbb\xee\x98\x3a\x2a"
        "\xc3\x71\x38\x31\x26\x4a\xdb\x47"
        "\xfb\x6b\xd1\xe0\x58\xd5\xf0\x04",
        "\xec\x01\x49\x82\x88\x51\x6f\xc9"
        "\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
        "\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25"
        "\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
        "\x98\xd8\x8c\xea\x92\x7a\xc7\xf5"
        "\x39\xf1\xed\xf2\x28\x37\x6d\x25");
#endif
#ifndef WOLFSSL_NOSHA3_512
    SHA3_GET_HASH_TEST(Sha3_512, SHA3_512,
        "\xa6\x9f\x73\xcc\xa2\x3a\x9a\xc5"
        "\xc8\xb5\x67\xdc\x18\x5a\x75\x6e"
        "\x97\xc9\x82\x16\x4f\xe2\x58\x59"
        "\xe0\xd1\xdc\xc1\x47\x5c\x80\xa6"
        "\x15\xb2\x12\x3a\xf1\xf5\xf9\x4c"
        "\x11\xe3\xe9\x40\x2c\x3a\xc5\x58"
        "\xf5\x00\x19\x9d\x95\xb6\xd3\xe3"
        "\x01\x75\x85\x86\x28\x1d\xcd\x26",
        "\xb7\x51\x85\x0b\x1a\x57\x16\x8a"
        "\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
        "\x08\xf6\x21\x82\x74\x44\xf7\x0d"
        "\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
        "\x10\xe1\x16\xe9\x19\x2a\xf3\xc9"
        "\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
        "\x57\x34\x0b\x4c\xf4\x08\xd5\xa5"
        "\x65\x92\xf8\x27\x4e\xec\x53\xf0");
#endif
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha3_Flags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_HASH_FLAGS) && \
    !defined(WOLFSSL_NOSHA3_256)
    DIGEST_ALT_FLAGS_TEST(wc_Sha3, Sha3, Sha3_256);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHAKE-128
 ******************************************************************************/

int test_wc_InitShake128(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_INIT_TEST(wc_Shake, Shake128);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_ALT_UPDATE_TEST(wc_Shake, Shake128);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_COUNT_FINAL_TEST(wc_Shake, Shake128, SHA3_128);
#endif
    return EXPECT_RESULT();
}

#define SHAKE128_KAT_CNT    7
int test_wc_Shake128_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_COUNT_KATS_TEST_VARS(wc_Shake, SHAKE128, SHA3_128);

    DIGEST_KATS_ADD("", 0,
        "\x7f\x9c\x2b\xa4\xe8\x8f\x82\x7d"
        "\x61\x60\x45\x50\x76\x05\x85\x3e"
        "\xd7\x3b\x80\x93\xf6\xef\xbc\x88"
        "\xeb\x1a\x6e\xac\xfa\x66\xef\x26"
        "\x3c\xb1\xee\xa9\x88\x00\x4b\x93"
        "\x10\x3c\xfb\x0a\xee\xfd\x2a\x68"
        "\x6e\x01\xfa\x4a\x58\xe8\xa3\x63"
        "\x9c\xa8\xa1\xe3\xf9\xae\x57\xe2"
        "\x35\xb8\xcc\x87\x3c\x23\xdc\x62"
        "\xb8\xd2\x60\x16\x9a\xfa\x2f\x75"
        "\xab\x91\x6a\x58\xd9\x74\x91\x88"
        "\x35\xd2\x5e\x6a\x43\x50\x85\xb2"
        "\xba\xdf\xd6\xdf\xaa\xc3\x59\xa5"
        "\xef\xbb\x7b\xcc\x4b\x59\xd5\x38"
        "\xdf\x9a\x04\x30\x2e\x10\xc8\xbc"
        "\x1c\xbf\x1a\x0b\x3a\x51\x20\xea"
        "\x17\xcd\xa7\xcf\xad\x76\x5f\x56"
        "\x23\x47\x4d\x36\x8c\xcc\xa8\xaf"
        "\x00\x07\xcd\x9f\x5e\x4c\x84\x9f"
        "\x16\x7a\x58\x0b\x14\xaa\xbd\xef"
        "\xae\xe7\xee\xf4\x7c\xb0\xfc\xa9");
    DIGEST_KATS_ADD("a", 1,
        "\x85\xc8\xde\x88\xd2\x88\x66\xbf"
        "\x08\x68\x09\x0b\x39\x61\x16\x2b"
        "\xf8\x23\x92\xf6\x90\xd9\xe4\x73"
        "\x09\x10\xf4\xaf\x7c\x6a\xb3\xee"
        "\x43\x54\xb4\x9c\xa7\x29\xeb\x35"
        "\x6e\xe3\xf5\xb0\xfb\xd2\x9b\x66"
        "\x76\x93\x83\xe5\xe4\x01\xb1\xf8"
        "\x5e\x04\x4c\x92\xbb\x52\x31\xaa"
        "\x4d\xee\x17\x99\xaf\x7a\x7c\xee"
        "\x21\x3a\x23\xad\xcd\x03\xc4\x80"
        "\x6c\x9a\x8b\x0d\x8a\x2e\xea\xd8"
        "\xea\x7a\x61\x34\xc1\x3e\x52\x3c"
        "\xcf\x93\xad\x39\xd2\x27\xd3\xe7"
        "\xd0\x22\xd9\x65\x4f\x3b\x49\x41"
        "\x37\x88\x75\x8a\x64\x17\xe4\x2d"
        "\x41\x95\x7c\xb3\x0c\xf0\x4d\xa3"
        "\x7f\x26\x89\x7c\x2c\xf2\xf8\x00"
        "\x55\x84\x62\x93\xfd\xe0\x23\x31"
        "\xcf\x4a\x26\x9a\xaf\x2d\x47\xeb"
        "\x27\xab\xa0\xfa\xba\x4a\x67\x8e"
        "\xc0\x02\xbc\x0d\x30\x64\xea\xd0");
    DIGEST_KATS_ADD("abc", 3,
        "\x58\x81\x09\x2d\xd8\x18\xbf\x5c"
        "\xf8\xa3\xdd\xb7\x93\xfb\xcb\xa7"
        "\x40\x97\xd5\xc5\x26\xa6\xd3\x5f"
        "\x97\xb8\x33\x51\x94\x0f\x2c\xc8"
        "\x44\xc5\x0a\xf3\x2a\xcd\x3f\x2c"
        "\xdd\x06\x65\x68\x70\x6f\x50\x9b"
        "\xc1\xbd\xde\x58\x29\x5d\xae\x3f"
        "\x89\x1a\x9a\x0f\xca\x57\x83\x78"
        "\x9a\x41\xf8\x61\x12\x14\xce\x61"
        "\x23\x94\xdf\x28\x6a\x62\xd1\xa2"
        "\x25\x2a\xa9\x4d\xb9\xc5\x38\x95"
        "\x6c\x71\x7d\xc2\xbe\xd4\xf2\x32"
        "\xa0\x29\x4c\x85\x7c\x73\x0a\xa1"
        "\x60\x67\xac\x10\x62\xf1\x20\x1f"
        "\xb0\xd3\x77\xcf\xb9\xcd\xe4\xc6"
        "\x35\x99\xb2\x7f\x34\x62\xbb\xa4"
        "\xa0\xed\x29\x6c\x80\x1f\x9f\xf7"
        "\xf5\x73\x02\xbb\x30\x76\xee\x14"
        "\x5f\x97\xa3\x2a\xe6\x8e\x76\xab"
        "\x66\xc4\x8d\x51\x67\x5b\xd4\x9a"
        "\xcc\x29\x08\x2f\x56\x47\x58\x4e");
    DIGEST_KATS_ADD("message digest", 14,
        "\xcb\xef\x73\x29\x61\xb5\x5b\x4c"
        "\x31\x39\x67\x96\x57\x7d\xf4\x91"
        "\xb6\xee\xd6\x1d\x89\x49\xce\x96"
        "\x72\x26\x80\x1e\x41\x1e\x53\xf0"
        "\x95\x44\xc1\x3f\xe4\xdf\x40\xfc"
        "\x8d\xf5\xf9\x85\x3e\x85\x41\xd0"
        "\x45\x41\xf1\x00\x77\xd9\xd4\x4e"
        "\x74\x93\xe8\x7f\x16\x0a\x0a\x0d"
        "\x37\xb3\xd6\xda\xc9\x64\x59\x88"
        "\xed\x5d\x06\xdd\x53\x21\x99\x3d"
        "\x87\x35\x74\xd1\x47\xe3\x36\xd7"
        "\x23\x3a\x68\x27\x31\x87\x21\x48"
        "\xe9\x3e\x72\x28\x16\xb3\xb1\xcc"
        "\x31\x3b\xc4\x33\x94\x5f\x74\xf2"
        "\x14\x39\xdf\xd8\xc8\x9b\xc5\x9b"
        "\xf3\xd1\x6d\x48\x9a\x5d\x5c\xaf"
        "\xdf\x77\xac\x07\xbe\x5d\x96\xa7"
        "\x6e\x95\x27\x53\x07\xd8\x83\xca"
        "\xd6\x25\x71\x43\xb5\x61\x00\x73"
        "\xcb\xbf\x7b\x8e\x89\x70\x31\x74"
        "\x66\xa8\xb6\x85\xd4\x81\x78\xb8");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\x96\x1c\x91\x9c\x08\x54\x57\x6e"
        "\x56\x13\x20\xe8\x15\x14\xbf\x37"
        "\x24\x19\x7d\x07\x15\xe1\x6a\x36"
        "\x45\x20\x38\x4e\xe9\x97\xf6\xef"
        "\x3b\xe7\xad\x1a\xb6\x87\xd3\x1e"
        "\xbd\x7e\x66\x04\xef\x2c\x76\x52"
        "\x93\x2e\x42\x06\x11\x3d\x26\x35"
        "\x14\xe7\x2f\x31\xf5\xe1\xdf\x87"
        "\xc5\xf5\x4f\xc4\x3e\x8f\x85\x7f"
        "\xc4\xa5\x2b\xbb\x56\x5b\xd6\xd4"
        "\x58\x69\xdf\x92\x59\xc0\x97\x74"
        "\x72\x83\x94\xe3\xe0\xc3\xb3\x26"
        "\x41\x00\x85\xc3\x56\xe5\xb1\x73"
        "\xd5\x70\x08\x79\x45\xb0\xf0\x68"
        "\xe4\xc6\x3a\x5b\x19\x1f\xef\x22"
        "\xd9\x3b\x9f\xd4\x21\x13\x28\xd7"
        "\x0e\x51\x4f\xec\x92\xb1\xb4\x86"
        "\x43\x49\x59\x18\xb6\x41\xea\xb0"
        "\x54\x60\xd0\x79\x8c\xbe\x42\xfd"
        "\xa4\x7a\x23\x75\xf1\x06\x5d\x03"
        "\x7e\xbc\x76\xbd\xce\xff\x29\xef");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x54\xdd\x20\x1e\x53\x24\x99\x10"
        "\xdb\x3c\x7d\x36\x65\x74\xfb\xb6"
        "\x4e\x71\xfa\xe4\x42\xa4\xba\xc1"
        "\x34\x39\xf2\x6d\xd4\x89\x68\x83"
        "\x70\xd0\x12\xa1\x55\x86\xd8\x7e"
        "\x73\x00\xbe\xed\xd9\x23\x3e\xea"
        "\x98\xf9\x16\xda\xb2\x66\x51\x38"
        "\x02\x50\x24\x40\x31\x5b\xba\x9e"
        "\x40\xcd\xb8\x60\x09\x7b\x12\xdf"
        "\xd8\x8d\x4f\x24\x2f\x77\xc2\x2e"
        "\x93\xad\xfd\x3e\xb7\x89\x94\x82"
        "\xd3\x9f\x7c\x0f\x16\x0e\xcc\x07"
        "\x04\x73\x47\x82\x94\x73\x31\x46"
        "\x74\xa5\x6a\x13\xe7\x01\xd5\xd8"
        "\xaa\x37\x54\x6b\x43\xc5\x73\x36"
        "\x56\xc1\xac\x3c\xa4\x69\x7a\x30"
        "\x32\x0b\x98\xad\xf9\xbc\xa3\xc6"
        "\x8b\xec\x9f\x14\xe3\x3b\x8f\xae"
        "\x30\xd5\x5e\xc6\x0e\x80\x15\xa5"
        "\x16\x80\xbb\x37\xeb\x5a\x7e\xbc"
        "\x90\x88\xcd\xcf\x09\xff\x2d\x6b");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x7b\xf4\x51\xc9\x2f\xdc\x77\xb9"
        "\x77\x1e\x6c\x90\x56\x44\x58\x94"
        "\xee\x86\x7f\x00\xc2\xb7\x0d\x3a"
        "\xf0\xd1\x96\xa0\xcf\x6b\x28\xe1"
        "\x2c\xed\x96\x05\x37\xf2\x2a\x0e"
        "\x90\x33\x41\x03\x67\x58\x44\x99"
        "\x3c\x4f\xd7\x13\x64\x68\x00\xbd"
        "\x89\x99\x51\xe5\x6f\x06\x45\xfc"
        "\xf0\x39\x78\xa6\x27\xc0\x7c\x62"
        "\xa7\x5a\x54\x3b\x8a\xf7\xed\xb0"
        "\xaf\xe7\x64\x3d\x94\x95\x36\x3b"
        "\x30\xbc\xc5\x50\x1c\x74\xdf\x19"
        "\x5b\x2a\xd4\x28\x83\x1b\x77\x9b"
        "\xf1\xab\x2a\x0d\xfc\x92\xa5\x92"
        "\x5a\xc8\xd5\x97\x90\xee\xbc\xf2"
        "\xec\x29\xb3\x33\x8f\x66\x0c\x5a"
        "\x6f\x66\x73\xce\x32\x2c\xc1\x03"
        "\x9a\xe5\xf1\x46\x3b\x86\xca\x7e"
        "\x96\xaa\xa9\x9a\x27\x09\x93\x02"
        "\x6a\xc8\x13\xda\xc4\xb9\xeb\x82"
        "\x14\xe3\x1c\xe8\x68\x27\xcb\x21");

    DIGEST_COUNT_KATS_TEST(Shake128, SHAKE128, SHA3_128);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_COUNT_OTHER_TEST(wc_Shake, Shake128, SHA3_128,
        "\x1b\xbe\x22\xa0\x40\xc7\x15\x88"
        "\xcc\x2b\xaa\x3e\x5a\x7c\x89\x03"
        "\x33\xd4\xac\x54\x27\x14\xf9\x96"
        "\x0e\x60\x3d\x8f\x13\x9a\xf8\x1e"
        "\x8f\x45\xc8\x37\xa8\x63\x16\x7b"
        "\x96\x69\xd4\xe4\x2e\x45\x9f\x1d"
        "\x50\xaa\x92\x2e\x0d\x32\x37\x97"
        "\xf7\xd7\xcc\x7c\x5c\xfa\x71\x42"
        "\xf3\x23\x68\x6a\x36\x03\xd4\x0a"
        "\x77\x7d\xd3\x84\x40\x75\xc5\xad"
        "\x1f\xb7\xa4\x90\x80\x66\x91\x49"
        "\x7d\x3e\x8a\x69\xb9\x94\xbf\x0f"
        "\x0a\x09\xde\xc8\xfe\x10\xb5\x4f"
        "\xe5\x78\xda\x4c\x3a\xcd\xcd\xc2"
        "\x30\xb0\x14\x75\x45\x2b\x2e\x40"
        "\x74\xf4\x5c\xad\x2e\xcf\x1c\xa0"
        "\x0b\x8d\x58\x30\xcd\x0f\xaa\x11"
        "\x68\x84\x2b\x55\xa7\x62\x1b\x9a"
        "\xec\x6e\xd6\xcc\xa1\xc9\x9f\xc8"
        "\x11\x74\xb4\x22\x18\xc0\xe6\x37"
        "\xc4\xef\xc2\xe4\xc3\x26\x27\x0b");
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    DIGEST_COUNT_COPY_TEST(wc_Shake, Shake128, SHA3_128,
        "\x7f\x9c\x2b\xa4\xe8\x8f\x82\x7d"
        "\x61\x60\x45\x50\x76\x05\x85\x3e"
        "\xd7\x3b\x80\x93\xf6\xef\xbc\x88"
        "\xeb\x1a\x6e\xac\xfa\x66\xef\x26"
        "\x3c\xb1\xee\xa9\x88\x00\x4b\x93"
        "\x10\x3c\xfb\x0a\xee\xfd\x2a\x68"
        "\x6e\x01\xfa\x4a\x58\xe8\xa3\x63"
        "\x9c\xa8\xa1\xe3\xf9\xae\x57\xe2"
        "\x35\xb8\xcc\x87\x3c\x23\xdc\x62"
        "\xb8\xd2\x60\x16\x9a\xfa\x2f\x75"
        "\xab\x91\x6a\x58\xd9\x74\x91\x88"
        "\x35\xd2\x5e\x6a\x43\x50\x85\xb2"
        "\xba\xdf\xd6\xdf\xaa\xc3\x59\xa5"
        "\xef\xbb\x7b\xcc\x4b\x59\xd5\x38"
        "\xdf\x9a\x04\x30\x2e\x10\xc8\xbc"
        "\x1c\xbf\x1a\x0b\x3a\x51\x20\xea"
        "\x17\xcd\xa7\xcf\xad\x76\x5f\x56"
        "\x23\x47\x4d\x36\x8c\xcc\xa8\xaf"
        "\x00\x07\xcd\x9f\x5e\x4c\x84\x9f"
        "\x16\x7a\x58\x0b\x14\xaa\xbd\xef"
        "\xae\xe7\xee\xf4\x7c\xb0\xfc\xa9",
        "\x58\x81\x09\x2d\xd8\x18\xbf\x5c"
        "\xf8\xa3\xdd\xb7\x93\xfb\xcb\xa7"
        "\x40\x97\xd5\xc5\x26\xa6\xd3\x5f"
        "\x97\xb8\x33\x51\x94\x0f\x2c\xc8"
        "\x44\xc5\x0a\xf3\x2a\xcd\x3f\x2c"
        "\xdd\x06\x65\x68\x70\x6f\x50\x9b"
        "\xc1\xbd\xde\x58\x29\x5d\xae\x3f"
        "\x89\x1a\x9a\x0f\xca\x57\x83\x78"
        "\x9a\x41\xf8\x61\x12\x14\xce\x61"
        "\x23\x94\xdf\x28\x6a\x62\xd1\xa2"
        "\x25\x2a\xa9\x4d\xb9\xc5\x38\x95"
        "\x6c\x71\x7d\xc2\xbe\xd4\xf2\x32"
        "\xa0\x29\x4c\x85\x7c\x73\x0a\xa1"
        "\x60\x67\xac\x10\x62\xf1\x20\x1f"
        "\xb0\xd3\x77\xcf\xb9\xcd\xe4\xc6"
        "\x35\x99\xb2\x7f\x34\x62\xbb\xa4"
        "\xa0\xed\x29\x6c\x80\x1f\x9f\xf7"
        "\xf5\x73\x02\xbb\x30\x76\xee\x14"
        "\x5f\x97\xa3\x2a\xe6\x8e\x76\xab"
        "\x66\xc4\x8d\x51\x67\x5b\xd4\x9a"
        "\xcc\x29\x08\x2f\x56\x47\x58\x4e");
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128Hash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    const byte  data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
    word32      len = sizeof(data);
    byte        hash[WC_SHA3_128_COUNT * 8];
    word32      hashLen = sizeof(hash);
    const char* expHash =
        "\x12\x27\xc5\xf8\x82\xf9\xc5\x7b"
        "\xf2\xe3\xe4\x8d\x2c\x87\xeb\x20"
        "\xf3\x82\xa4\xb6\x39\xb5\x4d\x26"
        "\xf6\xd5\x95\xff\x3d\xb9\x06\x4d"
        "\x07\x4e\xe7\x88\xf0\x74\x7c\xa3"
        "\xfc\x46\xce\x86\x93\x6c\xfc\x6b"
        "\xd3\x63\x8d\xae\x5a\x2b\x7d\x65"
        "\x92\x52\x29\x98\xd6\xda\x6f\xaa"
        "\x5f\x5d\x41\x5d\x99\xd5\x56\x51"
        "\x46\xee\x3c\xd2\xb8\xec\x15\x38"
        "\xbc\x62\xdd\xe9\x46\x94\x9b\x23"
        "\xb8\xcf\x3c\xa3\xe4\x7f\x35\x2d"
        "\x3c\x46\x2f\x16\x87\x10\x84\x34"
        "\xf7\x84\x95\x2c\xcf\xe3\x26\xaf"
        "\xdf\x78\x53\xb3\x98\x20\x22\xca"
        "\x14\x82\xbc\x9c\xd1\x8f\x9a\x6c"
        "\xe0\x92\x0b\x8f\x34\x5a\xa0\x4e"
        "\x7f\xd5\x83\xa4\xe2\x01\x25\x33"
        "\x45\x0b\x00\xc1\x6a\x5a\x14\xe8"
        "\x6a\xd1\x45\x0c\x4e\x8a\x4a\x6f"
        "\x37\xb4\x15\x5d\xd6\x0d\xd1\xab";

    ExpectIntEQ(wc_Shake128Hash(data, len, hash, hashLen), 0);
    ExpectBufEQ(hash, expHash, hashLen);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_Absorb(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    wc_Shake shake128;

    ExpectIntEQ(wc_InitShake128(&shake128, HEAP_HINT, INVALID_DEVID), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)
    ExpectIntEQ(wc_Shake128_Absorb(NULL     , NULL    , 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake128_Absorb(&shake128, NULL    , 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake128_Absorb(NULL     , NULL    , 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Shake128_Absorb(&shake128, NULL, 0), 0);
#endif

    ExpectIntEQ(wc_Shake128_Absorb(&shake128, (byte*)"a", 1), 0);

    wc_Shake128_Free(&shake128);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake128_SqueezeBlocks(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    wc_Shake shake128;
    byte hash[WC_SHA3_128_COUNT * 8];

    ExpectIntEQ(wc_InitShake128(&shake128, HEAP_HINT, INVALID_DEVID), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)
    ExpectIntEQ(wc_Shake128_SqueezeBlocks(NULL     , NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake128_SqueezeBlocks(&shake128, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake128_SqueezeBlocks(NULL     , NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Shake128_SqueezeBlocks(&shake128, NULL, 0), 0);
#endif
    ExpectIntEQ(wc_Shake128_SqueezeBlocks(&shake128, hash, 1), 0);

    wc_Shake128_Free(&shake128);
#endif
    return EXPECT_RESULT();
}

#define TEST_SHAKE128_MAX_BLOCKS     3
int test_wc_Shake128_XOF(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE128
    wc_Shake shake128;
    byte hash[WC_SHA3_128_COUNT * 8 * TEST_SHAKE128_MAX_BLOCKS];
    const char* expOut =
        "\xf4\x2f\xac\xcf\x13\x0e\x25\x5f"
        "\xfd\x4a\x29\xbb\x9d\x47\x25\xea"
        "\x19\xfe\x86\xd3\xeb\x58\xd7\x74"
        "\xc1\x3c\xf9\xc7\x0e\xdc\xc6\x3b"
        "\x4b\x97\x0d\x2b\xbc\xa6\x89\x4c"
        "\xda\x48\x8c\x02\x62\x15\x1f\x2e"
        "\x36\xb1\x95\x78\xfe\x02\x81\x35"
        "\x30\x55\x5f\x3c\x06\x47\x2b\x93"
        "\x1e\xf5\x8e\xf2\xfc\x81\x5b\xec"
        "\x9f\xde\xf3\xee\xc0\xac\xb0\x90"
        "\x5c\x19\xc8\x3e\x8a\xa4\xf6\xa7"
        "\xdf\xa3\x39\xdf\x22\x03\x6c\x07"
        "\xaa\xbb\xea\x3d\xec\x00\xc2\xb2"
        "\x6e\x4c\x6b\xdc\xb8\x39\x8b\xb5"
        "\x67\x3f\xdc\x2a\xf5\x91\x32\xb9"
        "\x07\xbc\x1d\xb3\x92\x79\x13\xdb"
        "\x56\xe5\xae\x43\x91\x58\x18\x41"
        "\xa8\xe1\x75\x8e\x5b\xeb\xac\x4f"
        "\xeb\x41\xac\x5d\x8b\x4a\x3d\xf6"
        "\xb6\x5f\xe6\x9c\x19\x1e\x33\x97"
        "\xbc\x7c\xa7\x7e\xed\x5c\xe5\x4b"
        "\xdb\xa2\x34\xcd\x90\x94\x46\x19"
        "\x2e\x60\xbb\xf4\xb1\xe6\x78\xc8"
        "\xb2\x89\x0b\x2b\x0a\xb9\x69\x81"
        "\x90\x36\xc7\x5e\xcc\x36\x46\xde"
        "\x5e\x1d\xb2\x1d\x62\x46\x58\xdf"
        "\x9a\x07\xea\xe5\x6e\xac\x06\x53"
        "\x4f\xb4\xb5\x1e\xe3\x78\x60\x84"
        "\xe0\x96\xfd\xe8\xc0\xf4\x3b\x80"
        "\x7a\x2d\xb5\x22\x3e\xb5\x0f\x21"
        "\xcb\x47\x13\x2d\x97\xb5\x28\x25"
        "\xe7\x84\xa1\x64\x46\xa8\xeb\x8d"
        "\xa7\xf9\xbe\x89\x3f\x96\x8a\x08"
        "\x97\x8d\x5c\x72\x7c\x9d\x52\x27"
        "\xea\xb2\xf0\x9d\x9c\x00\x0d\x3e"
        "\xd1\xa4\x0f\xdd\xba\x43\x41\xfb"
        "\xf8\x26\x13\x98\x27\x88\xae\x8b"
        "\xfb\x8f\xcd\x37\x72\xb3\x37\x09"
        "\xf4\xde\xde\x33\x8e\x1f\xbd\x49"
        "\x90\x3c\x8a\x8b\xd2\x89\xb0\x26"
        "\x39\xc8\x2f\xc7\xfc\x2d\xf9\xa7"
        "\xd3\x5d\x69\x3d\x90\x17\x9c\xc1"
        "\x83\xc7\x1d\xd6\xd3\xa2\x01\x57"
        "\x33\x4f\x0d\xfc\x52\x9e\x2a\xd1"
        "\x9e\xfb\x36\xdf\x3e\xb3\x49\x9f"
        "\x83\x22\xa8\x24\x0e\xa1\xfb\xca"
        "\xd5\x17\x58\x1a\x40\x3f\x4f\x54"
        "\x3f\xd4\xed\x99\xd2\x39\xad\x37"
        "\x03\x39\xf7\x3b\xcf\x52\x55\xc4"
        "\x76\x74\x1d\x33\x04\x76\x44\x0d"
        "\xf6\x93\x89\x9d\x74\x19\x9c\x09"
        "\xd9\xf4\x5f\x0b\xbc\xf4\x13\xec"
        "\x2c\xce\x5f\x2b\x00\xeb\x8b\xa0"
        "\xa2\xf1\xdd\x93\xc0\x9c\x7c\xb5"
        "\xca\xe2\xfb\x07\xa9\x1b\xa8\xc9"
        "\xc9\x84\x2b\x7e\x1e\x05\x8c\x98"
        "\xfd\x8d\x2a\xd0\xf2\x3a\x7b\x88"
        "\x26\x4d\xed\x2b\xdb\x99\xb8\x9f"
        "\x88\x01\x47\x29\xeb\x23\x80\x81"
        "\x2b\xdd\xac\xbf\xcb\x1e\x80\x0d"
        "\x4f\xba\xc3\x13\xfa\xb1\xa6\xa9"
        "\x69\x09\x48\xe6\xb8\xd5\x55\x12"
        "\xb5\x25\xba\xf6\xd4\x2a\x5e\xf0";
    int i;
    int j;

    for (i = 1; i <= TEST_SHAKE128_MAX_BLOCKS; i++) {
        ExpectIntEQ(wc_InitShake128(&shake128, HEAP_HINT, INVALID_DEVID), 0);

        ExpectIntEQ(wc_Shake128_Absorb(&shake128, (byte*)"Starting point", 15),
            0);

        for (j = 0; j < TEST_SHAKE128_MAX_BLOCKS; j += i) {
            int cnt = TEST_SHAKE128_MAX_BLOCKS - j;
            if (i < cnt)
                cnt = i;
            ExpectIntEQ(wc_Shake128_SqueezeBlocks(&shake128,
                hash + WC_SHA3_128_COUNT * 8 * j, cnt), 0);
        }
        ExpectBufEQ(hash, expOut,
            WC_SHA3_128_COUNT * 8 * TEST_SHAKE128_MAX_BLOCKS);
    }

    wc_Shake128_Free(&shake128);
#endif
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHAKE-256
 ******************************************************************************/

int test_wc_InitShake256(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_INIT_TEST(wc_Shake, Shake256);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256_Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_ALT_UPDATE_TEST(wc_Shake, Shake256);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256_Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_COUNT_FINAL_TEST(wc_Shake, Shake256, SHA3_256);
#endif
    return EXPECT_RESULT();
}

#define SHAKE256_KAT_CNT    7
int test_wc_Shake256_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_COUNT_KATS_TEST_VARS(wc_Shake, SHAKE256, SHA3_256);

    DIGEST_KATS_ADD("", 0,
        "\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13"
        "\x23\x3b\x3f\xeb\x74\x3e\xeb\x24"
        "\x3f\xcd\x52\xea\x62\xb8\x1b\x82"
        "\xb5\x0c\x27\x64\x6e\xd5\x76\x2f"
        "\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00"
        "\xcb\x05\x01\x9d\x67\xb5\x92\xf6"
        "\xfc\x82\x1c\x49\x47\x9a\xb4\x86"
        "\x40\x29\x2e\xac\xb3\xb7\xc4\xbe"
        "\x14\x1e\x96\x61\x6f\xb1\x39\x57"
        "\x69\x2c\xc7\xed\xd0\xb4\x5a\xe3"
        "\xdc\x07\x22\x3c\x8e\x92\x93\x7b"
        "\xef\x84\xbc\x0e\xab\x86\x28\x53"
        "\x34\x9e\xc7\x55\x46\xf5\x8f\xb7"
        "\xc2\x77\x5c\x38\x46\x2c\x50\x10"
        "\xd8\x46\xc1\x85\xc1\x51\x11\xe5"
        "\x95\x52\x2a\x6b\xcd\x16\xcf\x86"
        "\xf3\xd1\x22\x10\x9e\x3b\x1f\xdd");
    DIGEST_KATS_ADD("a", 1,
        "\x86\x7e\x2c\xb0\x4f\x5a\x04\xdc"
        "\xbd\x59\x25\x01\xa5\xe8\xfe\x9c"
        "\xea\xaf\xca\x50\x25\x56\x26\xca"
        "\x73\x6c\x13\x80\x42\x53\x0b\xa4"
        "\x36\xb7\xb1\xec\x0e\x06\xa2\x79"
        "\xbc\x79\x07\x33\xbb\x0a\xee\x6f"
        "\xa8\x02\x68\x3c\x7b\x35\x50\x63"
        "\xc4\x34\xe9\x11\x89\xb0\xc6\x51"
        "\xd0\x92\xb0\x1e\x55\xce\x4d\x61"
        "\x0b\x54\xa5\x46\x6d\x02\xf8\x8f"
        "\xc3\x78\x09\x6f\xb0\xda\xd0\x25"
        "\x48\x57\xfe\x1e\x63\x81\xab\xc0"
        "\x4e\x07\xe3\x3d\x91\x69\x35\x93"
        "\x56\x36\x00\x48\x96\xc5\xb1\x25"
        "\x34\x64\xf1\xcb\x5e\xa7\x3b\x00"
        "\x7b\xc5\x02\x8b\xbb\xea\x13\xeb"
        "\xc2\x86\x68\xdb\xfc\x26\xb1\x24");
    DIGEST_KATS_ADD("abc", 3,
        "\x48\x33\x66\x60\x13\x60\xa8\x77"
        "\x1c\x68\x63\x08\x0c\xc4\x11\x4d"
        "\x8d\xb4\x45\x30\xf8\xf1\xe1\xee"
        "\x4f\x94\xea\x37\xe7\x8b\x57\x39"
        "\xd5\xa1\x5b\xef\x18\x6a\x53\x86"
        "\xc7\x57\x44\xc0\x52\x7e\x1f\xaa"
        "\x9f\x87\x26\xe4\x62\xa1\x2a\x4f"
        "\xeb\x06\xbd\x88\x01\xe7\x51\xe4"
        "\x13\x85\x14\x12\x04\xf3\x29\x97"
        "\x9f\xd3\x04\x7a\x13\xc5\x65\x77"
        "\x24\xad\xa6\x4d\x24\x70\x15\x7b"
        "\x3c\xdc\x28\x86\x20\x94\x4d\x78"
        "\xdb\xcd\xdb\xd9\x12\x99\x3f\x09"
        "\x13\xf1\x64\xfb\x2c\xe9\x51\x31"
        "\xa2\xd0\x9a\x3e\x6d\x51\xcb\xfc"
        "\x62\x27\x20\xd7\xa7\x5c\x63\x34"
        "\xe8\xa2\xd7\xec\x71\xa7\xcc\x29");
    DIGEST_KATS_ADD("message digest", 14,
        "\x71\x8e\x22\x40\x88\x85\x68\x40"
        "\xad\xe4\xdc\x73\x48\x7e\x15\x82"
        "\x6a\x07\xec\xb8\xed\x5e\x2b\xda"
        "\x52\x6c\xc1\xac\xdd\xb9\x9d\x00"
        "\x60\x49\x81\x58\x44\xbe\x0c\x6c"
        "\x29\xb7\x59\xdb\x80\xb7\xda\xa6"
        "\x84\xcb\x46\xd9\x0f\x7e\xef\x10"
        "\x7d\x24\xaa\xfc\xfa\xf0\xda\xca"
        "\xca\x28\x88\xdf\xaa\x73\x76\x94"
        "\xbc\x46\xd5\xc9\x5f\x17\xc5\xcf"
        "\xe7\xb0\xc9\x5c\xfd\x6a\x12\x6d"
        "\xd9\x64\x0c\x8e\x62\xe5\xad\x1c"
        "\x06\xe5\x75\x61\x6a\x2d\xec\x06"
        "\x46\x06\x6e\x80\x37\xe5\x1a\x00"
        "\x54\x78\x3d\x82\x0b\x92\xc1\x14"
        "\x17\x96\xf7\xc3\xe9\x35\x03\x8e"
        "\x67\x13\xbb\xba\x46\x08\x0b\x2e");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xb7\xb7\x8b\x04\xa3\xdd\x30\xa2"
        "\x65\xc8\x88\x6c\x33\xfd\xa9\x47"
        "\x99\x85\x3d\xe5\xd3\xd1\x05\x41"
        "\xfd\x4e\x9f\x46\x13\x70\x1c\x61"
        "\x07\x52\x49\xbe\xd1\x6b\x07\x81"
        "\x10\x8f\xcf\xe0\x86\xdb\xf3\x8a"
        "\x7f\xb8\x30\x08\x07\xce\xa8\x5c"
        "\xc6\x49\x32\x8d\x07\xd4\xff\x2b"
        "\x5e\x89\x08\x56\x3f\xf0\xfd\xcc"
        "\x06\xa8\x09\x2f\xbf\xe7\x72\xf8"
        "\x0e\x49\xf8\x7a\x10\x3b\x2a\xee"
        "\x12\x99\x0c\xcb\x47\x98\xe9\xec"
        "\x03\xaa\x48\x18\xa4\xbf\x5a\xbd"
        "\xa0\x84\xe1\xa5\xfe\x68\x7c\x2c"
        "\xfe\xf4\x40\x68\x46\xfe\x47\xa0"
        "\xd0\x7b\xf4\x50\x55\xa2\x69\x9c"
        "\x37\xd6\xb6\xd9\xcd\x6c\x4f\xf0");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\x31\xf1\x9a\x09\x7c\x72\x3e\x91"
        "\xfa\x59\xb0\x99\x8d\xd8\x52\x3c"
        "\x2a\x9e\x7e\x13\xb4\x02\x5d\x6b"
        "\x48\xfc\xbc\x32\x89\x73\xa1\x08"
        "\x78\xcf\xbe\xb3\x81\x0d\x88\x2f"
        "\xdb\x6a\x06\xe8\x7f\x3e\xa5\x2c"
        "\xf8\x26\xca\x55\x22\x31\x6f\xb6"
        "\x45\xb7\x08\xac\xbe\x43\xb2\xcb"
        "\x32\x52\x09\x24\x32\x42\x70\x60"
        "\xc9\x63\x9e\x21\xa8\x98\xd3\x88"
        "\xa7\xe1\x53\xe4\x2a\x8b\x89\x33"
        "\xf2\xad\x0c\x27\x52\x97\x69\x8e"
        "\x25\x7e\x05\xd2\x62\x75\x39\xb4"
        "\x2c\x10\x1b\x97\x67\xbc\x6d\x90"
        "\x06\x39\x31\x1f\x8e\x4a\x2e\x88"
        "\x26\x7b\xbb\x85\xb3\xfa\x4e\xad"
        "\xf4\x01\xe0\x74\x18\x9f\x6b\xbf");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x24\xc5\x08\xad\xef\xdf\x5e\x3f"
        "\x25\x96\xe8\xb5\xa8\x88\xfe\x10"
        "\xeb\x7b\x5b\x22\xe1\xf3\x5d\x85"
        "\x8e\x6e\xff\x30\x25\xc4\xcc\x18"
        "\xa3\xc9\xac\xe5\x1d\xdd\x24\x3d"
        "\x08\xc8\xc7\x0c\xf6\x8e\x91\xd1"
        "\x70\x60\x3d\xc3\xe2\xa3\x1c\x6c"
        "\xa8\x9f\x20\xc4\xa5\x95\xa2\x65"
        "\x4f\xb7\xd5\x35\x29\x42\x7e\x81"
        "\x2d\xea\x48\xe8\xe8\x9a\xbe\x06"
        "\x2b\x88\x90\x2f\x9b\xff\xb5\xee"
        "\xf2\x8a\x65\x80\xfb\x24\x1a\x15"
        "\x20\x1f\x18\xf5\x29\x9d\x03\xc3"
        "\xe7\x17\x3d\x41\x43\x88\x68\x80"
        "\xe4\xfb\x0b\xe1\xf5\x03\xeb\x4a"
        "\x10\x9a\xf6\xf9\xe9\x7f\xa8\xdc"
        "\x2e\xe6\x42\xe3\xc9\x18\x1b\x85");

    DIGEST_COUNT_KATS_TEST(Shake256, SHAKE256, SHA3_256);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256_other(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_COUNT_OTHER_TEST(wc_Shake, Shake256, SHA3_256,
        "\x97\x52\xa7\xbe\xe4\x06\x06\x10"
        "\xb2\x43\xb5\xca\x1e\x3a\x76\x06"
        "\x68\xac\x62\xfe\xad\xa4\xad\xc9"
        "\x23\xa2\x72\xeb\x90\x54\xeb\xd9"
        "\x06\x7f\x1e\xea\x2d\x80\x92\xb2"
        "\xd1\xe7\xae\x6b\xc0\x1d\x46\x6a"
        "\x3f\x62\x67\x35\x7b\x50\x4b\xe2"
        "\x05\x63\xf7\x97\x10\x4e\x9c\x14"
        "\xff\x21\x64\x40\xf6\xd4\x55\x79"
        "\x2e\x7b\x9b\x5b\xfb\xa2\x15\xf9"
        "\x6d\x6a\x54\xae\x5e\x7d\x6c\x72"
        "\x4a\x4e\x91\xcc\xc2\x37\x1c\x9d"
        "\x14\x95\x27\x38\x64\x6c\x62\x10"
        "\x19\x04\x6f\x19\xde\x61\x5e\xc8"
        "\x6d\xd2\xcc\x5b\xf4\xe0\xf2\x54"
        "\x0f\xe9\x2a\xe7\x0a\x7d\xb0\x55"
        "\x8a\x74\x83\x49\xf0\x2a\x6e\xa9");
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    DIGEST_COUNT_COPY_TEST(wc_Shake, Shake256, SHA3_256,
        "\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13"
        "\x23\x3b\x3f\xeb\x74\x3e\xeb\x24"
        "\x3f\xcd\x52\xea\x62\xb8\x1b\x82"
        "\xb5\x0c\x27\x64\x6e\xd5\x76\x2f"
        "\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00"
        "\xcb\x05\x01\x9d\x67\xb5\x92\xf6"
        "\xfc\x82\x1c\x49\x47\x9a\xb4\x86"
        "\x40\x29\x2e\xac\xb3\xb7\xc4\xbe"
        "\x14\x1e\x96\x61\x6f\xb1\x39\x57"
        "\x69\x2c\xc7\xed\xd0\xb4\x5a\xe3"
        "\xdc\x07\x22\x3c\x8e\x92\x93\x7b"
        "\xef\x84\xbc\x0e\xab\x86\x28\x53"
        "\x34\x9e\xc7\x55\x46\xf5\x8f\xb7"
        "\xc2\x77\x5c\x38\x46\x2c\x50\x10"
        "\xd8\x46\xc1\x85\xc1\x51\x11\xe5"
        "\x95\x52\x2a\x6b\xcd\x16\xcf\x86"
        "\xf3\xd1\x22\x10\x9e\x3b\x1f\xdd",
        "\x48\x33\x66\x60\x13\x60\xa8\x77"
        "\x1c\x68\x63\x08\x0c\xc4\x11\x4d"
        "\x8d\xb4\x45\x30\xf8\xf1\xe1\xee"
        "\x4f\x94\xea\x37\xe7\x8b\x57\x39"
        "\xd5\xa1\x5b\xef\x18\x6a\x53\x86"
        "\xc7\x57\x44\xc0\x52\x7e\x1f\xaa"
        "\x9f\x87\x26\xe4\x62\xa1\x2a\x4f"
        "\xeb\x06\xbd\x88\x01\xe7\x51\xe4"
        "\x13\x85\x14\x12\x04\xf3\x29\x97"
        "\x9f\xd3\x04\x7a\x13\xc5\x65\x77"
        "\x24\xad\xa6\x4d\x24\x70\x15\x7b"
        "\x3c\xdc\x28\x86\x20\x94\x4d\x78"
        "\xdb\xcd\xdb\xd9\x12\x99\x3f\x09"
        "\x13\xf1\x64\xfb\x2c\xe9\x51\x31"
        "\xa2\xd0\x9a\x3e\x6d\x51\xcb\xfc"
        "\x62\x27\x20\xd7\xa7\x5c\x63\x34"
        "\xe8\xa2\xd7\xec\x71\xa7\xcc\x29");
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256Hash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    const byte  data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
    word32      len = sizeof(data);
    byte        hash[WC_SHA3_256_COUNT * 8];
    word32      hashLen = sizeof(hash);
    const char* expHash =
        "\x84\x0d\x1c\xe8\x1a\x43\x27\x84"
        "\x0b\x54\xcb\x1d\x41\x99\x07\xfd"
        "\x1f\x62\x35\x9b\xad\x33\x65\x6e"
        "\x05\x86\x53\xd2\xe4\x17\x2a\x43"
        "\xac\xc9\x58\xdb\xec\x0c\xf0\xd4"
        "\x73\xdb\x45\x8c\xe1\xc0\x07\xaa"
        "\x6e\xb4\x0e\xac\x92\xaa\x0e\x65"
        "\x20\x2e\xdb\x4d\x7f\xee\xd3\x78"
        "\x8a\x77\xed\x6a\x6d\xdc\x5a\xbf"
        "\xbf\xbf\xf7\x2f\x22\xf4\x9e\x66"
        "\x7e\x45\x03\x2c\x1e\xe8\xcf\xb0"
        "\x79\xf8\x08\x9b\x43\xd1\x6a\xe6"
        "\xe5\x8f\x06\x3a\x4d\x93\xef\x36"
        "\x99\xb3\x2b\x9d\x00\xb3\x3c\x37"
        "\x2c\x10\xa4\x8d\x72\xf6\x4d\xa0"
        "\x25\x97\xf4\xfa\x23\xd5\x89\x0a"
        "\x4d\x65\x0a\xcb\x7b\xf8\xd2\x36";

    ExpectIntEQ(wc_Shake256Hash(data, len, hash, hashLen), 0);
    ExpectBufEQ(hash, expHash, hashLen);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Shake256Hash */

int test_wc_Shake256_Absorb(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake shake256;

    ExpectIntEQ(wc_InitShake256(&shake256, HEAP_HINT, INVALID_DEVID), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)
    ExpectIntEQ(wc_Shake256_Absorb(NULL     , NULL    , 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_Absorb(&shake256, NULL    , 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_Absorb(NULL     , NULL    , 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Shake256_Absorb(&shake256, NULL, 0), 0);
#endif
    ExpectIntEQ(wc_Shake256_Absorb(&shake256, (byte*)"a", 1), 0);

    wc_Shake256_Free(&shake256);
#endif
    return EXPECT_RESULT();
}

int test_wc_Shake256_SqueezeBlocks(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake shake256;
    byte hash[WC_SHA3_256_COUNT * 8];

    ExpectIntEQ(wc_InitShake256(&shake256, HEAP_HINT, INVALID_DEVID), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)
    ExpectIntEQ(wc_Shake256_SqueezeBlocks(NULL     , NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_SqueezeBlocks(&shake256, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_SqueezeBlocks(NULL     , NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_Shake256_SqueezeBlocks(&shake256, NULL, 0), 0);
#endif
    ExpectIntEQ(wc_Shake256_SqueezeBlocks(&shake256, hash, 1), 0);

    wc_Shake256_Free(&shake256);
#endif
    return EXPECT_RESULT();
}

#define TEST_SHAKE256_MAX_BLOCKS    3
int test_wc_Shake256_XOF(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake shake256;
    byte hash[WC_SHA3_256_COUNT * 8 * TEST_SHAKE256_MAX_BLOCKS];
    const char* expOut =
        "\x26\x16\x27\x51\x34\xae\xba\x85"
        "\x2e\x81\x43\x9a\x50\x72\x03\xd8"
        "\x1c\x58\x2b\x87\xb5\x89\x3a\x45"
        "\x66\xfe\x0e\x5a\xde\x60\x8e\xca"
        "\x2e\x27\x87\x25\x08\x0f\x13\x0e"
        "\x4e\x82\xb0\x6a\x4b\xe0\xca\x79"
        "\xcc\x55\xd8\x3f\xb4\x36\x74\x18"
        "\x5d\x2d\xb9\xa7\x95\x25\x6b\x44"
        "\x70\xc5\xa0\xa5\x21\x7e\x88\xed"
        "\x70\x67\x71\x57\x61\xb2\x3c\xb8"
        "\x89\x0f\x43\x28\x8a\xa9\xf1\x29"
        "\x4c\x71\x33\xe7\x96\x4e\x8b\x58"
        "\x7c\x16\x12\xed\xac\x10\xfb\xc8"
        "\xf8\xd2\x1f\xa3\x12\x29\x34\xb2"
        "\xf1\xaa\xcd\x4a\x10\x7a\xd1\x68"
        "\x00\xc1\xb2\xb8\x4b\xb2\xe5\x8a"
        "\xa3\xa0\xda\x73\x15\x3e\xb4\x50"
        "\x70\x3a\x3c\x7f\x8d\xd7\xa8\xfc"
        "\x03\x63\x0f\x80\x15\xd7\x05\x4f"
        "\x48\x42\x52\x12\x4f\xa1\x87\x85"
        "\xb9\xa4\x9b\x04\x17\xdb\x9f\x62"
        "\x9a\xbb\x07\x40\x56\x6c\xb0\xb9"
        "\x20\xf1\x85\x18\x36\x4f\x2e\x71"
        "\x16\x7d\xc0\xed\xb3\x89\x22\x3c"
        "\x93\xbd\xee\x71\x36\x59\x25\x7b"
        "\xae\x3c\x8b\x4b\xa8\xac\x63\xef"
        "\xd5\xfe\x6c\x07\x6b\xb9\x3b\x41"
        "\x8f\x30\x6d\xee\x7b\x1d\xfc\x6c"
        "\xda\x21\x1f\xaa\x63\x72\xc6\xf1"
        "\x51\x27\xce\xdc\x6b\xb2\x84\x7c"
        "\x79\x3b\xa3\xaf\xf0\xb7\x2d\xd8"
        "\x6e\xd9\xc5\x2e\x5e\x48\x42\xbc"
        "\xc3\xe5\x3a\xee\x82\x6c\x90\x21"
        "\xc9\x17\x9e\x17\x2c\x30\x11\x34"
        "\x0a\x53\x33\x93\x47\xca\x7d\x9e"
        "\x4e\xb4\xea\x70\xb7\x58\x39\xc2"
        "\x3c\x29\x6c\x9d\x75\x45\x88\x3d"
        "\x68\x5c\x1c\x6a\x52\x56\x6c\xe5"
        "\x28\x51\xf1\x64\xce\x0b\x45\x66"
        "\x7a\xc4\xb7\x42\x08\x39\x00\x17"
        "\xbe\x55\xd2\xda\x05\x5e\x70\xc3"
        "\xdc\x65\x36\x0b\xa9\x49\x95\xce"
        "\x8a\x04\x04\x4e\xb2\xff\xfa\x31"
        "\x07\x09\x5d\xe4\xa8\x04\x10\xf2"
        "\x84\x3c\x5d\xf4\x99\x5d\x75\x23"
        "\x03\x66\xed\xac\x07\xbb\x89\x61"
        "\xd6\xd0\x5f\x19\xd2\x2f\x1c\xd7"
        "\x73\x4d\x92\x12\x85\x07\x9c\x38"
        "\xd2\x50\x6e\xe5\xe8\x15\x6c\xf6"
        "\xde\x66\x9a\x10\x6f\xa1\xaf\x20"
        "\x99\x1d\xc0\xe6\xdc\xeb\xbc\x74";
    int i;
    int j;

    for (i = 1; i <= TEST_SHAKE256_MAX_BLOCKS; i++) {
        ExpectIntEQ(wc_InitShake256(&shake256, HEAP_HINT, INVALID_DEVID), 0);

        ExpectIntEQ(wc_Shake256_Absorb(&shake256, (byte*)"Starting point", 15),
            0);

        for (j = 0; j < TEST_SHAKE256_MAX_BLOCKS; j += i) {
            int cnt = TEST_SHAKE256_MAX_BLOCKS - j;
            if (i < cnt)
                cnt = i;
            ExpectIntEQ(wc_Shake256_SqueezeBlocks(&shake256,
                hash + WC_SHA3_256_COUNT * 8 * j, cnt), 0);
        }
        ExpectBufEQ(hash, expOut,
            WC_SHA3_256_COUNT * 8 * TEST_SHAKE256_MAX_BLOCKS);
    }

    wc_Shake256_Free(&shake256);
#endif
    return EXPECT_RESULT();
}

/*----------------------------------------------------------------------------*
 | CryptoCB SHAKE128/SHAKE256 End-to-End Offload Tests
 *----------------------------------------------------------------------------*/

#if defined(WOLF_CRYPTO_CB) && \
    (defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256))

#include <wolfssl/wolfcrypt/cryptocb.h>

#define TEST_CRYPTOCB_SHAKE_DEVID  12

static int cryptoCbShakeUpdateCalled = 0;
static int cryptoCbShakeFinalCalled = 0;

/* Mock CryptoCB callback that "offloads" SHAKE.  It routes the request back to
 * the software implementation, temporarily setting devId to INVALID_DEVID so
 * the nested wc_Shake*_Update/Final() call runs in software (a SHAKE lookup by
 * INVALID_DEVID finds no device) instead of recursing into the callback. */
static int test_CryptoCb_Shake_Cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    wc_Shake* shake;

    (void)ctx;

    if (devId != TEST_CRYPTOCB_SHAKE_DEVID)
        return CRYPTOCB_UNAVAILABLE;
    if (info->algo_type != WC_ALGO_TYPE_HASH)
        return CRYPTOCB_UNAVAILABLE;
    if (info->hash.type != WC_HASH_TYPE_SHAKE128 &&
        info->hash.type != WC_HASH_TYPE_SHAKE256)
        return CRYPTOCB_UNAVAILABLE;

    shake = info->hash.sha3; /* wc_Shake is a wc_Sha3 */
    if (shake == NULL)
        return BAD_FUNC_ARG;

    /* run software, no recursion */
    shake->devId = INVALID_DEVID;
#ifdef WOLFSSL_SHAKE128
    if (info->hash.type == WC_HASH_TYPE_SHAKE128) {
        if (info->hash.in != NULL) {
            cryptoCbShakeUpdateCalled++;
            ret = wc_Shake128_Update(shake, info->hash.in, info->hash.inSz);
        }
        if (info->hash.digest != NULL) {
            cryptoCbShakeFinalCalled++;
            ret = wc_Shake128_Final(shake, info->hash.digest, info->hash.outSz);
        }
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (info->hash.type == WC_HASH_TYPE_SHAKE256) {
        if (info->hash.in != NULL) {
            cryptoCbShakeUpdateCalled++;
            ret = wc_Shake256_Update(shake, info->hash.in, info->hash.inSz);
        }
        if (info->hash.digest != NULL) {
            cryptoCbShakeFinalCalled++;
            ret = wc_Shake256_Final(shake, info->hash.digest, info->hash.outSz);
        }
    }
#endif
    shake->devId = TEST_CRYPTOCB_SHAKE_DEVID;

    return ret;
}
#endif /* WOLF_CRYPTO_CB && (WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256) */

/*
 * Test: End-to-End SHAKE128 Offload via CryptoCB
 * Verifies that wc_Shake128_Update/Final route through a registered CryptoCB
 * device, that the callback is invoked for both the update and final calls, and
 * that the offloaded digest matches a software-only reference.
 */
int test_wc_CryptoCb_Shake128_HashOffload(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHAKE128)
    wc_Shake shake;
    wc_Shake ref;
    static const byte msg[] = {
        0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c
    };
    byte refDigest[32];
    byte digest[32];
    int devRegistered = 0;

    XMEMSET(&shake, 0, sizeof(shake));
    XMEMSET(&ref, 0, sizeof(ref));
    XMEMSET(refDigest, 0, sizeof(refDigest));
    XMEMSET(digest, 0, sizeof(digest));

    cryptoCbShakeUpdateCalled = 0;
    cryptoCbShakeFinalCalled = 0;

    /* Software-only reference digest (no devId, no callback). */
    ExpectIntEQ(wc_InitShake128(&ref, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Shake128_Update(&ref, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Shake128_Final(&ref, refDigest, (word32)sizeof(refDigest)), 0);
    wc_Shake128_Free(&ref);

    /* Register the offload callback. */
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_CRYPTOCB_SHAKE_DEVID,
        test_CryptoCb_Shake_Cb, NULL), 0);
    if (EXPECT_SUCCESS())
        devRegistered = 1;

    /* Drive the public streaming API with the offload devId. */
    ExpectIntEQ(wc_InitShake128(&shake, HEAP_HINT, TEST_CRYPTOCB_SHAKE_DEVID), 0);
    ExpectIntEQ(wc_Shake128_Update(&shake, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(cryptoCbShakeUpdateCalled, 1);
    ExpectIntEQ(wc_Shake128_Final(&shake, digest, (word32)sizeof(digest)), 0);
    ExpectIntEQ(cryptoCbShakeFinalCalled, 1);

    /* Offloaded digest must match the software reference. */
    ExpectBufEQ(digest, refDigest, sizeof(refDigest));

    wc_Shake128_Free(&shake);

    if (devRegistered)
        wc_CryptoCb_UnRegisterDevice(TEST_CRYPTOCB_SHAKE_DEVID);
#endif /* WOLF_CRYPTO_CB && WOLFSSL_SHAKE128 */
    return EXPECT_RESULT();
}

/*
 * Test: End-to-End SHAKE256 Offload via CryptoCB
 * Verifies that wc_Shake256_Update/Final route through a registered CryptoCB
 * device, that the callback is invoked for both the update and final calls, and
 * that the offloaded digest matches a software-only reference.
 */
int test_wc_CryptoCb_Shake256_HashOffload(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHAKE256)
    wc_Shake shake;
    wc_Shake ref;
    static const byte msg[] = {
        0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c
    };
    byte refDigest[64];
    byte digest[64];
    int devRegistered = 0;

    XMEMSET(&shake, 0, sizeof(shake));
    XMEMSET(&ref, 0, sizeof(ref));
    XMEMSET(refDigest, 0, sizeof(refDigest));
    XMEMSET(digest, 0, sizeof(digest));

    cryptoCbShakeUpdateCalled = 0;
    cryptoCbShakeFinalCalled = 0;

    /* Software-only reference digest (no devId, no callback). */
    ExpectIntEQ(wc_InitShake256(&ref, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Shake256_Update(&ref, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Shake256_Final(&ref, refDigest, (word32)sizeof(refDigest)), 0);
    wc_Shake256_Free(&ref);

    /* Register the offload callback. */
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_CRYPTOCB_SHAKE_DEVID,
        test_CryptoCb_Shake_Cb, NULL), 0);
    if (EXPECT_SUCCESS())
        devRegistered = 1;

    /* Drive the public streaming API with the offload devId. */
    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, TEST_CRYPTOCB_SHAKE_DEVID), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(cryptoCbShakeUpdateCalled, 1);
    ExpectIntEQ(wc_Shake256_Final(&shake, digest, (word32)sizeof(digest)), 0);
    ExpectIntEQ(cryptoCbShakeFinalCalled, 1);

    /* Offloaded digest must match the software reference. */
    ExpectBufEQ(digest, refDigest, sizeof(refDigest));

    wc_Shake256_Free(&shake);

    if (devRegistered)
        wc_CryptoCb_UnRegisterDevice(TEST_CRYPTOCB_SHAKE_DEVID);
#endif /* WOLF_CRYPTO_CB && WOLFSSL_SHAKE256 */
    return EXPECT_RESULT();
}


/*******************************************************************************
 * KMAC (NIST SP 800-185)
 ******************************************************************************/

#ifdef WOLFSSL_KMAC128
/* Exercise one KMAC128 known-answer vector three ways: the one-shot API (for
 * fixed-length output), single-Update streaming, and byte-at-a-time streaming.
 * All must produce the expected output. */
static int kmac128_kat(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, const byte* exp,
    word32 expLen, int xof)
{
    EXPECT_DECLS;
    wc_Kmac kmac;
    byte out[200];
    word32 i;

    /* One-shot API - fixed-length and XOF variants. */
    if (xof) {
        ExpectIntEQ(wc_Kmac128HashXof(key, keyLen, custom, customLen, in,
            inLen, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac128Hash(key, keyLen, custom, customLen, in, inLen,
            out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);

    /* Streaming with a single Update call. */
    ExpectIntEQ(wc_InitKmac128(&kmac, key, keyLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Update(&kmac, in, inLen), 0);
    if (xof) {
        ExpectIntEQ(wc_Kmac128_FinalXof(&kmac, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac128_Final(&kmac, out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);
    wc_Kmac128_Free(&kmac);

    /* Streaming one byte at a time must give the same result. */
    ExpectIntEQ(wc_InitKmac128(&kmac, key, keyLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    for (i = 0; i < inLen; i++) {
        ExpectIntEQ(wc_Kmac128_Update(&kmac, in + i, 1), 0);
    }
    if (xof) {
        ExpectIntEQ(wc_Kmac128_FinalXof(&kmac, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac128_Final(&kmac, out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);
    wc_Kmac128_Free(&kmac);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_KMAC128 */

int test_wc_Kmac128_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KMAC128
    static const byte key[32] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    };
    static const byte custom[21] = {
        'M', 'y', ' ', 'T', 'a', 'g', 'g', 'e',
        'd', ' ', 'A', 'p', 'p', 'l', 'i', 'c',
        'a', 't', 'i', 'o', 'n'
    };
    static const byte msg4[4] = { 0x00, 0x01, 0x02, 0x03 };
    static const byte fx1[32] = {
        0xe5, 0x78, 0x0b, 0x0d, 0x3e, 0xa6, 0xf7, 0xd3,
        0xa4, 0x29, 0xc5, 0x70, 0x6a, 0xa4, 0x3a, 0x00,
        0xfa, 0xdb, 0xd7, 0xd4, 0x96, 0x28, 0x83, 0x9e,
        0x31, 0x87, 0x24, 0x3f, 0x45, 0x6e, 0xe1, 0x4e,
    };
    static const byte fx2[32] = {
        0x3b, 0x1f, 0xba, 0x96, 0x3c, 0xd8, 0xb0, 0xb5,
        0x9e, 0x8c, 0x1a, 0x6d, 0x71, 0x88, 0x8b, 0x71,
        0x43, 0x65, 0x1a, 0xf8, 0xba, 0x0a, 0x70, 0x70,
        0xc0, 0x97, 0x9e, 0x28, 0x11, 0x32, 0x4a, 0xa5,
    };
    static const byte fx3[32] = {
        0x1f, 0x5b, 0x4e, 0x6c, 0xca, 0x02, 0x20, 0x9e,
        0x0d, 0xcb, 0x5c, 0xa6, 0x35, 0xb8, 0x9a, 0x15,
        0xe2, 0x71, 0xec, 0xc7, 0x60, 0x07, 0x1d, 0xfd,
        0x80, 0x5f, 0xaa, 0x38, 0xf9, 0x72, 0x92, 0x30,
    };
    /* 200-byte customization (msg200) - the KMAC bytepad block
     * (encode_string("KMAC") || encode_string(custom)) spans multiple rate
     * blocks.  Cross-checked against OpenSSL EVP_MAC and a Keccak reference. */
    static const byte kc_lc128[32] = {
        0xe5, 0xe3, 0xeb, 0x4b, 0x78, 0x7f, 0x80, 0xa6,
        0xa8, 0x57, 0xba, 0xf5, 0x61, 0x33, 0x4c, 0x67,
        0x50, 0x13, 0x6e, 0x1d, 0x6a, 0x5a, 0x67, 0x8d,
        0xec, 0x84, 0x86, 0x15, 0xdb, 0xdd, 0x18, 0x84,
    };
    static const byte xf1[32] = {
        0xcd, 0x83, 0x74, 0x0b, 0xbd, 0x92, 0xcc, 0xc8,
        0xcf, 0x03, 0x2b, 0x14, 0x81, 0xa0, 0xf4, 0x46,
        0x0e, 0x7c, 0xa9, 0xdd, 0x12, 0xb0, 0x8a, 0x0c,
        0x40, 0x31, 0x17, 0x8b, 0xac, 0xd6, 0xec, 0x35,
    };
    static const byte xf2[32] = {
        0x31, 0xa4, 0x45, 0x27, 0xb4, 0xed, 0x9f, 0x5c,
        0x61, 0x01, 0xd1, 0x1d, 0xe6, 0xd2, 0x6f, 0x06,
        0x20, 0xaa, 0x5c, 0x34, 0x1d, 0xef, 0x41, 0x29,
        0x96, 0x57, 0xfe, 0x9d, 0xf1, 0xa3, 0xb1, 0x6c,
    };
    static const byte xf3[32] = {
        0x47, 0x02, 0x6c, 0x7c, 0xd7, 0x93, 0x08, 0x4a,
        0xa0, 0x28, 0x3c, 0x25, 0x3e, 0xf6, 0x58, 0x49,
        0x0c, 0x0d, 0xb6, 0x14, 0x38, 0xb8, 0x32, 0x6f,
        0xe9, 0xbd, 0xdf, 0x28, 0x1b, 0x83, 0xae, 0x0f,
    };
    /* 1-byte customization string ("Z"). */
    static const byte cust1[1] = { 0x5a };
    static const byte c1_128[32] = {
        0xd8, 0x82, 0xbb, 0x4f, 0x03, 0xfa, 0x26, 0xef,
        0x8a, 0x80, 0x9b, 0xff, 0xec, 0x07, 0x6a, 0xe8,
        0x0e, 0xfe, 0xc6, 0x69, 0x1a, 0x46, 0x10, 0x2f,
        0x44, 0xb1, 0x97, 0x3b, 0xab, 0x3d, 0xd1, 0xf3,
    };
    /* Empty message. */
    static const byte em_128[32] = {
        0x58, 0xe8, 0xa9, 0x94, 0x28, 0xd5, 0x76, 0x17,
        0xaa, 0x5c, 0xae, 0xae, 0x1d, 0xe3, 0xdb, 0x10,
        0x8a, 0xf4, 0x11, 0x28, 0x6e, 0x64, 0xa0, 0x0a,
        0x6e, 0x1f, 0x30, 0x8c, 0x3f, 0xe9, 0x55, 0x7c,
    };
    /* Fixed-length output longer than the rate (168) - multi-block squeeze. */
    static const byte lo_128[200] = {
        0x38, 0x15, 0x8a, 0x1c, 0xae, 0x4e, 0x1a, 0x25,
        0xd8, 0x5f, 0x20, 0x31, 0x24, 0x6a, 0xde, 0x69,
        0x7b, 0x32, 0x92, 0xfe, 0xf8, 0x8b, 0x09, 0x23,
        0xa5, 0x9a, 0x02, 0xd1, 0xd5, 0x3b, 0x70, 0x46,
        0x53, 0xee, 0x72, 0x42, 0x66, 0x2a, 0x10, 0x79,
        0x6b, 0xa2, 0x07, 0x79, 0xd3, 0x00, 0xd5, 0x2d,
        0x74, 0x32, 0x01, 0x87, 0x41, 0x23, 0x3d, 0x58,
        0x72, 0x52, 0xd3, 0x1d, 0xc4, 0x8b, 0xdb, 0x82,
        0x33, 0x28, 0x5d, 0x4a, 0x4a, 0xcd, 0x65, 0x84,
        0x85, 0x09, 0xb0, 0x51, 0xa4, 0x48, 0xd8, 0x73,
        0x64, 0x92, 0x28, 0xb6, 0x62, 0x6e, 0x5e, 0xf8,
        0x17, 0xc7, 0xaf, 0x2d, 0xed, 0xc9, 0x1f, 0x12,
        0x0f, 0x8c, 0xa5, 0x35, 0xa1, 0xee, 0x30, 0x1f,
        0xae, 0x81, 0x86, 0xfd, 0xed, 0xe5, 0xa7, 0x61,
        0x81, 0xa4, 0x72, 0xa3, 0x2c, 0xfa, 0xd1, 0xdd,
        0xd1, 0x39, 0x1e, 0x16, 0x2f, 0x12, 0x4d, 0x4a,
        0x75, 0x72, 0xad, 0x8a, 0x20, 0x07, 0x66, 0x01,
        0xbc, 0xf8, 0x1e, 0x4b, 0x03, 0x91, 0xf3, 0xe9,
        0x5a, 0xef, 0xfa, 0x70, 0x8c, 0x33, 0xc1, 0x21,
        0x7c, 0x96, 0xbe, 0x6a, 0x4f, 0x02, 0xfb, 0xbc,
        0x2d, 0x3b, 0x3b, 0x6f, 0xfa, 0xeb, 0x5b, 0xfd,
        0x3b, 0xe4, 0xa2, 0xe0, 0x2b, 0x75, 0x99, 0x3f,
        0xcc, 0x04, 0xda, 0x6f, 0xac, 0x4b, 0xfc, 0xb2,
        0xa9, 0xf0, 0x57, 0x92, 0xa1, 0xa5, 0xcc, 0x80,
        0xca, 0x34, 0x18, 0x62, 0x43, 0xef, 0xdb, 0x31,
    };
    /* 200-byte key - the key bytepad block spans multiple rate blocks. */
    static const byte kmacLongK[32] = {
        0x7b, 0x8d, 0x1e, 0xc0, 0xb6, 0x48, 0x6e, 0xe5,
        0x92, 0x54, 0xc8, 0x54, 0x18, 0x58, 0xd4, 0xb7,
        0xa4, 0xf7, 0x0c, 0x30, 0x29, 0x7e, 0xf8, 0x59,
        0xa3, 0x4c, 0x48, 0x28, 0x2b, 0x5b, 0x49, 0xa1,
    };
    byte msg200[200];
    int i;

    for (i = 0; i < 200; i++) {
        msg200[i] = (byte)i;
    }

    /* Fixed-length KMAC128 samples. */
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), NULL, 0, msg4,
        (word32)sizeof(msg4), fx1, (word32)sizeof(fx1), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg4, (word32)sizeof(msg4), fx2,
        (word32)sizeof(fx2), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg200, (word32)sizeof(msg200), fx3,
        (word32)sizeof(fx3), 0), TEST_SUCCESS);
    /* Customization longer than the rate (168) - bytepad block spans blocks. */
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), msg200,
        (word32)sizeof(msg200), msg4, (word32)sizeof(msg4), kc_lc128,
        (word32)sizeof(kc_lc128), 0), TEST_SUCCESS);

    /* KMACXOF128 samples. */
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), NULL, 0, msg4,
        (word32)sizeof(msg4), xf1, (word32)sizeof(xf1), 1), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg4, (word32)sizeof(msg4), xf2,
        (word32)sizeof(xf2), 1), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg200, (word32)sizeof(msg200), xf3,
        (word32)sizeof(xf3), 1), TEST_SUCCESS);

    /* Edge cases: 1-byte customization, empty message, and a fixed-length
     * output longer than the KECCAK rate (multi-block squeeze). */
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), cust1,
        (word32)sizeof(cust1), msg4, (word32)sizeof(msg4), c1_128,
        (word32)sizeof(c1_128), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), NULL, 0, NULL, 0,
        em_128, (word32)sizeof(em_128), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac128_kat(key, (word32)sizeof(key), NULL, 0, msg4,
        (word32)sizeof(msg4), lo_128, (word32)sizeof(lo_128), 0),
        TEST_SUCCESS);
    /* 200-byte key (msg200) - key bytepad block spans multiple rate blocks. */
    ExpectIntEQ(kmac128_kat(msg200, (word32)sizeof(msg200), NULL, 0, msg4,
        (word32)sizeof(msg4), kmacLongK, (word32)sizeof(kmacLongK), 0),
        TEST_SUCCESS);
#endif /* WOLFSSL_KMAC128 */
    return EXPECT_RESULT();
}

int test_wc_Kmac128_api(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KMAC128
    wc_Kmac kmac;
#ifdef HAVE_FIPS
    static const byte key[KMAC_FIPS_MIN_KEY] =
                               { 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01
                               };
#else
    static const byte key[4] = { 0x00, 0x01, 0x02, 0x03 };
#endif
    static const byte msg[4] = { 0x00, 0x01, 0x02, 0x03 };
    byte out[200];
    byte out2[200];

    /* wc_InitKmac128 argument checks. */
    ExpectIntEQ(wc_InitKmac128(NULL, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac128(&kmac, NULL, 4, NULL, 0, HEAP_HINT,
        INVALID_DEVID), BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 4,
        HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);

#ifdef HAVE_FIPS
    ExpectIntEQ(wc_InitKmac128(&kmac, NULL, 0, NULL, 0, HEAP_HINT,
        INVALID_DEVID), KMAC_MIN_KEYLEN_E);
#else
    /* NULL key with zero length is allowed. */
    ExpectIntEQ(wc_InitKmac128(&kmac, NULL, 0, NULL, 0, HEAP_HINT,
        INVALID_DEVID), 0);
#endif

    wc_Kmac128_Free(&kmac);

    /* wc_Kmac128_Update argument checks. */
    ExpectIntEQ(wc_Kmac128_Update(NULL, msg, (word32)sizeof(msg)),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Update(&kmac, NULL, 4), BAD_FUNC_ARG);
    /* NULL message with zero length is allowed. */
    ExpectIntEQ(wc_Kmac128_Update(&kmac, NULL, 0), 0);

    /* wc_Kmac128_Final / wc_Kmac128_FinalXof argument checks. */
    ExpectIntEQ(wc_Kmac128_Final(NULL, out, 32), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac128_Final(&kmac, NULL, 32), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac128_FinalXof(NULL, out, 32), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac128_FinalXof(&kmac, NULL, 32), BAD_FUNC_ARG);
    /* Finalize the still-open operation and free it. */
    ExpectIntEQ(wc_Kmac128_Final(&kmac, out, 32), 0);
    wc_Kmac128_Free(&kmac);

    /* wc_Kmac128Hash propagates argument errors. */
    ExpectIntEQ(wc_Kmac128Hash(NULL, 4, NULL, 0, msg, (word32)sizeof(msg),
        out, 32), BAD_FUNC_ARG);

    /* Freeing NULL must be safe. */
    wc_Kmac128_Free(NULL);

    /* Output length is bound into fixed-length KMAC: a 16-byte tag is not a
     * prefix of a 32-byte tag over the same input. */
    ExpectIntEQ(wc_Kmac128Hash(key, (word32)sizeof(key), NULL, 0, msg,
        (word32)sizeof(msg), out, 16), 0);
    ExpectIntEQ(wc_Kmac128Hash(key, (word32)sizeof(key), NULL, 0, msg,
        (word32)sizeof(msg), out2, 32), 0);
    ExpectIntNE(XMEMCMP(out, out2, 16), 0);

    /* XOF output is not length-bound: a short squeeze is a prefix of a longer
     * one, including a squeeze that spans multiple rate blocks (168 bytes). */
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Update(&kmac, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Kmac128_FinalXof(&kmac, out, 32), 0);
    wc_Kmac128_Free(&kmac);
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Update(&kmac, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Kmac128_FinalXof(&kmac, out2, 200), 0);
    wc_Kmac128_Free(&kmac);
    ExpectBufEQ(out, out2, 32);

    /* An empty message is valid. */
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Final(&kmac, out, 32), 0);
    wc_Kmac128_Free(&kmac);
#endif /* WOLFSSL_KMAC128 */
    return EXPECT_RESULT();
}

#ifdef WOLFSSL_KMAC256
/* KMAC256 analogue of kmac128_kat(). */
static int kmac256_kat(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, const byte* exp,
    word32 expLen, int xof)
{
    EXPECT_DECLS;
    wc_Kmac kmac;
    byte out[200];
    word32 i;

    if (xof) {
        ExpectIntEQ(wc_Kmac256HashXof(key, keyLen, custom, customLen, in,
            inLen, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac256Hash(key, keyLen, custom, customLen, in, inLen,
            out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);

    ExpectIntEQ(wc_InitKmac256(&kmac, key, keyLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac256_Update(&kmac, in, inLen), 0);
    if (xof) {
        ExpectIntEQ(wc_Kmac256_FinalXof(&kmac, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac256_Final(&kmac, out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);
    wc_Kmac256_Free(&kmac);

    ExpectIntEQ(wc_InitKmac256(&kmac, key, keyLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    for (i = 0; i < inLen; i++) {
        ExpectIntEQ(wc_Kmac256_Update(&kmac, in + i, 1), 0);
    }
    if (xof) {
        ExpectIntEQ(wc_Kmac256_FinalXof(&kmac, out, expLen), 0);
    }
    else {
        ExpectIntEQ(wc_Kmac256_Final(&kmac, out, expLen), 0);
    }
    ExpectBufEQ(out, exp, expLen);
    wc_Kmac256_Free(&kmac);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_KMAC256 */

int test_wc_Kmac256_KATs(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KMAC256
    static const byte key[32] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    };
    static const byte custom[21] = {
        'M', 'y', ' ', 'T', 'a', 'g', 'g', 'e',
        'd', ' ', 'A', 'p', 'p', 'l', 'i', 'c',
        'a', 't', 'i', 'o', 'n'
    };
    static const byte msg4[4] = { 0x00, 0x01, 0x02, 0x03 };
    static const byte fx4[64] = {
        0x20, 0xc5, 0x70, 0xc3, 0x13, 0x46, 0xf7, 0x03,
        0xc9, 0xac, 0x36, 0xc6, 0x1c, 0x03, 0xcb, 0x64,
        0xc3, 0x97, 0x0d, 0x0c, 0xfc, 0x78, 0x7e, 0x9b,
        0x79, 0x59, 0x9d, 0x27, 0x3a, 0x68, 0xd2, 0xf7,
        0xf6, 0x9d, 0x4c, 0xc3, 0xde, 0x9d, 0x10, 0x4a,
        0x35, 0x16, 0x89, 0xf2, 0x7c, 0xf6, 0xf5, 0x95,
        0x1f, 0x01, 0x03, 0xf3, 0x3f, 0x4f, 0x24, 0x87,
        0x10, 0x24, 0xd9, 0xc2, 0x77, 0x73, 0xa8, 0xdd,
    };
    static const byte fx5[64] = {
        0x75, 0x35, 0x8c, 0xf3, 0x9e, 0x41, 0x49, 0x4e,
        0x94, 0x97, 0x07, 0x92, 0x7c, 0xee, 0x0a, 0xf2,
        0x0a, 0x3f, 0xf5, 0x53, 0x90, 0x4c, 0x86, 0xb0,
        0x8f, 0x21, 0xcc, 0x41, 0x4b, 0xcf, 0xd6, 0x91,
        0x58, 0x9d, 0x27, 0xcf, 0x5e, 0x15, 0x36, 0x9c,
        0xbb, 0xff, 0x8b, 0x9a, 0x4c, 0x2e, 0xb1, 0x78,
        0x00, 0x85, 0x5d, 0x02, 0x35, 0xff, 0x63, 0x5d,
        0xa8, 0x25, 0x33, 0xec, 0x6b, 0x75, 0x9b, 0x69,
    };
    static const byte fx6[64] = {
        0xb5, 0x86, 0x18, 0xf7, 0x1f, 0x92, 0xe1, 0xd5,
        0x6c, 0x1b, 0x8c, 0x55, 0xdd, 0xd7, 0xcd, 0x18,
        0x8b, 0x97, 0xb4, 0xca, 0x4d, 0x99, 0x83, 0x1e,
        0xb2, 0x69, 0x9a, 0x83, 0x7d, 0xa2, 0xe4, 0xd9,
        0x70, 0xfb, 0xac, 0xfd, 0xe5, 0x00, 0x33, 0xae,
        0xa5, 0x85, 0xf1, 0xa2, 0x70, 0x85, 0x10, 0xc3,
        0x2d, 0x07, 0x88, 0x08, 0x01, 0xbd, 0x18, 0x28,
        0x98, 0xfe, 0x47, 0x68, 0x76, 0xfc, 0x89, 0x65,
    };
    static const byte xf4[64] = {
        0x17, 0x55, 0x13, 0x3f, 0x15, 0x34, 0x75, 0x2a,
        0xad, 0x07, 0x48, 0xf2, 0xc7, 0x06, 0xfb, 0x5c,
        0x78, 0x45, 0x12, 0xca, 0xb8, 0x35, 0xcd, 0x15,
        0x67, 0x6b, 0x16, 0xc0, 0xc6, 0x64, 0x7f, 0xa9,
        0x6f, 0xaa, 0x7a, 0xf6, 0x34, 0xa0, 0xbf, 0x8f,
        0xf6, 0xdf, 0x39, 0x37, 0x4f, 0xa0, 0x0f, 0xad,
        0x9a, 0x39, 0xe3, 0x22, 0xa7, 0xc9, 0x20, 0x65,
        0xa6, 0x4e, 0xb1, 0xfb, 0x08, 0x01, 0xeb, 0x2b,
    };
    static const byte xf5[64] = {
        0xff, 0x7b, 0x17, 0x1f, 0x1e, 0x8a, 0x2b, 0x24,
        0x68, 0x3e, 0xed, 0x37, 0x83, 0x0e, 0xe7, 0x97,
        0x53, 0x8b, 0xa8, 0xdc, 0x56, 0x3f, 0x6d, 0xa1,
        0xe6, 0x67, 0x39, 0x1a, 0x75, 0xed, 0xc0, 0x2c,
        0xa6, 0x33, 0x07, 0x9f, 0x81, 0xce, 0x12, 0xa2,
        0x5f, 0x45, 0x61, 0x5e, 0xc8, 0x99, 0x72, 0x03,
        0x1d, 0x18, 0x33, 0x73, 0x31, 0xd2, 0x4c, 0xeb,
        0x8f, 0x8c, 0xa8, 0xe6, 0xa1, 0x9f, 0xd9, 0x8b,
    };
    static const byte xf6[64] = {
        0xd5, 0xbe, 0x73, 0x1c, 0x95, 0x4e, 0xd7, 0x73,
        0x28, 0x46, 0xbb, 0x59, 0xdb, 0xe3, 0xa8, 0xe3,
        0x0f, 0x83, 0xe7, 0x7a, 0x4b, 0xff, 0x44, 0x59,
        0xf2, 0xf1, 0xc2, 0xb4, 0xec, 0xeb, 0xb8, 0xce,
        0x67, 0xba, 0x01, 0xc6, 0x2e, 0x8a, 0xb8, 0x57,
        0x8d, 0x2d, 0x49, 0x9b, 0xd1, 0xbb, 0x27, 0x67,
        0x68, 0x78, 0x11, 0x90, 0x02, 0x0a, 0x30, 0x6a,
        0x97, 0xde, 0x28, 0x1d, 0xcc, 0x30, 0x30, 0x5d,
    };
    /* Fixed-length output longer than the rate (136) - multi-block squeeze. */
    static const byte lo_256[200] = {
        0x78, 0x44, 0xa5, 0x78, 0x6d, 0xda, 0x33, 0x4a,
        0xc4, 0x05, 0xc1, 0x66, 0x6f, 0x92, 0x2a, 0x29,
        0xb3, 0x6f, 0x59, 0xc1, 0x82, 0xfa, 0xe9, 0x3b,
        0xa7, 0x3e, 0x73, 0x50, 0x27, 0x7c, 0xb5, 0xff,
        0x76, 0xd7, 0x1d, 0x54, 0xdd, 0xa6, 0xe6, 0x46,
        0x28, 0x2f, 0x2c, 0xe8, 0x95, 0x42, 0x7c, 0x8d,
        0x81, 0x14, 0xd1, 0xb3, 0x3d, 0xca, 0xbf, 0x85,
        0xcc, 0x36, 0x9e, 0x37, 0x5d, 0x97, 0x23, 0xb7,
        0x83, 0xd4, 0x19, 0xb2, 0x76, 0xe7, 0x06, 0xbd,
        0x68, 0x81, 0xa2, 0x23, 0x00, 0x4a, 0x80, 0x5a,
        0xae, 0xbd, 0x5b, 0xed, 0xd3, 0x04, 0x0e, 0x9a,
        0x5c, 0x32, 0x18, 0x2a, 0x17, 0x3f, 0x31, 0xdf,
        0x11, 0x5f, 0x25, 0x73, 0xff, 0x17, 0x1c, 0x5f,
        0x25, 0xb7, 0x0b, 0x2a, 0xc2, 0x57, 0x90, 0xe3,
        0x77, 0xfb, 0x34, 0x87, 0x47, 0xd2, 0xcd, 0xc6,
        0xf9, 0xd6, 0xcf, 0xee, 0x73, 0x23, 0x1b, 0xb7,
        0x09, 0x8c, 0x9a, 0x49, 0x20, 0x7a, 0xf5, 0xcb,
        0x00, 0xf1, 0xcb, 0xb4, 0xcb, 0x43, 0xd3, 0x74,
        0xee, 0xce, 0x1f, 0xd4, 0x05, 0x69, 0xf0, 0x67,
        0x74, 0x71, 0x33, 0x1b, 0x06, 0xda, 0xbb, 0xc2,
        0x2a, 0xbc, 0x88, 0x12, 0x3f, 0x79, 0x50, 0x19,
        0xa3, 0x5d, 0x91, 0xc4, 0x24, 0x86, 0x88, 0x8f,
        0xfe, 0x61, 0x11, 0x9d, 0x18, 0xd3, 0xd1, 0x9a,
        0x99, 0x83, 0x16, 0xb2, 0xed, 0xc5, 0x20, 0x07,
        0x5e, 0x8c, 0xb2, 0xb0, 0x2f, 0x96, 0x25, 0x07,
    };
    /* 150-byte customization (msg200[0..149]) - the KMAC bytepad block spans
     * multiple rate blocks.  Cross-checked vs OpenSSL and a Keccak ref. */
    static const byte kc_lc256[32] = {
        0xec, 0x73, 0x98, 0x6b, 0x47, 0x90, 0xea, 0xab,
        0x9e, 0x1a, 0x95, 0xf8, 0x08, 0xbe, 0x66, 0x99,
        0x70, 0x5f, 0xcf, 0x27, 0x8d, 0x76, 0xf0, 0x66,
        0x18, 0x29, 0xbb, 0x2d, 0x25, 0x6b, 0xa4, 0x1e,
    };
    byte msg200[200];
    int i;

    for (i = 0; i < 200; i++) {
        msg200[i] = (byte)i;
    }

    /* Fixed-length KMAC256 samples. */
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg4, (word32)sizeof(msg4), fx4,
        (word32)sizeof(fx4), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), NULL, 0, msg200,
        (word32)sizeof(msg200), fx5, (word32)sizeof(fx5), 0), TEST_SUCCESS);
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg200, (word32)sizeof(msg200), fx6,
        (word32)sizeof(fx6), 0), TEST_SUCCESS);
    /* Customization longer than the rate (136) - bytepad block spans blocks. */
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), msg200, 150, msg4,
        (word32)sizeof(msg4), kc_lc256, (word32)sizeof(kc_lc256), 0),
        TEST_SUCCESS);

    /* KMACXOF256 samples. */
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg4, (word32)sizeof(msg4), xf4,
        (word32)sizeof(xf4), 1), TEST_SUCCESS);
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), NULL, 0, msg200,
        (word32)sizeof(msg200), xf5, (word32)sizeof(xf5), 1), TEST_SUCCESS);
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), custom,
        (word32)sizeof(custom), msg200, (word32)sizeof(msg200), xf6,
        (word32)sizeof(xf6), 1), TEST_SUCCESS);

    /* Fixed-length output longer than the rate - multi-block squeeze. */
    ExpectIntEQ(kmac256_kat(key, (word32)sizeof(key), NULL, 0, msg4,
        (word32)sizeof(msg4), lo_256, (word32)sizeof(lo_256), 0),
        TEST_SUCCESS);
#endif /* WOLFSSL_KMAC256 */
    return EXPECT_RESULT();
}

int test_wc_Kmac256_api(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KMAC256
    wc_Kmac kmac;
#ifdef HAVE_FIPS
    static const byte key[KMAC_FIPS_MIN_KEY] =
                               { 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01
                               };
#else
    static const byte key[4] = { 0x00, 0x01, 0x02, 0x03 };
#endif
    static const byte msg[4] = { 0x00, 0x01, 0x02, 0x03 };
    byte out[200];
    byte out2[200];

    /* wc_InitKmac256 argument checks. */
    ExpectIntEQ(wc_InitKmac256(NULL, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac256(&kmac, NULL, 4, NULL, 0, HEAP_HINT,
        INVALID_DEVID), BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac256(&kmac, key, (word32)sizeof(key), NULL, 4,
        HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_InitKmac256(&kmac, NULL, 0, NULL, 0, HEAP_HINT,
        INVALID_DEVID), 0);
#endif
    wc_Kmac256_Free(&kmac);

    /* wc_Kmac256_Update argument checks. */
    ExpectIntEQ(wc_Kmac256_Update(NULL, msg, (word32)sizeof(msg)),
        BAD_FUNC_ARG);
    ExpectIntEQ(wc_InitKmac256(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac256_Update(&kmac, NULL, 4), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac256_Update(&kmac, NULL, 0), 0);

    /* wc_Kmac256_Final / wc_Kmac256_FinalXof argument checks. */
    ExpectIntEQ(wc_Kmac256_Final(NULL, out, 64), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac256_Final(&kmac, NULL, 64), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac256_FinalXof(NULL, out, 64), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac256_FinalXof(&kmac, NULL, 64), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac256_Final(&kmac, out, 64), 0);
    wc_Kmac256_Free(&kmac);

    /* wc_Kmac256Hash propagates argument errors. */
    ExpectIntEQ(wc_Kmac256Hash(NULL, 4, NULL, 0, msg, (word32)sizeof(msg),
        out, 64), BAD_FUNC_ARG);

    wc_Kmac256_Free(NULL);

    /* Output length is bound into fixed-length KMAC. */
    ExpectIntEQ(wc_Kmac256Hash(key, (word32)sizeof(key), NULL, 0, msg,
        (word32)sizeof(msg), out, 32), 0);
    ExpectIntEQ(wc_Kmac256Hash(key, (word32)sizeof(key), NULL, 0, msg,
        (word32)sizeof(msg), out2, 64), 0);
    ExpectIntNE(XMEMCMP(out, out2, 32), 0);

    /* XOF prefix property across a multi-block (136-byte rate) squeeze. */
    ExpectIntEQ(wc_InitKmac256(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac256_Update(&kmac, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Kmac256_FinalXof(&kmac, out, 64), 0);
    wc_Kmac256_Free(&kmac);
    ExpectIntEQ(wc_InitKmac256(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac256_Update(&kmac, msg, (word32)sizeof(msg)), 0);
    ExpectIntEQ(wc_Kmac256_FinalXof(&kmac, out2, 200), 0);
    wc_Kmac256_Free(&kmac);
    ExpectBufEQ(out, out2, 64);

    /* An empty message is valid. */
    ExpectIntEQ(wc_InitKmac256(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac256_Final(&kmac, out, 64), 0);
    wc_Kmac256_Free(&kmac);
#endif /* WOLFSSL_KMAC256 */
    return EXPECT_RESULT();
}

/*******************************************************************************
 * cSHAKE (NIST SP 800-185)
 ******************************************************************************/

#ifdef WOLFSSL_CSHAKE128
/* Run one cSHAKE128 known-answer vector via one-shot and streaming APIs. */
static int cshake128_kat(const byte* name, word32 nameLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, const byte* exp,
    word32 expLen)
{
    EXPECT_DECLS;
    wc_Cshake cshake;
    byte out[200];
    word32 i;

    ExpectIntEQ(wc_Cshake128(name, nameLen, custom, customLen, in, inLen,
        out, expLen), 0);
    ExpectBufEQ(out, exp, expLen);

    ExpectIntEQ(wc_InitCshake128(&cshake, name, nameLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Cshake128_Update(&cshake, in, inLen), 0);
    ExpectIntEQ(wc_Cshake128_Final(&cshake, out, expLen), 0);
    ExpectBufEQ(out, exp, expLen);
    wc_Cshake128_Free(&cshake);

    ExpectIntEQ(wc_InitCshake128(&cshake, name, nameLen, custom, customLen,
        HEAP_HINT, INVALID_DEVID), 0);
    for (i = 0; i < inLen; i++) {
        ExpectIntEQ(wc_Cshake128_Update(&cshake, in + i, 1), 0);
    }
    ExpectIntEQ(wc_Cshake128_Final(&cshake, out, expLen), 0);
    ExpectBufEQ(out, exp, expLen);
    wc_Cshake128_Free(&cshake);

    return EXPECT_RESULT();
}
#endif /* WOLFSSL_CSHAKE128 */

int test_wc_Cshake128(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_CSHAKE128
    /* "Email Signature", "Func", "Cust" per NIST cSHAKE samples / extra. */
    static const byte sName[4] = { 'F', 'u', 'n', 'c' };
    static const byte sCust[4] = { 'C', 'u', 's', 't' };
    static const byte emailS[15] = {
        'E', 'm', 'a', 'i', 'l', ' ', 'S', 'i',
        'g', 'n', 'a', 't', 'u', 'r', 'e'
    };
    static const byte msg4[4] = { 0x00, 0x01, 0x02, 0x03 };
        static const byte cs1_128[32] = {
            0xc1, 0xc3, 0x69, 0x25, 0xb6, 0x40, 0x9a, 0x04,
            0xf1, 0xb5, 0x04, 0xfc, 0xbc, 0xa9, 0xd8, 0x2b,
            0x40, 0x17, 0x27, 0x7c, 0xb5, 0xed, 0x2b, 0x20,
            0x65, 0xfc, 0x1d, 0x38, 0x14, 0xd5, 0xaa, 0xf5,
        };
        static const byte cs2_128[32] = {
            0xc5, 0x22, 0x1d, 0x50, 0xe4, 0xf8, 0x22, 0xd9,
            0x6a, 0x2e, 0x88, 0x81, 0xa9, 0x61, 0x42, 0x0f,
            0x29, 0x4b, 0x7b, 0x24, 0xfe, 0x3d, 0x20, 0x94,
            0xba, 0xed, 0x2c, 0x65, 0x24, 0xcc, 0x16, 0x6b,
        };
        static const byte csn_128[32] = {
            0x6d, 0xfa, 0x21, 0x3d, 0xd3, 0x43, 0x20, 0x05,
            0x3a, 0x78, 0x5b, 0x8a, 0xd8, 0x0f, 0x11, 0x12,
            0x8d, 0x5b, 0xe9, 0x76, 0x34, 0x07, 0x2c, 0xad,
            0xea, 0xc4, 0x1c, 0xfa, 0xc0, 0x8d, 0x7f, 0xb5,
        };
        static const byte cslong_128[200] = {
            0xc1, 0xc3, 0x69, 0x25, 0xb6, 0x40, 0x9a, 0x04,
            0xf1, 0xb5, 0x04, 0xfc, 0xbc, 0xa9, 0xd8, 0x2b,
            0x40, 0x17, 0x27, 0x7c, 0xb5, 0xed, 0x2b, 0x20,
            0x65, 0xfc, 0x1d, 0x38, 0x14, 0xd5, 0xaa, 0xf5,
            0x9c, 0xbc, 0xe8, 0x30, 0x07, 0x9c, 0x45, 0x2a,
            0xbd, 0xeb, 0x87, 0x53, 0x66, 0xa4, 0x9e, 0xbf,
            0xe7, 0x5b, 0x89, 0xef, 0x17, 0x39, 0x6e, 0x34,
            0x89, 0x8e, 0x90, 0x48, 0x30, 0xb0, 0xe1, 0x36,
            0xf1, 0x92, 0xcc, 0x06, 0x2b, 0xd2, 0xe1, 0x16,
            0xa0, 0x7f, 0xe6, 0xeb, 0x9b, 0x4f, 0xc9, 0xba,
            0x25, 0x4d, 0x7d, 0xbf, 0x6e, 0xc9, 0x86, 0x0c,
            0x5b, 0xa3, 0x86, 0x86, 0xea, 0x29, 0x4d, 0xd7,
            0x72, 0xc1, 0xfa, 0xd2, 0x0e, 0x42, 0x14, 0xaa,
            0xd5, 0x39, 0x4a, 0x26, 0x71, 0x01, 0xe4, 0xc9,
            0xd0, 0x9c, 0xe8, 0x02, 0x81, 0xdb, 0x7e, 0x91,
            0x70, 0xd6, 0x05, 0x2a, 0xbe, 0x6e, 0x5a, 0x93,
            0x57, 0x13, 0xe2, 0xc6, 0x23, 0x65, 0xf5, 0x9c,
            0x9a, 0x7d, 0xf5, 0xa9, 0x8e, 0x40, 0x40, 0xff,
            0x70, 0xe8, 0x50, 0x60, 0x10, 0x7f, 0x59, 0x6a,
            0xcd, 0xbf, 0x87, 0x6e, 0x67, 0x8d, 0x73, 0xf2,
            0xd4, 0x49, 0x43, 0x02, 0x22, 0x62, 0x19, 0xac,
            0xbf, 0x98, 0xd7, 0x04, 0x86, 0xaf, 0xf1, 0xd5,
            0xbb, 0xb1, 0xd5, 0x16, 0x2e, 0x02, 0x09, 0xb5,
            0xaf, 0xcc, 0x7a, 0x07, 0x29, 0x4a, 0x53, 0x09,
            0x45, 0xc3, 0xbc, 0x0b, 0x35, 0x1a, 0x05, 0x77,
        };
    /* Long function name N (60 bytes) - exercises the separate-absorb path
     * for the customization block (name too large to batch). */
    static const byte csLongN[32] = {
        0xb6, 0xee, 0x3a, 0x07, 0x14, 0x68, 0xda, 0x79,
        0x0a, 0x60, 0x3a, 0x49, 0x07, 0xf2, 0xca, 0x98,
        0x27, 0xb8, 0xf1, 0xd6, 0x3a, 0x94, 0x00, 0x3a,
        0xc5, 0x1f, 0xd7, 0x85, 0x85, 0xc7, 0xa0, 0x45,
    };
    /* Long customization S (200 bytes) - spans multiple rate blocks. */
    static const byte csLongS[32] = {
        0xf6, 0x42, 0x0e, 0x41, 0x80, 0x8c, 0xe8, 0x73,
        0xd0, 0x0f, 0x26, 0xb6, 0x28, 0x1e, 0xad, 0xaa,
        0x81, 0x86, 0x08, 0x69, 0xab, 0xc9, 0x4e, 0x95,
        0x5a, 0xbd, 0x88, 0xac, 0xe5, 0x8b, 0x56, 0x75,
    };
    /* Long function name N (200 bytes, S = "Cust") - the name overflows the
     * block, so the customization block spans multiple rate blocks. */
    static const byte cs_ln128[32] = {
        0xb9, 0x8f, 0x89, 0x0a, 0x12, 0x0e, 0x93, 0x35,
        0xbf, 0xe2, 0x48, 0x97, 0x71, 0x81, 0x76, 0xb9,
        0x01, 0x28, 0x6d, 0x2c, 0xe6, 0x98, 0x07, 0xb8,
        0x0b, 0x13, 0x7b, 0x2e, 0x1c, 0x61, 0x5d, 0xf6,
    };
    byte msg200[200];
#ifdef WOLFSSL_SHAKE128
    byte shakeOut[32];
    byte cshakeOut[32];
    wc_Shake shake;
#endif
    int i;

    for (i = 0; i < 200; i++) {
        msg200[i] = (byte)i;
    }

    /* NIST cSHAKE128 samples (N empty, S = "Email Signature"). */
    ExpectIntEQ(cshake128_kat(NULL, 0, emailS, (word32)sizeof(emailS), msg4,
        (word32)sizeof(msg4), cs1_128, (word32)sizeof(cs1_128)), TEST_SUCCESS);
    ExpectIntEQ(cshake128_kat(NULL, 0, emailS, (word32)sizeof(emailS), msg200,
        (word32)sizeof(msg200), cs2_128, (word32)sizeof(cs2_128)),
        TEST_SUCCESS);
    /* Non-empty function name N. */
    ExpectIntEQ(cshake128_kat(sName, (word32)sizeof(sName), sCust,
        (word32)sizeof(sCust), msg4, (word32)sizeof(msg4), csn_128,
        (word32)sizeof(csn_128)), TEST_SUCCESS);
    /* Output longer than the rate - multi-block squeeze. */
    ExpectIntEQ(cshake128_kat(NULL, 0, emailS, (word32)sizeof(emailS), msg4,
        (word32)sizeof(msg4), cslong_128, (word32)sizeof(cslong_128)),
        TEST_SUCCESS);
    /* Long function name (msg200[0..59]) - separate-absorb branch. */
    ExpectIntEQ(cshake128_kat(msg200, 60, sCust, (word32)sizeof(sCust), msg4,
        (word32)sizeof(msg4), csLongN, (word32)sizeof(csLongN)), TEST_SUCCESS);
    /* Long customization (200 bytes) - customization block spans blocks. */
    ExpectIntEQ(cshake128_kat(NULL, 0, msg200, (word32)sizeof(msg200), msg4,
        (word32)sizeof(msg4), csLongS, (word32)sizeof(csLongS)), TEST_SUCCESS);
    /* Long function name (200 bytes) - name overflows the block. */
    ExpectIntEQ(cshake128_kat(msg200, (word32)sizeof(msg200), sCust,
        (word32)sizeof(sCust), msg4, (word32)sizeof(msg4), cs_ln128,
        (word32)sizeof(cs_ln128)), TEST_SUCCESS);

#ifdef WOLFSSL_SHAKE128
    /* With empty name and customization, cSHAKE reduces to plain SHAKE.
     * (WOLFSSL_CSHAKE128 always implies WOLFSSL_SHAKE128 via the header's
     * feature derivation; the guard is defensive.) */
    ExpectIntEQ(wc_Cshake128(NULL, 0, NULL, 0, msg4, (word32)sizeof(msg4),
        cshakeOut, (word32)sizeof(cshakeOut)), 0);
    ExpectIntEQ(wc_InitShake128(&shake, HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Shake128_Update(&shake, msg4, (word32)sizeof(msg4)), 0);
    ExpectIntEQ(wc_Shake128_Final(&shake, shakeOut,
        (word32)sizeof(shakeOut)), 0);
    ExpectBufEQ(cshakeOut, shakeOut, (word32)sizeof(shakeOut));
    wc_Shake128_Free(&shake);
#endif

    /* Argument checks. */
    {
        wc_Cshake cshake;
        byte out[32];

        ExpectIntEQ(wc_InitCshake128(NULL, NULL, 0, emailS,
            (word32)sizeof(emailS), HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);
        ExpectIntEQ(wc_InitCshake128(&cshake, sName, 4, NULL, 4, HEAP_HINT,
            INVALID_DEVID), BAD_FUNC_ARG);
        ExpectIntEQ(wc_InitCshake128(&cshake, NULL, 4, NULL, 0, HEAP_HINT,
            INVALID_DEVID), BAD_FUNC_ARG);
        ExpectIntEQ(wc_InitCshake128(&cshake, NULL, 0, emailS,
            (word32)sizeof(emailS), HEAP_HINT, INVALID_DEVID), 0);
        ExpectIntEQ(wc_Cshake128_Update(NULL, msg4, 4), BAD_FUNC_ARG);
        ExpectIntEQ(wc_Cshake128_Update(&cshake, NULL, 4), BAD_FUNC_ARG);
        ExpectIntEQ(wc_Cshake128_Final(NULL, out, 32), BAD_FUNC_ARG);
        ExpectIntEQ(wc_Cshake128_Final(&cshake, NULL, 32), BAD_FUNC_ARG);
        ExpectIntEQ(wc_Cshake128_Final(&cshake, out, 32), 0);
        wc_Cshake128_Free(&cshake);
        wc_Cshake128_Free(NULL);
    }
#endif /* WOLFSSL_CSHAKE128 */
    return EXPECT_RESULT();
}

int test_wc_Cshake256(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_CSHAKE256
    static const byte emailS[15] = {
        'E', 'm', 'a', 'i', 'l', ' ', 'S', 'i',
        'g', 'n', 'a', 't', 'u', 'r', 'e'
    };
    static const byte msg4[4] = { 0x00, 0x01, 0x02, 0x03 };
        static const byte cs3_256[64] = {
            0xd0, 0x08, 0x82, 0x8e, 0x2b, 0x80, 0xac, 0x9d,
            0x22, 0x18, 0xff, 0xee, 0x1d, 0x07, 0x0c, 0x48,
            0xb8, 0xe4, 0xc8, 0x7b, 0xff, 0x32, 0xc9, 0x69,
            0x9d, 0x5b, 0x68, 0x96, 0xee, 0xe0, 0xed, 0xd1,
            0x64, 0x02, 0x0e, 0x2b, 0xe0, 0x56, 0x08, 0x58,
            0xd9, 0xc0, 0x0c, 0x03, 0x7e, 0x34, 0xa9, 0x69,
            0x37, 0xc5, 0x61, 0xa7, 0x4c, 0x41, 0x2b, 0xb4,
            0xc7, 0x46, 0x46, 0x95, 0x27, 0x28, 0x1c, 0x8c,
        };
        static const byte cs4_256[64] = {
            0x07, 0xdc, 0x27, 0xb1, 0x1e, 0x51, 0xfb, 0xac,
            0x75, 0xbc, 0x7b, 0x3c, 0x1d, 0x98, 0x3e, 0x8b,
            0x4b, 0x85, 0xfb, 0x1d, 0xef, 0xaf, 0x21, 0x89,
            0x12, 0xac, 0x86, 0x43, 0x02, 0x73, 0x09, 0x17,
            0x27, 0xf4, 0x2b, 0x17, 0xed, 0x1d, 0xf6, 0x3e,
            0x8e, 0xc1, 0x18, 0xf0, 0x4b, 0x23, 0x63, 0x3c,
            0x1d, 0xfb, 0x15, 0x74, 0xc8, 0xfb, 0x55, 0xcb,
            0x45, 0xda, 0x8e, 0x25, 0xaf, 0xb0, 0x92, 0xbb,
        };
    byte msg200[200];
    wc_Cshake cshake;
    byte out[64];
    int i;

    for (i = 0; i < 200; i++) {
        msg200[i] = (byte)i;
    }

    /* NIST cSHAKE256 samples (N empty, S = "Email Signature"). */
    ExpectIntEQ(wc_Cshake256(NULL, 0, emailS, (word32)sizeof(emailS), msg4,
        (word32)sizeof(msg4), out, (word32)sizeof(cs3_256)), 0);
    ExpectBufEQ(out, cs3_256, (word32)sizeof(cs3_256));

    ExpectIntEQ(wc_InitCshake256(&cshake, NULL, 0, emailS,
        (word32)sizeof(emailS), HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Cshake256_Update(&cshake, msg200, 100), 0);
    ExpectIntEQ(wc_Cshake256_Update(&cshake, msg200 + 100, 100), 0);
    ExpectIntEQ(wc_Cshake256_Final(&cshake, out, (word32)sizeof(cs4_256)), 0);
    ExpectBufEQ(out, cs4_256, (word32)sizeof(cs4_256));
    wc_Cshake256_Free(&cshake);

    /* Argument checks. */
    ExpectIntEQ(wc_InitCshake256(NULL, NULL, 0, emailS,
        (word32)sizeof(emailS), HEAP_HINT, INVALID_DEVID), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Cshake256_Update(NULL, msg4, 4), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Cshake256_Final(NULL, out, 64), BAD_FUNC_ARG);
    wc_Cshake256_Free(NULL);
#endif /* WOLFSSL_CSHAKE256 */
    return EXPECT_RESULT();
}

int test_wc_Kmac_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_KMAC128
    wc_Kmac kmac;
    wc_Kmac copy;
#ifdef HAVE_FIPS
    static const byte key[KMAC_FIPS_MIN_KEY] =
                               { 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01, 0x02, 0x03,
                                 0x00, 0x01
                               };
#else
    static const byte key[4] = { 0x00, 0x01, 0x02, 0x03 };
#endif
    static const byte msg[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    byte out1[32];
    byte out2[32];
    byte outRef[32];

    /* Reference: full message in one shot. */
    ExpectIntEQ(wc_Kmac128Hash(key, (word32)sizeof(key), NULL, 0, msg,
        (word32)sizeof(msg), outRef, (word32)sizeof(outRef)), 0);

    /* Argument checks. */
    ExpectIntEQ(wc_Kmac128_Copy(NULL, &copy), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Kmac128_Copy(&kmac, NULL), BAD_FUNC_ARG);

    /* Absorb a prefix, copy, then finalize both independently. The copy
     * destination is initialized first so any resources it holds are released
     * by wc_Kmac128_Copy(), matching the wc_Shake_Copy() convention. */
    ExpectIntEQ(wc_InitKmac128(&kmac, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitKmac128(&copy, key, (word32)sizeof(key), NULL, 0,
        HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Kmac128_Update(&kmac, msg, 4), 0);
    ExpectIntEQ(wc_Kmac128_Copy(&kmac, &copy), 0);
    /* Feed the rest to both - they must match each other and the reference. */
    ExpectIntEQ(wc_Kmac128_Update(&kmac, msg + 4, 4), 0);
    ExpectIntEQ(wc_Kmac128_Update(&copy, msg + 4, 4), 0);
    ExpectIntEQ(wc_Kmac128_Final(&kmac, out1, (word32)sizeof(out1)), 0);
    ExpectIntEQ(wc_Kmac128_Final(&copy, out2, (word32)sizeof(out2)), 0);
    ExpectBufEQ(out1, outRef, (word32)sizeof(outRef));
    ExpectBufEQ(out2, outRef, (word32)sizeof(outRef));
    wc_Kmac128_Free(&kmac);
    wc_Kmac128_Free(&copy);
#endif /* WOLFSSL_KMAC128 */
    return EXPECT_RESULT();
}

int test_wc_Cshake_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_CSHAKE128
    wc_Cshake cshake;
    wc_Cshake copy;
    static const byte custom[4] = { 'C', 'u', 's', 't' };
    static const byte msg[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };
    byte out1[32];
    byte out2[32];
    byte outRef[32];

    /* Reference: full message in one shot. */
    ExpectIntEQ(wc_Cshake128(NULL, 0, custom, (word32)sizeof(custom), msg,
        (word32)sizeof(msg), outRef, (word32)sizeof(outRef)), 0);

    /* Argument checks. */
    ExpectIntEQ(wc_Cshake128_Copy(NULL, &copy), BAD_FUNC_ARG);
    ExpectIntEQ(wc_Cshake128_Copy(&cshake, NULL), BAD_FUNC_ARG);

    /* Absorb a prefix, copy, then finalize both independently. The copy
     * destination is initialized first, matching wc_Shake_Copy convention. */
    ExpectIntEQ(wc_InitCshake128(&cshake, NULL, 0, custom,
        (word32)sizeof(custom), HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitCshake128(&copy, NULL, 0, custom,
        (word32)sizeof(custom), HEAP_HINT, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Cshake128_Update(&cshake, msg, 4), 0);
    ExpectIntEQ(wc_Cshake128_Copy(&cshake, &copy), 0);
    ExpectIntEQ(wc_Cshake128_Update(&cshake, msg + 4, 4), 0);
    ExpectIntEQ(wc_Cshake128_Update(&copy, msg + 4, 4), 0);
    ExpectIntEQ(wc_Cshake128_Final(&cshake, out1, (word32)sizeof(out1)), 0);
    ExpectIntEQ(wc_Cshake128_Final(&copy, out2, (word32)sizeof(out2)), 0);
    ExpectBufEQ(out1, outRef, (word32)sizeof(outRef));
    ExpectBufEQ(out2, outRef, (word32)sizeof(outRef));
    wc_Cshake128_Free(&cshake);
    wc_Cshake128_Free(&copy);
#endif /* WOLFSSL_CSHAKE128 */
    return EXPECT_RESULT();
}
