/* test_sha3.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_sha3.h>

/*******************************************************************************
 * SHA-3
 ******************************************************************************/

/*
 * Testing wc_InitSha3_224, wc_InitSha3_256, wc_InitSha3_384, and
 * wc_InitSha3_512
 */
int test_wc_InitSha3(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3)
    wc_Sha3 sha3;

    (void)sha3;

#if !defined(WOLFSSL_NOSHA3_224)
    ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitSha3_224(NULL, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_224_Free(&sha3);
#endif /* NOSHA3_224 */
#if !defined(WOLFSSL_NOSHA3_256)
    ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitSha3_256(NULL, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_256_Free(&sha3);
#endif /* NOSHA3_256 */
#if !defined(WOLFSSL_NOSHA3_384)
    ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitSha3_384(NULL, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_384_Free(&sha3);
#endif /* NOSHA3_384 */
#if !defined(WOLFSSL_NOSHA3_512)
    ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitSha3_512(NULL, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_512_Free(&sha3);
#endif /* NOSHA3_512 */
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha3 */

/*
 * Testing wc_Sha3_Update()
 */
int test_wc_Sha3_Update(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_XILINX_CRYPT) && \
   !defined(WOLFSSL_AFALG_XILINX)
    wc_Sha3 sha3;
    byte    msg[] = "Everybody's working for the weekend.";
    byte    msg2[] = "Everybody gets Friday off.";
    byte    msgCmp[] = "\x45\x76\x65\x72\x79\x62\x6f\x64\x79\x27\x73\x20"
                    "\x77\x6f\x72\x6b\x69\x6e\x67\x20\x66\x6f\x72\x20\x74"
                    "\x68\x65\x20\x77\x65\x65\x6b\x65\x6e\x64\x2e\x45\x76"
                    "\x65\x72\x79\x62\x6f\x64\x79\x20\x67\x65\x74\x73\x20"
                    "\x46\x72\x69\x64\x61\x79\x20\x6f\x66\x66\x2e";
    word32  msglen = sizeof(msg) - 1;
    word32  msg2len = sizeof(msg2);
    word32  msgCmplen = sizeof(msgCmp);

    #if !defined(WOLFSSL_NOSHA3_224)
        ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_224_Update(&sha3, msg, msglen), 0);
        ExpectIntEQ(XMEMCMP(msg, sha3.t, msglen), 0);
        ExpectTrue(sha3.i == msglen);

        ExpectIntEQ(wc_Sha3_224_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(sha3.t, msgCmp, msgCmplen), 0);

        /* Pass bad args. */
        ExpectIntEQ(wc_Sha3_224_Update(NULL, msg2, msg2len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sha3_224_Update(&sha3, NULL, 5),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_Sha3_224_Free(&sha3);

        ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_224_Update(&sha3, NULL, 0), 0);
        ExpectIntEQ(wc_Sha3_224_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(msg2, sha3.t, msg2len), 0);
        wc_Sha3_224_Free(&sha3);
    #endif /* SHA3_224 */

    #if !defined(WOLFSSL_NOSHA3_256)
        ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_256_Update(&sha3, msg, msglen), 0);
        ExpectIntEQ(XMEMCMP(msg, sha3.t, msglen), 0);
        ExpectTrue(sha3.i == msglen);

        ExpectIntEQ(wc_Sha3_256_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(sha3.t, msgCmp, msgCmplen), 0);

        /* Pass bad args. */
        ExpectIntEQ(wc_Sha3_256_Update(NULL, msg2, msg2len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sha3_256_Update(&sha3, NULL, 5),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_Sha3_256_Free(&sha3);

        ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_256_Update(&sha3, NULL, 0), 0);
        ExpectIntEQ(wc_Sha3_256_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(msg2, sha3.t, msg2len), 0);
        wc_Sha3_256_Free(&sha3);
    #endif /* SHA3_256 */

    #if !defined(WOLFSSL_NOSHA3_384)
        ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_384_Update(&sha3, msg, msglen), 0);
        ExpectIntEQ(XMEMCMP(msg, sha3.t, msglen), 0);
        ExpectTrue(sha3.i == msglen);

        ExpectIntEQ(wc_Sha3_384_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(sha3.t, msgCmp, msgCmplen), 0);

        /* Pass bad args. */
        ExpectIntEQ(wc_Sha3_384_Update(NULL, msg2, msg2len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sha3_384_Update(&sha3, NULL, 5),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_Sha3_384_Free(&sha3);

        ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_384_Update(&sha3, NULL, 0), 0);
        ExpectIntEQ(wc_Sha3_384_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(msg2, sha3.t, msg2len), 0);
        wc_Sha3_384_Free(&sha3);
    #endif /* SHA3_384 */

    #if !defined(WOLFSSL_NOSHA3_512)
        ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_512_Update(&sha3, msg, msglen), 0);
        ExpectIntEQ(XMEMCMP(msg, sha3.t, msglen), 0);
        ExpectTrue(sha3.i == msglen);

        ExpectIntEQ(wc_Sha3_512_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(sha3.t, msgCmp, msgCmplen), 0);

        /* Pass bad args. */
        ExpectIntEQ(wc_Sha3_512_Update(NULL, msg2, msg2len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_Sha3_512_Update(&sha3, NULL, 5),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_Sha3_512_Free(&sha3);

        ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_Sha3_512_Update(&sha3, NULL, 0), 0);
        ExpectIntEQ(wc_Sha3_512_Update(&sha3, msg2, msg2len), 0);
        ExpectIntEQ(XMEMCMP(msg2, sha3.t, msg2len), 0);
        wc_Sha3_512_Free(&sha3);
    #endif /* SHA3_512 */
#endif /* WOLFSSL_SHA3 */
    return EXPECT_RESULT();
} /* END test_wc_Sha3_Update */

/*
 *  Testing wc_Sha3_224_Final()
 */
int test_wc_Sha3_224_Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_224)
    wc_Sha3     sha3;
    const char* msg    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnom"
                         "nopnopq";
    const char* expOut = "\x8a\x24\x10\x8b\x15\x4a\xda\x21\xc9\xfd\x55"
                         "\x74\x49\x44\x79\xba\x5c\x7e\x7a\xb7\x6e\xf2"
                         "\x64\xea\xd0\xfc\xce\x33";
    byte        hash[WC_SHA3_224_DIGEST_SIZE];
    byte        hashRet[WC_SHA3_224_DIGEST_SIZE];

    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));

    ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_224_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_224_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(expOut, hash, WC_SHA3_224_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_224_Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_224_Final(&sha3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_224_Free(&sha3);

    ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashRet, 0, sizeof(hashRet));
    ExpectIntEQ(wc_Sha3_224_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_224_GetHash(&sha3, hashRet), 0);
    ExpectIntEQ(wc_Sha3_224_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, hashRet, WC_SHA3_224_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_224_GetHash(NULL, hashRet),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_224_GetHash(&sha3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_224_Free(&sha3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_224_Final */

/*
 *  Testing wc_Sha3_256_Final()
 */
int test_wc_Sha3_256_Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wc_Sha3     sha3;
    const char* msg    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnom"
                         "nopnopq";
    const char* expOut = "\x41\xc0\xdb\xa2\xa9\xd6\x24\x08\x49\x10\x03\x76\xa8"
                        "\x23\x5e\x2c\x82\xe1\xb9\x99\x8a\x99\x9e\x21\xdb\x32"
                        "\xdd\x97\x49\x6d\x33\x76";
    byte        hash[WC_SHA3_256_DIGEST_SIZE];
    byte        hashRet[WC_SHA3_256_DIGEST_SIZE];

    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));

    ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_256_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_256_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(expOut, hash, WC_SHA3_256_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_256_Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_256_Final(&sha3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_256_Free(&sha3);

    ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashRet, 0, sizeof(hashRet));
    ExpectIntEQ(wc_Sha3_256_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_256_GetHash(&sha3, hashRet), 0);
    ExpectIntEQ(wc_Sha3_256_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, hashRet, WC_SHA3_256_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_256_GetHash(NULL, hashRet),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_256_GetHash(&sha3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_256_Free(&sha3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_256_Final */

/*
 *  Testing wc_Sha3_384_Final()
 */
int test_wc_Sha3_384_Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_384)
    wc_Sha3        sha3;
    const char* msg    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnom"
                         "nopnopq";
    const char* expOut = "\x99\x1c\x66\x57\x55\xeb\x3a\x4b\x6b\xbd\xfb\x75\xc7"
                         "\x8a\x49\x2e\x8c\x56\xa2\x2c\x5c\x4d\x7e\x42\x9b\xfd"
                         "\xbc\x32\xb9\xd4\xad\x5a\xa0\x4a\x1f\x07\x6e\x62\xfe"
                         "\xa1\x9e\xef\x51\xac\xd0\x65\x7c\x22";
    byte        hash[WC_SHA3_384_DIGEST_SIZE];
    byte        hashRet[WC_SHA3_384_DIGEST_SIZE];

    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));

    ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_384_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_384_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(expOut, hash, WC_SHA3_384_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_384_Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_384_Final(&sha3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_384_Free(&sha3);

    ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashRet, 0, sizeof(hashRet));
    ExpectIntEQ(wc_Sha3_384_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_384_GetHash(&sha3, hashRet), 0);
    ExpectIntEQ(wc_Sha3_384_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, hashRet, WC_SHA3_384_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_384_GetHash(NULL, hashRet),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_384_GetHash(&sha3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_384_Free(&sha3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_384_Final */

/*
 *  Testing wc_Sha3_512_Final()
 */
int test_wc_Sha3_512_Final(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_512) && \
   !defined(WOLFSSL_NOSHA3_384)
    wc_Sha3     sha3;
    const char* msg    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnom"
                         "nopnopq";
    const char* expOut = "\x04\xa3\x71\xe8\x4e\xcf\xb5\xb8\xb7\x7c\xb4\x86\x10"
                         "\xfc\xa8\x18\x2d\xd4\x57\xce\x6f\x32\x6a\x0f\xd3\xd7"
                         "\xec\x2f\x1e\x91\x63\x6d\xee\x69\x1f\xbe\x0c\x98\x53"
                         "\x02\xba\x1b\x0d\x8d\xc7\x8c\x08\x63\x46\xb5\x33\xb4"
                         "\x9c\x03\x0d\x99\xa2\x7d\xaf\x11\x39\xd6\xe7\x5e";
    byte        hash[WC_SHA3_512_DIGEST_SIZE];
    byte        hashRet[WC_SHA3_512_DIGEST_SIZE];

    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));

    ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_512_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_512_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(expOut, hash, WC_SHA3_512_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_512_Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_512_Final(&sha3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Sha3_512_Free(&sha3);

    ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashRet, 0, sizeof(hashRet));
    ExpectIntEQ(wc_Sha3_512_Update(&sha3, (byte*)msg, (word32)XSTRLEN(msg)), 0);
    ExpectIntEQ(wc_Sha3_512_GetHash(&sha3, hashRet), 0);
    ExpectIntEQ(wc_Sha3_512_Final(&sha3, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, hashRet, WC_SHA3_512_DIGEST_SIZE), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_512_GetHash(NULL, hashRet),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_512_GetHash(&sha3, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_512_Free(&sha3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_512_Final */

/*
 *  Testing wc_Sha3_224_Copy()
 */
int test_wc_Sha3_224_Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_224)
    wc_Sha3     sha3, sha3Cpy;
    const char* msg = TEST_STRING;
    word32      msglen = (word32)TEST_STRING_SZ;
    byte        hash[WC_SHA3_224_DIGEST_SIZE];
    byte        hashCpy[WC_SHA3_224_DIGEST_SIZE];

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashCpy, 0, sizeof(hashCpy));
    XMEMSET(&sha3, 0, sizeof(wc_Sha3));
    XMEMSET(&sha3Cpy, 0, sizeof(wc_Sha3));

    ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_InitSha3_224(&sha3Cpy, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_224_Update(&sha3, (byte*)msg, msglen), 0);
    ExpectIntEQ(wc_Sha3_224_Copy(&sha3Cpy, &sha3), 0);
    ExpectIntEQ(wc_Sha3_224_Final(&sha3, hash), 0);
    ExpectIntEQ(wc_Sha3_224_Final(&sha3Cpy, hashCpy), 0);
    ExpectIntEQ(XMEMCMP(hash, hashCpy, sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_224_Copy(NULL, &sha3), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_224_Copy(&sha3Cpy, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_224_Free(&sha3);
    wc_Sha3_224_Free(&sha3Cpy);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_224_Copy */

/*
 *  Testing wc_Sha3_256_Copy()
 */
int test_wc_Sha3_256_Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wc_Sha3     sha3, sha3Cpy;
    const char* msg = TEST_STRING;
    word32      msglen = (word32)TEST_STRING_SZ;
    byte        hash[WC_SHA3_256_DIGEST_SIZE];
    byte        hashCpy[WC_SHA3_256_DIGEST_SIZE];

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashCpy, 0, sizeof(hashCpy));
    XMEMSET(&sha3, 0, sizeof(wc_Sha3));
    XMEMSET(&sha3Cpy, 0, sizeof(wc_Sha3));

    ExpectIntEQ(wc_InitSha3_256(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_InitSha3_256(&sha3Cpy, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_256_Update(&sha3, (byte*)msg, msglen), 0);
    ExpectIntEQ(wc_Sha3_256_Copy(&sha3Cpy, &sha3), 0);
    ExpectIntEQ(wc_Sha3_256_Final(&sha3, hash), 0);
    ExpectIntEQ(wc_Sha3_256_Final(&sha3Cpy, hashCpy), 0);
    ExpectIntEQ(XMEMCMP(hash, hashCpy, sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_256_Copy(NULL, &sha3), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_256_Copy(&sha3Cpy, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_256_Free(&sha3);
    wc_Sha3_256_Free(&sha3Cpy);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_256_Copy */

/*
 *  Testing wc_Sha3_384_Copy()
 */
int test_wc_Sha3_384_Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_384)
    wc_Sha3     sha3, sha3Cpy;
    const char* msg = TEST_STRING;
    word32      msglen = (word32)TEST_STRING_SZ;
    byte        hash[WC_SHA3_384_DIGEST_SIZE];
    byte        hashCpy[WC_SHA3_384_DIGEST_SIZE];

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashCpy, 0, sizeof(hashCpy));
    XMEMSET(&sha3, 0, sizeof(wc_Sha3));
    XMEMSET(&sha3Cpy, 0, sizeof(wc_Sha3));

    ExpectIntEQ(wc_InitSha3_384(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_InitSha3_384(&sha3Cpy, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_384_Update(&sha3, (byte*)msg, msglen), 0);
    ExpectIntEQ(wc_Sha3_384_Copy(&sha3Cpy, &sha3), 0);
    ExpectIntEQ(wc_Sha3_384_Final(&sha3, hash), 0);
    ExpectIntEQ(wc_Sha3_384_Final(&sha3Cpy, hashCpy), 0);
    ExpectIntEQ(XMEMCMP(hash, hashCpy, sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_384_Copy(NULL, &sha3), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_384_Copy(&sha3Cpy, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_384_Free(&sha3);
    wc_Sha3_384_Free(&sha3Cpy);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_384_Copy */

/*
 *  Testing wc_Sha3_512_Copy()
 */
int test_wc_Sha3_512_Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_512)
    wc_Sha3     sha3, sha3Cpy;
    const char* msg = TEST_STRING;
    word32      msglen = (word32)TEST_STRING_SZ;
    byte        hash[WC_SHA3_512_DIGEST_SIZE];
    byte        hashCpy[WC_SHA3_512_DIGEST_SIZE];

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashCpy, 0, sizeof(hashCpy));
    XMEMSET(&sha3, 0, sizeof(wc_Sha3));
    XMEMSET(&sha3Cpy, 0, sizeof(wc_Sha3));

    ExpectIntEQ(wc_InitSha3_512(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_InitSha3_512(&sha3Cpy, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_512_Update(&sha3, (byte*)msg, msglen), 0);
    ExpectIntEQ(wc_Sha3_512_Copy(&sha3Cpy, &sha3), 0);
    ExpectIntEQ(wc_Sha3_512_Final(&sha3, hash), 0);
    ExpectIntEQ(wc_Sha3_512_Final(&sha3Cpy, hashCpy), 0);
    ExpectIntEQ(XMEMCMP(hash, hashCpy, sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Sha3_512_Copy(NULL, &sha3), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha3_512_Copy(&sha3Cpy, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha3_512_Free(&sha3);
    wc_Sha3_512_Free(&sha3Cpy);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_512_Copy */

/*
 * Unit test function for wc_Sha3_GetFlags()
 */
int test_wc_Sha3_GetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha3 sha3;
    word32  flags = 0;

    /* Initialize */
    ExpectIntEQ(wc_InitSha3_224(&sha3, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Sha3_GetFlags(&sha3, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
    wc_Sha3_224_Free(&sha3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha3_GetFlags */

/*******************************************************************************
 * SHAKE-256
 ******************************************************************************/

int test_wc_InitShake256(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake shake;

    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, testDevId), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitShake256(NULL, HEAP_HINT, testDevId),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Shake256_Free(&shake);
#endif
    return EXPECT_RESULT();
}


int test_wc_Shake256_Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake shake;
    byte     msg[] = "Everybody's working for the weekend.";
    byte     msg2[] = "Everybody gets Friday off.";
    byte     msgCmp[] = "\x45\x76\x65\x72\x79\x62\x6f\x64\x79\x27\x73\x20"
                        "\x77\x6f\x72\x6b\x69\x6e\x67\x20\x66\x6f\x72\x20\x74"
                        "\x68\x65\x20\x77\x65\x65\x6b\x65\x6e\x64\x2e\x45\x76"
                        "\x65\x72\x79\x62\x6f\x64\x79\x20\x67\x65\x74\x73\x20"
                        "\x46\x72\x69\x64\x61\x79\x20\x6f\x66\x66\x2e";
    word32   msglen = sizeof(msg) - 1;
    word32   msg2len = sizeof(msg2);
    word32   msgCmplen = sizeof(msgCmp);

    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, msg, msglen), 0);
    ExpectIntEQ(XMEMCMP(msg, shake.t, msglen), 0);
    ExpectTrue(shake.i == msglen);

    ExpectIntEQ(wc_Shake256_Update(&shake, msg2, msg2len), 0);
    ExpectIntEQ(XMEMCMP(shake.t, msgCmp, msgCmplen), 0);

    /* Pass bad args. */
    ExpectIntEQ(wc_Shake256_Update(NULL, msg2, msg2len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_Update(&shake, NULL, 5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_Shake256_Free(&shake);

    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, NULL, 0), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, msg2, msg2len), 0);
    ExpectIntEQ(XMEMCMP(msg2, shake.t, msg2len), 0);
    wc_Shake256_Free(&shake);
#endif /* WOLFSSL_SHAKE256 */
    return EXPECT_RESULT();
}

int test_wc_Shake256_Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake    shake;
    const char* msg    = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnom"
                         "nopnopq";
    const char* expOut = "\x4d\x8c\x2d\xd2\x43\x5a\x01\x28\xee\xfb\xb8\xc3\x6f"
                         "\x6f\x87\x13\x3a\x79\x11\xe1\x8d\x97\x9e\xe1\xae\x6b"
                         "\xe5\xd4\xfd\x2e\x33\x29\x40\xd8\x68\x8a\x4e\x6a\x59"
                         "\xaa\x80\x60\xf1\xf9\xbc\x99\x6c\x05\xac\xa3\xc6\x96"
                         "\xa8\xb6\x62\x79\xdc\x67\x2c\x74\x0b\xb2\x24\xec\x37"
                         "\xa9\x2b\x65\xdb\x05\x39\xc0\x20\x34\x55\xf5\x1d\x97"
                         "\xcc\xe4\xcf\xc4\x91\x27\xd7\x26\x0a\xfc\x67\x3a\xf2"
                         "\x08\xba\xf1\x9b\xe2\x12\x33\xf3\xde\xbe\x78\xd0\x67"
                         "\x60\xcf\xa5\x51\xee\x1e\x07\x91\x41\xd4";
    byte        hash[114];

    /* Init stack variables. */
    XMEMSET(hash, 0, sizeof(hash));

    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_Shake256_Update(&shake, (byte*)msg, (word32)XSTRLEN(msg)),
        0);
    ExpectIntEQ(wc_Shake256_Final(&shake, hash, (word32)sizeof(hash)), 0);
    ExpectIntEQ(XMEMCMP(expOut, hash, (word32)sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Shake256_Final(NULL, hash, (word32)sizeof(hash)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_Final(&shake, NULL, (word32)sizeof(hash)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Shake256_Free(&shake);
#endif
    return EXPECT_RESULT();
}

/*
 *  Testing wc_Shake256_Copy()
 */
int test_wc_Shake256_Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    wc_Shake    shake, shakeCpy;
    const char* msg = TEST_STRING;
    word32      msglen = (word32)TEST_STRING_SZ;
    byte        hash[144];
    byte        hashCpy[144];
    word32      hashLen = sizeof(hash);
    word32      hashLenCpy = sizeof(hashCpy);

    XMEMSET(hash, 0, sizeof(hash));
    XMEMSET(hashCpy, 0, sizeof(hashCpy));

    ExpectIntEQ(wc_InitShake256(&shake, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_InitShake256(&shakeCpy, HEAP_HINT, testDevId), 0);

    ExpectIntEQ(wc_Shake256_Update(&shake, (byte*)msg, msglen), 0);
    ExpectIntEQ(wc_Shake256_Copy(&shakeCpy, &shake), 0);
    ExpectIntEQ(wc_Shake256_Final(&shake, hash, hashLen), 0);
    ExpectIntEQ(wc_Shake256_Final(&shakeCpy, hashCpy, hashLenCpy), 0);
    ExpectIntEQ(XMEMCMP(hash, hashCpy, sizeof(hash)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_Shake256_Copy(NULL, &shake), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Shake256_Copy(&shakeCpy, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Shake256_Free(&shake);
    wc_Shake256_Free(&shakeCpy);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Shake256_Copy */

/*
 * Unit test function for wc_Shake256Hash()
 */
int test_wc_Shake256Hash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHAKE256
    const byte data[] = { /* Hello World */
        0x48,0x65,0x6c,0x6c,0x6f,0x20,0x57,0x6f,
        0x72,0x6c,0x64
    };
    word32     len = sizeof(data);
    byte       hash[144];
    word32     hashLen = sizeof(hash);

    ExpectIntEQ(wc_Shake256Hash(data, len, hash, hashLen), 0);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Shake256Hash */

