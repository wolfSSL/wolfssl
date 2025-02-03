/* test_sm3.c
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

#include <wolfssl/wolfcrypt/sm3.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_sm3.h>

/*
 *  Testing wc_InitSm3(), wc_Sm3Free()
 */
int test_wc_InitSm3Free(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;

    /* Invalid Parameters */
    ExpectIntEQ(wc_InitSm3(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid Parameters */
    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);

    wc_Sm3Free(NULL);
    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_InitSm3 */

/*
 *  Testing wc_Sm3Update(), wc_Sm3Final()
 */
int test_wc_Sm3UpdateFinal(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;
    byte data[WC_SM3_BLOCK_SIZE * 4];
    byte hash[WC_SM3_DIGEST_SIZE];
    byte calcHash[WC_SM3_DIGEST_SIZE];
    byte expHash[WC_SM3_DIGEST_SIZE] = {
        0x38, 0x48, 0x15, 0xa7, 0x0e, 0xae, 0x0b, 0x27,
        0x5c, 0xde, 0x9d, 0xa5, 0xd1, 0xa4, 0x30, 0xa1,
        0xca, 0xd4, 0x54, 0x58, 0x44, 0xa2, 0x96, 0x1b,
        0xd7, 0x14, 0x80, 0x3f, 0x80, 0x1a, 0x07, 0xb6
    };
    word32 chunk;
    word32 i;

    XMEMSET(data, 0, sizeof(data));

    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);

    /* Invalid Parameters */
    ExpectIntEQ(wc_Sm3Update(NULL, NULL, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Update(&sm3, NULL, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Update(NULL, data, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid Parameters */
    ExpectIntEQ(wc_Sm3Update(&sm3, NULL, 0), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, 1), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, 1), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, WC_SM3_BLOCK_SIZE), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, WC_SM3_BLOCK_SIZE - 2), 0);
    ExpectIntEQ(wc_Sm3Update(&sm3, data, WC_SM3_BLOCK_SIZE * 2), 0);
    /* Ensure too many bytes for lengths. */
    ExpectIntEQ(wc_Sm3Update(&sm3, data, WC_SM3_PAD_SIZE), 0);

    /* Invalid Parameters */
    ExpectIntEQ(wc_Sm3Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Final(&sm3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid Parameters */
    ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
    ExpectBufEQ(hash, expHash, WC_SM3_DIGEST_SIZE);

    /* Chunk tests. */
    ExpectIntEQ(wc_Sm3Update(&sm3, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Sm3Final(&sm3, calcHash), 0);
    for (chunk = 1; chunk <= WC_SM3_BLOCK_SIZE + 1; chunk++) {
        for (i = 0; i + chunk <= (word32)sizeof(data); i += chunk) {
            ExpectIntEQ(wc_Sm3Update(&sm3, data + i, chunk), 0);
        }
        if (i < (word32)sizeof(data)) {
            ExpectIntEQ(wc_Sm3Update(&sm3, data + i, (word32)sizeof(data) - i),
                0);
        }
        ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
        ExpectBufEQ(hash, calcHash, WC_SM3_DIGEST_SIZE);
    }

    /* Not testing when the low 32-bit length overflows. */

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Update */

/*
 *  Testing wc_Sm3GetHash()
 */
int test_wc_Sm3GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SM3
    wc_Sm3 sm3;
    byte hash[WC_SM3_DIGEST_SIZE];
    byte calcHash[WC_SM3_DIGEST_SIZE];
    byte data[WC_SM3_BLOCK_SIZE];

    XMEMSET(data, 0, sizeof(data));

    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Sm3Final(&sm3, calcHash), 0);

    /* Invalid Parameters */
    ExpectIntEQ(wc_Sm3GetHash(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3GetHash(&sm3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3GetHash(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid Parameters */
    ExpectIntEQ(wc_Sm3GetHash(&sm3, hash), 0);
    ExpectBufEQ(hash, calcHash, WC_SM3_DIGEST_SIZE);

    /* With update. */
    ExpectIntEQ(wc_Sm3Update(&sm3, data, sizeof(data)), 0);
    ExpectIntEQ(wc_Sm3GetHash(&sm3, hash), 0);
    ExpectIntEQ(wc_Sm3Final(&sm3, calcHash), 0);
    ExpectBufEQ(hash, calcHash, WC_SM3_DIGEST_SIZE);

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Update */

/*
 *  Testing wc_Sm3Copy()
 */
int test_wc_Sm3Copy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sm3 sm3;
    wc_Sm3 sm3Copy;
    byte hash[WC_SM3_DIGEST_SIZE];
    byte hashCopy[WC_SM3_DIGEST_SIZE];
    byte data[WC_SM3_BLOCK_SIZE + 1];
    int i;

    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitSm3(&sm3Copy, NULL, INVALID_DEVID), 0);

    /* Invalid Parameters */
    ExpectIntEQ(wc_Sm3Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Copy(&sm3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Copy(NULL, &sm3Copy), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid Parameters */
    ExpectIntEQ(wc_Sm3Copy(&sm3, &sm3Copy), 0);

    /* Ensure all parts of data updated during hashing are copied. */
    for (i = 0; i < WC_SM3_BLOCK_SIZE + 1; i++) {
        ExpectIntEQ(wc_Sm3Update(&sm3, data, i), 0);
        ExpectIntEQ(wc_Sm3Copy(&sm3, &sm3Copy), 0);
        ExpectIntEQ(wc_Sm3Update(&sm3, data, 1), 0);
        ExpectIntEQ(wc_Sm3Update(&sm3Copy, data, 1), 0);
        ExpectIntEQ(wc_Sm3Final(&sm3, hash), 0);
        ExpectIntEQ(wc_Sm3Final(&sm3Copy, hashCopy), 0);
        ExpectBufEQ(hash, hashCopy, WC_SM3_DIGEST_SIZE);
    }

    wc_Sm3Free(&sm3Copy);
    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Copy */

/*
 * Testing wc_Sm3FinalRaw()
 */
int test_wc_Sm3FinalRaw(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_DEVCRYPTO) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 3))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    wc_Sm3 sm3;
    byte hash1[WC_SM3_DIGEST_SIZE];
    byte hash2[WC_SM3_DIGEST_SIZE];
    byte hash3[WC_SM3_DIGEST_SIZE];
    byte* hash_test[3] = { hash1, hash2, hash3 };
    int times;
    int i;

    XMEMSET(&sm3, 0, sizeof(sm3));

    /* Initialize */
    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);

    /* Invalid Parameters */
    ExpectIntEQ(wc_Sm3FinalRaw(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3FinalRaw(&sm3, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3FinalRaw(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    times = sizeof(hash_test) / sizeof(byte*);
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_Sm3FinalRaw(&sm3, hash_test[i]), 0);
    }

    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sm3FinalRaw */

/*
 *  Testing wc_Sm3GetFlags, wc_Sm3SetFlags()
 */
int test_wc_Sm3GetSetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sm3 sm3;
    wc_Sm3 sm3Copy;
    word32 flags = 0;

    ExpectIntEQ(wc_InitSm3(&sm3, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitSm3(&sm3Copy, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_Sm3GetFlags(NULL, &flags), 0);
    ExpectIntEQ(flags, 0);
    ExpectIntEQ(wc_Sm3SetFlags(NULL, WC_HASH_FLAG_WILLCOPY), 0);
    ExpectIntEQ(wc_Sm3GetFlags(NULL, &flags), 0);
    ExpectIntEQ(flags, 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3, &flags), 0);
    ExpectIntEQ(flags, 0);
    ExpectIntEQ(wc_Sm3SetFlags(&sm3, WC_HASH_FLAG_WILLCOPY), 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3, &flags), 0);
    ExpectIntEQ(flags, WC_HASH_FLAG_WILLCOPY);

    ExpectIntEQ(wc_Sm3Copy(&sm3, &sm3Copy), 0);
    ExpectIntEQ(wc_Sm3GetFlags(&sm3Copy, &flags), 0);
    ExpectIntEQ(flags, WC_HASH_FLAG_ISCOPY | WC_HASH_FLAG_WILLCOPY);

    wc_Sm3Free(&sm3Copy);
    wc_Sm3Free(&sm3);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Update */

/*
 *  Testing wc_Sm3Hash()
 */
int test_wc_Sm3Hash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SM3) && defined(WOLFSSL_HASH_FLAGS)
    byte data[WC_SM3_BLOCK_SIZE];
    byte hash[WC_SM3_DIGEST_SIZE];

    /* Invalid parameters. */
    ExpectIntEQ(wc_Sm3Hash(NULL, sizeof(data), hash),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sm3Hash(data, sizeof(data), NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid parameters. */
    ExpectIntEQ(wc_Sm3Hash(data, sizeof(data), hash), 0);
#endif
    return EXPECT_RESULT();
}  /* END test_wc_Sm3Hash */

