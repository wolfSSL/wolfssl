/* test_sha512.c
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

#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_sha512.h>

/*******************************************************************************
 * SHA-512
 ******************************************************************************/

/*
 * Testing wc_InitSha512()
 */
int test_wc_InitSha512(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha512(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha512 */


/*
 *  wc_Sha512Update() test.
 */
int test_wc_Sha512Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;
    byte hash[WC_SHA512_DIGEST_SIZE];
    byte hash_unaligned[WC_SHA512_DIGEST_SIZE + 1];
    testVector a, b, c;

    ExpectIntEQ(wc_InitSha512(&sha512), 0);

    /* Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha512Update(&sha512, NULL, 0), 0);
    ExpectIntEQ(wc_Sha512Update(&sha512,(byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha512Update(&sha512, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha512Final(&sha512, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
               "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b"
               "\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c"
               "\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a"
               "\x9a\xc9\x4f\xa5\x4c\xa4\x9f";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha512Update(&sha512, (byte*) a.input, (word32) a.inLen), 0);
    ExpectIntEQ(wc_Sha512Final(&sha512, hash), 0);

    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA512_DIGEST_SIZE), 0);

    /* Unaligned check. */
    ExpectIntEQ(wc_Sha512Update(&sha512, (byte*)a.input+1, (word32)a.inLen-1),
        0);
    ExpectIntEQ(wc_Sha512Final(&sha512, hash_unaligned+1), 0);

    /* Try passing in bad values */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_Sha512Update(&sha512, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_SHA512_DIGEST_SIZE;
    ExpectIntEQ(wc_Sha512Update(&sha512, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha512Update  */

#ifdef WOLFSSL_SHA512
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
        (!defined(WOLFSSL_NOSHA512_224) || !defined(WOLFSSL_NOSHA512_256))
/* Performs test for
 * - wc_Sha512Final/wc_Sha512FinalRaw
 * - wc_Sha512_224Final/wc_Sha512_224Final
 * - wc_Sha512_256Final/wc_Sha512_256Final
 * parameter:
 * - type : must be one of WC_HASH_TYPE_SHA512, WC_HASH_TYPE_SHA512_224 or
 *          WC_HASH_TYPE_SHA512_256
 * - isRaw: if is non-zero, xxxFinalRaw function will be tested
 *return 0 on success
 */
static int test_Sha512_Family_Final(int type, int isRaw)
{
    EXPECT_DECLS;
    wc_Sha512 sha512;
    byte* hash_test[3];
    byte hash1[WC_SHA512_DIGEST_SIZE];
    byte hash2[2*WC_SHA512_DIGEST_SIZE];
    byte hash3[5*WC_SHA512_DIGEST_SIZE];
    int times, i;

    int(*initFp)(wc_Sha512*);
    int(*finalFp)(wc_Sha512*, byte*);
    void(*freeFp)(wc_Sha512*);

    if (type == WC_HASH_TYPE_SHA512) {
        initFp  = wc_InitSha512;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    !defined(WOLFSSL_NO_HASH_RAW)
        finalFp = (isRaw)? wc_Sha512FinalRaw : wc_Sha512Final;
#else
        finalFp = (isRaw)? NULL : wc_Sha512Final;
#endif
        freeFp  = wc_Sha512Free;
    }
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(WOLFSSL_NOSHA512_224)
    else if (type == WC_HASH_TYPE_SHA512_224) {
        initFp  = wc_InitSha512_224;
    #if !defined(WOLFSSL_NO_HASH_RAW)
        finalFp = (isRaw)? wc_Sha512_224FinalRaw : wc_Sha512_224Final;
    #else
        finalFp = (isRaw)? NULL : wc_Sha512_224Final;
    #endif
        freeFp  = wc_Sha512_224Free;
    }
#endif
#if !defined(WOLFSSL_NOSHA512_256)
    else if (type == WC_HASH_TYPE_SHA512_256) {
        initFp  = wc_InitSha512_256;
    #if !defined(WOLFSSL_NO_HASH_RAW)
        finalFp = (isRaw)? wc_Sha512_256FinalRaw : wc_Sha512_256Final;
    #else
        finalFp = (isRaw)? NULL : wc_Sha512_256Final;
    #endif
        freeFp  = wc_Sha512_256Free;
    }
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    else
        return TEST_FAIL;

    /* Initialize  */
    ExpectIntEQ(initFp(&sha512), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte *);

#if defined(HAVE_FIPS) || defined(HAVE_SELFTEST) || \
        defined(WOLFSSL_NO_HASH_RAW)
    if (finalFp != NULL)
#endif
    {
        /* Good test args. */
        for (i = 0; i < times; i++) {
            ExpectIntEQ(finalFp(&sha512, hash_test[i]), 0);
        }
        /* Test bad args. */
        ExpectIntEQ(finalFp(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(finalFp(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(finalFp(&sha512, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    freeFp(&sha512);

    return EXPECT_RESULT();
}
#endif /* !HAVE_FIPS && !HAVE_SELFTEST &&
                        (!WOLFSSL_NOSHA512_224 || !WOLFSSL_NOSHA512_256) */
#endif /* WOLFSSL_SHA512 */
/*
 * Unit test function for wc_Sha512Final()
 */
int test_wc_Sha512Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;
    byte* hash_test[3];
    byte hash1[WC_SHA512_DIGEST_SIZE];
    byte hash2[2*WC_SHA512_DIGEST_SIZE];
    byte hash3[5*WC_SHA512_DIGEST_SIZE];
    int times, i;

    /* Initialize  */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte *);
    for (i = 0; i < times; i++) {
         ExpectIntEQ(wc_Sha512Final(&sha512, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha512Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Final(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Final(&sha512, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Final */
/*
 * Unit test function for wc_Sha512FinalRaw()
 */
int test_wc_Sha512FinalRaw(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_SHA512) && !defined(HAVE_SELFTEST) && \
     (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
      (HAVE_FIPS_VERSION >= 3)))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    wc_Sha512 sha512;
    byte* hash_test[3];
    byte hash1[WC_SHA512_DIGEST_SIZE];
    byte hash2[2*WC_SHA512_DIGEST_SIZE];
    byte hash3[5*WC_SHA512_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    /* Good test args. */
    for (i = 0; i < times; i++) {
         ExpectIntEQ(wc_Sha512FinalRaw(&sha512, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha512FinalRaw(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512FinalRaw(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512FinalRaw(&sha512, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512FinalRaw */

/*
 * Unit test function for wc_Sha512GetFlags()
 */
int test_wc_Sha512GetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha512 sha512;
    word32 flags = 0;

    /* Initialize */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);

    ExpectIntEQ(wc_Sha512GetFlags(&sha512, &flags), 0);
    ExpectIntEQ((flags & WC_HASH_FLAG_ISCOPY), 0);

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512GetFlags */

/*
 * Unit test function for wc_Sha512Free()
 */
int test_wc_Sha512Free(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Free */
#ifdef WOLFSSL_SHA512

#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
        (!defined(WOLFSSL_NOSHA512_224) || !defined(WOLFSSL_NOSHA512_256))
static int test_Sha512_Family_GetHash(int type )
{
    EXPECT_DECLS;
    int(*initFp)(wc_Sha512*);
    int(*ghashFp)(wc_Sha512*, byte*);
    wc_Sha512 sha512;
    byte hash1[WC_SHA512_DIGEST_SIZE];

    if (type == WC_HASH_TYPE_SHA512) {
        initFp  = wc_InitSha512;
        ghashFp = wc_Sha512GetHash;
    }
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if !defined(WOLFSSL_NOSHA512_224)
    else if (type == WC_HASH_TYPE_SHA512_224) {
        initFp  = wc_InitSha512_224;
        ghashFp = wc_Sha512_224GetHash;
    }
#endif
#if !defined(WOLFSSL_NOSHA512_256)
    else if (type == WC_HASH_TYPE_SHA512_256) {
        initFp  = wc_InitSha512_256;
        ghashFp = wc_Sha512_256GetHash;
    }
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    else {
        initFp  = NULL;
        ghashFp = NULL;
    }

    if (initFp == NULL || ghashFp == NULL)
        return TEST_FAIL;

    ExpectIntEQ(initFp(&sha512), 0);
    ExpectIntEQ(ghashFp(&sha512, hash1), 0);

    /* test bad arguments*/
    ExpectIntEQ(ghashFp(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(ghashFp(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(ghashFp(&sha512, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
    return EXPECT_RESULT();
}
#endif /* !HAVE_FIPS && !HAVE_SELFTEST &&
                        (!WOLFSSL_NOSHA512_224 || !WOLFSSL_NOSHA512_256) */
#endif /* WOLFSSL_SHA512 */

/*
 * Unit test function for wc_Sha512GetHash()
 */
int test_wc_Sha512GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;
    byte hash1[WC_SHA512_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);

    ExpectIntEQ(wc_Sha512GetHash(&sha512, hash1), 0);

    /* test bad arguments*/
    ExpectIntEQ(wc_Sha512GetHash(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512GetHash(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512GetHash(&sha512, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512GetHash */

/*
 * Unit test function for wc_Sha512Copy()
 */
int test_wc_Sha512Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;
    wc_Sha512 temp;

    XMEMSET(&sha512, 0, sizeof(wc_Sha512));
    XMEMSET(&temp, 0, sizeof(wc_Sha512));

    /* Initialize */
    ExpectIntEQ(wc_InitSha512(&sha512), 0);
    ExpectIntEQ(wc_InitSha512(&temp), 0);

    ExpectIntEQ(wc_Sha512Copy(&sha512, &temp), 0);

    /* test bad arguments*/
    ExpectIntEQ(wc_Sha512Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512Copy(&sha512, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512Free(&sha512);
    wc_Sha512Free(&temp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha512Copy */

/*******************************************************************************
 * SHA-512-224
 ******************************************************************************/

int test_wc_InitSha512_224(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    wc_Sha512 sha512;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha512_224(&sha512), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha512_224(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_224Free(&sha512);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_224 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_224Update(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    wc_Sha512 sha512;
    byte hash[WC_SHA512_DIGEST_SIZE];
    testVector a, c;

    ExpectIntEQ(wc_InitSha512_224(&sha512), 0);

    /* Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha512_224Update(&sha512, NULL, 0), 0);
    ExpectIntEQ(wc_Sha512_224Update(&sha512,(byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha512_224Update(&sha512, (byte*)a.input, (word32)a.inLen),
        0);
    ExpectIntEQ(wc_Sha512_224Final(&sha512, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\x46\x34\x27\x0f\x70\x7b\x6a\x54\xda\xae\x75\x30\x46\x08"
               "\x42\xe2\x0e\x37\xed\x26\x5c\xee\xe9\xa4\x3e\x89\x24\xaa";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha512_224Update(&sha512, (byte*) a.input, (word32) a.inLen),
        0);
    ExpectIntEQ(wc_Sha512_224Final(&sha512, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA512_224_DIGEST_SIZE), 0);

    c.input = NULL;
    c.inLen = WC_SHA512_224_DIGEST_SIZE;
    ExpectIntEQ(wc_Sha512_224Update(&sha512, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_224Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_224Free(&sha512);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_224 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_224Final(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    ExpectIntEQ(test_Sha512_Family_Final(WC_HASH_TYPE_SHA512_224, 0),
        TEST_SUCCESS);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_224 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_224FinalRaw(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    defined(WOLFSSL_SHA512) &&  !defined(WOLFSSL_NOSHA512_224) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    ExpectIntEQ(test_Sha512_Family_Final(WC_HASH_TYPE_SHA512_224, 1),
        TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_224GetFlags(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
    defined(WOLFSSL_HASH_FLAGS)
    wc_Sha512 sha512;
    wc_Sha512 copy;
    word32 flags = 0;

    XMEMSET(&sha512, 0, sizeof(wc_Sha512));
    XMEMSET(&copy, 0, sizeof(wc_Sha512));

    /* Initialize */
    ExpectIntEQ(wc_InitSha512_224(&sha512), 0);
    ExpectIntEQ(wc_InitSha512_224(&copy), 0);

    ExpectIntEQ(wc_Sha512_224GetFlags(&sha512, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);

    ExpectIntEQ(wc_Sha512_224Copy(&sha512, &copy), 0);
    ExpectIntEQ(wc_Sha512_224GetFlags(&copy, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == WC_HASH_FLAG_ISCOPY);

    wc_Sha512_224Free(&copy);
    wc_Sha512_224Free(&sha512);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_224Free(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    wc_Sha512_224Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_224GetHash(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    ExpectIntEQ(test_Sha512_Family_GetHash(WC_HASH_TYPE_SHA512_224),
        TEST_SUCCESS);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}
int test_wc_Sha512_224Copy(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
    wc_Sha512 sha512;
    wc_Sha512 temp;

    XMEMSET(&sha512, 0, sizeof(wc_Sha512));
    XMEMSET(&temp, 0, sizeof(wc_Sha512));

    /* Initialize */
    ExpectIntEQ(wc_InitSha512_224(&sha512), 0);
    ExpectIntEQ(wc_InitSha512_224(&temp), 0);

    ExpectIntEQ(wc_Sha512_224Copy(&sha512, &temp), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha512_224Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_224Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_224Copy(&sha512, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_224Free(&sha512);
    wc_Sha512_224Free(&temp);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-512-256
 ******************************************************************************/

int test_wc_InitSha512_256(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    wc_Sha512 sha512;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha512_256(&sha512), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha512_256(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_256Free(&sha512);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_256 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_256Update(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    wc_Sha512 sha512;
    byte hash[WC_SHA512_DIGEST_SIZE];
    testVector a, c;

    ExpectIntEQ(wc_InitSha512_256(&sha512), 0);

    /* Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha512_256Update(&sha512, NULL, 0), 0);
    ExpectIntEQ(wc_Sha512_256Update(&sha512,(byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha512_256Update(&sha512, (byte*)a.input, (word32)a.inLen),
        0);
    ExpectIntEQ(wc_Sha512_256Final(&sha512, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\x53\x04\x8e\x26\x81\x94\x1e\xf9\x9b\x2e\x29\xb7\x6b\x4c"
               "\x7d\xab\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46\xe0\xe2\xf1\x31"
               "\x07\xe7\xaf\x23";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha512_256Update(&sha512, (byte*) a.input, (word32) a.inLen),
        0);
    ExpectIntEQ(wc_Sha512_256Final(&sha512, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA512_256_DIGEST_SIZE), 0);

    c.input = NULL;
    c.inLen = WC_SHA512_256_DIGEST_SIZE;
    ExpectIntEQ(wc_Sha512_256Update(&sha512, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_256Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_256Free(&sha512);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_256 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_256Final(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    ExpectIntEQ(test_Sha512_Family_Final(WC_HASH_TYPE_SHA512_256, 0),
        TEST_SUCCESS);
#endif /* WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_256 */
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_256FinalRaw(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
    defined(WOLFSSL_SHA512) &&  !defined(WOLFSSL_NOSHA512_256) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    ExpectIntEQ(test_Sha512_Family_Final(WC_HASH_TYPE_SHA512_256, 1),
        TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

int test_wc_Sha512_256GetFlags(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
    defined(WOLFSSL_HASH_FLAGS)
    wc_Sha512 sha512, copy;
    word32 flags = 0;

    XMEMSET(&sha512, 0, sizeof(wc_Sha512));
    XMEMSET(&copy, 0, sizeof(wc_Sha512));

    /* Initialize */
    ExpectIntEQ(wc_InitSha512_256(&sha512), 0);
    ExpectIntEQ(wc_InitSha512_256(&copy), 0);

    ExpectIntEQ(wc_Sha512_256GetFlags(&sha512, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);

    ExpectIntEQ(wc_Sha512_256Copy(&sha512, &copy), 0);
    ExpectIntEQ(wc_Sha512_256GetFlags(&copy, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == WC_HASH_FLAG_ISCOPY);

    wc_Sha512_256Free(&sha512);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_256Free(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    wc_Sha512_256Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wc_Sha512_256GetHash(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    ExpectIntEQ(test_Sha512_Family_GetHash(WC_HASH_TYPE_SHA512_256),
        TEST_SUCCESS);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();

}

int test_wc_Sha512_256Copy(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
    wc_Sha512 sha512;
    wc_Sha512 temp;

    XMEMSET(&sha512, 0, sizeof(wc_Sha512));
    XMEMSET(&temp, 0, sizeof(wc_Sha512));

    /* Initialize */
    ExpectIntEQ(wc_InitSha512_256(&sha512), 0);
    ExpectIntEQ(wc_InitSha512_256(&temp), 0);

    ExpectIntEQ(wc_Sha512_256Copy(&sha512, &temp), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha512_256Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_256Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha512_256Copy(&sha512, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha512_256Free(&sha512);
    wc_Sha512_256Free(&temp);
#endif
#endif /* !HAVE_FIPS && !HAVE_SELFTEST */
    return EXPECT_RESULT();
}

/*******************************************************************************
 * SHA-384
 ******************************************************************************/

/*
 * Testing wc_InitSha384()
 */
int test_wc_InitSha384(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha384(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha384 */

/*
 * test wc_Sha384Update()
 */
int test_wc_Sha384Update(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;
    byte hash[WC_SHA384_DIGEST_SIZE];
    testVector a, b, c;

    ExpectIntEQ(wc_InitSha384(&sha384), 0);

    /* Input */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Sha384Update(&sha384, NULL, 0), 0);
    ExpectIntEQ(wc_Sha384Update(&sha384, (byte*)a.input, 0), 0);
    ExpectIntEQ(wc_Sha384Update(&sha384, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha384Final(&sha384, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50"
               "\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff"
               "\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34"
               "\xc8\x25\xa7";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Sha384Update(&sha384, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Sha384Final(&sha384, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA384_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_Sha384Update(&sha384, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_SHA384_DIGEST_SIZE;
    ExpectIntEQ( wc_Sha384Update(&sha384, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Update */

/*
 * Unit test function for wc_Sha384Final();
 */
int test_wc_Sha384Final(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;
    byte* hash_test[3];
    byte hash1[WC_SHA384_DIGEST_SIZE];
    byte hash2[2*WC_SHA384_DIGEST_SIZE];
    byte hash3[5*WC_SHA384_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    /* Good test args. */
    for (i = 0; i < times; i++) {
         ExpectIntEQ(wc_Sha384Final(&sha384, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha384Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384Final(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384Final(&sha384, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Final */

/*
 * Unit test function for wc_Sha384FinalRaw()
 */
int test_wc_Sha384FinalRaw(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_SHA384) && !defined(HAVE_SELFTEST) && \
     (!defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
      (HAVE_FIPS_VERSION >= 3)))) && \
    !defined(WOLFSSL_NO_HASH_RAW)
    wc_Sha384 sha384;
    byte* hash_test[3];
    byte hash1[WC_SHA384_DIGEST_SIZE];
    byte hash2[2*WC_SHA384_DIGEST_SIZE];
    byte hash3[5*WC_SHA384_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    /* Good test args. */
    for (i = 0; i < times; i++) {
         ExpectIntEQ(wc_Sha384FinalRaw(&sha384, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Sha384FinalRaw(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384FinalRaw(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384FinalRaw(&sha384, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384FinalRaw */

/*
 * Unit test function for wc_Sha384GetFlags()
 */
int test_wc_Sha384GetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_HASH_FLAGS)
    wc_Sha384 sha384;
    word32 flags = 0;

    /* Initialize */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);
    ExpectIntEQ(wc_Sha384GetFlags(&sha384, &flags), 0);
    ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha384GetFlags */

/*
 * Unit test function for wc_Sha384Free()
 */
int test_wc_Sha384Free(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384Free(NULL);
    /* Set result to SUCCESS. */
    ExpectTrue(1);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Sha384Free */

/*
 * Unit test function for wc_Sha384GetHash()
 */
int test_wc_Sha384GetHash(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;
    byte hash1[WC_SHA384_DIGEST_SIZE];

    /* Initialize */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);

    ExpectIntEQ(wc_Sha384GetHash(&sha384, hash1), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha384GetHash(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384GetHash(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384GetHash(&sha384, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384GetHash */

/*
 * Unit test function for wc_Sha384Copy()
 */
int test_wc_Sha384Copy(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;
    wc_Sha384 temp;

    XMEMSET(&sha384, 0, sizeof(wc_Sha384));
    XMEMSET(&temp, 0, sizeof(wc_Sha384));

    /* Initialize */
    ExpectIntEQ(wc_InitSha384(&sha384), 0);
    ExpectIntEQ(wc_InitSha384(&temp), 0);

    ExpectIntEQ(wc_Sha384Copy(&sha384, &temp), 0);
    /* test bad arguments*/
    ExpectIntEQ(wc_Sha384Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384Copy(NULL, &temp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Sha384Copy(&sha384, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Sha384Free(&sha384);
    wc_Sha384Free(&temp);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Sha384Copy */

