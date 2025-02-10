/* test_sha.c
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

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_sha.h>

/*
 * Unit test for the wc_InitSha()
 */
int test_wc_InitSha(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    wc_Sha sha;

    /* Test good arg. */
    ExpectIntEQ(wc_InitSha(&sha), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitSha(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ShaFree(&sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_InitSha */

/*
 *  Tesing wc_ShaUpdate()
 */
int test_wc_ShaUpdate(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    wc_Sha sha;
    byte hash[WC_SHA_DIGEST_SIZE];
    testVector a, b, c;

    ExpectIntEQ(wc_InitSha(&sha), 0);

    /* Input. */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);

    ExpectIntEQ(wc_ShaUpdate(&sha, NULL, 0), 0);
    ExpectIntEQ(wc_ShaUpdate(&sha, (byte*)a.input, 0), 0);
    ExpectIntEQ(wc_ShaUpdate(&sha, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_ShaFinal(&sha, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2"
               "\x6C\x9C\xD0\xD8\x9D";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);

    ExpectIntEQ(wc_ShaUpdate(&sha, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_ShaFinal(&sha, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_SHA_DIGEST_SIZE), 0);

    /* Try passing in bad values. */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_ShaUpdate(&sha, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_SHA_DIGEST_SIZE;
    ExpectIntEQ(wc_ShaUpdate(&sha, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ShaUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ShaFree(&sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaUpdate() */

/*
 * Unit test on wc_ShaFinal
 */
int test_wc_ShaFinal(void)
{
    EXPECT_DECLS;
#ifndef NO_SHA
    wc_Sha sha;
    byte* hash_test[3];
    byte hash1[WC_SHA_DIGEST_SIZE];
    byte hash2[2*WC_SHA_DIGEST_SIZE];
    byte hash3[5*WC_SHA_DIGEST_SIZE];
    int times, i;

    /* Initialize*/
    ExpectIntEQ(wc_InitSha(&sha), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test)/sizeof(byte*);
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_ShaFinal(&sha, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_ShaFinal(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ShaFinal(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ShaFinal(&sha, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ShaFree(&sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ShaFinal */

