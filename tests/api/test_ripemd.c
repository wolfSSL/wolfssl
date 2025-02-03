/* test_ripemd.c
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

#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_ripemd.h>

/*
 * Testing wc_InitRipeMd()
 */
int test_wc_InitRipeMd(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_RIPEMD
    RipeMd ripemd;

    /* Test good arg. */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitRipeMd(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    byte hash[RIPEMD_DIGEST_SIZE];
    testVector a, b, c;

    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);

    /* Input */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6"
               "\xb0\x87\xf1\x5a\x0b\xfc";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, RIPEMD_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = RIPEMD_DIGEST_SIZE;
    ExpectIntEQ(wc_RipeMdUpdate(&ripemd, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdUpdate(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
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
    byte* hash_test[3];
    byte hash1[RIPEMD_DIGEST_SIZE];
    byte hash2[2*RIPEMD_DIGEST_SIZE];
    byte hash3[5*RIPEMD_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitRipeMd(&ripemd), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test) / sizeof(byte*);
    /* Testing oversized buffers. */
    for (i = 0; i < times; i++) {
         ExpectIntEQ(wc_RipeMdFinal(&ripemd, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_RipeMdFinal(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdFinal(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_RipeMdFinal(&ripemd, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_RipeMdFinal */


