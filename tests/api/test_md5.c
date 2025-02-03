/* test_md5.c
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

#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_md5.h>

/*
 * Unit test for the wc_InitMd5()
 */
int test_wc_InitMd5(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    wc_Md5 md5;

    /* Test good arg. */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitMd5(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Md5Free(&md5);
#endif
    return EXPECT_RESULT();
}     /* END test_wc_InitMd5 */


/*
 * Testing wc_UpdateMd5()
 */
int test_wc_Md5Update(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    wc_Md5 md5;
    byte hash[WC_MD5_DIGEST_SIZE];
    testVector a, b, c;

    ExpectIntEQ(wc_InitMd5(&md5), 0);

    /* Input */
    a.input = "a";
    a.inLen = XSTRLEN(a.input);
    ExpectIntEQ(wc_Md5Update(&md5, (byte*)a.input, (word32)a.inLen), 0);
    ExpectIntEQ(wc_Md5Final(&md5, hash), 0);

    /* Update input. */
    a.input = "abc";
    a.output = "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f"
               "\x72";
    a.inLen = XSTRLEN(a.input);
    a.outLen = XSTRLEN(a.output);
    ExpectIntEQ(wc_Md5Update(&md5, (byte*) a.input, (word32) a.inLen), 0);
    ExpectIntEQ(wc_Md5Final(&md5, hash), 0);
    ExpectIntEQ(XMEMCMP(hash, a.output, WC_MD5_DIGEST_SIZE), 0);

    /* Pass in bad values. */
    b.input = NULL;
    b.inLen = 0;
    ExpectIntEQ(wc_Md5Update(&md5, (byte*)b.input, (word32)b.inLen), 0);
    c.input = NULL;
    c.inLen = WC_MD5_DIGEST_SIZE;
    ExpectIntEQ(wc_Md5Update(&md5, (byte*)c.input, (word32)c.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Md5Update(NULL, (byte*)a.input, (word32)a.inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Md5Free(&md5);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Md5Update()  */

/*
 *  Unit test on wc_Md5Final() in wolfcrypt/src/md5.c
 */
int test_wc_Md5Final(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    /* Instantiate */
    wc_Md5 md5;
    byte* hash_test[3];
    byte hash1[WC_MD5_DIGEST_SIZE];
    byte hash2[2*WC_MD5_DIGEST_SIZE];
    byte hash3[5*WC_MD5_DIGEST_SIZE];
    int times, i;

    /* Initialize */
    ExpectIntEQ(wc_InitMd5(&md5), 0);

    hash_test[0] = hash1;
    hash_test[1] = hash2;
    hash_test[2] = hash3;
    times = sizeof(hash_test)/sizeof(byte*);
    for (i = 0; i < times; i++) {
        ExpectIntEQ(wc_Md5Final(&md5, hash_test[i]), 0);
    }

    /* Test bad args. */
    ExpectIntEQ(wc_Md5Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Md5Final(NULL, hash1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Md5Final(&md5, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Md5Free(&md5);
#endif
    return EXPECT_RESULT();
}

