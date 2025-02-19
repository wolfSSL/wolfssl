/* test_blake2.c
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

#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_blake2.h>

/*
 * Unit test for the wc_InitBlake2b()
 */
int test_wc_InitBlake2b(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b blake;

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2b(&blake, 64), 0);
    /* Test bad arg. */
    ExpectIntEQ(wc_InitBlake2b(NULL, 64), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(NULL, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(&blake, 128), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b(&blake, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}     /* END test_wc_InitBlake2b*/

/*
 * Unit test for the wc_InitBlake2b_WithKey()
 */
int test_wc_InitBlake2b_WithKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2
    Blake2b     blake;
    word32      digestSz = BLAKE2B_KEYBYTES;
    byte        key[BLAKE2B_KEYBYTES];
    word32      keylen = BLAKE2B_KEYBYTES;

    XMEMSET(key, 0, sizeof(key));

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, key, keylen), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitBlake2b_WithKey(NULL, digestSz, key, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2b_WithKey(&blake, digestSz, NULL, keylen), 0);
#endif
    return EXPECT_RESULT();
}     /* END wc_InitBlake2b_WithKey*/

/*
 * Unit test for the wc_InitBlake2s_WithKey()
 */
int test_wc_InitBlake2s_WithKey(void)
{
    EXPECT_DECLS;
#ifdef HAVE_BLAKE2S
    Blake2s     blake;
    word32      digestSz = BLAKE2S_KEYBYTES;
    byte        *key = (byte*)"01234567890123456789012345678901";
    word32      keylen = BLAKE2S_KEYBYTES;

    /* Test good arg. */
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, key, keylen), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_InitBlake2s_WithKey(NULL, digestSz, key, keylen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, key, 256),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitBlake2s_WithKey(&blake, digestSz, NULL, keylen), 0);
#endif
    return EXPECT_RESULT();
}     /* END wc_InitBlake2s_WithKey*/

