/* test_hash.c
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

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_hash.h>

int test_wc_HashInit(void)
{
    EXPECT_DECLS;
    int i;  /* 0 indicates tests passed, 1 indicates failure */

    wc_HashAlg hash;

    /* enum for holding supported algorithms, #ifndef's restrict if disabled */
    enum wc_HashType enumArray[] = {
    #ifndef NO_MD5
        WC_HASH_TYPE_MD5,
    #endif
    #ifndef NO_SHA
        WC_HASH_TYPE_SHA,
    #endif
    #ifdef WOLFSSL_SHA224
        WC_HASH_TYPE_SHA224,
    #endif
    #ifndef NO_SHA256
        WC_HASH_TYPE_SHA256,
    #endif
    #ifdef WOLFSSL_SHA384
        WC_HASH_TYPE_SHA384,
    #endif
    #ifdef WOLFSSL_SHA512
        WC_HASH_TYPE_SHA512,
    #endif
    };
    /* dynamically finds the length */
    int enumlen = (sizeof(enumArray)/sizeof(enum wc_HashType));

    /* For loop to test various arguments... */
    for (i = 0; i < enumlen; i++) {
        /* check for bad args */
        ExpectIntEQ(wc_HashInit(&hash, enumArray[i]), 0);
        wc_HashFree(&hash, enumArray[i]);

        /* check for null ptr */
        ExpectIntEQ(wc_HashInit(NULL, enumArray[i]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    }  /* end of for loop */

    return EXPECT_RESULT();
}  /* end of test_wc_HashInit */

/*
 * Unit test function for wc_HashSetFlags()
 */
int test_wc_HashSetFlags(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HASH_FLAGS
    wc_HashAlg hash;
    word32 flags = 0;
    int i, j;
    int notSupportedLen;

    /* enum for holding supported algorithms, #ifndef's restrict if disabled */
    enum wc_HashType enumArray[] = {
    #ifndef NO_MD5
            WC_HASH_TYPE_MD5,
    #endif
    #ifndef NO_SHA
            WC_HASH_TYPE_SHA,
    #endif
    #ifdef WOLFSSL_SHA224
            WC_HASH_TYPE_SHA224,
    #endif
    #ifndef NO_SHA256
            WC_HASH_TYPE_SHA256,
    #endif
    #ifdef WOLFSSL_SHA384
            WC_HASH_TYPE_SHA384,
    #endif
    #ifdef WOLFSSL_SHA512
            WC_HASH_TYPE_SHA512,
    #endif
    #ifdef WOLFSSL_SHA3
            WC_HASH_TYPE_SHA3_224,
    #endif
    };
    enum wc_HashType notSupported[] = {
              WC_HASH_TYPE_MD5_SHA,
              WC_HASH_TYPE_MD2,
              WC_HASH_TYPE_MD4,
              WC_HASH_TYPE_BLAKE2B,
              WC_HASH_TYPE_BLAKE2S,
              WC_HASH_TYPE_NONE,
     };

    /* dynamically finds the length */
    int enumlen = (sizeof(enumArray)/sizeof(enum wc_HashType));

    /* For loop to test various arguments... */
    for (i = 0; i < enumlen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, enumArray[i]), 0);
        ExpectIntEQ(wc_HashSetFlags(&hash, enumArray[i], flags), 0);
        ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
        ExpectIntEQ(wc_HashSetFlags(NULL, enumArray[i], flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash, enumArray[i]);

    }
    /* For loop to test not supported cases */
    notSupportedLen = (sizeof(notSupported)/sizeof(enum wc_HashType));
    for (j = 0; j < notSupportedLen; j++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupported[j]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashSetFlags(&hash, notSupported[j], flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFree(&hash, notSupported[j]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}  /* END test_wc_HashSetFlags */

/*
 * Unit test function for wc_HashGetFlags()
 */
int test_wc_HashGetFlags(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HASH_FLAGS
    wc_HashAlg hash;
    word32 flags = 0;
    int i, j;

    /* enum for holding supported algorithms, #ifndef's restrict if disabled */
    enum wc_HashType enumArray[] = {
    #ifndef NO_MD5
            WC_HASH_TYPE_MD5,
    #endif
    #ifndef NO_SHA
            WC_HASH_TYPE_SHA,
    #endif
    #ifdef WOLFSSL_SHA224
            WC_HASH_TYPE_SHA224,
    #endif
    #ifndef NO_SHA256
            WC_HASH_TYPE_SHA256,
    #endif
    #ifdef WOLFSSL_SHA384
            WC_HASH_TYPE_SHA384,
    #endif
    #ifdef WOLFSSL_SHA512
            WC_HASH_TYPE_SHA512,
    #endif
    #ifdef WOLFSSL_SHA3
            WC_HASH_TYPE_SHA3_224,
    #endif
    };
    enum wc_HashType notSupported[] = {
              WC_HASH_TYPE_MD5_SHA,
              WC_HASH_TYPE_MD2,
              WC_HASH_TYPE_MD4,
              WC_HASH_TYPE_BLAKE2B,
              WC_HASH_TYPE_BLAKE2S,
              WC_HASH_TYPE_NONE,
    };
    int enumlen = (sizeof(enumArray)/sizeof(enum wc_HashType));
    int notSupportedLen;

    /* For loop to test various arguments... */
    for (i = 0; i < enumlen; i++) {
        ExpectIntEQ(wc_HashInit(&hash, enumArray[i]), 0);
        ExpectIntEQ(wc_HashGetFlags(&hash, enumArray[i], &flags), 0);
        ExpectTrue((flags & WC_HASH_FLAG_ISCOPY) == 0);
        ExpectIntEQ(wc_HashGetFlags(NULL, enumArray[i], &flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_HashFree(&hash, enumArray[i]);
    }
    /* For loop to test not supported cases */
    notSupportedLen = (sizeof(notSupported)/sizeof(enum wc_HashType));
    for (j = 0; j < notSupportedLen; j++) {
        ExpectIntEQ(wc_HashInit(&hash, notSupported[j]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashGetFlags(&hash, notSupported[j], &flags),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_HashFree(&hash, notSupported[j]),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif
    return EXPECT_RESULT();
}  /* END test_wc_HashGetFlags */

