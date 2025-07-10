/* test_wolfmath.c
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

#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_wolfmath.h>

/*
 * Testing mp_get_digit_count
 */
int test_mp_get_digit_count(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_MP)
    mp_int a;

    XMEMSET(&a, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), 0);

    ExpectIntEQ(mp_get_digit_count(NULL), 0);
    ExpectIntEQ(mp_get_digit_count(&a), 0);

    mp_clear(&a);
#endif
    return EXPECT_RESULT();
} /* End test_get_digit_count */

/*
 * Testing mp_get_digit
 */
int test_mp_get_digit(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    int    n = 0;

    XMEMSET(&a, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_get_digit(NULL, n), 0);
    ExpectIntEQ(mp_get_digit(&a, n), 0);

    mp_clear(&a);
#endif
    return EXPECT_RESULT();
} /* End test_get_digit */

/*
 * Testing mp_get_rand_digit
 */
int test_mp_get_rand_digit(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && defined(WOLFSSL_PUBLIC_MP)
    WC_RNG   rng;
    mp_digit d;

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(mp_get_rand_digit(&rng, &d), 0);
    ExpectIntEQ(mp_get_rand_digit(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_get_rand_digit(NULL, &d), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_get_rand_digit(&rng, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_get_rand_digit */

/*
 * Testing mp_cond_copy
 */
int test_mp_cond_copy(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_MP_COND_COPY)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    mp_int b;
    int    copy = 0;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&b, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);

    ExpectIntEQ(mp_cond_copy(NULL, copy, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(NULL, copy, &b), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(&a, copy, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_cond_copy(&a, copy, &b), 0);

    mp_clear(&a);
    mp_clear(&b);
#endif
    return EXPECT_RESULT();
} /* End test_mp_cond_copy */

/*
 * Testing mp_rand
 */
int test_mp_rand(void)
{
    EXPECT_DECLS;
#if defined(WC_RSA_BLINDING) && defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    WC_RNG rng;
    int    digits = 1;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(mp_rand(&a, digits, NULL), WC_NO_ERR_TRACE(MISSING_RNG_E));
    ExpectIntEQ(mp_rand(NULL, digits, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_rand(&a, 0, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(mp_rand(&a, digits, &rng), 0);

    mp_clear(&a);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
} /* End test_mp_rand */

/*
 * Testing wc_export_int
 */
int test_wc_export_int(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int mp;
    byte   buf[32];
    word32 keySz = (word32)sizeof(buf);
    word32 len = (word32)sizeof(buf);

    XMEMSET(&mp, 0, sizeof(mp_int));

    ExpectIntEQ(mp_init(&mp), MP_OKAY);
    ExpectIntEQ(mp_set(&mp, 1234), 0);

    ExpectIntEQ(wc_export_int(NULL, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    len = sizeof(buf)-1;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
        WC_NO_ERR_TRACE(BUFFER_E));
    len = sizeof(buf);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN), 0);
    len = 4; /* test input too small */
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR),
        WC_NO_ERR_TRACE(BUFFER_E));
    len = sizeof(buf);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR), 0);
    /* hex version of 1234 is 04D2 and should be 4 digits + 1 null */
    ExpectIntEQ(len, 5);

    mp_clear(&mp);
#endif
    return EXPECT_RESULT();
} /* End test_wc_export_int */

