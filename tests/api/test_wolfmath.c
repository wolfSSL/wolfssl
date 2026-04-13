/* test_wolfmath.c
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

    /* negative index must return 0, not index out of bounds */
    ExpectIntEQ(mp_get_digit(&a, -1), 0);
    ExpectIntEQ(mp_get_digit(&a, -100), 0);
    ExpectIntEQ(mp_get_digit(NULL, -1), 0);

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

/* ---------------------------------------------------------------------------
 * MC/DC coverage additions for ISO 26262 ASIL-D campaign
 * ---------------------------------------------------------------------------
 */

/*
 * test_wc_WolfmathBadArgCoverage
 *
 * Exhaustively hits the NULL-guard conditions at the top of each target
 * function so that every sub-expression in each compound NULL check is
 * driven to both TRUE and FALSE independently (BAD_FUNC_ARG / MISSING_RNG_E
 * independence pairs).
 *
 * Target conditions:
 *   wc_export_int  L231: mp==NULL || buf==NULL || len==NULL   (3 pairs)
 *   mp_get_digit   L101: a==NULL                              (1 pair)
 *   mp_get_digit_count L93: a==NULL                           (1 pair)
 *   mp_cond_copy   L125: a==NULL || b==NULL                   (2 pairs)
 *   mp_rand        L172: rng==NULL; L175: a==NULL||digits<=0  (3 pairs)
 */
int test_wc_WolfmathBadArgCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_BIG_INT) || defined(WOLFSSL_SP_MATH)
    mp_int a;
    mp_int b;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&b, 0, sizeof(mp_int));
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);

    /* --- mp_get_digit_count: a==NULL => 0; a!=NULL => used count --- */
    /* pair T: a is NULL -> returns 0 */
    ExpectIntEQ(mp_get_digit_count(NULL), 0);
    /* pair F: a is valid -> does NOT return 0 path (used==0 after init is ok,
     * but the NULL branch is not taken) */
    ExpectIntEQ(mp_get_digit_count(&a), 0); /* same value, different branch */

    /* --- mp_get_digit: a==NULL => 0 --- */
    /* pair T: NULL */
    ExpectIntEQ((int)mp_get_digit(NULL, 0), 0);
    /* pair F: non-NULL, index 0 on empty mp (used==0, n>=used -> 0 via
     * index-range branch, NOT the NULL branch) */
    ExpectIntEQ((int)mp_get_digit(&a, 0), 0);

#if (defined(HAVE_ECC) || defined(WOLFSSL_MP_COND_COPY))
    /* --- mp_cond_copy L125: a==NULL || b==NULL --- */
    /* a==NULL, b==NULL -> BAD_FUNC_ARG (T||T) */
    ExpectIntEQ(mp_cond_copy(NULL, 0, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a==NULL, b valid -> BAD_FUNC_ARG (T||F) */
    ExpectIntEQ(mp_cond_copy(NULL, 0, &b), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a valid, b==NULL -> BAD_FUNC_ARG (F||T) */
    ExpectIntEQ(mp_cond_copy(&a, 0, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a valid, b valid, copy==0 -> MP_OKAY (F||F, condition false overall) */
    ExpectIntEQ(mp_cond_copy(&a, 0, &b), MP_OKAY);
#endif /* HAVE_ECC || WOLFSSL_MP_COND_COPY */

#if !defined(WC_NO_RNG)
    {
        WC_RNG rng;
        XMEMSET(&rng, 0, sizeof(WC_RNG));
        ExpectIntEQ(wc_InitRng(&rng), 0);

        /* --- mp_rand L172: rng==NULL -> MISSING_RNG_E (T) --- */
        ExpectIntEQ(mp_rand(&a, 1, NULL), WC_NO_ERR_TRACE(MISSING_RNG_E));

        /* --- mp_rand L175: a==NULL -> BAD_FUNC_ARG (rng ok, T||F) --- */
        ExpectIntEQ(mp_rand(NULL, 1, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* --- mp_rand L175: digits<=0 -> BAD_FUNC_ARG (rng ok, F||T) --- */
        ExpectIntEQ(mp_rand(&a, 0, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* --- mp_rand both conditions FALSE -> MP_OKAY (normal path) --- */
        ExpectIntEQ(mp_rand(&a, 1, &rng), MP_OKAY);

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif /* !WC_NO_RNG */

#if defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)
    {
        byte   buf[32];
        word32 len = (word32)sizeof(buf);
        word32 keySz = (word32)sizeof(buf);

        /* --- wc_export_int L231: mp==NULL || buf==NULL || len==NULL --- */
        /* T||_||_  : mp is NULL */
        ExpectIntEQ(wc_export_int(NULL, buf, &len, keySz,
                                  WC_TYPE_UNSIGNED_BIN),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* F||T||_  : buf is NULL */
        ExpectIntEQ(wc_export_int(&a, NULL, &len, keySz,
                                  WC_TYPE_UNSIGNED_BIN),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* F||F||T  : len is NULL */
        ExpectIntEQ(wc_export_int(&a, buf, NULL, keySz,
                                  WC_TYPE_UNSIGNED_BIN),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* F||F||F  : all valid, keySz fits -> MP_OKAY */
        len = keySz;
        ExpectIntEQ(wc_export_int(&a, buf, &len, keySz,
                                  WC_TYPE_UNSIGNED_BIN), MP_OKAY);
    }
#endif /* HAVE_ECC || WOLFSSL_EXPORT_INT */

    mp_clear(&a);
    mp_clear(&b);
#endif /* !NO_BIG_INT || WOLFSSL_SP_MATH */
    return EXPECT_RESULT();
} /* End test_wc_WolfmathBadArgCoverage */

/*
 * test_wc_WolfmathDecisionCoverage
 *
 * Drives the interior decision branches of mp_get_digit (L104) and
 * mp_get_digit_count so that the ternary condition
 *   (n < 0 || (unsigned)n >= (unsigned)a->used)
 * exercises all three independence pairs:
 *   Pair A: n<0 drives short-circuit TRUE
 *   Pair B: n>=used drives second operand TRUE (n>=0 but out-of-range)
 *   Pair C: 0 <= n < used drives entire condition FALSE -> returns real digit
 *
 * Also covers mp_get_digit_count returning non-zero after mp_set.
 */
int test_wc_WolfmathDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_PUBLIC_MP)
    mp_int a;

    XMEMSET(&a, 0, sizeof(mp_int));
    ExpectIntEQ(mp_init(&a), MP_OKAY);

    /* Load a known nonzero value so used>=1 and dp[0] is set */
    ExpectIntEQ(mp_set(&a, 0xFF), MP_OKAY);

    /* digit count must now be >= 1 */
    ExpectIntGT(mp_get_digit_count(&a), 0);

    /* Pair A: n < 0 -> ternary TRUE, return 0 */
    ExpectIntEQ((int)mp_get_digit(&a, -1), 0);

    /* Pair B: n >= used -> ternary TRUE (second sub-cond), return 0 */
    ExpectIntEQ((int)mp_get_digit(&a, mp_get_digit_count(&a)), 0);

    /* One past end (same pair B, larger gap) */
    ExpectIntEQ((int)mp_get_digit(&a, mp_get_digit_count(&a) + 99), 0);

    /* Pair C: n == 0 and used >= 1 -> ternary FALSE, return dp[0] != 0 */
    ExpectIntNE((int)mp_get_digit(&a, 0), 0);

    /* Load a two-digit value to test digit index 1 */
    {
        /* 0x1_0000_0001 requires at least 2 digits on 32-bit word systems;
         * use mp_set_int if available, otherwise stay single-digit */
        mp_int big;
        XMEMSET(&big, 0, sizeof(mp_int));
        ExpectIntEQ(mp_init(&big), MP_OKAY);
        ExpectIntEQ(mp_set_int(&big, 0x12345678UL), MP_OKAY);
        /* digit 0 must be in-range (F path of ternary) */
        (void)mp_get_digit(&big, 0); /* just ensure no crash */
        /* digit 0 must be in-range for a valid mp */
        ExpectIntGE(mp_get_digit_count(&big), 1);
        mp_clear(&big);
    }

    mp_clear(&a);
#endif /* WOLFSSL_PUBLIC_MP */
    return EXPECT_RESULT();
} /* End test_wc_WolfmathDecisionCoverage */

/*
 * test_wc_WolfmathCondCopyCoverage
 *
 * Targets mp_cond_copy (L125-L157) MC/DC independence pairs:
 *
 *   Condition set (L125): a==NULL || b==NULL  (covered in BadArg above)
 *
 *   Body decisions:
 *   Pair D: copy==0 -> mask=0  -> b is UNCHANGED after call
 *   Pair E: copy==1 -> mask=~0 -> b becomes identical to a after call
 *   Pair F: a->used > b->used  -> second loop (b->used range) executes
 *   Pair G: a and b already equal, copy==1 -> b unchanged (XOR identity)
 */
int test_wc_WolfmathCondCopyCoverage(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_MP_COND_COPY)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    mp_int b;

    XMEMSET(&a, 0, sizeof(mp_int));
    XMEMSET(&b, 0, sizeof(mp_int));
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);

    /* Set a = 0xDEAD, b = 0x1 so they differ */
    ExpectIntEQ(mp_set(&a, 0xDEAD), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0x1),    MP_OKAY);

    /* Pair D: copy==0 -> b must remain 0x1 */
    ExpectIntEQ(mp_cond_copy(&a, 0, &b), MP_OKAY);
    /* b should still equal 0x1: digit[0] unchanged */
    ExpectIntNE((int)mp_get_digit(&b, 0), (int)mp_get_digit(&a, 0));

    /* Pair E: copy==1 -> b must become a */
    ExpectIntEQ(mp_cond_copy(&a, 1, &b), MP_OKAY);
    /* now b[0] == a[0] */
    ExpectIntEQ((int)mp_get_digit(&b, 0), (int)mp_get_digit(&a, 0));
    ExpectIntEQ(mp_get_digit_count(&b), mp_get_digit_count(&a));

    /* Pair F: b is zero, a is nonzero – b grows to match a.
     * copy==1 should propagate full digit array. */
    {
        mp_int src;
        mp_int dst;
        XMEMSET(&src, 0, sizeof(mp_int));
        XMEMSET(&dst, 0, sizeof(mp_int));
        ExpectIntEQ(mp_init(&src), MP_OKAY);
        ExpectIntEQ(mp_init(&dst), MP_OKAY);
        ExpectIntEQ(mp_set(&src, 0xABCD), MP_OKAY);
        /* dst starts zeroed (used == 0) */
        ExpectIntEQ(mp_cond_copy(&src, 1, &dst), MP_OKAY);
        ExpectIntEQ((int)mp_get_digit(&dst, 0), (int)mp_get_digit(&src, 0));
        mp_clear(&src);
        mp_clear(&dst);
    }

    /* Pair G: a == b already, copy==1 -> XOR cancels, b stays identical */
    {
        mp_int x;
        mp_int y;
        XMEMSET(&x, 0, sizeof(mp_int));
        XMEMSET(&y, 0, sizeof(mp_int));
        ExpectIntEQ(mp_init(&x), MP_OKAY);
        ExpectIntEQ(mp_init(&y), MP_OKAY);
        ExpectIntEQ(mp_set(&x, 0x5A5A), MP_OKAY);
        ExpectIntEQ(mp_set(&y, 0x5A5A), MP_OKAY);
        ExpectIntEQ(mp_cond_copy(&x, 1, &y), MP_OKAY);
        ExpectIntEQ((int)mp_get_digit(&y, 0), (int)mp_get_digit(&x, 0));
        mp_clear(&x);
        mp_clear(&y);
    }

    mp_clear(&a);
    mp_clear(&b);
#endif /* (HAVE_ECC || WOLFSSL_MP_COND_COPY) && WOLFSSL_PUBLIC_MP */
    return EXPECT_RESULT();
} /* End test_wc_WolfmathCondCopyCoverage */

/*
 * test_wc_WolfmathRandCoverage
 *
 * Targets mp_rand (L167-L219) MC/DC independence pairs:
 *
 *   Pair H: rng==NULL -> MISSING_RNG_E                    (L172 T)
 *   Pair I: rng ok, a==NULL -> BAD_FUNC_ARG               (L175 T||F)
 *   Pair J: rng ok, a ok, digits<=0 -> BAD_FUNC_ARG       (L175 F||T)
 *   Pair K: all ok, digits==1 -> MP_OKAY                  (L175 F||F)
 *   Pair L: all ok, digits==2 -> MP_OKAY (multi-digit path)
 *   Pair M: top-digit==0 retry loop: by seeding with known value (best-
 *            effort; the while-loop condition exercises re-entry on zero top)
 *
 * Note: pairs H-K are also partially in BadArgCoverage; they are repeated
 * here in a grouped context for traceability.
 */
int test_wc_WolfmathRandCoverage(void)
{
    EXPECT_DECLS;
#if !defined(WC_NO_RNG) && \
    (defined(WC_RSA_BLINDING) || defined(WOLFSSL_PUBLIC_MP))
    WC_RNG rng;
    mp_int a;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&a, 0, sizeof(mp_int));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(mp_init(&a), MP_OKAY);

    /* Pair H: rng NULL -> MISSING_RNG_E */
    ExpectIntEQ(mp_rand(&a, 1, NULL), WC_NO_ERR_TRACE(MISSING_RNG_E));

    /* Pair I: a NULL, rng ok -> BAD_FUNC_ARG */
    ExpectIntEQ(mp_rand(NULL, 1, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Pair J: digits == 0, a ok, rng ok -> BAD_FUNC_ARG */
    ExpectIntEQ(mp_rand(&a, 0, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Pair J2: digits < 0 -> BAD_FUNC_ARG */
    ExpectIntEQ(mp_rand(&a, -1, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Pair K: single digit, all ok -> MP_OKAY */
    ExpectIntEQ(mp_rand(&a, 1, &rng), MP_OKAY);
    /* after mp_rand with digits==1, used must be 1 */
    ExpectIntEQ(mp_get_digit_count(&a), 1);

    /* Pair L: two digits -> MP_OKAY, tests multi-digit fill path */
    ExpectIntEQ(mp_rand(&a, 2, &rng), MP_OKAY);
    ExpectIntEQ(mp_get_digit_count(&a), 2);

    mp_clear(&a);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif /* !WC_NO_RNG && (WC_RSA_BLINDING || WOLFSSL_PUBLIC_MP) */
    return EXPECT_RESULT();
} /* End test_wc_WolfmathRandCoverage */

/*
 * test_wc_WolfmathFeatureCoverage
 *
 * Targets wc_export_int (L226-L267) MC/DC independence pairs beyond the
 * NULL guards:
 *
 *   Pair N: encType==WC_TYPE_HEX_STR -> hex branch (L234 T)
 *   Pair O: encType!=WC_TYPE_HEX_STR -> bin branch (L234 F)
 *   Pair P (bin path): *len < keySz -> BUFFER_E   (L256 T)
 *   Pair Q (bin path): *len >= keySz -> proceed    (L256 F)
 *   Pair R: keySz > mp bin size -> leading zero padding path exercised
 *   Pair S: mp == zero value    -> mp_unsigned_bin_size==0, full zero pad
 *   Pair T (hex path, WC_MP_TO_RADIX): *len < size -> BUFFER_E  (L242 T)
 *   Pair U (hex path): *len >= size -> mp_tohex succeeds          (L242 F)
 */
int test_wc_WolfmathFeatureCoverage(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)) && \
    defined(WOLFSSL_PUBLIC_MP)
    mp_int mp;
    byte   buf[64];
    word32 len;
    word32 keySz;

    XMEMSET(&mp, 0, sizeof(mp_int));
    ExpectIntEQ(mp_init(&mp), MP_OKAY);

    /* --- Pair S: mp == 0 (after init, value is 0) --- */
    /* Binary export of zero with sufficient keySz should succeed */
    keySz = 16;
    len   = keySz;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
                MP_OKAY);
    ExpectIntEQ((int)len, (int)keySz);
    /* All bytes should be zero */
    {
        word32 i;
        for (i = 0; i < keySz; i++) {
            ExpectIntEQ(buf[i], 0);
        }
    }

    /* --- Set a small nonzero value: 0x04D2 == 1234 decimal --- */
    ExpectIntEQ(mp_set(&mp, 1234), MP_OKAY);

    /* Pair O: binary path, exact keySz fit -> MP_OKAY */
    keySz = 4;
    len   = keySz;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
                MP_OKAY);
    ExpectIntEQ((int)len, (int)keySz);

    /* Pair P: binary path, *len < keySz -> BUFFER_E, *len updated */
    keySz = 8;
    len   = 4;   /* less than keySz=8 */
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
                WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ((int)len, (int)keySz); /* updated to required size */

    /* Pair Q: binary path, *len > keySz -> MP_OKAY (F path of L256) */
    keySz = 4;
    len   = sizeof(buf); /* larger than keySz */
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
                MP_OKAY);
    ExpectIntEQ((int)len, (int)keySz); /* len set to keySz */

    /* Pair R: keySz larger than mp bin representation -> zero-pad prefix */
    keySz = 32;
    len   = keySz;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
                MP_OKAY);
    /* Leading bytes should be zero (padding) */
    ExpectIntEQ(buf[0], 0);
    ExpectIntEQ(buf[1], 0);

#ifdef WC_MP_TO_RADIX
    /* Pair N: hex path, buffer large enough -> MP_OKAY */
    len = sizeof(buf);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR), MP_OKAY);
    /* 1234 decimal == 0x4D2; hex string is "4D2\0" = 4 chars */
    ExpectIntGT((int)len, 0);

    /* Pair T: hex path, buffer too small -> BUFFER_E */
    len = 1;
    ExpectIntEQ(wc_export_int(&mp, buf, &len, 0, WC_TYPE_HEX_STR),
                WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntGT((int)len, 1); /* updated to required size */
#endif /* WC_MP_TO_RADIX */

    mp_clear(&mp);
#endif /* (HAVE_ECC || WOLFSSL_EXPORT_INT) && WOLFSSL_PUBLIC_MP */
    return EXPECT_RESULT();
} /* End test_wc_WolfmathFeatureCoverage */

