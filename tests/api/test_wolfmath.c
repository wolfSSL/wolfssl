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

    /* test mp_int too large for export buf */
    len = sizeof(buf);
    ExpectIntEQ(mp_init(&mp), MP_OKAY);
    ExpectIntEQ(mp_set_bit(&mp, 257), 0);
    ExpectIntEQ(wc_export_int(&mp, buf, &len, keySz, WC_TYPE_UNSIGNED_BIN),
        WC_NO_ERR_TRACE(BUFFER_E));

    mp_clear(&mp);
#endif
    return EXPECT_RESULT();
} /* End test_wc_export_int */

/*
 * MC/DC coverage for the sp_int.c multi-precision engine (the sp-math
 * module, iso26262/mcdc-per-module). These call the sp_* primitives
 * directly (not just their mp_* macro aliases in sp_int.h) since that is
 * the actual API under test; sp_* IS mp_* here whenever WOLFSSL_SP_MATH or
 * WOLFSSL_SP_MATH_ALL is the selected math backend. Each test below drives
 * an internal size/capacity guard or argument check that valid-sized inputs
 * never trip, using a deliberately undersized destination sp_int
 * (sp_init_size with a small size) or an out-of-range argument - both
 * legitimate, public ways to reach these decisions (as opposed to the
 * non-normalized-digit internal states that need the white-box supplement,
 * tests/unit-mcdc/test_sp_int_whitebox.c).
 */

/*
 * Testing sp_init_size / sp_grow / sp_copy / sp_exch: allocation and
 * capacity-guard decision branches.
 */
int test_wc_SpIntSizeDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int b;
    mp_int r;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&r, 0, sizeof(r));

    /* sp_init_size: NULL, size==0, size > SP_INT_DIGITS, normal. */
    ExpectIntEQ(sp_init_size(NULL, 4), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&a, 0), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&a, (unsigned int)SP_INT_DIGITS + 1),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&a, 4), 0);

    /* sp_grow: NULL, negative, too big for a->size, normal. */
    ExpectIntEQ(sp_grow(NULL, 1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_grow(&a, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_grow(&a, 100), WC_NO_ERR_TRACE(MP_MEM));
    ExpectIntEQ(sp_grow(&a, 2), 0);

    /* sp_copy: NULL args; a->used > r->size (undersized dest); a==r skips
     * the size check; normal. Build a multi-digit 'a' via sp_2expt (bit
     * index well beyond one word on any SP_WORD_SIZE) so the size check has
     * something to reject. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_copy(&a, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_copy(NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_copy(&a, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_copy(&a, &a), 0); /* same pointer: size check skipped */
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_copy(&a, &r), 0);

    /* sp_exch: NULL args; capacity mismatch in either direction; normal. */
    ExpectIntEQ(sp_exch(NULL, &b), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_exch(&a, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&b, 1), 0);
    /* b.size(1) < a.used: b too small to receive a (isolates the second
     * OR operand, a's size check on the first argument stays false since
     * b->used is 0 here). */
    ExpectIntEQ(sp_exch(&a, &b), WC_NO_ERR_TRACE(MP_VAL));
    /* a.size < b->used: the mirror image, isolating the first OR operand
     * with a small first argument and a bigger-used second argument. */
    {
        mp_int small;
        XMEMSET(&small, 0, sizeof(small));
        ExpectIntEQ(sp_init_size(&small, 1), 0);
        ExpectIntEQ(sp_init(&b), 0);
        ExpectIntEQ(sp_2expt(&b, 200), 0);
        ExpectIntEQ(sp_exch(&small, &b), WC_NO_ERR_TRACE(MP_VAL));
        mp_clear(&small);
    }
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_set(&b, 7), 0);
    /* a.size(SP_INT_DIGITS) < b.used never happens here; a<-b<->b<-a swap
     * with both large enough succeeds and exercises the false side. */
    ExpectIntEQ(sp_exch(&a, &b), 0);

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntSizeDecisionCoverage */

/*
 * Testing sp_set_bit / sp_2expt / sp_lshd / sp_rshb: bit/digit shift
 * argument and capacity-guard decision branches.
 */
int test_wc_SpIntShiftDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int r;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&r, 0, sizeof(r));

    /* sp_set_bit: negative index (NULL/too-large-index sides covered
     * elsewhere already). */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set_bit(&a, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_set_bit(&a, 3), 0);

    /* sp_2expt: NULL, negative exponent, normal. */
    ExpectIntEQ(sp_2expt(NULL, 5), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_2expt(&a, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_2expt(&a, 5), 0);

    /* sp_lshd: NULL, negative shift, overflow (used+s > size), normal. */
    ExpectIntEQ(sp_lshd(NULL, 1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&a, 2), 0);
    ExpectIntEQ(sp_set(&a, 1), 0);
    ExpectIntEQ(sp_lshd(&a, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_lshd(&a, 5), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_lshd(&a, 1), 0);

    /* sp_rshb: NULL, negative n, undersized dest, normal (dest != src and
     * dest == src both exercised). */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    ExpectIntEQ(sp_rshb(NULL, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_rshb(&a, -1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_rshb(&a, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_rshb(&a, 1, &r), 0);
    ExpectIntEQ(sp_rshb(&a, 1, &a), 0); /* in place: dest == src */
    /* Shift out every digit: hits the "ni >= a->used" short-circuit. */
    ExpectIntEQ(sp_rshb(&a, 4096, &r), 0);

    mp_clear(&a);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntShiftDecisionCoverage */

/*
 * Testing sp_add_d / sp_sub_d / sp_mul_d / sp_div_d / sp_mod_d / sp_div_2 /
 * sp_div_2_mod_ct: single-digit arithmetic capacity-guard decision
 * branches, and their WOLFSSL_SP_INT_NEGATIVE sign-path counterparts.
 */
int test_wc_SpIntDigitArithDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int r;
    sp_int_digit rem;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&r, 0, sizeof(r));

    /* sp_add_d: NULL args; undersized dest (a->used+1 > r->size); normal;
     * in-place (r == a, so _sp_add_d's "r != a" copy-tail is skipped). */
    ExpectIntEQ(sp_add_d(NULL, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_add_d(&a, 1, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_set(&a, SP_DIGIT_MAX), 0); /* forces a carry on add */
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_add_d(&a, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_add_d(&a, 1, &r), 0);
    ExpectIntEQ(sp_add_d(&a, 1, &a), 0); /* in place */

    /* sp_sub_d: NULL args; undersized dest; normal. */
    ExpectIntEQ(sp_sub_d(NULL, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_sub_d(&a, 1, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_sub_d(&a, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_sub_d(&a, 1, &r), 0);

    /* sp_mul_d: NULL args; undersized dest; normal. */
    ExpectIntEQ(sp_mul_d(NULL, 2, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mul_d(&a, 2, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_mul_d(&a, 2, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_mul_d(&a, 2, &r), 0);
    ExpectIntEQ(sp_mul_d(&a, 0, &r), 0); /* zero digit: used-clearing path */

    /* sp_div_d: NULL a, d==0; undersized dest (r may be NULL: rem-only
     * mode); normal, with a large/small divisor to hit both internal
     * divide strategies. */
    ExpectIntEQ(sp_div_d(NULL, 2, &r, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div_d(&a, 0, &r, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_div_d(&a, 2, &r, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_div_d(&a, 2, &r, &rem), 0);
    ExpectIntEQ(sp_div_d(&a, 2, NULL, &rem), 0); /* rem-only, r==NULL */
    ExpectIntEQ(sp_div_d(&a, SP_DIGIT_MAX, &r, &rem), 0); /* big divisor */

    /* sp_mod_d: NULL args, d==0; normal (power-of-2 and non-power-of-2
     * divisors take different internal paths). */
    ExpectIntEQ(sp_mod_d(NULL, 2, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mod_d(&a, 2, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mod_d(&a, 0, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mod_d(&a, 4, &rem), 0);   /* power of 2 */
    ExpectIntEQ(sp_mod_d(&a, 3, &rem), 0);   /* small, non power of 2 */
    ExpectIntEQ(sp_mod_d(&a, SP_DIGIT_MAX, &rem), 0); /* large divisor */

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
    /* sp_div_2: NULL args; undersized dest; normal. */
    ExpectIntEQ(sp_div_2(NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div_2(&a, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_div_2(&a, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_div_2(&a, &r), 0);

    /* sp_div_2_mod_ct: NULL args; undersized dest (m->used+1 > r->size);
     * normal. */
    {
        mp_int m;
        XMEMSET(&m, 0, sizeof(m));
        ExpectIntEQ(sp_init(&m), 0);
        ExpectIntEQ(sp_2expt(&m, 200), 0);
        ExpectIntEQ(sp_div_2_mod_ct(NULL, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_div_2_mod_ct(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_div_2_mod_ct(&a, &m, NULL), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init_size(&r, 1), 0);
        ExpectIntEQ(sp_div_2_mod_ct(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&r), 0);
        ExpectIntEQ(sp_div_2_mod_ct(&a, &m, &r), 0);
        mp_clear(&m);
    }
#endif /* WOLFSSL_SP_MATH_ALL && HAVE_ECC */

#ifdef WOLFSSL_SP_INT_NEGATIVE
    /* Negative-sign counterparts: sp_add_d/sp_sub_d select a different
     * capacity guard and internal path (add-magnitude vs subtract-magnitude)
     * when a->sign == MP_NEG. sp_mod_d's negative-remainder-normalize path
     * needs a negative dividend with a non-exact (nonzero remainder)
     * divisor. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    sp_setneg(&a);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    /* a->used > r->size, a negative: sp_add_d's MP_NEG capacity guard. */
    ExpectIntEQ(sp_add_d(&a, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_add_d(&a, 1, &r), 0); /* a negative, bigger than digit */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 1), 0);
    sp_setneg(&a);
    ExpectIntEQ(sp_add_d(&a, 5, &r), 0); /* a negative, <= digit: r = d-a */

    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    sp_setneg(&a);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    /* a->used+1 > r->size, a negative: sp_sub_d's MP_NEG capacity guard. */
    ExpectIntEQ(sp_sub_d(&a, 1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_sub_d(&a, 1, &r), 0);

    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 10), 0);
    sp_setneg(&a);
    /* Negative dividend, remainder nonzero: sign-normalize path taken. */
    ExpectIntEQ(sp_mod_d(&a, 3, &rem), 0);
    ExpectIntEQ(rem, 2); /* -10 mod 3 == 2 in sign-magnitude normalization */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 9), 0);
    sp_setneg(&a);
    /* Negative dividend, EXACT divisor: remainder zero, normalize skipped
     * (*r != 0 false side of the sign-normalize guard). */
    ExpectIntEQ(sp_mod_d(&a, 3, &rem), 0);
    ExpectIntEQ(rem, 0);
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    mp_clear(&a);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntDigitArithDecisionCoverage */

/*
 * Testing sp_add / sp_sub / sp_addmod_ct / sp_submod_ct / sp_div:
 * multi-precision arithmetic capacity-guard decision branches.
 */
int test_wc_SpIntArithDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int b;
    mp_int m;
    mp_int r;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&m, 0, sizeof(m));
    XMEMSET(&r, 0, sizeof(r));

    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_2expt(&b, 64), 0);

    /* sp_add: NULL args; undersized dest (a/b->used >= r->size); normal. */
    ExpectIntEQ(sp_add(NULL, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_add(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_add(&a, &b, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_add(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_add(&a, &b, &r), 0);
    ExpectIntEQ(sp_add(&b, &a, &r), 0); /* commute: b->used branch too */
    /* r sized strictly between b->used and a->used: isolates the b->used
     * term (idx1 false, idx2 true) from the a->used term. */
    ExpectIntEQ(sp_init_size(&r, 3), 0);
    ExpectIntEQ(sp_add(&b, &a, &r), WC_NO_ERR_TRACE(MP_VAL));

    /* sp_sub: NULL args; undersized dest; normal (a > b throughout, since
     * without WOLFSSL_SP_INT_NEGATIVE a must be >= b). */
    ExpectIntEQ(sp_sub(NULL, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_sub(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_sub(&a, &b, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_sub(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_sub(&a, &b, &r), 0);
    /* r sized strictly between the two used counts, with the smaller-used
     * operand first: isolates the second (b->used) term of the size check
     * from the first (a->used) term, mirroring the sp_add case above. The
     * size check itself runs before the sign-aware subtract, so passing
     * the bigger value as the second argument here is fine. */
    ExpectIntEQ(sp_init_size(&r, 3), 0);
    ExpectIntEQ(sp_sub(&b, &a, &r), WC_NO_ERR_TRACE(MP_VAL));

#if defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC)
    /* sp_addmod_ct / sp_submod_ct: undersized dest (m->used > r->size);
     * r == m aliasing rejected; normal. */
    ExpectIntEQ(sp_init(&m), 0);
    ExpectIntEQ(sp_2expt(&m, 96), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_addmod_ct(&a, &b, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_addmod_ct(&a, &b, &m, &m), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_addmod_ct(&a, &b, &m, &r), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_submod_ct(&a, &b, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_submod_ct(&a, &b, &m, &m), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_submod_ct(&a, &b, &m, &r), 0);
#endif /* WOLFSSL_SP_MATH_ALL && HAVE_ECC */

    /* sp_div: NULL args; d == 0; undersized quotient/remainder dest;
     * r-only, rem-only, and both together; a<d, a==d, a and d with the
     * same bit length (a>d, subtract shortcut) and a>>d (real long
     * division) to reach the internal fast-path and general-case
     * decisions. */
    ExpectIntEQ(sp_div(NULL, &b, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div(&a, NULL, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div(&a, &b, NULL, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&m), 0); /* zero */
    ExpectIntEQ(sp_div(&a, &m, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));

    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_div(&a, &b, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    {
        mp_int rem;
        XMEMSET(&rem, 0, sizeof(rem));
        ExpectIntEQ(sp_init_size(&rem, 1), 0);
        ExpectIntEQ(sp_div(&a, &b, &r, &rem), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&rem), 0);

        /* a < d */
        ExpectIntEQ(sp_div(&b, &a, &r, &rem), 0);
        /* a == d */
        ExpectIntEQ(sp_div(&a, &a, &r, &rem), 0);
        /* a, d same bit length, a > d (subtract shortcut) */
        {
            mp_int d2;
            XMEMSET(&d2, 0, sizeof(d2));
            ExpectIntEQ(sp_init(&d2), 0);
            ExpectIntEQ(sp_2expt(&d2, 200), 0);
            ExpectIntEQ(sp_set_bit(&d2, 5), 0); /* a > d2, same bit length */
            ExpectIntEQ(sp_div(&a, &d2, &r, &rem), 0);
            mp_clear(&d2);
        }
        /* a >> d: general long-division path, r-only and rem-only too. */
        ExpectIntEQ(sp_div(&a, &b, &r, &rem), 0);
        ExpectIntEQ(sp_div(&a, &b, &r, NULL), 0);
        ExpectIntEQ(sp_div(&a, &b, NULL, &rem), 0);
        mp_clear(&rem);
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&m);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntArithDecisionCoverage */

/*
 * Testing sp_div_2d / sp_mod_2d / sp_mul_2d / sp_sqrmod / sp_mont_red_ex /
 * sp_to_unsigned_bin_len(_ct) / sp_tohex / sp_read_radix (hex,
 * whitespace-tolerant tail): argument, capacity-guard, and parser decision
 * branches.
 */
int test_wc_SpIntConvDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int r;
    char buf[2048];
    byte bin[512];

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&r, 0, sizeof(r));
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);

#if defined(WOLFSSL_SP_MATH_ALL) || defined(OPENSSL_ALL)
    /* sp_div_2d: NULL args, negative e; undersized dest handled via
     * sp_rshb (covered above); zero-and-shift-out-everything path
     * (remBits <= 0); normal with and without a remainder out-param. */
    ExpectIntEQ(sp_div_2d(NULL, 5, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div_2d(&a, 5, NULL, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_div_2d(&a, -1, &r, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_div_2d(&a, 4096, &r, NULL), 0); /* shift out everything */
    {
        mp_int rem;
        XMEMSET(&rem, 0, sizeof(rem));
        ExpectIntEQ(sp_init(&rem), 0);
        ExpectIntEQ(sp_div_2d(&a, 4096, &r, &rem), 0);
        ExpectIntEQ(sp_div_2d(&a, 5, &r, &rem), 0); /* normal remBits > 0 */
        mp_clear(&rem);
    }
    ExpectIntEQ(sp_mul_2d(NULL, 5, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mul_2d(&a, 5, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mul_2d(&a, -1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_mul_2d(&a, 5, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_mul_2d(&a, 5, &r), 0);
    /* sp_lshb's internal partial-word-shift capacity guard
     * ((n != 0) && (r->used + s >= r->size)): a single-digit source with a
     * partial-word shift that exactly fills a single-digit destination
     * passes sp_mul_2d's own (bit-granularity) capacity pre-check but
     * still trips sp_lshb's (digit-granularity) one, since 1 digit's worth
     * of headroom is consumed exactly. Also toggle the "n != 0" side off
     * (whole-word shift) to complete that condition's pair. */
    {
        mp_int one;
        XMEMSET(&one, 0, sizeof(one));
        ExpectIntEQ(sp_init(&one), 0);
        ExpectIntEQ(sp_set(&one, 1), 0);
        ExpectIntEQ(sp_init_size(&r, 1), 0);
        ExpectIntEQ(sp_mul_2d(&one, 63, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&r), 0);
        ExpectIntEQ(sp_mul_2d(&one, 64, &r), 0); /* whole-word shift: n==0 */
        mp_clear(&one);
    }
#endif /* WOLFSSL_SP_MATH_ALL || OPENSSL_ALL */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(HAVE_ECC) || defined(OPENSSL_ALL)
    /* sp_mod_2d: NULL args, negative e; undersized dest; normal both with
     * digits <= a->used (mask off top digit) and digits > a->used
     * (identity copy). */
    ExpectIntEQ(sp_mod_2d(NULL, 5, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mod_2d(&a, 5, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_mod_2d(&a, -1, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_mod_2d(&a, 4096, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_mod_2d(&a, 5, &r), 0);      /* digits <= a->used */
    ExpectIntEQ(sp_mod_2d(&a, 4096, &r), 0);   /* digits > a->used */
#endif

    /* sp_sqrmod: NULL args; undersized dest (r != m path); a too big for
     * SP_INT_DIGITS when r == m (skipped: needs an operand at the compile
     * limit, documented residual); normal r != m and r == m. */
    {
        mp_int m;
        XMEMSET(&m, 0, sizeof(m));
        ExpectIntEQ(sp_init(&m), 0);
        ExpectIntEQ(sp_2expt(&m, 300), 0);
        ExpectIntEQ(sp_sqrmod(NULL, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_sqrmod(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_sqrmod(&a, &m, NULL), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init_size(&r, 1), 0);
        ExpectIntEQ(sp_sqrmod(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&r), 0);
        ExpectIntEQ(sp_sqrmod(&a, &m, &r), 0); /* r != m */
        ExpectIntEQ(sp_sqrmod(&m, &m, &m), 0); /* r == m */
        mp_clear(&m);
    }

    /* sp_mont_red_ex: NULL args, m == 0; a too small for the reduction
     * work area (a->size < m->used*2+1); normal. */
    {
        mp_int m;
        sp_int_digit mp;
        XMEMSET(&m, 0, sizeof(m));
        ExpectIntEQ(sp_init(&m), 0);
        ExpectIntEQ(sp_set(&m, 0xF1), 0);
        ExpectIntEQ(sp_mont_setup(&m, &mp), 0);
        ExpectIntEQ(sp_mont_red_ex(NULL, &m, mp, 0),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_mont_red_ex(&a, NULL, mp, 0),
            WC_NO_ERR_TRACE(MP_VAL));
        sp_zero(&m); /* zero modulus */
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 0), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&m), 0);
        ExpectIntEQ(sp_set(&m, 0xF1), 0);
        ExpectIntEQ(sp_init_size(&a, 1), 0);
        ExpectIntEQ(sp_set(&a, 3), 0);
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 0), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_init(&a), 0);
        ExpectIntEQ(sp_set(&a, 3), 0);
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 0), 0);
        ExpectIntEQ(sp_init(&a), 0);
        ExpectIntEQ(sp_set(&a, 3), 0);
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 1), 0); /* constant-time */
#ifdef WOLFSSL_SP_INT_NEGATIVE
        ExpectIntEQ(sp_init(&a), 0);
        ExpectIntEQ(sp_set(&a, 3), 0);
        sp_setneg(&a);
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 0),
            WC_NO_ERR_TRACE(MP_VAL)); /* a negative */
        ExpectIntEQ(sp_init(&a), 0);
        ExpectIntEQ(sp_set(&a, 3), 0);
        sp_setneg(&m);
        ExpectIntEQ(sp_mont_red_ex(&a, &m, mp, 0),
            WC_NO_ERR_TRACE(MP_VAL)); /* m negative */
#endif
        mp_clear(&m);
    }

    /* sp_to_unsigned_bin_len(_ct): NULL args, negative outSz; buffer too
     * small for the value (mid-digit truncation); normal. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 200), 0);
    ExpectIntEQ(sp_to_unsigned_bin_len(NULL, bin, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len(&a, NULL, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len(&a, bin, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len(&a, bin, 1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len(&a, bin, (int)sizeof(bin)), 0);
    ExpectIntEQ(sp_to_unsigned_bin_len_ct(NULL, bin, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len_ct(&a, NULL, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len_ct(&a, bin, -1),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_to_unsigned_bin_len_ct(&a, bin, (int)sizeof(bin)), 0);

    /* sp_tohex: nowhere else in this file drives it. NULL args + normal
     * (drives the leading-zero-byte skip loop over the top digit). */
    ExpectIntEQ(sp_tohex(NULL, buf), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_tohex(&a, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_tohex(&a, buf), 0);

    /* sp_read_radix (hex): trailing whitespace-only tail is skipped
     * (before any digit has been seen -> !eol_done true); embedded
     * whitespace after digits have started is rejected (eol_done already
     * true -> !eol_done false). The string is parsed from its last
     * character backwards, so a "trailing" separator here is encountered
     * first. */
    ExpectIntEQ(sp_read_radix(&a, "12 \t\n", 16), 0);
    ExpectIntEQ(sp_read_radix(&a, "12 34", 16), WC_NO_ERR_TRACE(MP_VAL));

    mp_clear(&a);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntConvDecisionCoverage */

/*
 * Testing sp_invmod / sp_exptmod_ex / sp_gcd / sp_prime_is_prime(_ex):
 * top-level argument-check and degenerate-input decision branches (the
 * inverse-mod / mod-exponent / gcd / primality state machines' internal
 * loops need the exact numeric properties documented as a residual class
 * in reports/sp-math/RESIDUALS.md).
 */
int test_wc_SpIntExptGcdDecisionCoverage(void)
{
    EXPECT_DECLS;
/* Guard on the union of the sp_* helpers these tests call: several
 * (sp_div_2d/sp_mod_2d/sp_mul_2d/sp_tohex/sp_exch/sp_2expt/sp_exptmod_ex) need
 * WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY, the ct helpers
 * (sp_addmod_ct/sp_submod_ct/sp_div_2_mod_ct/sp_div_2) need HAVE_ECC, and
 * sp_gcd needs !NO_RSA && WOLFSSL_KEY_GEN. This condition (which the campaign
 * sp-math config satisfies) guarantees every helper is compiled. */
#if defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int b;
    mp_int m;
    mp_int r;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&m, 0, sizeof(m));
    XMEMSET(&r, 0, sizeof(r));

    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 7), 0);
    ExpectIntEQ(sp_init(&m), 0);
    ExpectIntEQ(sp_set(&m, 15), 0);

    /* sp_invmod: NULL args, r == m aliasing; undersized dest
     * (m->used*2 > r->size); a == 0 or m == 0; a and m both even
     * (gcd != 1); a == 1 shortcut; normal. */
    ExpectIntEQ(sp_invmod(NULL, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_invmod(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_invmod(&a, &m, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_invmod(&a, &m, &m), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_invmod(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_invmod(&a, &m, &r), 0);
    sp_zero(&a);
    ExpectIntEQ(sp_invmod(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL)); /* a == 0 */
    sp_zero(&m);
    ExpectIntEQ(sp_set(&a, 3), 0);
    ExpectIntEQ(sp_invmod(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL)); /* m == 0 */
    ExpectIntEQ(sp_set(&a, 4), 0);
    ExpectIntEQ(sp_set(&m, 6), 0);
    ExpectIntEQ(sp_invmod(&a, &m, &r), WC_NO_ERR_TRACE(MP_VAL)); /* both even */
    ExpectIntEQ(sp_set(&a, 1), 0);
    ExpectIntEQ(sp_set(&m, 5), 0);
    ExpectIntEQ(sp_invmod(&a, &m, &r), 0); /* a == 1 shortcut */

    /* sp_exptmod_ex: NULL args, negative digits; m == 0; m == 1
     * (degenerate: result forced to 0); r aliasing e or m when base isn't
     * already reduced. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 4), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_set(&b, 3), 0);
    ExpectIntEQ(sp_init(&m), 0);
    ExpectIntEQ(sp_set(&m, 15), 0);
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_exptmod_ex(NULL, &b, 0, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_exptmod_ex(&a, NULL, 0, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, &m, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_exptmod_ex(&a, &b, -1, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    sp_zero(&m);
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, &m, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_set(&m, 1), 0);
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, &m, &r), 0); /* m == 1: r = 0 */
    ExpectIntEQ(sp_set(&m, 15), 0);
    /* Base already less than modulus: ordinary path. */
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, &m, &r), 0);
    /* r aliases m, base not reduced (a >= m): rejected. */
    ExpectIntEQ(sp_set(&a, 20), 0);
    ExpectIntEQ(sp_exptmod_ex(&a, &b, 0, &m, &m), WC_NO_ERR_TRACE(MP_VAL));

    /* sp_gcd: NULL args; a or b too big (>= SP_INT_DIGITS, skipped: needs
     * an operand at the compile limit, documented residual); undersized
     * dest; both zero (undefined); a zero, b nonzero (gcd = b); normal;
     * negative operand rejected under WOLFSSL_SP_INT_NEGATIVE. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 12), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_set(&b, 18), 0);
    ExpectIntEQ(sp_gcd(NULL, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_gcd(&a, NULL, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_gcd(&a, &b, NULL), WC_NO_ERR_TRACE(MP_VAL));
    /* Undersized dest, a->used(2) <= b->used(3): the size check's FIRST
     * ('a not bigger') clause fires; r sized 1 is below both. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 70), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_2expt(&b, 140), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), 0);
    /* Undersized dest, a->used(3) > b->used(2): the size check's SECOND
     * ('a bigger') clause fires; r sized 1 is below both. */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_2expt(&a, 140), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_2expt(&b, 70), 0);
    ExpectIntEQ(sp_init_size(&r, 1), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL));
    /* Same a > b shape, but r sized to cover b->used exactly: the second
     * clause's r->size < b->used half now goes false while a->used <
     * b->used stays true, isolating that operand's independence pair.
     * Size r to b->used (not a hard-coded 2) so this holds regardless of
     * SP_WORD_SIZE - at 32-bit words 2^70 occupies 3 digits, not 2. */
    ExpectIntEQ(sp_init_size(&r, b.used), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), 0);
    ExpectIntEQ(sp_init(&r), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), 0);
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 12), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_set(&b, 18), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), 0);
    sp_zero(&a);
    sp_zero(&b);
    ExpectIntEQ(sp_gcd(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL)); /* 0, 0 */
    ExpectIntEQ(sp_set(&b, 9), 0);
    ExpectIntEQ(sp_gcd(&a, &b, &r), 0); /* a == 0, b != 0 */
#ifdef WOLFSSL_SP_INT_NEGATIVE
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 12), 0);
    sp_setneg(&a);
    ExpectIntEQ(sp_gcd(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL)); /* a negative */
    ExpectIntEQ(sp_init(&a), 0);
    ExpectIntEQ(sp_set(&a, 12), 0);
    ExpectIntEQ(sp_init(&b), 0);
    ExpectIntEQ(sp_set(&b, 18), 0);
    sp_setneg(&b);
    ExpectIntEQ(sp_gcd(&a, &b, &r), WC_NO_ERR_TRACE(MP_VAL)); /* b negative */
#endif

    /* sp_prime_is_prime / sp_prime_is_prime_ex: trials out of range;
     * a == 1 shortcut; a even (composite, single-digit fast path). */
    {
        int result = 0;
        ExpectIntEQ(sp_init(&a), 0);
        ExpectIntEQ(sp_set(&a, 17), 0);
        ExpectIntEQ(sp_prime_is_prime(NULL, 8, &result),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_prime_is_prime(&a, 8, NULL), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_prime_is_prime(&a, 0, &result),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_prime_is_prime(&a, 1000000, &result),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(sp_set(&a, 1), 0);
        ExpectIntEQ(sp_prime_is_prime(&a, 8, &result), 0);
        ExpectIntEQ(result, MP_NO);
        ExpectIntEQ(sp_set(&a, 4), 0);
        ExpectIntEQ(sp_prime_is_prime(&a, 8, &result), 0);
        ExpectIntEQ(result, MP_NO);

#if !defined(WC_NO_RNG)
        {
            WC_RNG rng;
            XMEMSET(&rng, 0, sizeof(rng));
            ExpectIntEQ(wc_InitRng(&rng), 0);
            ExpectIntEQ(sp_prime_is_prime_ex(NULL, 8, &result, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(sp_prime_is_prime_ex(&a, 8, NULL, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(sp_prime_is_prime_ex(&a, 8, &result, NULL),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(sp_prime_is_prime_ex(&a, 0, &result, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(sp_prime_is_prime_ex(&a, 1000000, &result, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(sp_set(&a, 1), 0);
            ExpectIntEQ(sp_prime_is_prime_ex(&a, 8, &result, &rng), 0);
            ExpectIntEQ(result, MP_NO);
            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }
#endif /* !WC_NO_RNG */
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&m);
    mp_clear(&r);
#endif
    return EXPECT_RESULT();
} /* End test_wc_SpIntExptGcdDecisionCoverage */

/*
 * Testing fp_mul_2/fp_mul_2d/fp_div_2d/fp_mod_2d/fp_invmod/
 * fp_invmod_mont_ct/fp_to_unsigned_bin_len/mp_read_radix/mp_radix_size/
 * mp_toradix/mp_rand_prime/mp_prime_is_prime(_ex): argument-check,
 * capacity/FP_SIZE-guard and sign-dispatch decision branches of the
 * FASTMATH (tfm.c) backend (bigint-tfm module).
 */
int test_wc_TfmDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_FAST_MATH) && defined(WOLFSSL_PUBLIC_MP)
    fp_int a;
    fp_int b;
    fp_int c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));

    /* fp_mul_2: range check is
     *   (a->used > FP_SIZE-1) || ((a->used == FP_SIZE-1) && (top bit set))
     * Four calls complete all three operands' independence pairs (masking
     * MC/DC: the OR's first operand shares 'a->used' with the AND's first
     * operand, so they cannot vary independently of each other - each is
     * paired against the boundary case instead). */
    fp_zero(&a);
    a.used = FP_SIZE; /* a->used > FP_SIZE-1: true, rest masked */
    ExpectIntEQ(fp_mul_2(&a, &b), WC_NO_ERR_TRACE(FP_VAL));
    fp_zero(&a);
    a.used = FP_SIZE - 2; /* both OR operands false: ordinary small value */
    a.dp[FP_SIZE - 3] = 1;
    ExpectIntEQ(fp_mul_2(&a, &b), FP_OKAY);
    /* Note: the guard reads the FIXED sentinel slot a->dp[FP_SIZE-1] (one
     * past the last digit ->used == FP_SIZE-1 actually counts), not
     * a->dp[a->used-1] - so the "top bit set" side needs that specific
     * slot poked directly (fp_zero() leaves it 0, which every legitimate
     * caller's value would too, since it is beyond ->used). */
    fp_zero(&a);
    a.used = FP_SIZE - 1; /* a->used == FP_SIZE-1 true, top bit clear */
    a.dp[FP_SIZE - 2] = 1;
    ExpectIntEQ(fp_mul_2(&a, &b), FP_OKAY);
    fp_zero(&a);
    a.used = FP_SIZE - 1; /* a->used == FP_SIZE-1 true, top bit SET */
    a.dp[FP_SIZE - 2] = 1;
    a.dp[FP_SIZE - 1] = (fp_digit)1 << (DIGIT_BIT - 1);
    ExpectIntEQ(fp_mul_2(&a, &b), WC_NO_ERR_TRACE(FP_VAL));

    /* fp_mul_2d: "carry && x < FP_SIZE" - carry true with room to store it
     * (x < FP_SIZE, small 'a') vs carry true with the destination already
     * completely full (x == FP_SIZE, top digit high bit set). */
    fp_zero(&a);
    fp_set(&a, 1);
    a.dp[0] = (fp_digit)1 << (DIGIT_BIT - 1); /* shifting by 1 overflows */
    ExpectIntEQ(fp_mul_2d(&a, 1, &c), FP_OKAY); /* carry true, x(1) < FP_SIZE */
    fp_zero(&a);
    a.used = FP_SIZE;
    a.dp[FP_SIZE - 1] = (fp_digit)1 << (DIGIT_BIT - 1);
    ExpectIntEQ(fp_mul_2d(&a, 1, &c), WC_NO_ERR_TRACE(FP_VAL)); /* x==FP_SIZE */

    /* fp_div_2d: "a == c && d != NULL" / "a != c && d != NULL". Three
     * calls complete both operands' independence pairs. */
    fp_zero(&a);
    fp_set(&a, 200);
    fp_div_2d(&a, 3, &a, &c); /* a == c (true), d != NULL (true) */
    fp_zero(&a);
    fp_set(&a, 200);
    fp_div_2d(&a, 3, &b, &c); /* a != c (false/true pair vs above), d!=NULL */
    fp_zero(&a);
    fp_set(&a, 200);
    fp_div_2d(&a, 3, &b, NULL); /* a != c, d == NULL: isolates d!=NULL */

    /* fp_mod_2d: first guard "c->sign==FP_ZPOS && b>=DIGIT_BIT*a->used"
     * (c is fp_copy(a,c) inside, so c->sign tracks a->sign); second guard
     * "c->sign==FP_NEG && bmax>=FP_SIZE" (only reached once the first is
     * false). */
    fp_zero(&a);
    fp_set(&a, 5); /* a->used == 1 */
    fp_mod_2d(&a, (int)DIGIT_BIT, &c); /* ZPOS(T) && b>=DIGIT_BIT*1(T):
                                    early return, c == a unchanged (5) */
    ExpectIntEQ(fp_cmp_d(&c, 5), FP_EQ);
    fp_zero(&a);
    fp_set(&a, 5);
    fp_setneg(&a);
    fp_mod_2d(&a, (int)DIGIT_BIT, &c); /* ZPOS(F): isolates the sign operand */
    fp_zero(&a);
    fp_set(&a, 5);
    fp_mod_2d(&a, 0, &c); /* ZPOS(T), b>=... (F): isolates the 'b' operand */
    ExpectIntEQ(fp_iszero(&c), FP_YES);
    /* second guard: build a huge negative 'a' (a->used == FP_SIZE) so the
     * first guard's "b >= DIGIT_BIT*a->used" is false for a 'b' just under
     * FP_SIZE*DIGIT_BIT, yet bmax = ceil(b/DIGIT_BIT) can still reach
     * FP_SIZE. */
    fp_zero(&a);
    a.used = FP_SIZE;
    a.dp[FP_SIZE - 1] = 1;
    fp_setneg(&a);
    fp_mod_2d(&a, (int)(DIGIT_BIT * FP_SIZE) - 1, &c); /* NEG(T), bmax>=FP_SIZE(T) */
    fp_zero(&a);
    a.used = FP_SIZE;
    a.dp[FP_SIZE - 1] = 1;
    fp_mod_2d(&a, (int)(DIGIT_BIT * FP_SIZE) - 1, &c); /* ZPOS: isolates NEG op */
    fp_zero(&a);
    a.used = FP_SIZE;
    a.dp[FP_SIZE - 1] = 1;
    fp_setneg(&a);
    fp_mod_2d(&a, 4, &c); /* NEG(T), bmax small (F): isolates bmax operand */

    /* fp_invmod: "b->sign==FP_NEG || fp_iszero(b)==FP_YES" (fp_iszero(b)
     * half already shown elsewhere; complete the sign operand's pair). */
    fp_zero(&a);
    fp_set(&a, 3);
    fp_zero(&b);
    fp_set(&b, 7);
    fp_setneg(&b);
    ExpectIntEQ(fp_invmod(&a, &b, &c), WC_NO_ERR_TRACE(FP_VAL));
    fp_zero(&b);
    fp_set(&b, 7);
    ExpectIntEQ(fp_invmod(&a, &b, &c), FP_OKAY);

    /* fp_invmod_mont_ct: "(a->used*2 > FP_SIZE) || (b->used*2 > FP_SIZE)".
     * Three calls complete both operands' pairs. */
    fp_zero(&a);
    a.used = FP_SIZE;
    fp_zero(&b);
    fp_set(&b, 3);
    ExpectIntEQ(fp_invmod_mont_ct(&a, &b, &c, 1), WC_NO_ERR_TRACE(FP_VAL));
    fp_zero(&a);
    fp_set(&a, 2);
    fp_zero(&b);
    b.used = FP_SIZE;
    ExpectIntEQ(fp_invmod_mont_ct(&a, &b, &c, 1), WC_NO_ERR_TRACE(FP_VAL));
    fp_zero(&a);
    fp_set(&a, 2);
    fp_zero(&b);
    fp_set(&b, 3);
    ExpectIntNE(fp_invmod_mont_ct(&a, &b, &c, 1), WC_NO_ERR_TRACE(FP_VAL));

    /* fp_to_unsigned_bin_len: "i == a->used-1 && (a->dp[i]>>j) != 0" -
     * output length exactly reaches the top digit, with (A) enough spare
     * high bits to hold it (success) and (B) not enough (truncated,
     * FP_VAL). A third call with a fully-sized buffer isolates the
     * "i == a->used-1" operand (never reached: overall false). */
#if DIGIT_BIT == 64 || DIGIT_BIT == 32 || DIGIT_BIT == 16
    {
        byte buf[8];
        XMEMSET(buf, 0, sizeof(buf));
        fp_zero(&a);
        fp_set(&a, 0xFF); /* fits in 1 byte */
        ExpectIntEQ(fp_to_unsigned_bin_len(&a, buf, 4), FP_OKAY); /* i!=used-1 */
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(fp_to_unsigned_bin_len(&a, buf, 1), FP_OKAY); /* i==used-1,
                                                       top bits already 0 */
        fp_zero(&a);
        fp_set(&a, 0x1FF); /* needs 2 bytes */
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(fp_to_unsigned_bin_len(&a, buf, 1),
            WC_NO_ERR_TRACE(FP_VAL)); /* i==used-1, top bits nonzero */
    }
#endif

    /* mp_read_radix (fp_read_radix): "radix < 2 || radix > 64". */
    ExpectIntEQ(mp_read_radix(&a, "10", 1), WC_NO_ERR_TRACE(FP_VAL));
    ExpectIntEQ(mp_read_radix(&a, "10", 65), WC_NO_ERR_TRACE(FP_VAL));
    ExpectIntEQ(mp_read_radix(&a, "10", MP_RADIX_DEC), FP_OKAY);

    /* mp_radix_size / mp_toradix: "radix < 2 || radix > 64" (each function
     * has its own copy of the guard). */
    {
        int size = 0;
        char buf[8];

        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_radix_size(&a, 1, &size), WC_NO_ERR_TRACE(FP_VAL));
        ExpectIntEQ(mp_radix_size(&a, 65, &size), WC_NO_ERR_TRACE(FP_VAL));
        ExpectIntEQ(mp_radix_size(&a, MP_RADIX_DEC, &size), FP_OKAY);

        ExpectIntEQ(mp_toradix(&a, buf, 1), WC_NO_ERR_TRACE(FP_VAL));
        ExpectIntEQ(mp_toradix(&a, buf, 65), WC_NO_ERR_TRACE(FP_VAL));
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_toradix(&a, buf, MP_RADIX_DEC), FP_OKAY);
    }

#if !defined(WC_NO_RNG)
    /* mp_rand_prime (fp_randprime): "len < 2 || len > 512" (len<2 already
     * shown elsewhere; complete the len>512 operand's pair). */
    {
        WC_RNG rng;

        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        fp_zero(&a);
        ExpectIntEQ(mp_rand_prime(&a, 513, &rng, HEAP_HINT),
            WC_NO_ERR_TRACE(FP_VAL));
        ExpectIntEQ(mp_rand_prime(&a, 32, &rng, HEAP_HINT), FP_OKAY);

        /* mp_prime_is_prime_ex (own trial-division/Miller-Rabin engine):
         * "t <= 0 || t > FP_PRIME_SIZE" (t<=0 already shown elsewhere;
         * complete the t>FP_PRIME_SIZE operand's pair). */
        {
            int result = 0;

            fp_zero(&a);
            fp_set(&a, 17);
            ExpectIntEQ(mp_prime_is_prime_ex(&a, FP_PRIME_SIZE + 1, &result,
                &rng), WC_NO_ERR_TRACE(FP_VAL));
            ExpectIntEQ(mp_prime_is_prime_ex(&a, 8, &result, &rng), FP_OKAY);
            ExpectIntEQ(result, FP_YES);
        }

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif /* !WC_NO_RNG */

    /* mp_prime_is_prime (fp_isprime_ex): trial-division loop
     * "res != MP_OKAY || d == 0" - only the 'd == 0' half is targeted here
     * (res != MP_OKAY is a defensive residual, see REPORT.md); and the
     * Miller-Rabin loop "err != FP_OKAY || res == FP_NO": a composite that
     * survives trial division (product of two primes above the built-in
     * table) reaches Miller-Rabin and is correctly rejected there. */
    {
        int result = 0;

        fp_zero(&a);
        fp_set(&a, 17); /* prime: table hit */
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), FP_OKAY);
        ExpectIntEQ(result, FP_YES);

        fp_zero(&a);
        fp_set(&a, 6); /* divisible by 2 and 3 */
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), FP_OKAY);
        ExpectIntEQ(result, FP_NO);

        /* 1013 * 1019 = 1032247: both factors are larger than every prime
         * in the FP_PRIME_SIZE (256) built-in table, so trial division
         * finds no divisor and the composite reaches Miller-Rabin, which
         * correctly reports it composite (res == FP_NO). */
        fp_zero(&a);
        fp_set(&a, 1032247u);
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), FP_OKAY);
        ExpectIntEQ(result, FP_NO);
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
#endif /* USE_FAST_MATH && WOLFSSL_PUBLIC_MP */
    return EXPECT_RESULT();
} /* End test_wc_TfmDecisionCoverage */

/*
 * Testing fp_exptmod/fp_exptmod_ex/fp_exptmod_nct: the negative-exponent
 * (X->sign == FP_NEG) branch's "invmod succeeded" / "modulus is negative"
 * decision chain, common to all three entry points, and the tail
 * "mode == 2 && bitcpy > 0" leftover-window decision inside the shared
 * non-constant-time engine (bigint-tfm module, tfm.c).
 */
int test_wc_TfmExptModDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_FAST_MATH) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(POSITIVE_EXP_ONLY)
    fp_int g;
    fp_int x;
    fp_int p;
    fp_int y;

    XMEMSET(&g, 0, sizeof(g));
    XMEMSET(&x, 0, sizeof(x));
    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&y, 0, sizeof(y));

    /* fp_exptmod: "fp_iszero(P) || (P->used > FP_SIZE/2)" - the iszero half
     * is exercised elsewhere; complete the size operand's pair with a huge
     * (but nonzero) modulus. */
    fp_set(&g, 3);
    fp_set(&x, 2);
    fp_zero(&p);
    p.used = (FP_SIZE / 2) + 1;
    p.dp[p.used - 1] = 1;
    ExpectIntEQ(fp_exptmod(&g, &x, &p, &y), WC_NO_ERR_TRACE(FP_VAL));
    fp_set(&p, 15);
    ExpectIntEQ(fp_exptmod(&g, &x, &p, &y), FP_OKAY);

    /* fp_exptmod / fp_exptmod_ex / fp_exptmod_nct share the same
     * negative-exponent chain:
     *   if ((err == 0) && (P->sign == FP_NEG)) { err = fp_add(Y, P, Y); }
     * where 'err' comes from invmod(G, |P|, ...). Three calls per entry
     * point complete both operands' independence pairs:
     *   call A: G=3, X=-3, P=7  (invmod succeeds: err==0 T; P ZPOS: F)
     *   call B: G=3, X=-3, P=-7 (invmod succeeds: err==0 T; P NEG: T)
     *   call C: G=7, X=-3, P=-7 (invmod fails (gcd=7): err==0 F; P NEG: T)
     * Pair (A,B) isolates the P->sign operand (err==0 held true);
     * pair (B,C) isolates the err==0 operand (P->sign held negative). */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    ExpectIntEQ(fp_exptmod(&g, &x, &p, &y), FP_OKAY); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod(&g, &x, &p, &y), FP_OKAY); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod(&g, &x, &p, &y), WC_NO_ERR_TRACE(FP_VAL)); /* call C */

    /* fp_exptmod_ex: same size guard ("fp_iszero(P)||P->used>FP_SIZE/2")
     * and the same negative-exponent chain, reached through its own entry
     * point (digits == 0 lets it pick X->used internally). */
    fp_set(&g, 3);
    fp_set(&x, 2);
    fp_zero(&p);
    p.used = (FP_SIZE / 2) + 1;
    p.dp[p.used - 1] = 1;
    ExpectIntEQ(fp_exptmod_ex(&g, &x, 0, &p, &y), WC_NO_ERR_TRACE(FP_VAL));

    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    ExpectIntEQ(fp_exptmod_ex(&g, &x, 0, &p, &y), FP_OKAY); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod_ex(&g, &x, 0, &p, &y), FP_OKAY); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod_ex(&g, &x, 0, &p, &y),
        WC_NO_ERR_TRACE(FP_VAL)); /* call C */

    /* fp_exptmod_nct: always uses the non-constant-time engine regardless
     * of TFM_TIMING_RESISTANT, so its own copy of the negative-exponent
     * chain is independently reachable through this entry point. */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    ExpectIntEQ(fp_exptmod_nct(&g, &x, &p, &y), FP_OKAY); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod_nct(&g, &x, &p, &y), FP_OKAY); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    ExpectIntEQ(fp_exptmod_nct(&g, &x, &p, &y),
        WC_NO_ERR_TRACE(FP_VAL)); /* call C */

    /* _fp_exptmod_nct tail (reached via the public fp_exptmod_nct):
     * "mode == 2 && bitcpy > 0" - winsize is chosen from fp_count_bits(X):
     * <=21 bits picks winsize 1, which flushes every bit immediately
     * (bitcpy is always 0 at the tail: the false side); a bigger X (e.g.
     * 30 bits, winsize 3) leaves a partial window at the end (bitcpy > 0:
     * the true side). */
    fp_set(&g, 3);
    fp_set(&x, 7); /* 3 bits: winsize 1, bitcpy==0 tail */
    fp_set(&p, 15);
    ExpectIntEQ(fp_exptmod_nct(&g, &x, &p, &y), FP_OKAY);
    fp_set(&g, 3);
    fp_set(&x, 0x3FFFFFFF); /* 30 bits: winsize 3 */
    fp_set(&p, 15);
    ExpectIntEQ(fp_exptmod_nct(&g, &x, &p, &y), FP_OKAY);

    mp_clear(&g);
    mp_clear(&x);
    mp_clear(&p);
    mp_clear(&y);
#endif /* USE_FAST_MATH && WOLFSSL_PUBLIC_MP && !POSITIVE_EXP_ONLY */
    return EXPECT_RESULT();
} /* End test_wc_TfmExptModDecisionCoverage */

/* Helper for test_wc_IntegerDecisionCoverage: grow 'a' to 'used' real
 * digits (a legitimate, if arbitrary, big value - not a corrupted/
 * non-normalized state) and fill every digit with 'fill'. */
#if defined(USE_INTEGER_HEAP_MATH) && defined(WOLFSSL_PUBLIC_MP)
static void wolfmath_big_fill(mp_int* a, int used, mp_digit fill)
{
    int i;
    XMEMSET(a, 0, sizeof(*a));
    mp_init(a);
    mp_grow(a, used);
    for (i = 0; i < used; i++) {
        a->dp[i] = fill;
    }
    a->used = used;
    a->sign = MP_ZPOS;
}
#endif

/*
 * Testing mp_init_multi/mp_copy/mp_grow/mp_mod_2d/mp_exptmod/mp_invmod/
 * mp_invmod_slow/mp_cmp_d/s_mp_add/s_mp_sub/mp_exptmod_fast/
 * mp_exptmod_base_2/mp_montgomery_reduce/mp_set_bit/mp_mul_d/mp_sqr/mp_mul/
 * s_mp_mul_digs/s_mp_exptmod/s_mp_mul_high_digs/mp_add_d/mp_sub_d/
 * mp_prime_is_prime(_ex)/mp_rand_prime/mp_read_radix/mp_radix_size/
 * mp_toradix: argument-check, capacity/MP_WARRAY-threshold and
 * sign-dispatch decision branches of the HEAPMATH (integer.c) backend
 * (bigint-integer module).
 */
int test_wc_IntegerDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_INTEGER_HEAP_MATH) && defined(WOLFSSL_PUBLIC_MP)
    mp_int a;
    mp_int b;
    mp_int c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));

    /* mp_init_multi: each "if (X && (mp_init(X) != MP_OKAY))" - the
     * pointer-non-null operand's pair (NULL vs non-NULL for that slot);
     * mp_init() itself cannot fail for a non-NULL pointer (no allocation
     * happens in mp_init - see REPORT.md), so the "!= MP_OKAY" operand's
     * true side is a documented residual for all six slots. */
    {
        mp_int ia, ib, ic, id, ie, iff;
        XMEMSET(&ia, 0, sizeof(ia)); XMEMSET(&ib, 0, sizeof(ib));
        XMEMSET(&ic, 0, sizeof(ic)); XMEMSET(&id, 0, sizeof(id));
        XMEMSET(&ie, 0, sizeof(ie)); XMEMSET(&iff, 0, sizeof(iff));

        ExpectIntEQ(mp_init_multi(NULL, NULL, NULL, NULL, NULL, NULL),
            MP_OKAY);
        ExpectIntEQ(mp_init_multi(&ia, &ib, &ic, &id, &ie, &iff), MP_OKAY);
        mp_clear(&ia); mp_clear(&ib); mp_clear(&ic);
        mp_clear(&id); mp_clear(&ie); mp_clear(&iff);
    }

    /* mp_copy: NULL args. */
    ExpectIntEQ(mp_copy(NULL, &a), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_copy(&a, NULL), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_copy(&a, &b), MP_OKAY);

    /* mp_grow: "(a->alloc < size) || (size == 0) || (a->alloc == 0)". A
     * fresh mp_int (a->alloc == 0) with a negative size makes the FIRST
     * two operands false (0 < -5 is false; -5 == 0 is false) so only the
     * third ('a->alloc == 0') determines the true outcome and enters the
     * realloc branch; with MP_LOW_MEM's MP_PREC==1 the negative size isn't
     * padded back to positive, so the (size_t) cast wraps to a huge
     * request and the realloc legitimately fails (MP_MEM) - the branch
     * itself is still what this pair targets, not the exact return code.
     * A pre-grown 'a' with a smaller, nonzero request makes all three
     * operands false, isolating the third operand's false side. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_grow(&a, -5),
        WC_NO_ERR_TRACE(MP_MEM)); /* alloc==0 (true), rest false */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_grow(&a, 10), MP_OKAY);
    ExpectIntEQ(mp_grow(&a, 4), MP_OKAY); /* alloc(>=10) != 0, size(4)!=0,
                                              alloc(>=10) >= size(4): all F */

    /* mp_mod_2d: same two-guard shape as fp_mod_2d (tfm.c); mp_mod_2d
     * copies 'a' into 'c' first, so c->sign tracks a->sign. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_mod_2d(&a, (int)DIGIT_BIT, &c), MP_OKAY); /* ZPOS(T) &&
                    b>=DIGIT_BIT*1 (T): early return, c == a unchanged (5) */
    ExpectIntEQ(mp_cmp_d(&c, 5), MP_EQ);
    a.sign = MP_NEG;
    ExpectIntEQ(mp_mod_2d(&a, (int)DIGIT_BIT, &c), MP_OKAY); /* ZPOS(F) */
    a.sign = MP_ZPOS;
    ExpectIntEQ(mp_mod_2d(&a, 0, &c), MP_OKAY); /* ZPOS(T), b>=...(F) */
    ExpectIntEQ(mp_cmp_d(&c, 0), MP_EQ);

    /* mp_exptmod: "mp_iszero(P) || P->sign == MP_NEG" - the iszero half is
     * shown elsewhere; complete the sign operand's pair with a nonzero
     * negative modulus. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 2), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_set(&c, 7), MP_OKAY);
    c.sign = MP_NEG;
    ExpectIntEQ(mp_exptmod(&a, &b, &c, &a), WC_NO_ERR_TRACE(MP_VAL));

    /* mp_invmod: "b sign NEG || iszero(b) || iszero(a)" - three operands,
     * each isolated in turn against an otherwise-valid a=3,b=7 pair. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    b.sign = MP_NEG;
    ExpectIntEQ(mp_invmod(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY); /* reset sign to ZPOS */
    mp_zero(&b);
    ExpectIntEQ(mp_invmod(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY);
    mp_zero(&a);
    ExpectIntEQ(mp_invmod(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_invmod(&a, &b, &c), MP_OKAY);

    /* mp_invmod_slow (public in the integer.c backend): its own copy of
     * the same "b sign NEG || iszero(b)" guard. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 10), MP_OKAY); /* even modulus: slow path */
    b.sign = MP_NEG;
    ExpectIntEQ(mp_invmod_slow(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    mp_zero(&b);
    ExpectIntEQ(mp_invmod_slow(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&b, 10), MP_OKAY);
    ExpectIntEQ(mp_invmod_slow(&a, &b, &c), MP_OKAY);

    /* mp_cmp_d: "a->used==0 && b==0" and "(b && a->used==0) || sign==NEG".
     * Five calls complete all four independent operands' pairs (the
     * a->used==0 operand is shared between the two decisions). */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_cmp_d(&a, 0), MP_EQ); /* a->used==0(T) && b==0(T) */
    ExpectIntEQ(mp_set(&a, 9), MP_OKAY);
    ExpectIntEQ(mp_cmp_d(&a, 0), MP_GT); /* a->used==0(F): isolates op0 */
    ExpectIntEQ(mp_init(&a), MP_OKAY); /* a->used==0 again */
    ExpectIntEQ(mp_cmp_d(&a, 5), MP_LT); /* b==0(F): isolates op1; also
                        (b(T) && a->used==0(T)) => MP_LT: op2/op3 baseline */
    ExpectIntEQ(mp_set(&a, 9), MP_OKAY);
    ExpectIntEQ(mp_cmp_d(&a, 5), MP_GT); /* b(T) && a->used==0(F): isolates
                                            the "a->used==0" operand of the
                                            second decision, sign ZPOS(F) */
    a.sign = MP_NEG;
    ExpectIntEQ(mp_cmp_d(&a, 5), MP_LT); /* sign==NEG(T): isolates op3 */

    /* mp_add / s_mp_add: "min_ab > 0 && (dp==NULL...)" - the dp==NULL
     * combination needs a non-normalized/corrupted mp_int (impossible via
     * any public mutator) and is exercised in test_integer_whitebox.c
     * instead; complete the "min_ab > 0" operand's pair here (both
     * operands nonzero vs one operand zero-used). */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 4), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(s_mp_add(&a, &b, &c), MP_OKAY); /* min_ab(1) > 0: true */
    mp_zero(&b);
    ExpectIntEQ(s_mp_add(&a, &b, &c), MP_OKAY); /* min_ab(0) > 0: false */

    /* mp_sub / s_mp_sub: "min_b > 0 && (tmpa==NULL || tmpb==NULL)" - unlike
     * s_mp_add above, min_b is just b->used (not MIN(a,b)), so "tmpa==NULL"
     * is legitimately reachable: a freshly-initialized, never-grown 'a'
     * (->used==0) has ->dp==NULL regardless of b. tmpb==NULL still needs a
     * corrupted b (exercised in test_integer_whitebox.c instead). */
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 4), MP_OKAY);
    ExpectIntEQ(s_mp_sub(&a, &b, &c), MP_OKAY); /* min_b(1) > 0: true */
    mp_zero(&b);
    ExpectIntEQ(s_mp_sub(&a, &b, &c), MP_OKAY); /* min_b(0) > 0: false */
    ExpectIntEQ(mp_init(&a), MP_OKAY); /* a->used==0: tmpa == a->dp == NULL */
    ExpectIntEQ(mp_set(&b, 4), MP_OKAY); /* min_b(1) > 0 */
    ExpectIntEQ(s_mp_sub(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL)); /* tmpa==NULL:
                                                                    true */

    /* mp_exptmod_fast / mp_exptmod_base_2 / mp_montgomery_reduce: all
     * three share
     *   (N->used * 2 + 1 < MP_WARRAY) && (N->used < 1L<<(WORD_BITS-2*DB))
     * (or the SUM-based digs variant for mp_montgomery_reduce) to pick
     * between the comba-accelerated and generic montgomery reduce - both
     * arms are functionally equivalent (just performance), so a small and
     * a large (real, legitimately grown) modulus both succeed; only the
     * dispatch is different. The two thresholds are numerically disjoint
     * for this shape (N->used <= 255 from the first vs N->used >= 256
     * needed for the second to go false), so the second operand's false
     * side can never coexist with the first operand's true side -
     * documented residual (see REPORT.md); only the first operand's pair
     * is targeted here (small N takes the comba path, big N the generic
     * one). */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 2), MP_OKAY);
    wolfmath_big_fill(&c, 20, 3); /* small odd-ish modulus-shaped value */
    c.dp[0] |= 1; /* keep it odd so montgomery_setup succeeds */
    ExpectIntEQ(mp_exptmod_fast(&a, &b, &c, &a, 0), MP_OKAY); /* small N */
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    {
        mp_int big;
        XMEMSET(&big, 0, sizeof(big));
        wolfmath_big_fill(&big, 300, 3); /* N->used(300)*2+1 >= MP_WARRAY:
                                             takes the generic reduce path */
        big.dp[0] |= 1;
        ExpectIntEQ(mp_exptmod_fast(&a, &b, &big, &a, 0), MP_OKAY);
        mp_clear(&big);
    }
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_exptmod_base_2(&b, &c, &a), MP_OKAY);
    {
        mp_digit rho = 0;
        ExpectIntEQ(mp_montgomery_setup(&c, &rho), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
        ExpectIntEQ(mp_montgomery_reduce(&a, &c, rho), MP_OKAY);
    }

    /* mp_set_bit: "b < 0 || (a->dp==NULL && (a->alloc!=0 || a->used!=0))".
     * The parenthesized clause needs a non-normalized/corrupted mp_int (a
     * real dp==NULL is only ever paired with alloc==0 && used==0) and is
     * exercised in test_integer_whitebox.c instead; complete the "b < 0"
     * operand's pair here. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set_bit(&a, -1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set_bit(&a, 3), MP_OKAY);

    /* mp_mul_d: "c->dp==NULL || c->alloc < a->used+1" - both operands are
     * legitimately reachable: a fresh (never-grown) destination naturally
     * has dp==NULL; an under-grown destination has dp!=NULL but too small
     * an alloc; a sufficiently pre-grown destination makes both false. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 7), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY); /* fresh: c->dp == NULL */
    ExpectIntEQ(mp_mul_d(&a, 3, &c), MP_OKAY); /* dp==NULL(T): grows */
    ExpectIntEQ(mp_init_size(&c, 1), MP_OKAY); /* dp!=NULL, alloc(1) < 2 */
    ExpectIntEQ(mp_mul_d(&a, 3, &c), MP_OKAY); /* dp==NULL(F), alloc<..(T) */
    ExpectIntEQ(mp_init_size(&c, 8), MP_OKAY); /* alloc(8) >= used(1)+1 */
    ExpectIntEQ(mp_mul_d(&a, 3, &c), MP_OKAY); /* both false */

    /* mp_sqr / s_mp_sqr: "(a->used*2+1 < MP_WARRAY) && a->used <
     * (1 << (WORD_BITS - 2*DIGIT_BIT - 1))" - unlike the montgomery/
     * exptmod shape above, the "- 1" here shrinks the second threshold
     * below the first, so both thresholds' independence pairs ARE jointly
     * satisfiable: a middling a->used (>= second threshold, < first) shows
     * the second operand false while the first stays true. */
    wolfmath_big_fill(&a, 10, 3);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_sqr(&a, &c), MP_OKAY); /* both thresholds true */
    wolfmath_big_fill(&a, 200, 3); /* > 2nd threshold(~128), < 1st(255) */
    ExpectIntEQ(mp_sqr(&a, &c), MP_OKAY); /* 1st true, 2nd false */
    wolfmath_big_fill(&a, 300, 3); /* > 1st threshold too */
    ExpectIntEQ(mp_sqr(&a, &c), MP_OKAY); /* both false: falls back */

    /* mp_mul: "(digs < MP_WARRAY) && MIN(a->used,b->used) <= threshold" -
     * digs is the SUM a->used+b->used+1, so making MIN large forces BOTH
     * operands large, which forces digs large too - the same disjoint-
     * threshold shape as mp_exptmod_fast/mp_montgomery_reduce above.
     * Documented residual for the MIN operand's false side (see
     * REPORT.md); the digs operand's pair is targeted here (small
     * operands vs one huge operand with the other tiny, which keeps MIN
     * small while pushing digs past MP_WARRAY). */
    wolfmath_big_fill(&a, 10, 3);
    wolfmath_big_fill(&b, 2, 3);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_mul(&a, &b, &c), MP_OKAY); /* digs small: true */
    wolfmath_big_fill(&a, 600, 3); /* digs = 600+2+1 >= MP_WARRAY(512) */
    ExpectIntEQ(mp_mul(&a, &b, &c), MP_OKAY); /* digs large: false */

    /* s_mp_mul_digs: same shape, but 'digs' is a caller-supplied parameter
     * independent of a->used/b->used (as long as digs >= a->used, which is
     * required for memory safety regardless of MC/DC), so BOTH operands'
     * pairs are directly reachable. */
    wolfmath_big_fill(&a, 1, 3);
    wolfmath_big_fill(&b, 1, 3);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(s_mp_mul_digs(&a, &b, &c, 5), MP_OKAY); /* digs(5)<WARRAY:T,
                                                    MIN(1,1)<256: T */
    ExpectIntEQ(s_mp_mul_digs(&a, &b, &c, 600), MP_OKAY); /* digs(600):F */
    wolfmath_big_fill(&a, 300, 3);
    wolfmath_big_fill(&b, 300, 3);
    ExpectIntEQ(s_mp_mul_digs(&a, &b, &c, 305), MP_OKAY); /* digs(305)<
                                    WARRAY:T, MIN(300,300)<256: F */

    /* s_mp_exptmod tail: "mode == 2 && bitcpy > 0" - same window-size
     * reasoning as tfm.c's _fp_exptmod_nct (see
     * test_wc_TfmExptModDecisionCoverage): a small exponent (<= 21 bits)
     * always flushes its window exactly (bitcpy==0 at the tail); a bigger
     * exponent leaves a partial window (bitcpy>0). */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY); /* 3 bits: winsize 1 */
    ExpectIntEQ(s_mp_exptmod(&a, &b, &c, &a, 0), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0x3FFFFFFF), MP_OKAY); /* 30 bits: winsize 3 */
    ExpectIntEQ(s_mp_exptmod(&a, &b, &c, &a, 0), MP_OKAY);

    /* s_mp_mul_high_digs: "(digs < MP_WARRAY) && MIN(a->used,b->used) <
     * threshold" - here 'digs' is only used AFTER the threshold check
     * (the check itself is SUM-based, from a->used+b->used, not the
     * parameter), so it has the same disjoint-threshold shape as mp_mul;
     * documented residual for the MIN operand (see REPORT.md), first
     * operand's pair targeted here. */
    wolfmath_big_fill(&a, 10, 3);
    wolfmath_big_fill(&b, 2, 3);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(s_mp_mul_high_digs(&a, &b, &c, 0), MP_OKAY); /* sum small:T */
    wolfmath_big_fill(&a, 600, 3);
    ExpectIntEQ(s_mp_mul_high_digs(&a, &b, &c, 0), MP_OKAY); /* sum big: F */

    /* mp_add_d / mp_sub_d: "tmpa==NULL || tmpc==NULL". Both functions grow
     * 'c' themselves (via "c->alloc < a->used+1") immediately before this
     * check, so tmpc is never NULL when it runs - a documented residual,
     * same class as s_mp_add's tmpc (see REPORT.md). tmpa==NULL IS
     * legitimately reachable via a freshly mp_init'd (never grown) 'a',
     * whose ->dp is NULL; the function then correctly reports MP_MEM
     * (the guard doubles as an allocation-sanity check). */
    ExpectIntEQ(mp_init(&a), MP_OKAY); /* a->dp == NULL */
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_add_d(&a, 5, &c), WC_NO_ERR_TRACE(MP_MEM)); /* tmpa==NULL:
                                                                    true */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_sub_d(&a, 5, &c), WC_NO_ERR_TRACE(MP_MEM)); /* tmpa==NULL:
                                                                    true */

    /* mp_add_d: "a->sign==MP_NEG && (a->used>1 || a->dp[0]>=b)" - three
     * operands, each isolated against an otherwise-fixed baseline. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY); /* a->used==1, dp[0]==3 */
    a.sign = MP_NEG;
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_add_d(&a, 1, &c), MP_OKAY); /* NEG(T), used>1(F),
                                                   dp[0](3)>=b(1)(T) */
    a.sign = MP_ZPOS;
    ExpectIntEQ(mp_add_d(&a, 1, &c), MP_OKAY); /* NEG(F): isolates sign op */
    ExpectIntEQ(mp_set(&a, 1), MP_OKAY);
    a.sign = MP_NEG;
    ExpectIntEQ(mp_add_d(&a, 3, &c), MP_OKAY); /* dp[0](1)>=b(3): F,
                                                   isolates that operand */

    /* mp_sub_d: "(a->used==1 && a->dp[0]<=b) || a->used==0" - the
     * a->used==0 operand's pair (a->used==1 half is exercised by the
     * ordinary single-digit subtraction paths elsewhere in this file).
     * Use a previously-grown-then-zeroed 'a' (->dp allocated, ->used==0)
     * rather than a freshly mp_init'd one, so the "tmpa==NULL" guard
     * above doesn't intercept the call first. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 9), MP_OKAY);
    mp_zero(&a); /* ->dp stays allocated; ->used reset to 0 */
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_sub_d(&a, 1, &c), MP_OKAY); /* a->used==0: true */
    ExpectIntEQ(mp_set(&a, 9), MP_OKAY);
    ExpectIntEQ(mp_sub_d(&a, 1, &c), MP_OKAY); /* a->used==0: false */

    /* mp_cnt_lsb: "x < a->used && a->dp[x]==0" - the "x < a->used going
     * false via running out of digits" side needs a non-normalized
     * all-zero-digit value (test_integer_whitebox.c); the "a->dp[x]==0"
     * operand's own pair IS legitimately reachable: a value whose lowest
     * digit is zero (shifted by exactly one whole digit) vs one whose
     * lowest digit is already nonzero. */
    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
    ExpectIntEQ(mp_cnt_lsb(&a), 0); /* dp[0]==0: false immediately */
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 1), MP_OKAY);
    ExpectIntEQ(mp_mul_2d(&a, (int)DIGIT_BIT, &c), MP_OKAY); /* dp[0]==0,
                                                    dp[1]!=0: a legitimate,
                                                    normalized value */
    ExpectIntNE(mp_cnt_lsb(&c), 0); /* dp[0]==0(T) then dp[1]!=0 stops it */

    /* mp_prime_is_prime: "t<=0 || t>PRIME_SIZE" (t<=0 half shown
     * elsewhere); complete t>PRIME_SIZE's pair. */
    {
        int result = 0;

        ExpectIntEQ(mp_init(&a), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 17), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, PRIME_SIZE + 1, &result),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_YES);
    }

#if !defined(WC_NO_RNG)
    {
        WC_RNG rng;
        int result = 0;

        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);

        /* mp_prime_is_prime_ex: "t<=0 || t>PRIME_SIZE" - both operands'
         * pairs, plus the composite-survives-trial-division case that
         * reaches Miller-Rabin. */
        ExpectIntEQ(mp_prime_is_prime_ex(&a, 0, &result, &rng),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_prime_is_prime_ex(&a, PRIME_SIZE + 1, &result, &rng),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_prime_is_prime_ex(&a, 8, &result, &rng), MP_OKAY);
        ExpectIntEQ(result, MP_YES);
        ExpectIntEQ(mp_set(&a, 1032247u), MP_OKAY); /* 1013 * 1019: both
                            factors bigger than every ltm_prime_tab entry */
        ExpectIntEQ(mp_prime_is_prime_ex(&a, 8, &result, &rng), MP_OKAY);
        ExpectIntEQ(result, MP_NO);

        /* mp_rand_prime: "a==NULL||rng==NULL" and "len<2||len>512". */
        ExpectIntEQ(mp_rand_prime(NULL, 32, &rng, HEAP_HINT),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_rand_prime(&a, 32, NULL, HEAP_HINT),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_rand_prime(&a, 1, &rng, HEAP_HINT),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_rand_prime(&a, 513, &rng, HEAP_HINT),
            WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_rand_prime(&a, 32, &rng, HEAP_HINT), MP_OKAY);

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif /* !WC_NO_RNG */

    /* mp_read_radix: "radix < MP_RADIX_BIN || radix > MP_RADIX_MAX". */
    ExpectIntEQ(mp_read_radix(&a, "10", 1), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_read_radix(&a, "10", 65), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_read_radix(&a, "10", MP_RADIX_DEC), MP_OKAY);

    /* mp_radix_size / mp_toradix: "radix < BIN || radix > MAX" (each has
     * its own copy); "(digs & 1) && (radix == 16)" hex zero-padding
     * (each has its own copy too). A value needing an odd number of hex
     * digits (e.g. 0x1, one digit) vs an even count (e.g. 0x12, two
     * digits) completes that operand's pair; radix != 16 completes the
     * other operand while digs is odd. */
    {
        int size = 0;
        char buf[16];

        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_radix_size(&a, 65, &size), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_set(&a, 0x1), MP_OKAY); /* 1 hex digit: odd */
        ExpectIntEQ(mp_radix_size(&a, MP_RADIX_HEX, &size), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x12), MP_OKAY); /* 2 hex digits: even */
        ExpectIntEQ(mp_radix_size(&a, MP_RADIX_HEX, &size), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x1), MP_OKAY);
        ExpectIntEQ(mp_radix_size(&a, MP_RADIX_DEC, &size), MP_OKAY); /* not
                                                                    hex */

        ExpectIntEQ(mp_toradix(&a, buf, 65), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_set(&a, 0x1), MP_OKAY);
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_toradix(&a, buf, MP_RADIX_HEX), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x12), MP_OKAY);
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_toradix(&a, buf, MP_RADIX_HEX), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x1), MP_OKAY);
        XMEMSET(buf, 0, sizeof(buf));
        ExpectIntEQ(mp_toradix(&a, buf, MP_RADIX_DEC), MP_OKAY);
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
#endif /* USE_INTEGER_HEAP_MATH && WOLFSSL_PUBLIC_MP */
    return EXPECT_RESULT();
} /* End test_wc_IntegerDecisionCoverage */

