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
 * MC/DC coverage for the FASTMATH multi-precision engine (wolfcrypt/src/tfm.c,
 * the bigint-tfm module, iso26262/mcdc-per-module). Under USE_FAST_MATH the
 * public mp_* API IS the fp_* engine (mp_* are macro/thin wrappers over fp_*),
 * so these drive tfm.c's argument checks, capacity/FP_SIZE guards, sign paths,
 * and degenerate-input decisions through the public, WOLFSSL_PUBLIC_MP-exposed
 * surface. Decisions that live only in file-static helpers unreachable from the
 * public API (fp_invmod_slow, _fp_exptmod_ct/_nct/_base_2,
 * fp_montgomery_reduce_mulx, fp_cond_swap_ct, s_is_power_of_two,
 * fp_prime_miller_rabin, fp_read_radix_16 internals) are supplemented by
 * tests/unit-mcdc/test_tfm_whitebox.c.
 */

/*
 * Testing fp_div / fp_div_d / fp_mod_d / fp_gcd / fp_lcm / fp_montgomery_* /
 * fp_read_radix / mp_toradix / mp_radix_size / conversion helpers: argument,
 * divisor-zero, degenerate-magnitude, capacity, sign, and radix-parser
 * decision branches reachable from the public fastmath API.
 */
int test_wc_TfmDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_FAST_MATH) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int b;
    mp_int c;
    mp_int d;
    mp_digit rem = 0;
    byte bin[64];
    char str[256];

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    XMEMSET(&d, 0, sizeof(d));
    XMEMSET(bin, 0, sizeof(bin));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_init(&d), MP_OKAY);

    /* fp_div: divisor zero (fp_iszero(b) true) -> MP_VAL; a<b fast path (both
     * the d!=NULL/c!=NULL copy legs and their NULL counterparts); and a real
     * division (both operands nonzero, a>b). */
    ExpectIntEQ(mp_set(&a, 100), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), WC_NO_ERR_TRACE(MP_VAL)); /* b == 0 */
    ExpectIntEQ(mp_set(&b, 200), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), MP_OKAY);   /* a < b: q=0,r=a; d,c!=NULL */
    ExpectIntEQ(mp_div(&a, &b, NULL, &d), MP_OKAY); /* a < b: c==NULL leg */
    ExpectIntEQ(mp_div(&a, &b, &c, NULL), MP_OKAY); /* a < b: d==NULL leg */
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), MP_OKAY);   /* a > b: real division */
    ExpectIntEQ(mp_div(&a, &b, &c, NULL), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, NULL, &d), MP_OKAY);

    /* fp_mod_d via mp_mod_d: divisor 0 -> MP_VAL; divisor 1 / zero-dividend
     * quick-out; power-of-two divisor (s_is_power_of_two true); non-power-of-2
     * (general long-division loop). */
    ExpectIntEQ(mp_set(&a, 0x9ABC), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 0, &rem), WC_NO_ERR_TRACE(MP_VAL)); /* b == 0 */
    ExpectIntEQ(mp_mod_d(&a, 1, &rem), MP_OKAY);       /* b == 1 quick out */
    ExpectIntEQ(mp_mod_d(&a, 16, &rem), MP_OKAY);      /* power of two */
    ExpectIntEQ(mp_mod_d(&a, 13, &rem), MP_OKAY);      /* non power of two */
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 13, &rem), MP_OKAY);      /* zero dividend quick out */

    /* fp_gcd: gcd(0,0) undefined -> MP_VAL; one operand zero (result is the
     * other); both nonzero normal; the cmp_mag sort both ways (a>=b and a<b). */
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL)); /* 0,0 */
    ExpectIntEQ(mp_set(&b, 18), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);          /* a==0, b!=0 */
    ExpectIntEQ(mp_set(&a, 18), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);          /* a!=0, b==0 */
    ExpectIntEQ(mp_set(&a, 48), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 36), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);          /* a>=b sort */
    ExpectIntEQ(mp_set(&a, 36), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 48), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);          /* a<b sort */

    /* fp_lcm: lcm(0,x) undefined -> MP_VAL (both operand positions); normal
     * both cmp_mag branches (a>b and a<=b select which operand is divided). */
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 5), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL)); /* a == 0 */
    ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL)); /* b == 0 */
    ExpectIntEQ(mp_set(&a, 12), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 8), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), MP_OKAY);          /* |a| > |b| */
    ExpectIntEQ(mp_set(&a, 8), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 12), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), MP_OKAY);          /* |a| <= |b| */

    /* fp_montgomery_setup / fp_montgomery_reduce(_ex): setup on an odd modulus;
     * reduce with the non-constant-time (ct==0) and constant-time (ct==1)
     * decision arms. */
    {
        mp_digit mont = 0;
        ExpectIntEQ(mp_set(&b, 0xF1), MP_OKAY);       /* odd modulus */
        ExpectIntEQ(mp_montgomery_setup(&b, &mont), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x3), MP_OKAY);
        ExpectIntEQ(mp_montgomery_reduce(&a, &b, mont), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x3), MP_OKAY);
        ExpectIntEQ(mp_montgomery_reduce_ex(&a, &b, mont, 0), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x3), MP_OKAY);
        ExpectIntEQ(mp_montgomery_reduce_ex(&a, &b, mont, 1), MP_OKAY); /* ct */
    }

    /* fp_to_unsigned_bin_len_ct: NULL a, NULL out, negative outSz -> MP_VAL;
     * normal. */
    ExpectIntEQ(mp_set(&a, 0x123456), MP_OKAY);
    ExpectIntEQ(mp_to_unsigned_bin_len_ct(NULL, bin, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_to_unsigned_bin_len_ct(&a, NULL, (int)sizeof(bin)),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_to_unsigned_bin_len_ct(&a, bin, -1),
        WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_to_unsigned_bin_len_ct(&a, bin, (int)sizeof(bin)), MP_OKAY);
    ExpectIntEQ(mp_to_unsigned_bin_len(&a, bin, (int)sizeof(bin)), MP_OKAY);

    /* fp_read_radix (generic radix-10 loop): normal; leading '-' sign path;
     * trailing-whitespace tolerated (y>=radix then whitespace-to-EOL break);
     * embedded invalid char after digits -> MP_VAL. */
    ExpectIntEQ(mp_read_radix(&a, "255", 10), MP_OKAY);
    ExpectIntEQ(mp_read_radix(&a, "-255", 10), MP_OKAY);       /* neg sign */
    ExpectIntEQ(mp_read_radix(&a, "255 \t", 10), MP_OKAY);     /* trailing ws */
    ExpectIntEQ(mp_read_radix(&a, "25!5", 10), WC_NO_ERR_TRACE(MP_VAL));
    /* fp_read_radix_16 path (DIGIT_BIT==64/32 && radix==16): normal; trailing
     * whitespace before any digit seen (eol_done false -> continue); embedded
     * whitespace after digits seen (eol_done true -> MP_VAL); '-' sign. */
    ExpectIntEQ(mp_read_radix(&a, "1Ab2", 16), MP_OKAY);
    ExpectIntEQ(mp_read_radix(&a, "1Ab2 \n", 16), MP_OKAY);    /* trailing ws */
    ExpectIntEQ(mp_read_radix(&a, "1A b2", 16), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_read_radix(&a, "-1Ab2", 16), MP_OKAY);      /* neg sign */

#ifdef WC_MP_TO_RADIX
    /* mp_radix_size / mp_toradix: radix==2 special; radix<2 -> MP_VAL; zero
     * special (radix 16 padded and non-16); negative-sign; odd-hex-digit
     * padding; general path. */
    {
        int size = 0;
        ExpectIntEQ(mp_set(&a, 0xABCDE), MP_OKAY);
        ExpectIntEQ(mp_radix_size(&a, 2, &size), MP_OKAY);       /* binary */
        ExpectIntEQ(mp_radix_size(&a, 1, &size), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_radix_size(&a, 16, &size), MP_OKAY);      /* general */
        ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
        ExpectIntEQ(mp_radix_size(&a, 16, &size), MP_OKAY);      /* zero, hex */
        ExpectIntEQ(mp_radix_size(&a, 10, &size), MP_OKAY);      /* zero, dec */

        ExpectIntEQ(mp_toradix(&a, str, 1), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_toradix(&a, str, 16), MP_OKAY);           /* zero, hex */
        ExpectIntEQ(mp_toradix(&a, str, 10), MP_OKAY);           /* zero, dec */
        ExpectIntEQ(mp_set(&a, 0xABCDE), MP_OKAY);
        ExpectIntEQ(mp_toradix(&a, str, 16), MP_OKAY);           /* general hex */
        ExpectIntEQ(mp_toradix(&a, str, 10), MP_OKAY);           /* general dec */
    }
#endif

    /* fp_add / fp_sub sign matrix (tfm always carries a sign field): build a
     * negative operand by subtracting a larger value, then drive same-sign and
     * opposite-sign add/sub combinations so the fp_add/fp_sub magnitude-vs-sign
     * dispatch branches are all taken. */
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 10), MP_OKAY);
    ExpectIntEQ(mp_sub(&a, &b, &c), MP_OKAY);      /* c = -7 (negative) */
    ExpectIntEQ(mp_add(&c, &b, &d), MP_OKAY);      /* neg + pos */
    ExpectIntEQ(mp_add(&b, &c, &d), MP_OKAY);      /* pos + neg */
    ExpectIntEQ(mp_add(&c, &c, &d), MP_OKAY);      /* neg + neg */
    ExpectIntEQ(mp_sub(&c, &b, &d), MP_OKAY);      /* neg - pos */
    ExpectIntEQ(mp_sub(&b, &c, &d), MP_OKAY);      /* pos - neg */
    ExpectIntEQ(mp_sub(&c, &c, &d), MP_OKAY);      /* neg - neg */

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
    mp_clear(&d);
#endif
    return EXPECT_RESULT();
} /* End test_wc_TfmDecisionCoverage */

/*
 * Testing fp_exptmod / fp_exptmod_ex / fp_exptmod_nct / fp_invmod /
 * fp_invmod_mont_ct / fp_isprime_ex / mp_prime_is_prime(_ex): the top-level
 * modulus/degenerate-input decision chain (P==0, P->used capacity, P==1,
 * X==0, G==0, base-2 special, negative-exponent invmod branch) plus the
 * primality argument checks and small-value fast paths.
 */
int test_wc_TfmExptModDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_FAST_MATH) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int g;
    mp_int x;
    mp_int p;
    mp_int y;

    XMEMSET(&g, 0, sizeof(g));
    XMEMSET(&x, 0, sizeof(x));
    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&y, 0, sizeof(y));

    ExpectIntEQ(mp_init(&g), MP_OKAY);
    ExpectIntEQ(mp_init(&x), MP_OKAY);
    ExpectIntEQ(mp_init(&p), MP_OKAY);
    ExpectIntEQ(mp_init(&y), MP_OKAY);

    /* fp_exptmod (constant-time arm under TFM_TIMING_RESISTANT, otherwise nct):
     * P==0 -> MP_VAL; P==1 -> Y=0; X==0 -> Y=1; G==0 -> Y=0; G==2 base-2
     * special; ordinary base/exp. */
    ExpectIntEQ(mp_set(&g, 4), MP_OKAY);
    ExpectIntEQ(mp_set(&x, 13), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), WC_NO_ERR_TRACE(MP_VAL)); /* P==0 */
    ExpectIntEQ(mp_set(&p, 1), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), MP_OKAY);   /* P==1 -> Y=0 */
    ExpectIntEQ(mp_set(&p, 497), MP_OKAY);
    ExpectIntEQ(mp_set(&x, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), MP_OKAY);   /* X==0 -> Y=1 */
    ExpectIntEQ(mp_set(&x, 13), MP_OKAY);
    ExpectIntEQ(mp_set(&g, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), MP_OKAY);   /* G==0 -> Y=0 */
    ExpectIntEQ(mp_set(&g, 2), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), MP_OKAY);   /* G==2 base-2 special */
    ExpectIntEQ(mp_set(&g, 4), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&g, &x, &p, &y), MP_OKAY);   /* ordinary */

    /* fp_exptmod_ex: same degenerate chain plus an explicit digit count. */
    ExpectIntEQ(mp_set(&p, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod_ex(&g, &x, x.used, &p, &y), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&p, 1), MP_OKAY);
    ExpectIntEQ(mp_exptmod_ex(&g, &x, x.used, &p, &y), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 497), MP_OKAY);
    ExpectIntEQ(mp_exptmod_ex(&g, &x, x.used, &p, &y), MP_OKAY);

    /* fp_exptmod_nct (explicit non-constant-time arm, always compiled): P==0
     * -> MP_VAL; P==1 -> Y=0; X==0 -> Y=1; G==0 -> Y=0; ordinary. This is the
     * disjoint _fp_exptmod_nct path (the MCDC_NO_TFM_TR variant routes the main
     * exptmod here too). */
    ExpectIntEQ(mp_set(&g, 4), MP_OKAY);
    ExpectIntEQ(mp_set(&x, 13), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod_nct(&g, &x, &p, &y), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&p, 1), MP_OKAY);
    ExpectIntEQ(mp_exptmod_nct(&g, &x, &p, &y), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 497), MP_OKAY);
    ExpectIntEQ(mp_set(&x, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod_nct(&g, &x, &p, &y), MP_OKAY);
    ExpectIntEQ(mp_set(&x, 13), MP_OKAY);
    ExpectIntEQ(mp_set(&g, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod_nct(&g, &x, &p, &y), MP_OKAY);
    ExpectIntEQ(mp_set(&g, 4), MP_OKAY);
    ExpectIntEQ(mp_exptmod_nct(&g, &x, &p, &y), MP_OKAY);

    /* fp_invmod: inverse of 3 mod 497; then a non-invertible (even/even) input
     * so the gcd!=1 rejection branch is taken. */
    ExpectIntEQ(mp_set(&g, 3), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 497), MP_OKAY);
    ExpectIntEQ(mp_invmod(&g, &p, &y), MP_OKAY);
    ExpectIntEQ(mp_set(&g, 4), MP_OKAY);
    ExpectIntEQ(mp_set(&p, 6), MP_OKAY);
    ExpectIntNE(mp_invmod(&g, &p, &y), MP_OKAY);   /* gcd(4,6)!=1: not invertible */

    /* fp_invmod_mont_ct: inverse mod an odd modulus with the Montgomery
     * constant from setup (constant-time inverse used by ECC). */
    {
        mp_digit mont = 0;
        ExpectIntEQ(mp_set(&p, 497), MP_OKAY);
        ExpectIntEQ(mp_montgomery_setup(&p, &mont), MP_OKAY);
        ExpectIntEQ(mp_set(&g, 3), MP_OKAY);
        ExpectIntEQ(mp_invmod_mont_ct(&g, &p, &y, mont), MP_OKAY);
    }

    /* fp_isprime_ex via mp_prime_is_prime: t out of range (t<=0, t>PRIME_SIZE)
     * -> MP_VAL; a==1 -> NO; a in small-primes table -> YES; a composite even
     * (trial division catches it) -> NO; a a larger prime (needs Miller-Rabin)
     * -> YES. */
    {
        int result = 0;
        ExpectIntEQ(mp_set(&g, 17), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&g, 0, &result),
            WC_NO_ERR_TRACE(MP_VAL));                /* t <= 0 */
        ExpectIntEQ(mp_prime_is_prime(&g, 1000000, &result),
            WC_NO_ERR_TRACE(MP_VAL));                /* t > FP_PRIME_SIZE */
        ExpectIntEQ(mp_set(&g, 1), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&g, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_NO);                  /* a == 1 */
        ExpectIntEQ(mp_set(&g, 7), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&g, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_YES);                 /* in primes table */
        ExpectIntEQ(mp_set(&g, 100), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&g, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_NO);                  /* even composite */
        ExpectIntEQ(mp_set(&g, 1009), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&g, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_YES);                 /* prime via Miller-Rabin */

#if !defined(WC_NO_RNG)
        {
            WC_RNG rng;
            XMEMSET(&rng, 0, sizeof(rng));
            ExpectIntEQ(wc_InitRng(&rng), 0);
            /* mp_prime_is_prime_ex NULL/degenerate checks + a real trial. */
            ExpectIntEQ(mp_prime_is_prime_ex(NULL, 8, &result, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(mp_prime_is_prime_ex(&g, 8, NULL, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(mp_prime_is_prime_ex(&g, 8, &result, NULL),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(mp_prime_is_prime_ex(&g, 0, &result, &rng),
                WC_NO_ERR_TRACE(MP_VAL));
            ExpectIntEQ(mp_set(&g, 1), MP_OKAY);
            ExpectIntEQ(mp_prime_is_prime_ex(&g, 8, &result, &rng), MP_OKAY);
            ExpectIntEQ(result, MP_NO);
            ExpectIntEQ(mp_set(&g, 1009), MP_OKAY);
            ExpectIntEQ(mp_prime_is_prime_ex(&g, 8, &result, &rng), MP_OKAY);
            ExpectIntEQ(result, MP_YES);
            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }
#endif /* !WC_NO_RNG */
    }

    mp_clear(&g);
    mp_clear(&x);
    mp_clear(&p);
    mp_clear(&y);
#endif
    return EXPECT_RESULT();
} /* End test_wc_TfmExptModDecisionCoverage */

/*
 * MC/DC coverage for the HEAPMATH multi-precision engine
 * (wolfcrypt/src/integer.c, the bigint-integer module,
 * iso26262/mcdc-per-module). Under USE_INTEGER_HEAP_MATH the public mp_* API
 * IS integer.c. These drive its argument checks, divisor-zero / degenerate
 * guards, capacity paths and radix parser through the public,
 * WOLFSSL_PUBLIC_MP-exposed surface. The file-static helpers (mp_div_d,
 * mp_prime_miller_rabin, mp_prime_is_divisible, s_is_power_of_two, bn_reverse)
 * are supplemented by tests/unit-mcdc/test_integer_whitebox.c.
 */
int test_wc_IntegerDecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(USE_INTEGER_HEAP_MATH) && defined(WOLFSSL_PUBLIC_MP) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(NO_RSA) && \
    defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC)
    mp_int a;
    mp_int b;
    mp_int c;
    mp_int d;
    mp_digit rem = 0;
    byte bin[64];
    char str[256];

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    XMEMSET(&d, 0, sizeof(d));
    XMEMSET(bin, 0, sizeof(bin));

    ExpectIntEQ(mp_init(&a), MP_OKAY);
    ExpectIntEQ(mp_init(&b), MP_OKAY);
    ExpectIntEQ(mp_init(&c), MP_OKAY);
    ExpectIntEQ(mp_init(&d), MP_OKAY);

    /* mp_div: divisor zero -> MP_VAL; a<b fast path (q=0,r=a) with c/d present
     * and NULL; a>b real division; quotient-only and remainder-only. */
    ExpectIntEQ(mp_set(&a, 100), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), WC_NO_ERR_TRACE(MP_VAL)); /* b==0 */
    ExpectIntEQ(mp_set(&b, 200), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), MP_OKAY);  /* a<b */
    ExpectIntEQ(mp_div(&a, &b, NULL, &d), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, NULL), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 7), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, &c, &d), MP_OKAY);  /* a>b division */
    ExpectIntEQ(mp_div(&a, &b, &c, NULL), MP_OKAY);
    ExpectIntEQ(mp_div(&a, &b, NULL, &d), MP_OKAY);

    /* mp_mod_d: divisor 0 -> MP_VAL; divisor 1 / zero-dividend quick out;
     * power-of-two vs non-power-of-two divisor. */
    ExpectIntEQ(mp_set(&a, 0x9ABC), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 0, &rem), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_mod_d(&a, 1, &rem), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 16, &rem), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 13, &rem), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_mod_d(&a, 13, &rem), MP_OKAY);

    /* mp_gcd: gcd(0,0) -> MP_VAL; one-operand-zero; normal both sort orders. */
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&b, 18), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);      /* a==0 */
    ExpectIntEQ(mp_set(&a, 48), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 36), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 36), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 48), MP_OKAY);
    ExpectIntEQ(mp_gcd(&a, &b, &c), MP_OKAY);

    /* mp_lcm: lcm with a zero operand -> MP_VAL (both positions); normal. */
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 5), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&a, 5), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), WC_NO_ERR_TRACE(MP_VAL));
    ExpectIntEQ(mp_set(&a, 12), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 8), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 8), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 12), MP_OKAY);
    ExpectIntEQ(mp_lcm(&a, &b, &c), MP_OKAY);

    /* mp_exptmod: P==0 -> MP_VAL; P==1; X==0; G==0; ordinary. */
    ExpectIntEQ(mp_set(&a, 4), MP_OKAY);   /* base */
    ExpectIntEQ(mp_set(&b, 13), MP_OKAY);  /* exp  */
    ExpectIntEQ(mp_set(&c, 0), MP_OKAY);   /* mod  */
    ExpectIntNE(mp_exptmod(&a, &b, &c, &d), MP_OKAY); /* P==0 */
    ExpectIntEQ(mp_set(&c, 1), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&a, &b, &c, &d), MP_OKAY);
    ExpectIntEQ(mp_set(&c, 497), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&a, &b, &c, &d), MP_OKAY); /* X==0 */
    ExpectIntEQ(mp_set(&b, 13), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&a, &b, &c, &d), MP_OKAY); /* G==0 */
    ExpectIntEQ(mp_set(&a, 4), MP_OKAY);
    ExpectIntEQ(mp_exptmod(&a, &b, &c, &d), MP_OKAY); /* ordinary */
    ExpectIntEQ(mp_exptmod_nct(&a, &b, &c, &d), MP_OKAY);

    /* mp_invmod: normal inverse; non-invertible (even/even) rejection. */
    ExpectIntEQ(mp_set(&a, 3), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 497), MP_OKAY);
    ExpectIntEQ(mp_invmod(&a, &b, &c), MP_OKAY);
    ExpectIntEQ(mp_set(&a, 4), MP_OKAY);
    ExpectIntEQ(mp_set(&b, 6), MP_OKAY);
    ExpectIntNE(mp_invmod(&a, &b, &c), MP_OKAY);

    /* mp_montgomery_setup / mp_montgomery_reduce on an odd modulus. */
    {
        mp_digit mont = 0;
        ExpectIntEQ(mp_set(&b, 0xF1), MP_OKAY);
        ExpectIntEQ(mp_montgomery_setup(&b, &mont), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0x3), MP_OKAY);
        ExpectIntEQ(mp_montgomery_reduce(&a, &b, mont), MP_OKAY);
    }

    /* mp_read_radix: generic radix-10 (normal, negative, trailing whitespace,
     * embedded invalid); radix-16. */
    ExpectIntEQ(mp_read_radix(&a, "255", 10), MP_OKAY);
    ExpectIntEQ(mp_read_radix(&a, "-255", 10), MP_OKAY);
    ExpectIntEQ(mp_read_radix(&a, "1Ab2", 16), MP_OKAY);

    /* mp_to_unsigned_bin_len + conversion. */
    ExpectIntEQ(mp_set(&a, 0x123456), MP_OKAY);
    ExpectIntEQ(mp_to_unsigned_bin_len(&a, bin, (int)sizeof(bin)), MP_OKAY);

#ifdef WC_MP_TO_RADIX
    /* mp_radix_size / mp_toradix: radix==2 special; radix<2 -> MP_VAL; zero
     * special; general hex and decimal. */
    {
        int size = 0;
        ExpectIntEQ(mp_set(&a, 0xABCDE), MP_OKAY);
        ExpectIntEQ(mp_radix_size(&a, 2, &size), MP_OKAY);
        ExpectIntEQ(mp_radix_size(&a, 1, &size), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_radix_size(&a, 16, &size), MP_OKAY);
        ExpectIntEQ(mp_toradix(&a, str, 1), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_toradix(&a, str, 16), MP_OKAY);
        ExpectIntEQ(mp_toradix(&a, str, 10), MP_OKAY);
        ExpectIntEQ(mp_set(&a, 0), MP_OKAY);
        ExpectIntEQ(mp_toradix(&a, str, 16), MP_OKAY);  /* zero */
    }
#endif

    /* mp_prime_is_prime: t out of range; a==1; table prime; even composite;
     * larger prime via Miller-Rabin. */
    {
        int result = 0;
        ExpectIntEQ(mp_set(&a, 17), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, 0, &result), WC_NO_ERR_TRACE(MP_VAL));
        ExpectIntEQ(mp_set(&a, 1), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_NO);
        ExpectIntEQ(mp_set(&a, 7), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_YES);
        ExpectIntEQ(mp_set(&a, 100), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_NO);
        ExpectIntEQ(mp_set(&a, 1009), MP_OKAY);
        ExpectIntEQ(mp_prime_is_prime(&a, 8, &result), MP_OKAY);
        ExpectIntEQ(result, MP_YES);
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
    mp_clear(&d);
#endif
    return EXPECT_RESULT();
} /* End test_wc_IntegerDecisionCoverage */

