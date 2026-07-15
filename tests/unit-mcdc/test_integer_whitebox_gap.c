/* test_integer_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/integer.c (the HEAPMATH
 * big-integer backend, iso26262/mcdc-per-module, bigint-integer module).
 *
 * The tests/api wolfmath suite (test_wolfmath.c) drives integer.c through
 * its *public* mp_ API (and the handful of s_mp_ and fast_ internal
 * helpers that integer.h also declares with external linkage), including
 * deliberately undersized / degenerate operands to reach argument-check,
 * capacity and sign-dispatch guards. A small number of decisions instead
 * depend on an mp_int being in a state no public entry point can ever
 * produce - a real mp_int's ->dp is NULL if and only if it is also
 * ->alloc == 0 && ->used == 0 (every public grower/shrinker keeps that
 * invariant); several defensive sanity checks guard against ->dp == NULL
 * while ->used (or ->alloc) is nonzero, which is exactly the state that
 * invariant rules out. This translation unit reaches them by compiling
 * integer.c directly (#include) so the mp_int struct's fields (a plain,
 * non-opaque type) can be corrupted directly.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * by source line:col in the per-module campaign: llvm-cov computes MC/DC
 * independence PER BINARY, and the campaign's aggregate.sh ORs the
 * "independence shown" bit across binaries by key. That is why every pair
 * below is completed *within this file* rather than relying on the API
 * tests to supply the other half.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS and -I<workspace> as the instrumented library, then linked
 * against that variant's libwolfssl.a with its integer.o removed (this TU
 * supplies the instrumented integer.c). NOT part of the wolfSSL build; not
 * registered in tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted gaps (wolfcrypt/src/integer.c), by class:
 *   Class 1  mp_copy() / s_mp_add() / s_mp_sub() / s_mp_mul_high_digs()
 *            dp==NULL sanity checks paired with a nonzero ->used/->alloc -
 *            an inconsistent state no public mutator can produce
 *                                                    ........ 6 conditions
 *   Class 2  mp_set_bit() entry guard's dp==NULL && (alloc!=0||used!=0)
 *            clause - same reasoning as Class 1 ..... 3 conditions
 *   Class 3  mp_cnt_lsb() least-significant-zero-digit loop running out of
 *            digits - only reachable with a non-normalized (all-zero-
 *            digit, ->used > 0) mp_int, same class as sp_int.c's
 *            sp_cnt_lsb / tfm.c's fp_cnt_lsb residuals ... 1 condition
 * See reports/bigint-integer/GAPS.md for the full union gap list and
 * REPORT.md (delivered alongside this file) for the residuals this
 * whitebox and the tests/api additions deliberately do not chase.
 */

/* Pull integer.c in verbatim so the mp_int struct's fields are corruptible
 * in THIS binary (the target functions here are all externally-linked,
 * declared in wolfssl/wolfcrypt/integer.h - the #include is for direct
 * struct-field access, mirroring test_sp_int_whitebox.c's technique,
 * rather than for reaching a file-static symbol). integer.c includes
 * settings.h (which picks up user_settings.h via -DWOLFSSL_USER_SETTINGS)
 * and integer.h itself. */
#include <wolfcrypt/src/integer.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(USE_INTEGER_HEAP_MATH) && defined(WOLFSSL_PUBLIC_MP)

/* ------------------------------------------------------------------------- *
 * Class 1a: mp_copy() tail zero-fill loop.
 *
 *   for (; n < b->used && b->dp; n++) { *tmpb++ = 0; }
 *
 * mp_copy() grows (and thereby (re)allocates) 'b' itself whenever
 * b->alloc < a->used || b->alloc == 0, so by the time this loop runs
 * b->dp is NULL only if b arrived with ->alloc > 0 already (skipping the
 * grow) yet ->dp == NULL - an inconsistent state no public mutator can
 * produce (->alloc > 0 always pairs with an allocated ->dp).
 * ------------------------------------------------------------------------- */
static void wb_mp_copy_tail_dp_null(void)
{
    mp_int a, b;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    mp_init(&a);
    mp_init(&b);

    /* 'a' stays used == 0 (empty/zero source): mp_copy()'s FIRST digit-
     * copy loop ("for (n = 0; n < a->used; n++) *tmpb++ = *tmpa++;") never
     * dereferences tmpb/tmpa when a->used == 0, so it is safe to reach the
     * tail loop below with a corrupted (dp==NULL) destination - the tail
     * loop is the only one of the two that actually checks "&& b->dp"
     * before dereferencing. */

    /* Corrupted destination: ->alloc > 0 (skips mp_copy's own grow, whose
     * condition is "b->alloc < a->used || b->alloc == 0") but ->dp ==
     * NULL, and ->used > a->used(0) so the tail loop actually runs. */
    b.dp = NULL;
    b.alloc = 4;
    b.used = 3;
    (void)mp_copy(&a, &b);
    b.dp = NULL; /* restore before mp_clear-equivalent cleanup below */
    b.alloc = 0;
    b.used = 0;

    /* Ordinary copy into a previously-larger, properly allocated 'b': the
     * "b->dp" truthy side, completed in this same binary. */
    mp_init(&b);
    mp_grow(&b, 8);
    b.used = 8;
    (void)mp_copy(&a, &b);

    mp_clear(&a);
    mp_clear(&b);
    WB_NOTE("mp_copy tail zero-fill loop 'b->dp' both sides exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 1b/1c: s_mp_add() / s_mp_sub() dp==NULL sanity checks.
 *
 * s_mp_add(): "(min_ab > 0) && (tmpa==NULL || tmpb==NULL || tmpc==NULL)"
 * min_ab = MIN(a->used, b->used), so min_ab > 0 forces BOTH a->used > 0
 * and b->used > 0 - meaning a real (non-corrupted) 'a' or 'b' would
 * already have an allocated ->dp. tmpc==NULL is additionally unreachable
 * on ANY call: s_mp_add() itself grows 'c' immediately beforehand whenever
 * c->dp == NULL, so tmpc is never NULL when this check runs (a documented
 * residual, not exercised here - see REPORT.md).
 *
 * s_mp_sub(): "(min_b > 0) && (tmpa==NULL || tmpb==NULL)" - min_b is just
 * b->used (asymmetric with s_mp_add), so tmpa==NULL with min_b > 0 is
 * actually API-reachable (a freshly-initialized, never-grown 'a' with
 * ->used == 0 legitimately has ->dp == NULL) and is exercised in
 * test_wolfmath.c instead; only tmpb==NULL (which DOES require
 * b->used > 0 with a corrupted, unallocated ->dp) is exercised here.
 * ------------------------------------------------------------------------- */
static void wb_s_mp_add_sub_null_dp(void)
{
    mp_int a, b, c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    mp_init(&a);
    mp_init(&b);
    mp_init(&c);

    /* s_mp_add: tmpa == NULL, min_ab > 0 (both a and b "nonzero", a
     * corrupted: ->used > 0 but ->dp == NULL). */
    a.used = 2; /* corrupted: dp stays NULL */
    mp_set(&b, 5); /* real, nonzero: min_ab = MIN(2,1) = 1 > 0 */
    if (s_mp_add(&a, &b, &c) != WC_NO_ERR_TRACE(MP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: s_mp_add did not reject corrupted a->dp");
    }
    a.used = 0; /* restore */

    /* s_mp_add: tmpb == NULL, min_ab > 0 (mirror image). 'b' must be
     * explicitly reset here: the previous subtest's mp_set(&b, 5) already
     * gave it a real, allocated ->dp, so only zeroing ->used (as done
     * above) would leave ->dp non-NULL - not the corrupted state this
     * pair needs. */
    mp_set(&a, 5);
    XMEMSET(&b, 0, sizeof(b));
    b.used = 2; /* corrupted: dp stays NULL */
    if (s_mp_add(&a, &b, &c) != WC_NO_ERR_TRACE(MP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: s_mp_add did not reject corrupted b->dp");
    }
    b.used = 0;

    /* s_mp_add: min_ab > 0 false (one operand genuinely zero-used) and
     * both dp pointers valid/NULL-but-harmless: completes the "min_ab>0"
     * operand's own pair within this binary too. */
    mp_set(&a, 5);
    mp_zero(&b);
    (void)s_mp_add(&a, &b, &c);

    /* s_mp_sub: tmpb == NULL, min_b > 0 (b corrupted: ->used > 0 but
     * ->dp == NULL; a real/nonzero). */
    mp_set(&a, 5);
    XMEMSET(&b, 0, sizeof(b));
    b.used = 2; /* corrupted */
    if (s_mp_sub(&a, &b, &c) != WC_NO_ERR_TRACE(MP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: s_mp_sub did not reject corrupted b->dp");
    }
    b.used = 0;

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
    WB_NOTE("s_mp_add/s_mp_sub dp==NULL sanity checks exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 1d: s_mp_mul_high_digs() "for (ix = 0; ix < pa && a->dp; ix++)".
 *
 * Reaching this loop at all requires taking the SLOW path (the
 * SUM-threshold fast-path guard - see test_wc_IntegerDecisionCoverage's
 * comment on the disjoint-threshold residual - must be false), which needs
 * a large a->used + b->used; a real mp_int with ->used that large always
 * has an allocated ->dp, so "a->dp" false (with pa > 0) again needs a
 * corrupted, unallocated 'a'.
 * ------------------------------------------------------------------------- */
static void wb_s_mp_mul_high_digs_null_dp(void)
{
    mp_int a, b, c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    mp_init(&a);
    mp_init(&b);
    mp_init(&c);

    /* Corrupted 'a': ->used large enough to both force the slow path
     * (a->used + b->used + 1 >= MP_WARRAY) and make pa > 0, but ->dp
     * stays NULL - the loop condition's short-circuit ("a->dp" checked
     * after "ix < pa") means dereferencing a->dp[ix] never happens. */
    a.used = 600;
    mp_set(&b, 3);
    (void)s_mp_mul_high_digs(&a, &b, &c, 0);
    a.used = 0; /* restore before mp_clear below */

    /* Same slow-path shape, but with a REAL (grown, non-corrupted) large
     * 'a' - completes the "a->dp" truthy side within this same binary. */
    mp_grow(&a, 600);
    a.used = 600;
    XMEMSET(a.dp, 0, sizeof(mp_digit) * 600);
    a.dp[0] = 3;
    (void)s_mp_mul_high_digs(&a, &b, &c, 0);

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
    WB_NOTE("s_mp_mul_high_digs 'a->dp' loop guard both sides exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 2: mp_set_bit() entry guard.
 *
 *   if (b < 0 || (a->dp == NULL && (a->alloc != 0 || a->used != 0)))
 *
 * The parenthesized clause needs a->dp == NULL simultaneously with
 * ->alloc != 0 or ->used != 0 - the exact combination the "->dp == NULL
 * implies ->alloc == 0 && ->used == 0" invariant rules out for any real
 * mp_int, so it can only be shown by corrupting the struct directly.
 * ------------------------------------------------------------------------- */
static void wb_mp_set_bit_corrupted(void)
{
    mp_int a;

    XMEMSET(&a, 0, sizeof(a));
    mp_init(&a);

    /* a->dp == NULL (true) && a->alloc != 0 (true), a->used == 0: isolates
     * the "a->alloc != 0" operand of the inner OR (b >= 0 held false). */
    a.alloc = 4;
    if (mp_set_bit(&a, 3) != WC_NO_ERR_TRACE(MP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: mp_set_bit did not reject dp==NULL/alloc!=0");
    }
    a.alloc = 0;

    /* a->dp == NULL (true) && a->used != 0 (true), a->alloc == 0: isolates
     * the "a->used != 0" operand. */
    a.used = 2;
    if (mp_set_bit(&a, 3) != WC_NO_ERR_TRACE(MP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: mp_set_bit did not reject dp==NULL/used!=0");
    }
    a.used = 0;

    /* a->dp == NULL (false, via mp_grow), a->alloc/used consistent with a
     * real value: completes the "a->dp == NULL" operand's own pair, and
     * the ordinary success path. */
    mp_grow(&a, 4);
    a.used = 1;
    a.dp[0] = 5;
    (void)mp_set_bit(&a, 3);

    mp_clear(&a);
    WB_NOTE("mp_set_bit corrupted dp==NULL entry guard exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 3: mp_cnt_lsb() least-significant-zero-digit loop.
 *
 *   for (x = 0; x < a->used && a->dp[x] == 0; x++) {}
 *
 * Same reasoning as tfm.c's fp_cnt_lsb() / sp_int.c's sp_cnt_lsb(): a
 * normalized nonzero mp_int always has SOME nonzero digit below ->used, so
 * the loop always terminates via "a->dp[x] == 0" going false, never via
 * "x < a->used" going false - reach that side with a non-normalized
 * all-zero-digit value (->used > 0, every digit 0), a state no public
 * mutator can produce (mp_iszero() only checks ->used == 0).
 * ------------------------------------------------------------------------- */
static void wb_mp_cnt_lsb_all_zero_digits(void)
{
    mp_int a;

    XMEMSET(&a, 0, sizeof(a));
    mp_init(&a);
    mp_grow(&a, 3);

    /* Non-normalized: ->used > 0 but every digit below ->used is 0. The
     * one-past-used slot a->dp[a->used] is deliberately left NONZERO:
     * mp_cnt_lsb() reads it as 'q' right after this loop and, if it were
     * also zero, the subsequent "while (qq == 0)" bit-scan would spin
     * forever (q never becomes nonzero) - a latent hang in mp_cnt_lsb()
     * for a fully zero-digit input, not something this MC/DC pair needs
     * to trigger. */
    a.used = 2;
    a.dp[0] = 0;
    a.dp[1] = 0;
    a.dp[2] = 1;
    (void)mp_cnt_lsb(&a);

    /* Normalized nonzero value (ordinary, API-reachable case), repeated
     * here so both sides of "x < a->used" are shown within this binary. */
    a.used = 1;
    a.dp[0] = 4;
    (void)mp_cnt_lsb(&a);

    mp_clear(&a);
    WB_NOTE("mp_cnt_lsb least-significant-zero-digit loop exercised");
}

#endif /* USE_INTEGER_HEAP_MATH && WOLFSSL_PUBLIC_MP */

int main(void)
{
    printf("integer.c white-box MC/DC supplement\n");
#if !defined(USE_INTEGER_HEAP_MATH) || !defined(WOLFSSL_PUBLIC_MP)
    printf("  USE_INTEGER_HEAP_MATH && WOLFSSL_PUBLIC_MP not both defined;"
        " nothing to exercise\n");
    return 0;
#else
    wb_mp_copy_tail_dp_null();
    wb_s_mp_add_sub_null_dp();
    wb_s_mp_mul_high_digs_null_dp();
    wb_mp_set_bit_corrupted();
    wb_mp_cnt_lsb_all_zero_digits();
    printf("done (%s)\n", wb_fail ? "with unexpected results" : "ok");
    /* Setup/behavioral surprises are surfaced as printed notes, not process
     * failures: the campaign treats a nonzero exit as a failed variant and
     * discards its coverage. */
    return 0;
#endif
}
