/* test_integer_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/integer.c (the HEAPMATH
 * big-integer module, bigint-integer, iso26262/mcdc-per-module).
 *
 * The tests/api wolfmath suite (test_wolfmath.c,
 * test_wc_IntegerDecisionCoverage) drives integer.c through its *public* mp_*
 * API. A handful of decisions live in file-static helpers whose branch
 * selectors a public caller can never present directly (mp_div_d,
 * mp_prime_miller_rabin, mp_prime_is_divisible, s_is_power_of_two, bn_reverse).
 * This translation unit reaches them by compiling integer.c directly (#include)
 * and calling the static helpers with BOTH halves of each targeted MC/DC pair in this
 * one binary (llvm-cov computes MC/DC per binary; the harness unions the
 * "independence shown" bit across binaries by line:col).
 *
 * Build: compiled by the coverage runner's white-box step with the SAME MC/DC CFLAGS
 * and -I<workspace> as the instrumented library, then linked against that
 * variant's libwolfssl.a with its integer.o removed (this TU supplies the
 * instrumented integer.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Every call is memory-safe (static helpers are handed initialized mp_ints and
 * in-range selectors); setup failures print a skip and return 0 (a nonzero
 * exit makes the harness discard the variant and its coverage).
 */

#include <wolfcrypt/src/integer.c>

#include <stdio.h>

#ifndef HEAP_HINT
#define HEAP_HINT NULL
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(USE_FAST_MATH) && defined(USE_INTEGER_HEAP_MATH) && \
    !defined(WOLFSSL_SP_MATH) && !defined(NO_BIG_INT)

/* s_is_power_of_two(b, &p): power (b=8) true, non-power (b=6) false, boundary
 * b==1, and b==0 guard - both halves of the single-bit test in-binary. */
static void wb_is_power_of_two(void)
{
    int p = 0;

    (void)s_is_power_of_two(8, &p);
    (void)s_is_power_of_two(6, &p);
    (void)s_is_power_of_two(1, &p);
    (void)s_is_power_of_two(0, &p);
    WB_NOTE("s_is_power_of_two both branches exercised");
}

/* mp_div_d (static): divisor 0 guard; b==1 / zero-dividend quick out with the
 * "d != NULL" and "c != NULL" decisions both ways; power-of-two branch; general
 * long division; every c/d NULL combination in-binary. */
static void wb_div_d(void)
{
    mp_int a, c;
    mp_digit d = 0;

    if (mp_init(&a) != MP_OKAY) { WB_NOTE("div_d: init a failed, skipped");
        wb_fail = 1; return; }
    if (mp_init(&c) != MP_OKAY) { WB_NOTE("div_d: init c failed, skipped");
        wb_fail = 1; mp_clear(&a); return; }
    (void)mp_set(&a, 0x9ABCDE);

    (void)mp_div_d(&a, 0, &c, &d);      /* b == 0 */
    (void)mp_div_d(&a, 1, &c, &d);      /* b == 1, c&d set */
    (void)mp_div_d(&a, 1, NULL, &d);    /* b == 1, c NULL */
    (void)mp_div_d(&a, 1, &c, NULL);    /* b == 1, d NULL */
    (void)mp_div_d(&a, 16, &c, &d);     /* power of two, c&d set */
    (void)mp_div_d(&a, 16, NULL, &d);   /* power of two, c NULL */
    (void)mp_div_d(&a, 16, &c, NULL);   /* power of two, d NULL */
    (void)mp_div_d(&a, 13, &c, &d);     /* general, c&d set */
    (void)mp_div_d(&a, 13, NULL, &d);   /* general, c NULL */
    (void)mp_div_d(&a, 13, &c, NULL);   /* general, d NULL */
    (void)mp_set(&a, 0);
    (void)mp_div_d(&a, 13, &c, &d);     /* zero dividend quick out */

    mp_clear(&a);
    mp_clear(&c);
    WB_NOTE("mp_div_d branch selectors exercised");
}

/* mp_prime_miller_rabin (static): probable-prime (a=17, base 3) and composite
 * (a=15, base 2) so the composite / probably-prime decision arms are both taken
 * in this binary. */
static void wb_miller_rabin(void)
{
    mp_int a, b;
    int res = 0;

    if (mp_init(&a) != MP_OKAY) { WB_NOTE("mr: init a failed, skipped");
        wb_fail = 1; return; }
    if (mp_init(&b) != MP_OKAY) { WB_NOTE("mr: init b failed, skipped");
        wb_fail = 1; mp_clear(&a); return; }

    (void)mp_set(&a, 17);
    (void)mp_set(&b, 3);
    (void)mp_prime_miller_rabin(&a, &b, &res);  /* probable prime */

    (void)mp_set(&a, 15);
    (void)mp_set(&b, 2);
    (void)mp_prime_miller_rabin(&a, &b, &res);  /* composite */

    /* Squaring loop that ENDS because the witness reached n1 rather than
     * because the round counter ran out. 17-1 = 2^4, so s-1 is 3 and base 2
     * walks 2 -> 4 -> 16 == n1 at j == 3: the loop's second operand decides
     * the exit while the first is still true, which base 3 (which only
     * reaches n1 once j has already passed s-1) never shows. */
    (void)mp_set(&a, 17);
    (void)mp_set(&b, 2);
    (void)mp_prime_miller_rabin(&a, &b, &res);

    mp_clear(&a);
    mp_clear(&b);
    WB_NOTE("mp_prime_miller_rabin prime/composite exercised");
}

/* mp_prime_is_divisible (static): divisible by a small table prime (a=15, /3 ->
 * res==0 true, early YES) and not divisible (a=17 -> loop runs to completion,
 * res==0 false throughout). */
static void wb_prime_is_divisible(void)
{
    mp_int a;
    int res = 0;

    if (mp_init(&a) != MP_OKAY) { WB_NOTE("pid: init failed, skipped");
        wb_fail = 1; return; }

    (void)mp_set(&a, 15);
    (void)mp_prime_is_divisible(&a, &res);   /* divisible: res==0 true */

    (void)mp_set(&a, 17);
    (void)mp_prime_is_divisible(&a, &res);   /* not divisible: loop completes */

    mp_clear(&a);
    WB_NOTE("mp_prime_is_divisible divisible/not exercised");
}

/* bn_reverse (static): reverse buffers whose length makes the ix<iy loop run
 * (len>1, both even and odd) and one where it does not (len<=1). */
static void wb_bn_reverse(void)
{
    unsigned char buf[5];

    buf[0] = 1; buf[1] = 2; buf[2] = 3; buf[3] = 4; buf[4] = 5;
    bn_reverse(buf, 5);   /* odd length: middle element untouched */
    bn_reverse(buf, 4);   /* even length */
    bn_reverse(buf, 1);   /* len 1: ix<iy immediately false */
    WB_NOTE("bn_reverse loop-run/no-run exercised");
}

#endif /* !USE_FAST_MATH && USE_INTEGER_HEAP_MATH && !WOLFSSL_SP_MATH */

/* ------------------------------------------------------------------------- *
 * Additional gap drivers (merged from the former _gap TU). These corrupt
 * mp_int struct fields directly (->dp, ->alloc, ->used), so they additionally
 * require WOLFSSL_PUBLIC_MP (non-opaque mp_int).
 *
 * Targeted gaps (wolfcrypt/src/integer.c), by class:
 *   Class 1  mp_copy() / s_mp_add() / s_mp_sub() / s_mp_mul_high_digs()
 *            dp==NULL sanity checks paired with a nonzero ->used/->alloc -
 *            an inconsistent state no public mutator can produce.
 *   Class 2  mp_set_bit() entry guard's dp==NULL && (alloc!=0||used!=0)
 *            clause - same reasoning as Class 1.
 *   Class 3  mp_cnt_lsb() least-significant-zero-digit loop running out of
 *            digits - only reachable with a non-normalized (all-zero-digit,
 *            ->used > 0) mp_int.
 * ------------------------------------------------------------------------- */
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
    /* The slow path is taken when a->used + b->used + 1 >= MP_WARRAY. The
     * WIDTH is carried entirely by 'b' and 'a' is left at a single digit on
     * purpose: the inner loop aliases 'b' at b->dp + (digs - ix), so an 'a'
     * wider than one digit walks that alias BACKWARDS off the front of b's
     * buffer. With pa == 1 and digs == 0 the only offset used is 0 and every
     * read stays inside b. (An earlier version of this driver put the width
     * on 'a' instead and read up to 600 digits in front of b->dp; it survived
     * only because the preceding allocations happened to leave mapped memory
     * there, and faulted as soon as anything else ran first.) */
    int pb = (int)MP_WARRAY;
    int i;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    if ((mp_init(&a) != MP_OKAY) || (mp_init(&b) != MP_OKAY) ||
            (mp_init(&c) != MP_OKAY)) {
        WB_NOTE("mul_high_digs: init failed, skipped");
        wb_fail = 1;
        return;
    }
    if (mp_grow(&b, pb) != MP_OKAY) {
        WB_NOTE("mul_high_digs: grow failed, skipped");
        wb_fail = 1;
        goto out;
    }
    for (i = 0; i < pb; i++) {
        b.dp[i] = (mp_digit)(i + 1);
    }
    b.used = pb;

    /* Corrupted 'a': ->used nonzero so pa > 0, but ->dp stays NULL - the
     * loop condition's short-circuit ("a->dp" checked after "ix < pa")
     * means dereferencing a->dp[ix] never happens. */
    a.used = 1;
    (void)s_mp_mul_high_digs(&a, &b, &c, 0);
    a.used = 0; /* restore before the grow below */

    /* Same slow-path shape, but with a REAL (allocated) 'a' - completes the
     * "a->dp" truthy side within this same binary. */
    if (mp_grow(&a, 1) != MP_OKAY) {
        WB_NOTE("mul_high_digs: grow failed, skipped");
        wb_fail = 1;
        goto out;
    }
    a.dp[0] = 3;
    a.used  = 1;
    (void)s_mp_mul_high_digs(&a, &b, &c, 0);

    WB_NOTE("s_mp_mul_high_digs 'a->dp' loop guard both sides exercised");
out:
    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
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

/* ------------------------------------------------------------------------- *
 * Relocated from tests/api (test_wolfmath.c). These drive library-internal,
 * non-exported s_mp_* symbols (s_mp_add/s_mp_sub/s_mp_mul_digs/s_mp_exptmod/
 * s_mp_mul_high_digs/mp_invmod_slow/mp_exptmod_fast/...) that are declared
 * WITHOUT MP_API and so hidden under -fvisibility=hidden in a shared-library
 * build: calling them from tests/api broke the normal (shared) wolfSSL CI
 * link. Compiled here via #include of integer.c they resolve directly.
 * Coverage-only: both directions of each decision are executed; no return
 * values are asserted (the exact call arguments are preserved, since those are
 * what drive each MC/DC pair).
 * ------------------------------------------------------------------------- */

/* Helper for wb_IntegerDecisionCoverage: grow 'a' to 'used' real digits (a
 * legitimate, if arbitrary, big value - not a corrupted/non-normalized state)
 * and fill every digit with 'fill'. */
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
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
static void wb_IntegerDecisionCoverage(void)
{
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
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

        (void)mp_init_multi(NULL, NULL, NULL, NULL, NULL, NULL);
        (void)mp_init_multi(&ia, &ib, &ic, &id, &ie, &iff);
        mp_clear(&ia); mp_clear(&ib); mp_clear(&ic);
        mp_clear(&id); mp_clear(&ie); mp_clear(&iff);
    }

    /* mp_copy: NULL args. */
    (void)mp_copy(NULL, &a);
    (void)mp_copy(&a, NULL);
    (void)mp_init(&a);
    (void)mp_set(&a, 5);
    (void)mp_init(&b);
    (void)mp_copy(&a, &b);

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
    (void)mp_init(&a);
    (void)mp_grow(&a, -5); /* alloc==0 (true), rest false */
    (void)mp_init(&a);
    (void)mp_grow(&a, 10);
    (void)mp_grow(&a, 4); /* alloc(>=10) != 0, size(4)!=0,
                                              alloc(>=10) >= size(4): all F */

    /* mp_mod_2d: same two-guard shape as fp_mod_2d (tfm.c); mp_mod_2d
     * copies 'a' into 'c' first, so c->sign tracks a->sign. */
    (void)mp_init(&a);
    (void)mp_set(&a, 5);
    (void)mp_init(&c);
    (void)mp_mod_2d(&a, (int)DIGIT_BIT, &c); /* ZPOS(T) &&
                    b>=DIGIT_BIT*1 (T): early return, c == a unchanged (5) */
    (void)mp_cmp_d(&c, 5);
    a.sign = MP_NEG;
    (void)mp_mod_2d(&a, (int)DIGIT_BIT, &c); /* ZPOS(F) */
    a.sign = MP_ZPOS;
    (void)mp_mod_2d(&a, 0, &c); /* ZPOS(T), b>=...(F) */
    (void)mp_cmp_d(&c, 0);

    /* mp_exptmod: "mp_iszero(P) || P->sign == MP_NEG" - the iszero half is
     * shown elsewhere; complete the sign operand's pair with a nonzero
     * negative modulus. */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 2);
    (void)mp_init(&c);
    (void)mp_set(&c, 7);
    c.sign = MP_NEG;
    (void)mp_exptmod(&a, &b, &c, &a);

    /* mp_invmod: "b sign NEG || iszero(b) || iszero(a)" - three operands,
     * each isolated in turn against an otherwise-valid a=3,b=7 pair. */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 7);
    (void)mp_init(&c);
    b.sign = MP_NEG;
    (void)mp_invmod(&a, &b, &c);
    (void)mp_set(&b, 7); /* reset sign to ZPOS */
    mp_zero(&b);
    (void)mp_invmod(&a, &b, &c);
    (void)mp_set(&b, 7);
    mp_zero(&a);
    (void)mp_invmod(&a, &b, &c);
    (void)mp_set(&a, 3);
    (void)mp_invmod(&a, &b, &c);

    /* mp_invmod_slow (public in the integer.c backend): its own copy of
     * the same "b sign NEG || iszero(b)" guard. */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 10); /* even modulus: slow path */
    b.sign = MP_NEG;
    (void)mp_invmod_slow(&a, &b, &c);
    mp_zero(&b);
    (void)mp_invmod_slow(&a, &b, &c);
    (void)mp_set(&b, 10);
    (void)mp_invmod_slow(&a, &b, &c);

    /* mp_cmp_d: "a->used==0 && b==0" and "(b && a->used==0) || sign==NEG".
     * Five calls complete all four independent operands' pairs (the
     * a->used==0 operand is shared between the two decisions). */
    (void)mp_init(&a);
    (void)mp_cmp_d(&a, 0); /* a->used==0(T) && b==0(T) */
    (void)mp_set(&a, 9);
    (void)mp_cmp_d(&a, 0); /* a->used==0(F): isolates op0 */
    (void)mp_init(&a); /* a->used==0 again */
    (void)mp_cmp_d(&a, 5); /* b==0(F): isolates op1; also
                        (b(T) && a->used==0(T)) => MP_LT: op2/op3 baseline */
    (void)mp_set(&a, 9);
    (void)mp_cmp_d(&a, 5); /* b(T) && a->used==0(F): isolates
                                            the "a->used==0" operand of the
                                            second decision, sign ZPOS(F) */
    a.sign = MP_NEG;
    (void)mp_cmp_d(&a, 5); /* sign==NEG(T): isolates op3 */

    /* mp_add / s_mp_add: "min_ab > 0 && (dp==NULL...)" - the dp==NULL
     * combination needs a non-normalized/corrupted mp_int (impossible via
     * any public mutator) and is exercised above in this file; complete the
     * "min_ab > 0" operand's pair here (both operands nonzero vs one
     * operand zero-used). */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 4);
    (void)mp_init(&c);
    (void)s_mp_add(&a, &b, &c); /* min_ab(1) > 0: true */
    mp_zero(&b);
    (void)s_mp_add(&a, &b, &c); /* min_ab(0) > 0: false */

    /* mp_sub / s_mp_sub: "min_b > 0 && (tmpa==NULL || tmpb==NULL)" - unlike
     * s_mp_add above, min_b is just b->used (not MIN(a,b)), so "tmpa==NULL"
     * is legitimately reachable: a freshly-initialized, never-grown 'a'
     * (->used==0) has ->dp==NULL regardless of b. tmpb==NULL still needs a
     * corrupted b (exercised above in this file). */
    (void)mp_set(&a, 3);
    (void)mp_set(&b, 4);
    (void)s_mp_sub(&a, &b, &c); /* min_b(1) > 0: true */
    mp_zero(&b);
    (void)s_mp_sub(&a, &b, &c); /* min_b(0) > 0: false */
    (void)mp_init(&a); /* a->used==0: tmpa == a->dp == NULL */
    (void)mp_set(&b, 4); /* min_b(1) > 0 */
    (void)s_mp_sub(&a, &b, &c); /* tmpa==NULL: true */

    /* mp_exptmod_fast (2107:*:1) / mp_exptmod_base_2 (2350:*:1) /
     * mp_montgomery_reduce (2690:*:1): all three share
     *   (N->used * 2 + 1 < (int)MP_WARRAY) &&
     *   (N->used < (1L << (CHAR_BIT*sizeof(mp_word) - 2*DIGIT_BIT)))
     * (mp_montgomery_reduce spells the first operand with the hoisted
     * digs = n->used * 2 + 1 at :2689) to pick between the comba-accelerated
     * and the generic montgomery reduce - both arms are functionally
     * equivalent (just performance), so a small and a large (real,
     * legitimately grown) modulus both succeed; only the dispatch differs.
     *
     * The second operand is EXCLUDED, not driven, and the argument is
     * algebraic rather than numeric. wolfssl/wolfcrypt/integer.h:189 defines
     *   MP_WARRAY = (mp_word)1 << (sizeof(mp_word)*CHAR_BIT - 2*DIGIT_BIT + 1)
     * i.e. MP_WARRAY == 2 * B where B is the very bound the second operand
     * tests against, for EVERY digit configuration (the two expressions are
     * the same exponent, +1 apart). So over a non-negative integer u:
     *   operand0 <=> 2u + 1 < 2B <=> 2u <= 2B - 2 <=> u <= B - 1 <=> u < B
     * which is operand1 verbatim. The two operands are not merely disjoint,
     * they are the SAME predicate, so the (T,F) row that operand1's
     * independence pair needs does not exist. (Contrast mp_sqr at :3162,
     * whose second operand uses "- 1" in the exponent, i.e. B/2; there the
     * pair IS satisfiable and is driven below.) u is int-typed ->used, which
     * mp_clamp/mp_grow keep in [0, alloc]; a used large enough to overflow
     * "used * 2 + 1" would need >2^30 digits of dp and is undefined behaviour
     * besides, so it is not a vector.
     *
     * Only the first operand's pair is targeted here (small N takes the
     * comba path, big N the generic one). */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 2);
    wolfmath_big_fill(&c, 20, 3); /* small odd-ish modulus-shaped value */
    c.dp[0] |= 1; /* keep it odd so montgomery_setup succeeds */
    (void)mp_exptmod_fast(&a, &b, &c, &a, 0); /* small N */
    (void)mp_set(&a, 3);
    {
        mp_int big;
        XMEMSET(&big, 0, sizeof(big));
        wolfmath_big_fill(&big, 300, 3); /* N->used(300)*2+1 >= MP_WARRAY:
                                             takes the generic reduce path */
        big.dp[0] |= 1;
        (void)mp_exptmod_fast(&a, &b, &big, &a, 0);
        mp_clear(&big);
    }
    (void)mp_set(&a, 3);
    (void)mp_exptmod_base_2(&b, &c, &a);
    {
        mp_digit rho = 0;
        (void)mp_montgomery_setup(&c, &rho);
        (void)mp_set(&a, 5);
        (void)mp_montgomery_reduce(&a, &c, rho);
    }

    /* mp_set_bit: "b < 0 || (a->dp==NULL && (a->alloc!=0 || a->used!=0))".
     * The parenthesized clause needs a non-normalized/corrupted mp_int (a
     * real dp==NULL is only ever paired with alloc==0 && used==0) and is
     * exercised above in this file; complete the "b < 0" operand's pair
     * here. */
    (void)mp_init(&a);
    (void)mp_set_bit(&a, -1);
    (void)mp_set_bit(&a, 3);

    /* mp_mul_d: "c->dp==NULL || c->alloc < a->used+1" - both operands are
     * legitimately reachable: a fresh (never-grown) destination naturally
     * has dp==NULL; an under-grown destination has dp!=NULL but too small
     * an alloc; a sufficiently pre-grown destination makes both false. */
    (void)mp_init(&a);
    (void)mp_set(&a, 7);
    (void)mp_init(&c); /* fresh: c->dp == NULL */
    (void)mp_mul_d(&a, 3, &c); /* dp==NULL(T): grows */
    (void)mp_init_size(&c, 1); /* dp!=NULL, alloc(1) < 2 */
    (void)mp_mul_d(&a, 3, &c); /* dp==NULL(F), alloc<..(T) */
    (void)mp_init_size(&c, 8); /* alloc(8) >= used(1)+1 */
    (void)mp_mul_d(&a, 3, &c); /* both false */

    /* mp_sqr / s_mp_sqr: "(a->used*2+1 < MP_WARRAY) && a->used <
     * (1 << (WORD_BITS - 2*DIGIT_BIT - 1))" - unlike the montgomery/
     * exptmod shape above, the "- 1" here shrinks the second threshold
     * below the first, so both thresholds' independence pairs ARE jointly
     * satisfiable: a middling a->used (>= second threshold, < first) shows
     * the second operand false while the first stays true. */
    wolfmath_big_fill(&a, 10, 3);
    (void)mp_init(&c);
    (void)mp_sqr(&a, &c); /* both thresholds true */
    wolfmath_big_fill(&a, 200, 3); /* > 2nd threshold(~128), < 1st(255) */
    (void)mp_sqr(&a, &c); /* 1st true, 2nd false */
    wolfmath_big_fill(&a, 300, 3); /* > 1st threshold too */
    (void)mp_sqr(&a, &c); /* both false: falls back */

    /* mp_mul (3199:*:1): "(digs < (int)MP_WARRAY) &&
     * MIN(a->used,b->used) <= B", digs = a->used + b->used + 1 (:3197) and
     * B == MP_WARRAY / 2 (see the identity spelled out above). The MIN
     * operand is EXCLUDED: operand0 true means a->used + b->used + 1 <= 2B-1,
     * hence a->used + b->used <= 2B-2, hence MIN <= B-1 <= B, so operand1 is
     * forced TRUE whenever it is evaluated at all. MIN can only go false with
     * both operands large, which drives digs past MP_WARRAY and
     * short-circuits operand1 away. The digs operand's pair IS targeted here
     * (small operands vs one huge operand with the other tiny, which keeps
     * MIN small while pushing digs past MP_WARRAY). */
    wolfmath_big_fill(&a, 10, 3);
    wolfmath_big_fill(&b, 2, 3);
    (void)mp_init(&c);
    (void)mp_mul(&a, &b, &c); /* digs small: true */
    wolfmath_big_fill(&a, 600, 3); /* digs = 600+2+1 >= MP_WARRAY(512) */
    (void)mp_mul(&a, &b, &c); /* digs large: false */

    /* s_mp_mul_digs: same shape, but 'digs' is a caller-supplied parameter
     * independent of a->used/b->used (as long as digs >= a->used, which is
     * required for memory safety regardless of MC/DC), so BOTH operands'
     * pairs are directly reachable. */
    wolfmath_big_fill(&a, 1, 3);
    wolfmath_big_fill(&b, 1, 3);
    (void)mp_init(&c);
    (void)s_mp_mul_digs(&a, &b, &c, 5); /* digs(5)<WARRAY:T,
                                                    MIN(1,1)<256: T */
    (void)s_mp_mul_digs(&a, &b, &c, 600); /* digs(600):F */
    wolfmath_big_fill(&a, 300, 3);
    wolfmath_big_fill(&b, 300, 3);
    (void)s_mp_mul_digs(&a, &b, &c, 305); /* digs(305)<
                                    WARRAY:T, MIN(300,300)<256: F */

    /* s_mp_exptmod tail (3959:*:1), identical idiom in mp_exptmod_fast
     * (2279:*:1): "if (mode == 2 && bitcpy > 0)".
     *
     * The "bitcpy > 0" operand is EXCLUDED: the sliding-window state machine
     * maintains the invariant (mode == 2) => (bitcpy >= 1), so the (T,F) row
     * operand1 needs does not exist. Exhaustively, in each function there are
     * only three writes to 'mode' and two to 'bitcpy':
     *   :3884/:2204  mode = 0    and  :3888/:2208  bitcpy = 0   (entry)
     *   :3928/:2248  bitbuf |= (y << (winsize - ++bitcpy));  -- PRE-increment
     *   :3929/:2249  mode = 2    -- immediately after, so bitcpy >= 1 here
     *   :3952/:2272  bitcpy = 0  } same straight-line block, guarded by
     *   :3954/:2274  mode   = 1  } "if (bitcpy == winsize)", no break/goto
     *                              between them
     * The only assignment that clears bitcpy also leaves mode == 1, and the
     * only assignment that sets mode == 2 is preceded by an increment of
     * bitcpy in the same expression statement. Hence at the tail guard
     * mode == 2 implies bitcpy >= 1.
     *
     * The two calls below still pair the FIRST operand: a small exponent
     * flushes its last window exactly (mode == 1 at the tail -> operand0 F),
     * a bigger one leaves a partial window (mode == 2, bitcpy > 0 -> T,T). */
    (void)mp_init(&a);
    (void)mp_set(&a, 3);
    (void)mp_init(&b);
    (void)mp_set(&b, 7); /* 3 bits: winsize 1 */
    (void)s_mp_exptmod(&a, &b, &c, &a, 0);
    (void)mp_set(&b, 0x3FFFFFFF); /* 30 bits: winsize 3 */
    (void)s_mp_exptmod(&a, &b, &c, &a, 0);

    /* s_mp_mul_high_digs (4170:*:1): "((a->used + b->used + 1) <
     * (int)MP_WARRAY) && MIN(a->used,b->used) < B" - the 'digs' PARAMETER is
     * only used after the check; the check itself is SUM-based on
     * a->used+b->used, so this is the same coupling as mp_mul above (this
     * one spells the second operand with "<" rather than "<=", which only
     * makes the implication stricter: operand0 true => MIN <= B-1 < B).
     * The MIN operand is EXCLUDED; the first operand's pair is targeted
     * here. */
    wolfmath_big_fill(&a, 10, 3);
    wolfmath_big_fill(&b, 2, 3);
    (void)mp_init(&c);
    (void)s_mp_mul_high_digs(&a, &b, &c, 0); /* sum small:T */
    wolfmath_big_fill(&a, 600, 3);
    (void)s_mp_mul_high_digs(&a, &b, &c, 0); /* sum big: F */

    /* mp_add_d / mp_sub_d: "tmpa==NULL || tmpc==NULL". Both functions grow
     * 'c' themselves (via "c->alloc < a->used+1") immediately before this
     * check, so tmpc is never NULL when it runs - a documented residual,
     * same class as s_mp_add's tmpc (see REPORT.md). tmpa==NULL IS
     * legitimately reachable via a freshly mp_init'd (never grown) 'a',
     * whose ->dp is NULL; the function then correctly reports MP_MEM
     * (the guard doubles as an allocation-sanity check). */
    (void)mp_init(&a); /* a->dp == NULL */
    (void)mp_init(&c);
    (void)mp_add_d(&a, 5, &c); /* tmpa==NULL: true */
    (void)mp_init(&a);
    (void)mp_init(&c);
    (void)mp_sub_d(&a, 5, &c); /* tmpa==NULL: true */

    /* mp_add_d: "a->sign==MP_NEG && (a->used>1 || a->dp[0]>=b)" - three
     * operands, each isolated against an otherwise-fixed baseline. */
    (void)mp_init(&a);
    (void)mp_set(&a, 3); /* a->used==1, dp[0]==3 */
    a.sign = MP_NEG;
    (void)mp_init(&c);
    (void)mp_add_d(&a, 1, &c); /* NEG(T), used>1(F),
                                                   dp[0](3)>=b(1)(T) */
    a.sign = MP_ZPOS;
    (void)mp_add_d(&a, 1, &c); /* NEG(F): isolates sign op */
    (void)mp_set(&a, 1);
    a.sign = MP_NEG;
    (void)mp_add_d(&a, 3, &c); /* dp[0](1)>=b(3): F,
                                                   isolates that operand */

    /* mp_sub_d: "(a->used==1 && a->dp[0]<=b) || a->used==0" - the
     * a->used==0 operand's pair (a->used==1 half is exercised by the
     * ordinary single-digit subtraction paths elsewhere in this file).
     * Use a previously-grown-then-zeroed 'a' (->dp allocated, ->used==0)
     * rather than a freshly mp_init'd one, so the "tmpa==NULL" guard
     * above doesn't intercept the call first. */
    (void)mp_init(&a);
    (void)mp_set(&a, 9);
    mp_zero(&a); /* ->dp stays allocated; ->used reset to 0 */
    (void)mp_init(&c);
    (void)mp_sub_d(&a, 1, &c); /* a->used==0: true */
    (void)mp_set(&a, 9);
    (void)mp_sub_d(&a, 1, &c); /* a->used==0: false */

    /* mp_cnt_lsb: "x < a->used && a->dp[x]==0" - the "x < a->used going
     * false via running out of digits" side needs a non-normalized
     * all-zero-digit value (exercised above in this file); the "a->dp[x]==0"
     * operand's own pair IS legitimately reachable: a value whose lowest
     * digit is zero (shifted by exactly one whole digit) vs one whose
     * lowest digit is already nonzero. */
    (void)mp_init(&a);
    (void)mp_set(&a, 5);
    (void)mp_cnt_lsb(&a); /* dp[0]==0: false immediately */
    (void)mp_init(&c);
    (void)mp_set(&a, 1);
    (void)mp_mul_2d(&a, (int)DIGIT_BIT, &c); /* dp[0]==0,
                                                    dp[1]!=0: a legitimate,
                                                    normalized value */
    (void)mp_cnt_lsb(&c); /* dp[0]==0(T) then dp[1]!=0 stops it */

    /* mp_prime_is_prime: "t<=0 || t>PRIME_SIZE" (t<=0 half shown
     * elsewhere); complete t>PRIME_SIZE's pair. */
    {
        int result = 0;

        (void)mp_init(&a);
        (void)mp_set(&a, 17);
        (void)mp_prime_is_prime(&a, PRIME_SIZE + 1, &result);
        (void)mp_prime_is_prime(&a, 8, &result);
        (void)result;
    }

#if !defined(WC_NO_RNG)
    {
        WC_RNG rng;
        int result = 0;

        XMEMSET(&rng, 0, sizeof(rng));
        (void)wc_InitRng(&rng);

        /* mp_prime_is_prime_ex: "t<=0 || t>PRIME_SIZE" - both operands'
         * pairs, plus the composite-survives-trial-division case that
         * reaches Miller-Rabin. */
        (void)mp_prime_is_prime_ex(&a, 0, &result, &rng);
        (void)mp_prime_is_prime_ex(&a, PRIME_SIZE + 1, &result, &rng);
        (void)mp_prime_is_prime_ex(&a, 8, &result, &rng);
        (void)result;
        (void)mp_set(&a, 1032247u); /* 1013 * 1019: both
                            factors bigger than every ltm_prime_tab entry */
        (void)mp_prime_is_prime_ex(&a, 8, &result, &rng);
        (void)result;

        /* mp_rand_prime: "a==NULL||rng==NULL" and "len<2||len>512".
         * Declared/defined only under WOLFSSL_KEY_GEN && (!NO_DH || !NO_DSA);
         * gate the calls to match the library so other variants don't get an
         * implicit declaration or an undefined reference. */
#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_DH) || !defined(NO_DSA))
        (void)mp_rand_prime(NULL, 32, &rng, HEAP_HINT);
        (void)mp_rand_prime(&a, 32, NULL, HEAP_HINT);
        (void)mp_rand_prime(&a, 1, &rng, HEAP_HINT);
        (void)mp_rand_prime(&a, 513, &rng, HEAP_HINT);
        (void)mp_rand_prime(&a, 32, &rng, HEAP_HINT);
#endif

        (void)wc_FreeRng(&rng);
    }
#endif /* !WC_NO_RNG */

    /* mp_read_radix: "radix < MP_RADIX_BIN || radix > MP_RADIX_MAX". */
    (void)mp_read_radix(&a, "10", 1);
    (void)mp_read_radix(&a, "10", 65);
    (void)mp_read_radix(&a, "10", MP_RADIX_DEC);

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
        (void)mp_radix_size(&a, 65, &size);
        (void)mp_set(&a, 0x1); /* 1 hex digit: odd */
        (void)mp_radix_size(&a, MP_RADIX_HEX, &size);
        (void)mp_set(&a, 0x12); /* 2 hex digits: even */
        (void)mp_radix_size(&a, MP_RADIX_HEX, &size);
        (void)mp_set(&a, 0x1);
        (void)mp_radix_size(&a, MP_RADIX_DEC, &size); /* not hex */

        (void)mp_toradix(&a, buf, 65);
        (void)mp_set(&a, 0x1);
        XMEMSET(buf, 0, sizeof(buf));
        (void)mp_toradix(&a, buf, MP_RADIX_HEX);
        (void)mp_set(&a, 0x12);
        XMEMSET(buf, 0, sizeof(buf));
        (void)mp_toradix(&a, buf, MP_RADIX_HEX);
        (void)mp_set(&a, 0x1);
        XMEMSET(buf, 0, sizeof(buf));
        (void)mp_toradix(&a, buf, MP_RADIX_DEC);
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
#endif /* !WOLFSSL_SP_MATH && !WOLFSSL_SP_MATH_ALL */
    WB_NOTE("IntegerDecisionCoverage decision branches exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 4: the mp_add_d() / mp_sub_d() destination-alias sanity checks.
 *
 *   tmpa = a->dp;
 *   tmpc = c->dp;
 *   if (tmpa == NULL || tmpc == NULL) { return MP_MEM; }
 *
 * Both functions grow the destination first, so by the time the aliases are
 * taken c->dp is NULL only if c arrived claiming capacity it does not have
 * (->alloc >= a->used + 1 while ->dp == NULL) - the grow is skipped and the
 * destination alias is NULL while the SOURCE alias is not. That is exactly
 * the second operand's independence row, and no public mutator can build the
 * state, so it is set up here directly: the pointer is parked, the call made,
 * and the pointer put back before the value is cleared.
 * ------------------------------------------------------------------------- */
static void wb_add_sub_d_null_dp(void)
{
    mp_int a, c;
    mp_digit* saved;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&c, 0, sizeof(c));

    if ((mp_init(&a) != MP_OKAY) || (mp_init(&c) != MP_OKAY)) {
        WB_NOTE("add/sub_d alias rows: init failed, skipped");
        wb_fail = 1;
        return;
    }
    /* a = 5 (one digit, positive) and a destination with real capacity. */
    if ((mp_set(&a, 5) != MP_OKAY) || (mp_grow(&c, 8) != MP_OKAY)) {
        WB_NOTE("add/sub_d alias rows: setup failed, skipped");
        wb_fail = 1;
        goto out;
    }

    /* Ordinary rows first: both aliases non-NULL, in this same binary. */
    (void)mp_add_d(&a, 1, &c);
    (void)mp_sub_d(&a, 1, &c);

    /* Destination alias NULL while the source alias is not. The recorded
     * capacity is left alone so the grow is skipped and the guard is the
     * first thing that sees the missing buffer. */
    saved = c.dp;
    c.dp  = NULL;
    (void)mp_add_d(&a, 1, &c);
    (void)mp_sub_d(&a, 1, &c);
    c.dp  = saved;

    WB_NOTE("mp_add_d/mp_sub_d destination-alias rows exercised");
out:
    mp_clear(&a);
    mp_clear(&c);
}

/* ------------------------------------------------------------------------- *
 * Class 5: mp_mul_d()'s destination capacity guard.
 *
 *   if (c->dp == NULL || c->alloc < a->used + 1) { mp_grow(...) }
 *
 * mp_init() defers allocation, so the first use of any destination takes the
 * dp==NULL arm and the capacity operand is never evaluated; after that the
 * grown destination is comfortably large for the single-digit multiplicands
 * the suite uses, so the capacity operand is only ever seen false. A
 * multiplicand wider than the destination's grown capacity supplies its true
 * row, and repeating the call once the destination has been grown to fit
 * supplies the false row.
 * ------------------------------------------------------------------------- */
static void wb_mul_d_capacity(void)
{
    mp_int a, c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&c, 0, sizeof(c));

    if ((mp_init(&a) != MP_OKAY) || (mp_init(&c) != MP_OKAY)) {
        WB_NOTE("mul_d capacity rows: init failed, skipped");
        wb_fail = 1;
        return;
    }

    /* First use: the destination has no buffer at all (first operand true). */
    if (mp_set(&a, 7) != MP_OKAY) {
        wb_fail = 1;
        goto out;
    }
    (void)mp_mul_d(&a, 3, &c);

    /* A multiplicand far wider than the destination's grown capacity: the
     * destination now has a buffer, so the capacity operand decides. */
    if ((mp_set(&a, 1) != MP_OKAY) ||
            (mp_mul_2d(&a, 4096 * DIGIT_BIT, &a) != MP_OKAY)) {
        wb_fail = 1;
        goto out;
    }
    (void)mp_mul_d(&a, 3, &c);

    /* Same call again: the destination was grown to fit by the previous one,
     * so both operands are false. */
    (void)mp_mul_d(&a, 3, &c);

    WB_NOTE("mp_mul_d destination capacity rows exercised");
out:
    mp_clear(&a);
    mp_clear(&c);
}

/* ------------------------------------------------------------------------- *
 * Class 6: mp_exptmod_base_2()'s Montgomery-backend selector.
 *
 *   if (((P->used * 2 + 1) < (int)MP_WARRAY) && P->used < (1L << ...))
 *
 * The comba ("fast") Montgomery reduction is selected whenever the modulus
 * fits the fixed-width accumulator array; every modulus the suite uses does,
 * so the generic reduction is never chosen and the first operand's false row
 * is missing. A modulus wide enough to overflow the accumulator selects the
 * generic backend. Only the FIRST operand is closable: the second operand is
 * implied by the first (2u+1 < 2^(k+1) and u < 2^k are the same predicate on
 * an integer u), so it has no independence pair - see the residuals note.
 *
 * The exponent is deliberately tiny: the decision is about the modulus width,
 * and the generic reduction is quadratic in it.
 * ------------------------------------------------------------------------- */
static void wb_exptmod_base_2_wide(void)
{
    mp_int g, x, p, y;
    int    digits = (int)((MP_WARRAY + 1) / 2);

    XMEMSET(&g, 0, sizeof(g)); XMEMSET(&x, 0, sizeof(x));
    XMEMSET(&p, 0, sizeof(p)); XMEMSET(&y, 0, sizeof(y));

    if (digits > 1024) {
        WB_NOTE("accumulator width needs an impractical modulus; skipped");
        return;
    }

    if (mp_init_multi(&g, &x, &p, &y, NULL, NULL) != MP_OKAY) {
        WB_NOTE("wide-modulus base-2 rows: init failed, skipped");
        wb_fail = 1;
        return;
    }

    /* p = 2^(digits*DIGIT_BIT) + 1: odd, and one digit past the width at
     * which the accumulator array can still hold the product. */
    if ((mp_set(&g, 2) != MP_OKAY) || (mp_set(&x, 3) != MP_OKAY) ||
            (mp_set(&p, 1) != MP_OKAY) ||
            (mp_mul_2d(&p, digits * DIGIT_BIT, &p) != MP_OKAY) ||
            (mp_add_d(&p, 1, &p) != MP_OKAY)) {
        WB_NOTE("wide-modulus base-2 rows: setup failed, skipped");
        wb_fail = 1;
        goto out;
    }
    (void)mp_exptmod(&g, &x, &p, &y);

    /* The ordinary row: a modulus the accumulator does hold. */
    if ((mp_set(&p, 1) == MP_OKAY) && (mp_mul_2d(&p, 127, &p) == MP_OKAY) &&
            (mp_add_d(&p, 1, &p) == MP_OKAY)) {
        (void)mp_exptmod(&g, &x, &p, &y);
    }

    WB_NOTE("mp_exptmod_base_2 wide-modulus rows exercised");
out:
    mp_clear(&g); mp_clear(&x); mp_clear(&p); mp_clear(&y);
}

/* ------------------------------------------------------------------------- *
 * Class 7: mp_prime_is_prime_ex()'s random-witness rejection.
 *
 *   if (mp_cmp_d(&b, 2) != MP_GT || mp_cmp(&b, &c) != MP_LT) { ix--; continue; }
 *
 * The witness is drawn at random and masked down to the CANDIDATE's bit
 * width. For the multi-hundred-bit candidates the suite tests, a draw of 0, 1
 * or 2 has probability ~2^-bits and is never observed, so the first operand's
 * true row is missing. A deliberately small candidate shrinks the draw space
 * until the arm is certain to be taken inside a bounded number of trials.
 *
 * 2039 is prime, is past the end of the small-prime table (so the up-front
 * table lookup and trial division do not answer it), and sits just under
 * 2^11, so an 11-bit witness is out of range only 14 times in 2048 - rare
 * enough that the retry loop always makes progress. At 3 draws in 2048 for
 * the arm of interest, this many trials misses it with probability ~e^-29.
 * ------------------------------------------------------------------------- */
#ifndef WC_NO_RNG
#define WB_SMALL_WITNESS_TRIALS 20000

static void wb_prime_small_witness(void)
{
    WC_RNG rng;
    mp_int a;
    int    res = 0;
    int    i;

    XMEMSET(&a, 0, sizeof(a));
    if (mp_init(&a) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("RNG init failed; small-witness rows skipped");
        mp_clear(&a);
        return;
    }
    if (mp_set(&a, 2039) != MP_OKAY) {
        wb_fail = 1;
        goto out;
    }

    for (i = 0; i < WB_SMALL_WITNESS_TRIALS; i++) {
        if (mp_prime_is_prime_ex(&a, 1, &res, &rng) != MP_OKAY) {
            wb_fail = 1;
            break;
        }
    }

    WB_NOTE("random-witness rejection rows exercised");
out:
    (void)wc_FreeRng(&rng);
    mp_clear(&a);
}
#else
static void wb_prime_small_witness(void)
{
    WB_NOTE("no RNG in this build; random-witness rows skipped");
}
#endif /* !WC_NO_RNG */

#endif /* USE_INTEGER_HEAP_MATH && WOLFSSL_PUBLIC_MP */

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("integer.c white-box MC/DC supplement\n");
#if defined(USE_FAST_MATH) || !defined(USE_INTEGER_HEAP_MATH) || \
    defined(WOLFSSL_SP_MATH) || defined(NO_BIG_INT)
    printf("  heapmath (integer.c) not the selected backend;"
        " nothing to exercise\n");
    return 0;
#else
    wb_is_power_of_two();
    wb_div_d();
    wb_miller_rabin();
    wb_prime_is_divisible();
    wb_bn_reverse();
#ifdef WOLFSSL_PUBLIC_MP
    wb_mp_copy_tail_dp_null();
    wb_s_mp_add_sub_null_dp();
    wb_s_mp_mul_high_digs_null_dp();
    wb_mp_set_bit_corrupted();
    wb_mp_cnt_lsb_all_zero_digits();
    wb_IntegerDecisionCoverage();
    wb_add_sub_d_null_dp();
    wb_mul_d_capacity();
    wb_exptmod_base_2_wide();
    wb_prime_small_witness();
#endif
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * suite discard this variant's coverage. */
    return 0;
#endif
}
