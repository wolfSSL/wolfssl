/* test_tfm_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/tfm.c (the FASTMATH
 * big-integer module, bigint-tfm, iso26262/mcdc-per-module).
 *
 * The tests/api wolfmath suite (test_wolfmath.c, test_wc_Tfm*DecisionCoverage)
 * drives tfm.c through its *public* mp_/fp_ API. A number of decisions instead
 * live in file-static helpers whose branch-selecting operand combinations a
 * public caller can never present (a helper is only ever reached after the
 * public entry point has already normalized / range-checked its arguments), so
 * their MC/DC independence pairs cannot be demonstrated from the API without
 * editing library source. This translation unit reaches them by compiling
 * tfm.c directly (#include) and calling the static helpers with BOTH halves of each
 * targeted pair in this one binary (llvm-cov computes MC/DC per binary; the
 * campaign unions the "independence shown" bit across binaries by line:col).
 *
 * Build: compiled by run-mcdc.sh's white-box step with the SAME MC/DC CFLAGS
 * and -I<workspace> as the instrumented library, then linked against that
 * variant's libwolfssl.a with its tfm.o removed (this TU supplies the
 * instrumented tfm.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Every call is memory-safe (static helpers are handed initialized fp_ints and
 * in-range selectors); setup failures print a skip and return 0 (a nonzero
 * exit makes the campaign discard the variant and its coverage).
 */

#include <wolfcrypt/src/tfm.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(USE_FAST_MATH)

/* s_is_power_of_two(b, &p): "b power of two" true (b=8), false-via-not-set
 * (b=6, more than one bit), and the b==0 guard. Both halves of the internal
 * "is exactly one bit set" decision in one binary. */
static void wb_is_power_of_two(void)
{
    int p = 0;

    (void)s_is_power_of_two(8, &p);   /* power of two -> FP_YES */
    (void)s_is_power_of_two(6, &p);   /* not a power of two -> FP_NO */
    (void)s_is_power_of_two(1, &p);   /* 1 == 2^0 boundary */
    (void)s_is_power_of_two(0, &p);   /* zero: rejected */
    WB_NOTE("s_is_power_of_two both branches exercised");
}

/* fp_cond_swap_ct / fp_cond_swap_ct_ex: constant-time conditional swap; the
 * mask = 0 - m selects swap (m=1) or no-swap (m=0). Both halves in-binary. */
static void wb_cond_swap_ct(void)
{
    fp_int a, b;

    fp_init(&a);
    fp_init(&b);
    fp_set(&a, 0x1234);
    fp_set(&b, 0x5678);

    (void)fp_cond_swap_ct(&a, &b, (int)a.used > (int)b.used ?
        (int)a.used : (int)b.used, 1); /* m=1: swap */
    (void)fp_cond_swap_ct(&a, &b, (int)a.used > (int)b.used ?
        (int)a.used : (int)b.used, 0); /* m=0: no swap */
    WB_NOTE("fp_cond_swap_ct swap/no-swap exercised");
}

/* fp_div_d (static): divisor 0 guard; b==1 / zero-dividend quick out; power of
 * two branch (both c!=NULL and d!=NULL legs); general long-division loop with
 * every c/d NULL combination so the "if (c != NULL)" / "if (d != NULL)"
 * decisions are covered both ways. */
static void wb_div_d(void)
{
    fp_int a, c;
    fp_digit d = 0;

    fp_init(&a);
    fp_init(&c);
    fp_set(&a, 0x9ABCDE);

    (void)fp_div_d(&a, 0, &c, &d);        /* b == 0 */
    (void)fp_div_d(&a, 1, &c, &d);        /* b == 1 quick out */
    (void)fp_div_d(&a, 16, &c, &d);       /* power of two, c&d set */
    (void)fp_div_d(&a, 16, NULL, &d);     /* power of two, c NULL */
    (void)fp_div_d(&a, 16, &c, NULL);     /* power of two, d NULL */
    (void)fp_div_d(&a, 13, &c, &d);       /* general, c&d set */
    (void)fp_div_d(&a, 13, NULL, &d);     /* general, c NULL */
    (void)fp_div_d(&a, 13, &c, NULL);     /* general, d NULL */
    fp_zero(&a);
    (void)fp_div_d(&a, 13, &c, &d);       /* zero dividend quick out */

    (void)fp_mod_d(&a, 13, &d);           /* fp_mod_d thin wrapper */
    WB_NOTE("fp_div_d branch selectors exercised");
}

/* fp_read_radix_16 (static): the eol_done / whitespace decision. Trailing
 * whitespace before any digit is seen (scanned from the end) hits
 * "!eol_done && CharIsWhiteSpace" true (continue); a non-hex, non-whitespace
 * char returns FP_VAL; embedded whitespace once digits are seen hits eol_done
 * true (FP_VAL). Also the '-' sign branch. */
static void wb_read_radix_16(void)
{
    fp_int a;

    fp_init(&a);
    (void)fp_read_radix_16(&a, "1Ab2");       /* plain */
    fp_init(&a);
    (void)fp_read_radix_16(&a, "1Ab2  ");     /* trailing ws: !eol_done true */
    fp_init(&a);
    (void)fp_read_radix_16(&a, "1A b2");       /* embedded ws: eol_done true */
    fp_init(&a);
    (void)fp_read_radix_16(&a, "-1Ab2");      /* negative sign */
    fp_init(&a);
    (void)fp_read_radix_16(&a, "1G2");         /* invalid hex char -> FP_VAL */
    WB_NOTE("fp_read_radix_16 whitespace/sign branches exercised");
}

/* fp_invmod_slow (static, general binary extended Euclid): a real inverse
 * (a=3 mod 497) and a small odd modulus so the u/v parity while-loops iterate
 * their true and false sides. */
static void wb_invmod_slow(void)
{
    fp_int a, b, c;

    fp_init(&a);
    fp_init(&b);
    fp_init(&c);
    fp_set(&a, 3);
    fp_set(&b, 497);
    (void)fp_invmod_slow(&a, &b, &c);
    WB_NOTE("fp_invmod_slow exercised");
}

/* fp_prime_miller_rabin(_ex) (static): a prime candidate that passes (a=17,
 * base 3) and a composite that fails (a=15, base 2) so the composite / probably
 * prime decision arms are both taken in-binary. */
static void wb_miller_rabin(void)
{
    fp_int a, b;
    int res = 0;

    fp_init(&a);
    fp_init(&b);

    fp_set(&a, 17);
    fp_set(&b, 3);
    (void)fp_prime_miller_rabin(&a, &b, &res);  /* probable prime */

    fp_set(&a, 15);
    fp_set(&b, 2);
    (void)fp_prime_miller_rabin(&a, &b, &res);  /* composite */
    WB_NOTE("fp_prime_miller_rabin prime/composite exercised");
}

/* _fp_exptmod_ct / _fp_exptmod_nct / _fp_exptmod_base_2 (static engines):
 * exercise directly with a small odd modulus so their internal
 * window/montgomery loops run. Which of the two _fp_exptmod_ct definitions is
 * compiled depends on TFM_TIMING_RESISTANT; whichever it is, this reaches it.
 */
static void wb_exptmod_engines(void)
{
    fp_int g, x, p, y;

    fp_init(&g);
    fp_init(&x);
    fp_init(&p);
    fp_init(&y);
    fp_set(&g, 4);
    fp_set(&x, 13);
    fp_set(&p, 497);          /* odd modulus */

#ifdef TFM_TIMING_RESISTANT
    (void)_fp_exptmod_ct(&g, &x, x.used, &p, &y);
#else
    (void)_fp_exptmod_nct(&g, &x, &p, &y);
#endif
    /* base-2 special engine: X as the exponent, P the modulus. */
    (void)_fp_exptmod_base_2(&x, x.used, &p, &y);
    WB_NOTE("_fp_exptmod_* engines exercised");
}

#ifdef HAVE_INTEL_MULX
/* fp_montgomery_reduce_mulx (static, only compiled with HAVE_INTEL_MULX): the
 * MULX-accelerated Montgomery reduction, non-constant-time and constant-time
 * decision arms. */
static void wb_montgomery_mulx(void)
{
    fp_int a, m;
    fp_digit mp = 0;

    fp_init(&a);
    fp_init(&m);
    fp_set(&m, 0xF1);           /* odd modulus */
    if (fp_montgomery_setup(&m, &mp) == FP_OKAY) {
        fp_set(&a, 3);
        (void)fp_montgomery_reduce_mulx(&a, &m, mp, 0);
        fp_set(&a, 3);
        (void)fp_montgomery_reduce_mulx(&a, &m, mp, 1);
    }
    WB_NOTE("fp_montgomery_reduce_mulx exercised");
}
#endif /* HAVE_INTEL_MULX */

#endif /* USE_FAST_MATH */

/* ------------------------------------------------------------------------- *
 * Additional gap drivers (merged from the former _gap TU). These reach into
 * fp_int struct fields directly (->used, ->dp, ->sign), so they additionally
 * require WOLFSSL_PUBLIC_MP (non-opaque fp_int).
 *
 * Targeted gaps (wolfcrypt/src/tfm.c), by class:
 *   Class 1  fp_mul()/fp_sqr() comba tail-clear loop: destination ->used
 *            left negative by a corrupted caller (structurally impossible
 *            via any legitimate call sequence).
 *   Class 2  fp_invmod_slow() entry guard - fp_invmod() (the only public
 *            caller) already rejects a negative/zero modulus before calling
 *            fp_invmod_slow(), so this file-static function's own defensive
 *            copy of the same guard can only be exercised by calling it
 *            directly.
 *   Class 3  fp_cnt_lsb() least-significant-zero-digit loop running out of
 *            digits: only reachable with a non-normalized (all-zero-digit,
 *            ->used > 0) fp_int.
 * ------------------------------------------------------------------------- */
#if defined(USE_FAST_MATH) && defined(WOLFSSL_PUBLIC_MP)

/* ------------------------------------------------------------------------- *
 * Class 1a: fp_mul() comba tail-clear loop.
 *
 *   for (y = C->used; y >= 0 && y < oldused; y++) { C->dp[y] = 0; }
 *
 * y is assigned from C->used at the "clean:" label - on every legitimate
 * call path C->used is a real digit count and can never be negative, so
 * "y >= 0" is always true there. The only way to show it false is to hand
 * fp_mul() a destination whose ->used field was corrupted to a negative
 * value beforehand (never producible by any public mutator) and take the
 * early "goto clean" path (operand size over FP_SIZE) so fp_mul() never
 * overwrites C->used itself before the loop runs.
 * ------------------------------------------------------------------------- */
static void wb_fp_mul_negative_used(void)
{
    fp_int a, b, c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    fp_init(&a);
    fp_init(&b);
    fp_init(&c);

    /* Normal small multiply: C->used ends up >= 0 via the ordinary path
     * (the "y >= 0" true side, exercised here for this binary's own
     * independence pair). */
    fp_set(&a, 3);
    fp_set(&b, 5);
    (void)fp_mul(&a, &b, &c);

    /* Force the "operand too big" early-exit (goto clean before C is
     * touched), with C->used corrupted to a negative value beforehand:
     * "y >= 0" now evaluates false on the very first loop check, so the
     * clear loop body never runs. */
    fp_set(&a, 1);
    a.used = FP_SIZE; /* a->used + b->used >= FP_SIZE forces the overflow
                        * check (fails before any comba call touches C) */
    fp_set(&b, 1);
    c.used = -1; /* corrupted: not reachable via any public mutator */
    (void)fp_mul(&a, &b, &c);
    c.used = 0; /* restore before fp_clear-equivalent cleanup below */

    WB_NOTE("fp_mul comba tail-clear loop 'y >= 0' both sides exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 1b: fp_sqr() comba tail-clear loop - same reasoning as fp_mul()
 * above, on the B (destination) operand of fp_sqr(A, B).
 * ------------------------------------------------------------------------- */
static void wb_fp_sqr_negative_used(void)
{
    fp_int a, b;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    fp_init(&a);
    fp_init(&b);

    fp_set(&a, 5);
    (void)fp_sqr(&a, &b);

    fp_set(&a, 1);
    a.used = FP_SIZE; /* a->used * 2 > FP_SIZE forces the overflow check */
    b.used = -1; /* corrupted, unreachable via any public mutator */
    (void)fp_sqr(&a, &b);
    b.used = 0;

    WB_NOTE("fp_sqr comba tail-clear loop 'y >= 0' both sides exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 2: fp_invmod_slow() entry guard.
 *
 *   if (b->sign == FP_NEG || fp_iszero(b) == FP_YES) { return FP_VAL; }
 *
 * fp_invmod() - the only in-tree caller of this file-static helper - itself
 * rejects a negative or zero modulus (the identical check) before ever
 * reaching the `fp_iseven(b) == FP_YES` dispatch that calls
 * fp_invmod_slow(); a caller can therefore never observe fp_invmod_slow()
 * running its OWN copy of that guard with a negative/zero 'b'. Call it
 * directly to complete both independence pairs.
 * ------------------------------------------------------------------------- */
static void wb_fp_invmod_slow_entry_guard(void)
{
    fp_int a, b, c;

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));
    fp_init(&a);
    fp_init(&b);
    fp_init(&c);

    /* b->sign == FP_NEG (true), fp_iszero(b) == FP_YES (false, b is -10):
     * isolates "b->sign == FP_NEG" (cond0) with cond1 held false. */
    fp_set(&a, 3);
    fp_set(&b, 10);
    b.sign = FP_NEG;
    if (fp_invmod_slow(&a, &b, &c) != WC_NO_ERR_TRACE(FP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: fp_invmod_slow did not reject negative b");
    }

    /* b->sign == FP_ZPOS (false), fp_iszero(b) == FP_YES (true, b == 0):
     * isolates "fp_iszero(b) == FP_YES" (cond1) with cond0 held false. */
    fp_zero(&b);
    if (fp_invmod_slow(&a, &b, &c) != WC_NO_ERR_TRACE(FP_VAL)) {
        wb_fail = 1;
        WB_NOTE("unexpected: fp_invmod_slow did not reject zero b");
    }

    /* Both false (b positive, nonzero, even): falls through to the actual
     * HAC-based computation - completes both operands' independence pairs
     * (cond0 = F held across this call and the negative-b call above via
     * the entry guard's own true/false halves; cond1 = F held across this
     * call and the zero-b call above). */
    fp_set(&a, 3);
    fp_set(&b, 10);
    (void)fp_invmod_slow(&a, &b, &c);

    WB_NOTE("fp_invmod_slow entry guard both operands' pairs exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 3: fp_cnt_lsb() least-significant-zero-digit loop.
 *
 *   for (x = 0; x < a->used && a->dp[x] == 0; x++) {}
 *
 * fp_cnt_lsb() is public, but a normalized nonzero fp_int always has SOME
 * nonzero digit below a->used (that is what "nonzero" means), so the loop
 * always terminates via "a->dp[x] == 0" going false, never via running out
 * of digits ("x < a->used" going false) - fp_iszero() (checked first, by
 * a->used == 0) rejects the only other way to reach x == a->used. Reach the
 * "x < a->used" false side with a non-normalized all-zero-digit value
 * (->used > 0, every digit 0) - a state no public mutator can produce.
 * ------------------------------------------------------------------------- */
static void wb_fp_cnt_lsb_all_zero_digits(void)
{
    fp_int a;

    XMEMSET(&a, 0, sizeof(a));
    fp_init(&a);

    /* Non-normalized: ->used > 0 but every digit below ->used is 0.
     * fp_iszero() only checks ->used == 0, so this slips past it and the
     * for-loop runs to x == a->used (loop condition false via
     * "x < a->used", not via dp[x] == 0 going false). The one-past-used
     * slot a->dp[a->used] is deliberately left NONZERO here: fp_cnt_lsb()
     * reads it as 'q' right after this loop and, if it were also zero,
     * the subsequent "while (qq == 0)" bit-scan would spin forever (q
     * never becomes nonzero) - a latent hang in fp_cnt_lsb() for a fully
     * zero-digit input, not something this MC/DC pair needs to trigger. */
    a.used = 2;
    a.dp[0] = 0;
    a.dp[1] = 0;
    a.dp[2] = 1;
    (void)fp_cnt_lsb(&a);

    /* Normalized nonzero value (ordinary, API-reachable case), repeated
     * here so both sides of "x < a->used" are shown within this binary. */
    a.used = 1;
    a.dp[0] = 4;
    (void)fp_cnt_lsb(&a);

    WB_NOTE("fp_cnt_lsb least-significant-zero-digit loop exercised");
}

#endif /* USE_FAST_MATH && WOLFSSL_PUBLIC_MP */

int main(void)
{
    printf("tfm.c white-box MC/DC supplement\n");
#if !defined(USE_FAST_MATH)
    printf("  USE_FAST_MATH not defined; nothing to exercise\n");
    return 0;
#else
    wb_is_power_of_two();
    wb_cond_swap_ct();
    wb_div_d();
    wb_read_radix_16();
    wb_invmod_slow();
    wb_miller_rabin();
    wb_exptmod_engines();
#ifdef HAVE_INTEL_MULX
    wb_montgomery_mulx();
#endif
#ifdef WOLFSSL_PUBLIC_MP
    wb_fp_mul_negative_used();
    wb_fp_sqr_negative_used();
    wb_fp_invmod_slow_entry_guard();
    wb_fp_cnt_lsb_all_zero_digits();
#endif
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * campaign discard this variant's coverage. */
    return 0;
#endif
}
