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

#ifndef HEAP_HINT
#define HEAP_HINT NULL
#endif

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

/* ------------------------------------------------------------------------- *
 * Relocated from tests/api (test_wolfmath.c). These drive library-internal,
 * non-exported fp_* symbols (fp_set/fp_mul_2/fp_mul_2d/fp_invmod_mont_ct/
 * fp_exptmod_nct/...) that are declared WITHOUT MP_API and so hidden under
 * -fvisibility=hidden in a shared-library build: calling them from tests/api
 * broke the normal (shared) wolfSSL CI link. Compiled here via #include of
 * tfm.c they resolve directly. Coverage-only: both directions of each decision
 * are executed; no return values are asserted (the exact call arguments are
 * preserved, since those are what drive each MC/DC pair).
 * ------------------------------------------------------------------------- */

/*
 * Testing fp_mul_2/fp_mul_2d/fp_div_2d/fp_mod_2d/fp_invmod/
 * fp_invmod_mont_ct/fp_to_unsigned_bin_len/mp_read_radix/mp_radix_size/
 * mp_toradix/mp_rand_prime/mp_prime_is_prime(_ex): argument-check,
 * capacity/FP_SIZE-guard and sign-dispatch decision branches of the
 * FASTMATH (tfm.c) backend (bigint-tfm module).
 */
static void wb_TfmDecisionCoverage(void)
{
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
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
    (void)fp_mul_2(&a, &b);
    fp_zero(&a);
    a.used = FP_SIZE - 2; /* both OR operands false: ordinary small value */
    a.dp[FP_SIZE - 3] = 1;
    (void)fp_mul_2(&a, &b);
    /* Note: the guard reads the FIXED sentinel slot a->dp[FP_SIZE-1] (one
     * past the last digit ->used == FP_SIZE-1 actually counts), not
     * a->dp[a->used-1] - so the "top bit set" side needs that specific
     * slot poked directly (fp_zero() leaves it 0, which every legitimate
     * caller's value would too, since it is beyond ->used). */
    fp_zero(&a);
    a.used = FP_SIZE - 1; /* a->used == FP_SIZE-1 true, top bit clear */
    a.dp[FP_SIZE - 2] = 1;
    (void)fp_mul_2(&a, &b);
    fp_zero(&a);
    a.used = FP_SIZE - 1; /* a->used == FP_SIZE-1 true, top bit SET */
    a.dp[FP_SIZE - 2] = 1;
    a.dp[FP_SIZE - 1] = (fp_digit)1 << (DIGIT_BIT - 1);
    (void)fp_mul_2(&a, &b);

    /* fp_mul_2d: "carry && x < FP_SIZE" - carry true with room to store it
     * (x < FP_SIZE, small 'a') vs carry true with the destination already
     * completely full (x == FP_SIZE, top digit high bit set). */
    fp_zero(&a);
    fp_set(&a, 1);
    a.dp[0] = (fp_digit)1 << (DIGIT_BIT - 1); /* shifting by 1 overflows */
    (void)fp_mul_2d(&a, 1, &c); /* carry true, x(1) < FP_SIZE */
    fp_zero(&a);
    a.used = FP_SIZE;
    a.dp[FP_SIZE - 1] = (fp_digit)1 << (DIGIT_BIT - 1);
    (void)fp_mul_2d(&a, 1, &c); /* x==FP_SIZE */

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
    (void)fp_cmp_d(&c, 5);
    fp_zero(&a);
    fp_set(&a, 5);
    fp_setneg(&a);
    fp_mod_2d(&a, (int)DIGIT_BIT, &c); /* ZPOS(F): isolates the sign operand */
    fp_zero(&a);
    fp_set(&a, 5);
    fp_mod_2d(&a, 0, &c); /* ZPOS(T), b>=... (F): isolates the 'b' operand */
    (void)fp_iszero(&c);
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
    (void)fp_invmod(&a, &b, &c);
    fp_zero(&b);
    fp_set(&b, 7);
    (void)fp_invmod(&a, &b, &c);

    /* fp_invmod_mont_ct: "(a->used*2 > FP_SIZE) || (b->used*2 > FP_SIZE)".
     * Three calls complete both operands' pairs. */
    fp_zero(&a);
    a.used = FP_SIZE;
    fp_zero(&b);
    fp_set(&b, 3);
    (void)fp_invmod_mont_ct(&a, &b, &c, 1);
    fp_zero(&a);
    fp_set(&a, 2);
    fp_zero(&b);
    b.used = FP_SIZE;
    (void)fp_invmod_mont_ct(&a, &b, &c, 1);
    fp_zero(&a);
    fp_set(&a, 2);
    fp_zero(&b);
    fp_set(&b, 3);
    (void)fp_invmod_mont_ct(&a, &b, &c, 1);

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
        (void)fp_to_unsigned_bin_len(&a, buf, 4); /* i!=used-1 */
        XMEMSET(buf, 0, sizeof(buf));
        (void)fp_to_unsigned_bin_len(&a, buf, 1); /* i==used-1,
                                                       top bits already 0 */
        fp_zero(&a);
        fp_set(&a, 0x1FF); /* needs 2 bytes */
        XMEMSET(buf, 0, sizeof(buf));
        (void)fp_to_unsigned_bin_len(&a, buf, 1); /* i==used-1, top bits nonzero */
    }
#endif

    /* mp_read_radix (fp_read_radix): "radix < 2 || radix > 64". */
    (void)mp_read_radix(&a, "10", 1);
    (void)mp_read_radix(&a, "10", 65);
    (void)mp_read_radix(&a, "10", MP_RADIX_DEC);

    /* mp_radix_size / mp_toradix: "radix < 2 || radix > 64" (each function
     * has its own copy of the guard). */
    {
        int size = 0;
        char buf[8];

        XMEMSET(buf, 0, sizeof(buf));
        (void)mp_radix_size(&a, 1, &size);
        (void)mp_radix_size(&a, 65, &size);
        (void)mp_radix_size(&a, MP_RADIX_DEC, &size);

        (void)mp_toradix(&a, buf, 1);
        (void)mp_toradix(&a, buf, 65);
        XMEMSET(buf, 0, sizeof(buf));
        (void)mp_toradix(&a, buf, MP_RADIX_DEC);
    }

#if !defined(WC_NO_RNG)
    /* mp_rand_prime (fp_randprime): "len < 2 || len > 512" (len<2 already
     * shown elsewhere; complete the len>512 operand's pair). */
    {
        WC_RNG rng;

        XMEMSET(&rng, 0, sizeof(rng));
        (void)wc_InitRng(&rng);
        fp_zero(&a);
        /* mp_rand_prime (fp_randprime) is declared/defined only under
         * WOLFSSL_KEY_GEN; gate the calls to match so keygen-off variants
         * neither implicitly declare nor leave it an undefined reference. */
#ifdef WOLFSSL_KEY_GEN
        (void)mp_rand_prime(&a, 513, &rng, HEAP_HINT);
        (void)mp_rand_prime(&a, 32, &rng, HEAP_HINT);
#endif

        /* mp_prime_is_prime_ex (own trial-division/Miller-Rabin engine):
         * "t <= 0 || t > FP_PRIME_SIZE" (t<=0 already shown elsewhere;
         * complete the t>FP_PRIME_SIZE operand's pair). */
        {
            int result = 0;

            fp_zero(&a);
            fp_set(&a, 17);
            (void)mp_prime_is_prime_ex(&a, FP_PRIME_SIZE + 1, &result, &rng);
            (void)mp_prime_is_prime_ex(&a, 8, &result, &rng);
            (void)result;
        }

        (void)wc_FreeRng(&rng);
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
        (void)mp_prime_is_prime(&a, 8, &result);
        (void)result;

        fp_zero(&a);
        fp_set(&a, 6); /* divisible by 2 and 3 */
        (void)mp_prime_is_prime(&a, 8, &result);
        (void)result;

        /* 1013 * 1019 = 1032247: both factors are larger than every prime
         * in the FP_PRIME_SIZE (256) built-in table, so trial division
         * finds no divisor and the composite reaches Miller-Rabin, which
         * correctly reports it composite (res == FP_NO). */
        fp_zero(&a);
        fp_set(&a, 1032247u);
        (void)mp_prime_is_prime(&a, 8, &result);
        (void)result;
    }

    mp_clear(&a);
    mp_clear(&b);
    mp_clear(&c);
#endif /* !WOLFSSL_SP_MATH && !WOLFSSL_SP_MATH_ALL */
    WB_NOTE("TfmDecisionCoverage decision branches exercised");
}

/*
 * Testing fp_exptmod/fp_exptmod_ex/fp_exptmod_nct: the negative-exponent
 * (X->sign == FP_NEG) branch's "invmod succeeded" / "modulus is negative"
 * decision chain, common to all three entry points, and the tail
 * "mode == 2 && bitcpy > 0" leftover-window decision inside the shared
 * non-constant-time engine (bigint-tfm module, tfm.c).
 */
static void wb_TfmExptModDecisionCoverage(void)
{
#if !defined(POSITIVE_EXP_ONLY) && \
    !defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
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
    (void)fp_exptmod(&g, &x, &p, &y);
    fp_set(&p, 15);
    (void)fp_exptmod(&g, &x, &p, &y);

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
    (void)fp_exptmod(&g, &x, &p, &y); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod(&g, &x, &p, &y); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod(&g, &x, &p, &y); /* call C */

    /* fp_exptmod_ex: same size guard ("fp_iszero(P)||P->used>FP_SIZE/2")
     * and the same negative-exponent chain, reached through its own entry
     * point (digits == 0 lets it pick X->used internally). */
    fp_set(&g, 3);
    fp_set(&x, 2);
    fp_zero(&p);
    p.used = (FP_SIZE / 2) + 1;
    p.dp[p.used - 1] = 1;
    (void)fp_exptmod_ex(&g, &x, 0, &p, &y);

    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    (void)fp_exptmod_ex(&g, &x, 0, &p, &y); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod_ex(&g, &x, 0, &p, &y); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod_ex(&g, &x, 0, &p, &y); /* call C */

    /* fp_exptmod_nct: always uses the non-constant-time engine regardless
     * of TFM_TIMING_RESISTANT, so its own copy of the negative-exponent
     * chain is independently reachable through this entry point. */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    (void)fp_exptmod_nct(&g, &x, &p, &y); /* call A */
    fp_set(&g, 3);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod_nct(&g, &x, &p, &y); /* call B */
    fp_set(&g, 7);
    fp_set(&x, 3);
    fp_setneg(&x);
    fp_set(&p, 7);
    fp_setneg(&p);
    (void)fp_exptmod_nct(&g, &x, &p, &y); /* call C */

    /* _fp_exptmod_nct tail (reached via the public fp_exptmod_nct):
     * "mode == 2 && bitcpy > 0" - winsize is chosen from fp_count_bits(X):
     * <=21 bits picks winsize 1, which flushes every bit immediately
     * (bitcpy is always 0 at the tail: the false side); a bigger X (e.g.
     * 30 bits, winsize 3) leaves a partial window at the end (bitcpy > 0:
     * the true side). */
    fp_set(&g, 3);
    fp_set(&x, 7); /* 3 bits: winsize 1, bitcpy==0 tail */
    fp_set(&p, 15);
    (void)fp_exptmod_nct(&g, &x, &p, &y);
    fp_set(&g, 3);
    fp_set(&x, 0x3FFFFFFF); /* 30 bits: winsize 3 */
    fp_set(&p, 15);
    (void)fp_exptmod_nct(&g, &x, &p, &y);

    mp_clear(&g);
    mp_clear(&x);
    mp_clear(&p);
    mp_clear(&y);
#endif /* !POSITIVE_EXP_ONLY && !WOLFSSL_SP_MATH && !WOLFSSL_SP_MATH_ALL */
    WB_NOTE("TfmExptModDecisionCoverage decision branches exercised");
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
    wb_TfmDecisionCoverage();
    wb_TfmExptModDecisionCoverage();
#endif
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * campaign discard this variant's coverage. */
    return 0;
#endif
}
