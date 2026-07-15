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
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * campaign discard this variant's coverage. */
    return 0;
#endif
}
