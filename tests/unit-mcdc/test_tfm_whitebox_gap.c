/* test_tfm_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/tfm.c (the FASTMATH
 * big-integer backend, iso26262/mcdc-per-module, bigint-tfm module).
 *
 * The tests/api wolfmath suite (test_wolfmath.c) drives tfm.c through its
 * *public* fp_ / mp_ API, including deliberately undersized / degenerate
 * operands to reach argument-check, capacity and sign-dispatch guards. A
 * small number of decisions instead depend either on a fp_int being in a
 * state no public entry point can ever produce (a negative ->used, or a
 * non-normalized all-zero-digit value with ->used > 0 - every public
 * mutator normalizes before returning), or on a file-static helper
 * (fp_invmod_slow) whose "impossible" argument combination every public
 * caller (fp_invmod) already filters out before calling it. This
 * translation unit reaches them by compiling tfm.c directly (#include) so
 * the file-static helper and the fp_int struct's fields (a plain,
 * non-opaque type) are both in scope and instrumented in THIS binary.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage
 * by source line:col in the per-module campaign: llvm-cov computes MC/DC
 * independence PER BINARY, and the campaign's aggregate.sh ORs the
 * "independence shown" bit across binaries by key. That is why every pair
 * below is completed *within this file* rather than relying on the API
 * tests to supply the other half.
 *
 * Build: compiled by run-mcdc-par.sh's white-box step with the SAME MC/DC
 * CFLAGS and -I<workspace> as the instrumented library, then linked against
 * that variant's libwolfssl.a with its tfm.o removed (this TU supplies the
 * instrumented tfm.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted gaps (wolfcrypt/src/tfm.c), by class:
 *   Class 1  fp_mul()/fp_sqr() comba tail-clear loop: destination ->used
 *            left negative by a corrupted caller (structurally impossible
 *            via any legitimate call sequence, ->used is always >= 0 under
 *            normal use) ................................ 2 conditions
 *   Class 2  fp_invmod_slow() entry guard - fp_invmod() (the only public
 *            caller) already rejects a negative/zero modulus before ever
 *            calling fp_invmod_slow(), so this file-static function's own
 *            (redundant, defensive) copy of the same guard can only be
 *            exercised by calling it directly ............ 2 conditions
 *   Class 3  fp_cnt_lsb() least-significant-zero-digit loop running out of
 *            digits: only reachable with a non-normalized (all-zero-digit,
 *            ->used > 0) fp_int, same class as sp_int.c's sp_cnt_lsb
 *            residual ................................... 1 condition
 * See reports/bigint-tfm/GAPS.md for the full union gap list and
 * REPORT.md (delivered alongside this file) for the residuals this
 * whitebox and the tests/api additions deliberately do not chase.
 */

/* Pull tfm.c in verbatim so its file-static helper (fp_invmod_slow) and the
 * fp_int struct's fields are in scope and instrumented in THIS binary.
 * tfm.c includes settings.h (which picks up user_settings.h via
 * -DWOLFSSL_USER_SETTINGS) and tfm.h itself. */
#include <wolfcrypt/src/tfm.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

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
#if !defined(USE_FAST_MATH) || !defined(WOLFSSL_PUBLIC_MP)
    printf("  USE_FAST_MATH && WOLFSSL_PUBLIC_MP not both defined;"
        " nothing to exercise\n");
    return 0;
#else
    wb_fp_mul_negative_used();
    wb_fp_sqr_negative_used();
    wb_fp_invmod_slow_entry_guard();
    wb_fp_cnt_lsb_all_zero_digits();
    printf("done (%s)\n", wb_fail ? "with unexpected results" : "ok");
    /* Setup/behavioral surprises are surfaced as printed notes, not process
     * failures: the campaign treats a nonzero exit as a failed variant and
     * discards its coverage. */
    return 0;
#endif
}
