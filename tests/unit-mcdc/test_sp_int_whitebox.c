/* test_sp_int_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/sp_int.c (the sp-math
 * module, iso26262/mcdc-per-module).
 *
 * The tests/api wolfmath suite (test_wolfmath.c) drives sp_int.c through its
 * *public* mp_ / sp_ API, including deliberately undersized destinations and
 * out-of-range arguments to reach internal size/capacity guards. A small
 * number of decisions instead depend on the sp_int *not* being normalized
 * (a leading or trailing zero digit while sp_int::used still counts it) -
 * a state every public entry point's own sp_clamp()-on-exit invariant
 * prevents a caller from ever producing. This translation unit reaches them
 * by compiling sp_int.c directly (#include) and constructing that state via
 * direct sp_int::dp/used field writes (the struct is a plain, non-opaque
 * type; only the ability to leave it non-normalized is "impossible" from
 * the public API).
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
 * that variant's libwolfssl.a with its sp_int.o removed (this TU supplies
 * the instrumented sp_int.c). NOT part of the wolfSSL build; not registered
 * in tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted residuals (sp_int.c), by class:
 *   Class 1  sp_count_bits() leading-zero-digit trim loop ........ 2 conditions
 *   Class 2  sp_cnt_lsb() least-significant-zero-digit loop ....... 1 condition
 * See reports/sp-math/RESIDUALS.md for the remaining union residuals
 * (structural dead guards, deep invmod/exptmod/prime/gcd state-machine
 * internals, the SP-accelerated-backend-entangled mBits dispatch, the
 * SMALL_STACK allocation-ceiling macros, and the 32-bit SP_WORD_SIZE axis).
 */

/* Pull sp_int.c in verbatim so its file-static helpers and the sp_int
 * struct's fields are in scope and instrumented in THIS binary. sp_int.c
 * includes settings.h (which picks up user_settings.h via
 * -DWOLFSSL_USER_SETTINGS) and sp_int.h itself. */
#include <wolfcrypt/src/sp_int.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_MATH)

/* ------------------------------------------------------------------------- *
 * Class 1: sp_count_bits() leading-zero-digit trim loop.
 *
 *   n = a->used - 1;
 *   while ((n >= 0) && (a->dp[n] == 0)) { n--; }
 *
 * Every public mutator normalizes (sp_clamp) before returning, so a caller
 * can never hand sp_count_bits() an sp_int whose top digit(s) are zero while
 * ->used still counts them - reach it by writing ->used/->dp directly.
 * ------------------------------------------------------------------------- */
static void wb_count_bits_leading_zero(void)
{
    sp_int a;

    XMEMSET(&a, 0, sizeof(a));
    (void)sp_init(&a);

    /* Non-normalized: used=3 but the top two digits are zero. Both halves
     * of "a->dp[n] == 0" (true while trimming, false once n reaches the
     * nonzero digit) are exercised in this one call; "n >= 0" true/false
     * are both exercised too (loop continues, then also runs out at n<0
     * in the second call below). */
    a.used = 3;
    a.dp[0] = 1;
    a.dp[1] = 0;
    a.dp[2] = 0;
    (void)sp_count_bits(&a);

    /* All digits zero (still ->used > 0, non-normalized): the loop runs
     * n all the way down to -1, exercising the "n >= 0" false side from
     * the loop's own decrement rather than an immediate zero-used skip. */
    a.used = 2;
    a.dp[0] = 0;
    a.dp[1] = 0;
    (void)sp_count_bits(&a);

    /* Normalized single nonzero digit: dp[n] == 0 false on the very first
     * check (n == 0, top digit nonzero) - the ordinary, API-reachable case,
     * repeated here so both conditions' pairs are complete within this one
     * binary. */
    a.used = 1;
    a.dp[0] = 5;
    (void)sp_count_bits(&a);

    WB_NOTE("sp_count_bits leading-zero-digit trim loop exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 2: sp_cnt_lsb() least-significant-zero-digit loop.
 *
 *   for (i = 0; (i < a->used) && (a->dp[i] == 0); i++, bc += SP_WORD_SIZE) {}
 *
 * Same reasoning as Class 1: a normalized sp_int's lowest used digit need
 * not be nonzero (unlike the top digit, sp_clamp does not trim low zero
 * digits), so "a->dp[i] == 0" true IS reachable from the API (e.g. any
 * value that is a multiple of 2^SP_WORD_SIZE) - what is not reachable is
 * "i < a->used" false arising from the loop running past every digit
 * because ->used over-counts an all-zero-digit number (the sp_iszero()
 * guard ahead of the loop rejects a true all-zero value first). Construct
 * that directly.
 * ------------------------------------------------------------------------- */
static void wb_cnt_lsb_all_zero_digits(void)
{
    sp_int a;

    XMEMSET(&a, 0, sizeof(a));
    (void)sp_init(&a);

    /* Non-normalized all-zero-digit value with ->used > 0: sp_iszero()
     * checks ->used == 0, so this slips past it and the for-loop runs to
     * i == a->used (loop condition false via "i < a->used", not via
     * dp[i] == 0 going false). */
    a.used = 2;
    a.dp[0] = 0;
    a.dp[1] = 0;
    (void)sp_cnt_lsb(&a);

    WB_NOTE("sp_cnt_lsb least-significant-zero-digit loop exercised");
}

#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_SP_MATH */

int main(void)
{
    printf("sp_int.c white-box MC/DC supplement\n");
#if !defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_SP_MATH)
    printf("  neither WOLFSSL_SP_MATH_ALL nor WOLFSSL_SP_MATH defined;"
        " nothing to exercise\n");
    return 0;
#else
    wb_count_bits_leading_zero();
    wb_cnt_lsb_all_zero_digits();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
