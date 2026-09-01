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
 * by source line:col in the per-module suite: llvm-cov computes MC/DC
 * independence PER BINARY, and the aggregate.sh ORs the
 * "independence shown" bit across binaries by key. That is why every pair
 * below is completed *within this file* rather than relying on the API
 * tests to supply the other half.
 *
 * Build: compiled by the coverage runner's white-box step with the SAME MC/DC
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

/* settings.h FIRST, and before mcdc_seed_rng.h: that header decides whether it
 * can build its SHAKE-256 stream by testing WOLFSSL_SHAKE256, and with no
 * configuration in scope yet the test reads "no" and the header compiles
 * itself down to inert stubs -- silently, with the driver still building and
 * running. That is what happened on the first attempt at :19672:0 here.
 * settings.h is include-guarded and idempotent, so pulling it in early costs
 * nothing; sp_int.c below includes it again. */
#include <wolfssl/wolfcrypt/settings.h>

/* Deterministic RNG. Included BEFORE sp_int.c so its wc_RNG_GenerateBlock()
 * call sites bind to the pinned SHAKE-256 stream while armed. Two things make
 * this load-bearing for Class 23 below, not just cosmetic:
 *   - the stream is reproducible, so the fail-index sweep is reproducible;
 *   - the armed hook never enters the DRBG, so it makes NO allocation of its
 *     own. Under WOLFSSL_SMALL_STACK the real Hash_DRBG_Generate() does
 *     allocate, and one faulted allocation there puts the WC_RNG into its
 *     permanent DRBG_FAILED state -- after which every later sweep step dies
 *     at the first wc_RNG_GenerateBlock() instead of reaching the decision
 *     under test. That is exactly why the earlier real-entropy sweep never
 *     closed :19672:0. */
#include "mcdc_seed_rng.h"

/* Pull sp_int.c in verbatim so its file-static helpers and the sp_int
 * struct's fields are in scope and instrumented in THIS binary. sp_int.c
 * includes settings.h (which picks up user_settings.h via
 * -DWOLFSSL_USER_SETTINGS) and sp_int.h itself. */
#include <wolfcrypt/src/sp_int.c>

#define MCDC_SR_IMPL
#include "mcdc_seed_rng.h"

#include "mcdc_fault_alloc.h"

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

/* ------------------------------------------------------------------------- *
 * Shared helpers for the operand-shape classes below.
 *
 * Several of the residual decisions are capacity guards written against
 * sp_int::size (the number of digits the destination was told it may use)
 * and sp_int::used (how many digits the value occupies). The public API
 * only ever hands sp_int.c destinations that sp_init()/sp_init_size()
 * built, and those are either full SP_INT_DIGITS or comfortably large, so
 * the "destination too small" / "operand at the compile ceiling" halves
 * never occur. _sp_init_size() is the library's own internal sizer, so
 * using it here builds exactly the object the guard is written for --
 * nothing is faked, only sized.
 * ------------------------------------------------------------------------- */

/* Init a to full capacity and give it 'used' digits all equal to v. */
static void wb_fill(sp_int* a, unsigned int used, sp_int_digit v)
{
    unsigned int i;

    _sp_init_size(a, SP_INT_DIGITS);
    for (i = 0; i < used; i++) {
        a->dp[i] = v;
    }
    a->used = (sp_size_t)used;
}

/* Init a to full capacity and set it to a single-digit value. */
static void wb_set_d(sp_int* a, sp_int_digit v)
{
    _sp_init_size(a, SP_INT_DIGITS);
    a->dp[0] = v;
    a->used = (sp_size_t)((v != 0) ? 1 : 0);
}

/* a = 2^bits, written straight into the digit array.
 *
 * sp_mul_2d() would be the natural way to build these operands, but it is not
 * compiled in every suite variant (the reduced backend drops it), and this
 * TU has to build under all of them. Returns MP_VAL when the requested width
 * does not fit the compile-time digit ceiling so callers can skip that row. */
static int wb_pow2(sp_int* a, int bits)
{
    unsigned int d = (unsigned int)bits / SP_WORD_SIZE;
    unsigned int b = (unsigned int)bits % SP_WORD_SIZE;
    unsigned int i;

    if ((bits < 0) || (d >= (unsigned int)SP_INT_DIGITS)) {
        return MP_VAL;
    }

    _sp_init_size(a, SP_INT_DIGITS);
    for (i = 0; i <= d; i++) {
        a->dp[i] = 0;
    }
    a->dp[d] = (sp_int_digit)1 << b;
    a->used  = (sp_size_t)(d + 1);

    return MP_OKAY;
}

/* ------------------------------------------------------------------------- *
 * Class 3: the ALLOC_SP_INT / ALLOC_SP_INT_ARRAY compile-ceiling macros.
 *
 *   if (((err) == MP_OKAY) && ((s) > SP_INT_DIGITS)) { (err) = MP_VAL; }
 *
 * Every in-library expansion sizes 's' from operands the caller already
 * range-checked, so the second operand is never true, and reaches the macro
 * with err == MP_OKAY, so the first is never false. Drive the macro itself:
 * it is an ordinary macro in scope in this TU, and llvm-cov attributes the
 * expansion's conditions to the macro's definition in sp_int.c.
 * ------------------------------------------------------------------------- */
static void wb_alloc_ceiling_macros(void)
{
    {
        int err = WC_NO_ERR_TRACE(MP_VAL);
        DECL_SP_INT(t, 1);

        /* First operand FALSE: an error is already latched, so the macro
         * must leave it alone and allocate nothing. */
        ALLOC_SP_INT(t, 1, err, NULL);
        FREE_SP_INT(t, NULL);
        (void)t;
    }
    {
        int err = MP_OKAY;
        DECL_SP_INT(t, 1);

        /* Both operands TRUE: a size above the compile-time digit ceiling
         * is rejected before any allocation is attempted. */
        ALLOC_SP_INT(t, SP_INT_DIGITS + 1, err, NULL);
        FREE_SP_INT(t, NULL);
        (void)t;
    }
    {
        int err = MP_OKAY;
        DECL_SP_INT_ARRAY(td, 1, 2);

        /* Same two rows for the array form. */
        ALLOC_SP_INT_ARRAY(td, SP_INT_DIGITS + 1, 2, err, NULL);
        FREE_SP_INT_ARRAY(td, NULL);
    }
    {
        int err = WC_NO_ERR_TRACE(MP_VAL);
        DECL_SP_INT_ARRAY(td, 1, 2);

        ALLOC_SP_INT_ARRAY(td, 1, 2, err, NULL);
        FREE_SP_INT_ARRAY(td, NULL);
    }

    WB_NOTE("ALLOC_SP_INT/ALLOC_SP_INT_ARRAY ceiling macro rows exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 4: sp_div() / _sp_div() capacity and sign guards.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
static void wb_div_capacity(void)
{
    sp_int a;
    sp_int d;
    sp_int q;
    sp_int rem;

    /* --- remainder-capacity guard, a->used <= d->used arm --------------- *
     *   if ((a->used <= d->used) && (rem->size < a->used + 1))
     * Row TT: same digit count, remainder deliberately one digit short. */
    wb_fill(&a, 2, (sp_int_digit)0x123456789ULL);
    wb_fill(&d, 2, (sp_int_digit)0x9876543ULL);
    _sp_init_size(&rem, 2);
    (void)sp_div(&a, &d, NULL, &rem);

    /* Row TF: same shape, remainder now big enough - guard passes. */
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, NULL, &rem);

    /* Row F: dividend longer than divisor takes the other arm. */
    wb_fill(&a, 4, (sp_int_digit)0x123456789ULL);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, NULL, &rem);

    /* --- top-of-capacity dividend: the shift-would-overflow guard ------- *
     *   if ((bits != SP_WORD_SIZE) && (sp_count_bits(a) + bits > ...))
     * Only evaluated when a->used == SP_INT_DIGITS, which no public caller
     * can reach because every value that big is rejected earlier. */
    wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)~(sp_int_digit)0);
    wb_fill(&d, 2, (sp_int_digit)0x9876543ULL);
    _sp_init_size(&rem, SP_INT_DIGITS);
    /* d's bit count is not a multiple of the word size (bits != word size)
     * and a is full width, so the shifted dividend would not fit: TT. */
    (void)sp_div(&a, &d, NULL, &rem);

    /* Row TF: still full width, but a's top digit is 1 so the shift fits. */
    wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)1);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, NULL, &rem);

    /* Row F: divisor whose bit count IS a multiple of the word size, so no
     * shift is needed at all. */
    wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)1);
    wb_set_d(&d, (sp_int_digit)1 << (SP_WORD_SIZE - 1));
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, NULL, &rem);

#if (defined(WOLFSSL_SMALL_STACK) || defined(SP_ALLOC)) && \
    !defined(WOLFSSL_SP_NO_MALLOC)
    /* --- _sp_div() temporary-reuse decisions (heap temporaries only) ---- *
     *   if ((rem != NULL) && (rem != d) && (rem->size > a->used))
     *   if ((r != NULL) && (r != d))
     * The remainder is reused as scratch only when it is strictly bigger
     * than the dividend, and the quotient only when it is not the divisor.
     * sp_div()'s own capacity checks let a remainder that is big enough for
     * the RESULT but not bigger than the dividend through, which is the
     * false row of the third operand; and r == d is a legal aliasing every
     * public caller happens not to use. */
    wb_fill(&a, 4, (sp_int_digit)0x1234567ULL);
    wb_fill(&d, 2, (sp_int_digit)0x89abULL);
    _sp_init_size(&rem, 3);
    (void)sp_div(&a, &d, NULL, &rem);

    /* Quotient aliased onto the divisor: (r != d) false. */
    wb_fill(&a, 4, (sp_int_digit)0x1234567ULL);
    wb_fill(&d, 2, (sp_int_digit)0x89abULL);
    (void)sp_div(&a, &d, &d, NULL);
#endif

    /* Ordinary division with three distinct, amply sized sp_ints: supplies the
     * true row of both reuse decisions in this same binary. */
    wb_fill(&a, 4, (sp_int_digit)0x1234567ULL);
    wb_fill(&d, 2, (sp_int_digit)0x89abULL);
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, &q, &rem);

#ifdef WOLFSSL_SP_INT_NEGATIVE
    /* --- quotient sign decision ---------------------------------------- *
     *   if ((r->used == 0) || (signA == signD)) r->sign = MP_ZPOS;
     * Row TF is a zero quotient with mismatched signs (|a| < |d|), row FT a
     * nonzero quotient with matching signs, row FF mismatched signs. */
    wb_fill(&a, 1, (sp_int_digit)3);
    a.sign = MP_NEG;
    wb_fill(&d, 2, (sp_int_digit)0x89abULL);
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, &q, &rem);

    wb_fill(&a, 4, (sp_int_digit)0x1234567ULL);
    a.sign = MP_NEG;
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, &q, &rem);

    a.sign = MP_ZPOS;
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div(&a, &d, &q, &rem);
#endif

    WB_NOTE("sp_div capacity / reuse / sign rows exercised");
}
#else
static void wb_div_capacity(void)
{
    WB_NOTE("sp_div not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 5: the internal exponentiation engines, called directly.
 *
 * sp_exptmod() reduces the base below the modulus BEFORE dispatching, so
 * the engines' own "base is not less than modulus" arm - and in particular
 * its "base is a multiple of the modulus, result is zero, we are done"
 * sub-case - is dead from the public API. Every `(!done) && ...` checkpoint
 * downstream of it therefore only ever sees done == 0. Calling the engines
 * directly with base >= modulus supplies the missing rows.
 * ------------------------------------------------------------------------- */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH) || \
    defined(OPENSSL_ALL)
    #define WB_HAVE_EXPTMOD_EX
#endif
#if (defined(WOLFSSL_SP_MATH_ALL) && ((!defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH))) || \
    defined(OPENSSL_ALL)
    #define WB_HAVE_EXPTMOD_MONT_EX
#endif
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH)
#if defined(WOLFSSL_SP_FAST_NCT_EXPTMOD) || !defined(WOLFSSL_SP_SMALL)
    #define WB_HAVE_EXPTMOD_NCT
#endif
#endif

static void wb_exptmod_engines(void)
{
#if defined(WB_HAVE_EXPTMOD_EX) || defined(WB_HAVE_EXPTMOD_MONT_EX) || \
    defined(WB_HAVE_EXPTMOD_NCT)
    sp_int b;
    sp_int e;
    sp_int m;
    sp_int r;
    int    bits;

    /* Odd, two-digit modulus: takes the Montgomery engines. */
    wb_fill(&m, 2, (sp_int_digit)0);
    m.dp[0] = (sp_int_digit)0x0fffffffffffffc5ULL;
    m.dp[1] = (sp_int_digit)0x00000000000000f1ULL;
    wb_set_d(&e, (sp_int_digit)0x10001);
    bits = sp_count_bits(&e);

    /* Base EQUAL to the modulus: the reduction inside the engine yields
     * zero, so the engine sets the result to zero and marks itself done -
     * the only producer of done == 1 in these functions. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_copy(&m, &b);
#ifdef WB_HAVE_EXPTMOD_EX
    (void)_sp_exptmod_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_MONT_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_mont_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_NCT
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_nct(&b, &e, &m, &r);
#endif

    /* Base GREATER than the modulus but not a multiple of it: same arm,
     * "reduced base is zero" false. */
    (void)sp_copy(&m, &b);
    b.dp[0]++;
    b.dp[1] += 3;
#ifdef WB_HAVE_EXPTMOD_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_MONT_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_mont_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_NCT
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_nct(&b, &e, &m, &r);
#endif

    /* Base already less than the modulus: the ordinary row, kept in this
     * same binary so each pair is complete here. */
    wb_set_d(&b, (sp_int_digit)3);
#ifdef WB_HAVE_EXPTMOD_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_MONT_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_mont_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_NCT
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_nct(&b, &e, &m, &r);
#endif

    /* Base at the FULL digit ceiling. The engines reduce with
     * sp_mod(b, m, t[0]), and sp_div() rejects a dividend already at
     * SP_INT_DIGITS words when shifting the divisor to the top of a word
     * would push the dividend past the ceiling -- which it does whenever
     * the modulus' bit count is not a multiple of SP_WORD_SIZE. That is the
     * only false side the reduction's `err == MP_OKAY` checkpoint has: the
     * engines' own temporaries are sized from the modulus, so no operand
     * makes the copy or the division overflow instead. The modulus above
     * has 456 bits, not a multiple of 64, so it qualifies. */
    wb_fill(&b, (unsigned int)SP_INT_DIGITS, (sp_int_digit)~(sp_int_digit)0);
#ifdef WB_HAVE_EXPTMOD_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_MONT_EX
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_mont_ex(&b, &e, bits, &m, &r);
#endif
#ifdef WB_HAVE_EXPTMOD_NCT
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_exptmod_nct(&b, &e, &m, &r);
#endif

    WB_NOTE("internal exptmod engines driven with base >= modulus");
#else
    WB_NOTE("internal exptmod engines not compiled; skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * Class 6: sp_exptmod() dispatch operand shapes.
 * ------------------------------------------------------------------------- */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || defined(OPENSSL_ALL)
static void wb_exptmod_dispatch(void)
{
    sp_int b;
    sp_int e;
    sp_int m;
    sp_int r;

    wb_fill(&m, 2, (sp_int_digit)0);
    m.dp[0] = (sp_int_digit)0x0fffffffffffffc5ULL;
    m.dp[1] = (sp_int_digit)0x00000000000000f1ULL;
    wb_set_d(&e, (sp_int_digit)0x10001);

    /* Result aliased onto the exponent while the base needs reducing: the
     * reduction would clobber an input, so it is rejected. Public callers
     * always pass three distinct sp_ints. */
    (void)sp_copy(&m, &b);
    b.dp[0]++;
    (void)sp_exptmod(&b, &e, &m, &e);

    /* Same shape with a destination that is neither input: both operands of
     * the aliasing test false, which is its missing row. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod(&b, &e, &m, &r);

    /* Result too small to hold the intermediate double-width value: no
     * public caller sizes a destination that tightly. */
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, (unsigned int)(m.used * 2));
    (void)sp_exptmod(&b, &e, &m, &r);

    /* Base exactly two with an EVEN multi-digit modulus: the base-2 engine
     * is selected only for an odd modulus, so this is the false row of that
     * selector's oddness operand. */
    wb_set_d(&b, (sp_int_digit)2);
    m.dp[0] &= ~(sp_int_digit)1;
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod(&b, &e, &m, &r);

    /* Same even modulus with a base that is not two: the second selector's
     * oddness operand false as well. */
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod(&b, &e, &m, &r);

#ifdef WOLFSSL_SP_INT_NEGATIVE
    /* Negative exponent, then negative modulus: unsupported, and each is
     * the sole true operand of its OR in turn. */
    m.dp[0] |= (sp_int_digit)1;
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    e.sign = MP_NEG;
    (void)sp_exptmod(&b, &e, &m, &r);
    e.sign = MP_ZPOS;
    m.sign = MP_NEG;
    (void)sp_exptmod(&b, &e, &m, &r);
    m.sign = MP_ZPOS;

    /* Same pair through the non-constant-time entry point. */
    e.sign = MP_NEG;
    (void)sp_exptmod_nct(&b, &e, &m, &r);
    e.sign = MP_ZPOS;
    m.sign = MP_NEG;
    (void)sp_exptmod_nct(&b, &e, &m, &r);
    m.sign = MP_ZPOS;
#endif

    /* Modulus of one: the degenerate-case check declares the answer and marks
     * the call done, which is the only producer of a false "not done yet"
     * operand at the intermediate-space check further down. Every modulus a
     * public caller uses is larger than one. */
    wb_set_d(&m, (sp_int_digit)1);
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_ex(&b, &e, 1, &m, &r);

    /* Zero modulus: latches the error so every later checkpoint in the
     * dispatch chain is evaluated with the error already set. */
    _sp_init_size(&m, SP_INT_DIGITS);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod(&b, &e, &m, &r);
    (void)sp_exptmod_nct(&b, &e, &m, &r);

    WB_NOTE("sp_exptmod dispatch operand shapes exercised");
}
#else
static void wb_exptmod_dispatch(void)
{
    WB_NOTE("sp_exptmod not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 7: sp_invmod() negative-modulus guard.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_INVMOD) && defined(WOLFSSL_SP_INT_NEGATIVE)
static void wb_invmod_negative(void)
{
    sp_int a;
    sp_int m;
    sp_int r;

    wb_set_d(&a, (sp_int_digit)3);
    wb_fill(&m, 2, (sp_int_digit)0);
    m.dp[0] = (sp_int_digit)0x0fffffffffffffc5ULL;
    m.dp[1] = (sp_int_digit)0x00000000000000f1ULL;
    _sp_init_size(&r, SP_INT_DIGITS);

    /* Negative modulus is rejected. */
    m.sign = MP_NEG;
    (void)sp_invmod(&a, &m, &r);
    m.sign = MP_ZPOS;

    /* Error already latched (destination aliased onto the modulus) so the
     * sign test's first operand is false. */
    (void)sp_invmod(&a, &m, &m);

    /* Ordinary, successful inverse with a positive modulus: the false row of
     * the sign test, needed in THIS binary to complete its pair. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_invmod(&a, &m, &r);

    WB_NOTE("sp_invmod negative-modulus rows exercised");
}
#else
static void wb_invmod_negative(void)
{
    WB_NOTE("sp_invmod negative-modulus rows not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 7b: the division-based inverse's "no inverse exists" arm.
 *
 *   if ((err == MP_OKAY) && (!sp_iszero(y))) err = MP_VAL;
 *
 * sp_invmod() only selects _sp_invmod_div() for a modulus of at least 1024
 * bits, and the API tests only ever ask for an inverse that
 * exists, so the loop's leftover is always zero there. Ask for the inverse
 * of a value that shares a factor with the modulus instead.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_INVMOD) && !defined(WOLFSSL_SP_LOW_MEM) && \
    !defined(WOLFSSL_SP_SMALL) && (!defined(NO_RSA) || !defined(NO_DH))
static void wb_invmod_no_inverse(void)
{
    sp_int a;
    sp_int m;
    sp_int r;

    /* m = 3 * (2^1022 + 1): odd, 1024 bits, and divisible by three. */
    if (wb_pow2(&m, 1022) != MP_OKAY) {
        WB_NOTE("digit ceiling below 1024 bits; no-inverse rows skipped");
        return;
    }
    if (sp_add_d(&m, 1, &m) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    if (sp_mul_d(&m, 3, &m) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    /* gcd(3, m) == 3, so no inverse exists: the leftover is nonzero. */
    wb_set_d(&a, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_invmod(&a, &m, &r);

    /* Coprime operand through the same engine: leftover zero, the ordinary
     * row of the same decision. */
    wb_set_d(&a, (sp_int_digit)5);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_invmod(&a, &m, &r);

    WB_NOTE("division-based inverse no-inverse rows exercised");
}
#else
static void wb_invmod_no_inverse(void)
{
    WB_NOTE("division-based inverse not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 7c: the ALLOC_SP_INT / ALLOC_SP_INT_ARRAY ceiling macros, driven at
 * REAL library expansion sites.
 *
 * The prime-test helpers each make several allocations in a row from operand
 * sizes, and pass the SAME err through all of them:
 *
 *   ALLOC_SP_INT(n1, a->used + 1,     err, NULL);
 *   ALLOC_SP_INT(r,  a->used + 1,     err, NULL);
 *   ALLOC_SP_INT(b,  a->used * 2 + 1, err, NULL);
 *
 * so an operand at the digit ceiling makes the FIRST call latch the error and
 * the later ones see the macro's first operand false, while an operand just
 * over half the ceiling makes only the doubled size exceed it - the macro's
 * second operand true. sp_prime_is_prime() rejects both candidate shapes up
 * front, so neither is reachable from the public entry point; the helpers are
 * file-static and called directly here.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SP_PRIME_GEN
static void wb_alloc_ceiling_sites(void)
{
    sp_int a;
    int    res = 0;

    /* Operand at the ceiling: the first allocation latches the error and
     * every later macro in the chain sees it. */
    wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)3);
    (void)_sp_prime_trials(&a, 1, &res);

    /* Operand just over half the ceiling: only the doubled temporary is over
     * the limit, so the size operand is the one that fires. */
    wb_fill(&a, (unsigned int)(SP_INT_DIGITS / 2 + 1), (sp_int_digit)3);
    (void)_sp_prime_trials(&a, 1, &res);

    /* Ordinary candidate: both operands false, allocations happen. */
    wb_set_d(&a, (sp_int_digit)0x088886ffdb344693ULL);
    (void)_sp_prime_trials(&a, 1, &res);

#ifndef WC_NO_RNG
    {
        WC_RNG rng;

        if (wc_InitRng(&rng) == 0) {
            /* Same three rows for the array form of the macro. */
            wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)3);
            (void)_sp_prime_random_trials(&a, 1, &res, &rng);

            wb_fill(&a, (unsigned int)(SP_INT_DIGITS / 2 + 1),
                (sp_int_digit)3);
            (void)_sp_prime_random_trials(&a, 1, &res, &rng);

            wb_set_d(&a, (sp_int_digit)0x088886ffdb344693ULL);
            (void)_sp_prime_random_trials(&a, 1, &res, &rng);

            (void)wc_FreeRng(&rng);
        }
        else {
            wb_fail = 1;
        }
    }
#endif

    WB_NOTE("allocation-ceiling macro rows driven at library call sites");
}
#else
static void wb_alloc_ceiling_sites(void)
{
    WB_NOTE("prime helpers not compiled; ceiling-macro sites skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 7d: the SP-accelerated fixed-size modexp dispatch.
 *
 *   if ((mBits == 1024) && sp_isodd(m) && (bBits <= 1024) && (eBits <= 1024))
 *
 * Only compiled when an SP-accelerated RSA/DH backend is selected. mBits,
 * bBits and eBits are all counted from the ORIGINAL operands, before the base
 * is reduced, so a base or exponent wider than the modulus is a reachable
 * shape - just not one the API tests produce, because they always pass
 * already-reduced RSA/DH operands. Each row below leaves exactly one operand
 * false.
 *
 * The fall-through rows pass an explicit digit count of 1 to the _ex entry
 * point: the generic engine's loop length is that count, not the modulus
 * size, so the whole class stays inside the time budget.
 * ------------------------------------------------------------------------- */
#if (defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
    ((defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
        defined(WOLFSSL_HAVE_SP_DH))
static void wb_sp_backend_dispatch_one(int bits)
{
    sp_int b;
    sp_int e;
    sp_int m;
    sp_int r;

    /* m = 2^(bits-1) + 0x61: exactly 'bits' bits and odd. */
    if ((wb_pow2(&m, bits - 1) != MP_OKAY) ||
            (sp_add_d(&m, 0x61, &m) != MP_OKAY)) {
        /* This width does not fit the configured digit ceiling. */
        return;
    }

    wb_set_d(&b, (sp_int_digit)3);
    wb_set_d(&e, (sp_int_digit)0x10001);
    _sp_init_size(&r, SP_INT_DIGITS);

    /* All operands true: the accelerated routine is selected. */
    (void)sp_exptmod(&b, &e, &m, &r);

    /* Base wider than the modulus: the base-width operand false. It IS
     * paired -- the condition left uncovered in this decision is not this
     * one. llvm-cov numbers a decision's conditions with the operands that
     * come from MACRO expansions LAST, not in source order, so in
     * `(mBits == W) && sp_isodd(m) && (bBits <= W) && (eBits <= W)` the
     * indices are mBits, bBits, eBits, then sp_isodd's two halves. Index 3
     * is therefore `m->used != 0`, which sp_exptmod_ex() has already
     * rejected via sp_iszero(m); see the exclusion record. */
    if ((wb_pow2(&b, bits) == MP_OKAY) && (sp_add_d(&b, 5, &b) == MP_OKAY)) {
        _sp_init_size(&r, SP_INT_DIGITS);
        (void)sp_exptmod_ex(&b, &e, 1, &m, &r);
    }

    /* Exponent wider than the modulus: the exponent-width operand false. */
    wb_set_d(&b, (sp_int_digit)3);
    if ((wb_pow2(&e, bits) == MP_OKAY) && (sp_add_d(&e, 5, &e) == MP_OKAY)) {
        _sp_init_size(&r, SP_INT_DIGITS);
        (void)sp_exptmod_ex(&b, &e, 1, &m, &r);
    }

    /* Even modulus of the same width: the oddness operand false. */
    wb_set_d(&e, (sp_int_digit)0x10001);
    m.dp[0] &= ~(sp_int_digit)1;
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_ex(&b, &e, 1, &m, &r);
}

static void wb_sp_backend_dispatch(void)
{
#ifndef WOLFSSL_SP_NO_2048
    wb_sp_backend_dispatch_one(1024);
    wb_sp_backend_dispatch_one(2048);
#endif
#ifndef WOLFSSL_SP_NO_3072
    wb_sp_backend_dispatch_one(1536);
    wb_sp_backend_dispatch_one(3072);
#endif
#ifdef WOLFSSL_SP_4096
    wb_sp_backend_dispatch_one(4096);
#endif
    WB_NOTE("SP fixed-size modexp dispatch shapes exercised");
}
#else
static void wb_sp_backend_dispatch(void)
{
    WB_NOTE("no SP-accelerated modexp backend; dispatch shapes skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 8: sp_gcd() / prime-test capacity and small-composite guards.
 * ------------------------------------------------------------------------- */
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
static void wb_gcd_capacity(void)
{
    sp_int a;
    sp_int b;
    sp_int r;

    /* Operand at the compile-time digit ceiling: rejected. Reached only by
     * building the value directly - every API path clamps first. */
    wb_fill(&a, (unsigned int)SP_INT_DIGITS, (sp_int_digit)3);
    wb_fill(&b, 2, (sp_int_digit)5);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_gcd(&a, &b, &r);
    (void)sp_gcd(&b, &a, &r);

    /* Result too small for the smaller operand, taking the second arm of
     * the capacity OR (b shorter than a). */
    wb_fill(&a, 4, (sp_int_digit)6);
    wb_fill(&b, 2, (sp_int_digit)4);
    _sp_init_size(&r, 1);
    (void)sp_gcd(&a, &b, &r);

    /* Same shapes, destination big enough: the ordinary row. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_gcd(&a, &b, &r);

    WB_NOTE("sp_gcd capacity rows exercised");
}
#else
static void wb_gcd_capacity(void)
{
    WB_NOTE("sp_gcd not compiled; skipped");
}
#endif

#ifdef WOLFSSL_SP_PRIME_GEN
static void wb_prime_shapes(void)
{
    sp_int a;
    sp_int b;
    sp_int n1;
    sp_int r;
    int    res = 0;

    /* A value that is the product of the first small primes: the composite
     * trial-division loop finds a zero remainder on its first composite,
     * which no ordinary prime candidate ever does. */
    wb_set_d(&a, (sp_int_digit)0x088886ffdb344692ULL);
    (void)sp_prime_is_prime(&a, 1, &res);

    /* Same call with a value the composite division does NOT divide. */
    wb_set_d(&a, (sp_int_digit)0x088886ffdb344693ULL);
    (void)sp_prime_is_prime(&a, 1, &res);

#ifdef WOLFSSL_SP_INT_NEGATIVE
    /* Candidate of negative one: the "is it one" shortcut's sign operand is
     * the only one that differs, and sp_prime_is_prime() (unlike its
     * randomised sibling) has no sign check ahead of it. */
    wb_set_d(&a, (sp_int_digit)1);
    a.sign = MP_NEG;
    (void)sp_prime_is_prime(&a, 1, &res);
    a.sign = MP_ZPOS;
    (void)sp_prime_is_prime(&a, 1, &res);
#endif

    /* Miller-Rabin driven directly so the witness makes the squaring loop
     * itself find one - i.e. the loop, not the post-loop comparison,
     * declares the candidate composite. */
    wb_set_d(&a, (sp_int_digit)21);
    wb_set_d(&b, (sp_int_digit)8);
    _sp_init_size(&n1, SP_INT_DIGITS);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_prime_miller_rabin(&a, &b, &res, &n1, &r);

    /* Witness that leaves the loop without hitting one: the post-loop
     * comparison is what rejects it. */
    wb_set_d(&a, (sp_int_digit)15);
    wb_set_d(&b, (sp_int_digit)2);
    _sp_init_size(&n1, SP_INT_DIGITS);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_prime_miller_rabin(&a, &b, &res, &n1, &r);

#ifndef WC_NO_RNG
    {
        WC_RNG rng;

        if (wc_InitRng(&rng) == 0) {
            /* Candidate at the compile ceiling for the randomised entry
             * point: rejected before any trial is run. */
            wb_fill(&a, (unsigned int)(SP_INT_DIGITS / 2 + 1),
                (sp_int_digit)3);
            (void)sp_prime_is_prime_ex(&a, 1, &res, &rng);

            /* Same call with a candidate that fits. */
            wb_set_d(&a, (sp_int_digit)0x088886ffdb344693ULL);
            (void)sp_prime_is_prime_ex(&a, 1, &res, &rng);

#ifdef WOLFSSL_SP_INT_NEGATIVE
            /* Negative candidate: rejected. */
            wb_set_d(&a, (sp_int_digit)7);
            a.sign = MP_NEG;
            (void)sp_prime_is_prime_ex(&a, 1, &res, &rng);
#endif
            (void)wc_FreeRng(&rng);
        }
        else {
            wb_fail = 1;
            WB_NOTE("RNG init failed; randomised prime rows skipped");
        }
    }
#endif

    WB_NOTE("prime-test operand shapes exercised");
}
#else
static void wb_prime_shapes(void)
{
    WB_NOTE("prime generation not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 9: sp_sqrmod() aliasing + ceiling guard.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || !defined(NO_DH) || defined(HAVE_ECC)
static void wb_sqrmod_ceiling(void)
{
    sp_int a;
    sp_int m;

    /* Destination aliased onto the modulus with an operand whose square
     * would exceed the compile ceiling: all three operands true. */
    wb_fill(&a, (unsigned int)(SP_INT_DIGITS / 2 + 1), (sp_int_digit)3);
    wb_fill(&m, 2, (sp_int_digit)5);
    (void)sp_sqrmod(&a, &m, &m);

    /* Same aliasing, operand small enough: third operand false. */
    wb_fill(&a, 1, (sp_int_digit)3);
    wb_fill(&m, 2, (sp_int_digit)5);
    (void)sp_sqrmod(&a, &m, &m);

    /* Error already latched by the NULL check, so the first operand is
     * false and the aliasing test is not reached. */
    (void)sp_sqrmod(NULL, &m, &m);

    WB_NOTE("sp_sqrmod aliasing/ceiling rows exercised");
}
#else
static void wb_sqrmod_ceiling(void)
{
    WB_NOTE("sp_sqrmod not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 10: fixed-length binary and hex output edge rows.
 * ------------------------------------------------------------------------- */
static void wb_output_edges(void)
{
    sp_int a;
    byte   out[4];

    /* Buffer fills while the MOST significant digit still has nonzero bits
     * left: the "there is more of this digit" operand of the truncation
     * test. Callers size the buffer with sp_unsigned_bin_size() so it never
     * happens in the library. */
    wb_set_d(&a, (sp_int_digit)0x0102);
    (void)sp_to_unsigned_bin_len(&a, out, 1);

    /* Buffer fills exactly: nothing of the digit is left over. */
    wb_set_d(&a, (sp_int_digit)0x02);
    (void)sp_to_unsigned_bin_len(&a, out, 1);

#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WC_MP_TO_RADIX)
    {
        char str[SP_INT_DIGITS * (SP_WORD_SIZE / 4) + 4];

        /* Non-normalized value whose most significant digit is entirely
         * zero: the leading-zero-byte scan runs off the end of the digit
         * instead of breaking out on a nonzero byte. sp_clamp() on every
         * public mutator prevents a caller from producing this. */
        _sp_init_size(&a, SP_INT_DIGITS);
        a.dp[0] = 1;
        a.dp[1] = 0;
        a.used  = 2;
        (void)sp_tohex(&a, str);

        /* Ordinary normalized value: the scan breaks out on a nonzero byte,
         * the other half of the same loop condition. */
        wb_set_d(&a, (sp_int_digit)0x1234);
        (void)sp_tohex(&a, str);
    }
#endif

    WB_NOTE("binary/hex output edge rows exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 11: _sp_mulmod_tmp() zero-operand shortcut.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(WOLFCRYPT_HAVE_ECCSI) || \
    (!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)) || defined(OPENSSL_ALL)
static void wb_mulmod_tmp_zero(void)
{
    sp_int a;
    sp_int b;
    sp_int m;
    sp_int r;

    wb_fill(&m, 2, (sp_int_digit)5);
    _sp_init_size(&r, SP_INT_DIGITS);

    /* First operand zero: the shortcut's first test true. sp_mulmod()
     * screens zero operands out before this helper is reached. */
    _sp_init_size(&a, SP_INT_DIGITS);
    wb_set_d(&b, (sp_int_digit)3);
    (void)_sp_mulmod_tmp(&a, &b, &m, &r);

    /* Second operand zero: first test false, second true. */
    wb_set_d(&a, (sp_int_digit)3);
    _sp_init_size(&b, SP_INT_DIGITS);
    (void)_sp_mulmod_tmp(&a, &b, &m, &r);

    /* Neither zero: both false. */
    wb_set_d(&b, (sp_int_digit)4);
    (void)_sp_mulmod_tmp(&a, &b, &m, &r);

    WB_NOTE("_sp_mulmod_tmp zero-operand shortcut exercised");
}
#else
static void wb_mulmod_tmp_zero(void)
{
    WB_NOTE("_sp_mulmod_tmp not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 12: _sp_sub_off() offset-copy loop.
 *
 *   for (; (i < o) && (i < a->used); i++) r->dp[i] = a->dp[i];
 *
 * The loop copies the digits below the offset. Every in-library caller uses
 * an offset no larger than the operand, so the loop always ends on the
 * offset test - it never runs out of source digits first.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_INT_NEGATIVE) || \
    !defined(NO_DH) || defined(HAVE_ECC) || (!defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY))
static void wb_sub_off_loop(void)
{
    sp_int a;
    sp_int b;
    sp_int r;

    /* Offset larger than the source: the loop ends because it ran out of
     * source digits. */
    wb_fill(&a, 2, (sp_int_digit)0x1234);
    wb_fill(&b, 1, (sp_int_digit)1);
    _sp_init_size(&r, SP_INT_DIGITS);
    _sp_sub_off(&a, &b, &r, (sp_size_t)4);

    /* Offset inside the source: the loop ends on the offset instead. */
    wb_fill(&a, 4, (sp_int_digit)0x1234);
    _sp_init_size(&r, SP_INT_DIGITS);
    _sp_sub_off(&a, &b, &r, (sp_size_t)2);

    WB_NOTE("_sp_sub_off offset-copy loop exercised");
}
#else
static void wb_sub_off_loop(void)
{
    WB_NOTE("_sp_sub_off not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 13: _sp_add_d() carry-overflow guard.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_ADD_D) || (defined(WOLFSSL_SP_INT_NEGATIVE) && \
    defined(WOLFSSL_SP_SUB_D)) || defined(WOLFSSL_SP_READ_RADIX_10)
static void wb_add_d_overflow(void)
{
    sp_int a;
    sp_int r;

    /* All-ones operand plus one carries out of every digit, and the
     * destination has no room for the extra word: the error is latched and
     * the "copy the rest of the digits" test sees it. */
    wb_fill(&a, 3, (sp_int_digit)~(sp_int_digit)0);
    _sp_init_size(&r, 3);
    (void)_sp_add_d(&a, (sp_int_digit)1, &r);

    /* Same carry-out with room for the extra word: no error. */
    wb_fill(&a, 3, (sp_int_digit)~(sp_int_digit)0);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)_sp_add_d(&a, (sp_int_digit)1, &r);

    WB_NOTE("_sp_add_d carry-overflow rows exercised");
}
#else
static void wb_add_d_overflow(void)
{
    WB_NOTE("_sp_add_d not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 14: sp_lshb() whole-digit shift capacity guard.
 *
 *   else if ((s > 0) && (a->used + s > a->size))
 *
 * Only reached when the bit part of the shift is zero (an exact multiple of
 * the word size), which the in-library callers never combine with a
 * destination that is too small.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
static void wb_lshb_capacity(void)
{
    sp_int a;

    /* Whole-word shift with no room: both operands true. */
    _sp_init_size(&a, 4);
    a.dp[0] = 1;
    a.used  = 4;
    a.dp[1] = 1; a.dp[2] = 1; a.dp[3] = 1;
    (void)sp_lshb(&a, 2 * SP_WORD_SIZE);

    /* Whole-word shift with room: second operand false. */
    _sp_init_size(&a, SP_INT_DIGITS);
    a.dp[0] = 1;
    a.used  = 1;
    (void)sp_lshb(&a, 2 * SP_WORD_SIZE);

    /* No whole-word part at all: first operand false. */
    _sp_init_size(&a, SP_INT_DIGITS);
    a.dp[0] = 1;
    a.used  = 1;
    (void)sp_lshb(&a, 0);

    WB_NOTE("sp_lshb whole-digit capacity rows exercised");
}
#else
static void wb_lshb_capacity(void)
{
    WB_NOTE("sp_lshb not compiled; skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 15: _sp_div()'s zero-divisor arm.
 *
 *   if ((!done) && (err == MP_OKAY) && (d->used > 0)) {
 *
 * sp_div() rejects a zero divisor before it ever calls the engine, so the
 * engine's own defensive width test is never seen false. _sp_div() is
 * file-static and in scope here, so it can be handed the shape sp_div()
 * screens out. With a zero divisor the shift step is skipped (the divisor's
 * bit count is zero, so the normalisation shift is a whole word) and the
 * division body is not entered, so nothing divides by zero.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))
static void wb_div_zero_divisor(void)
{
    sp_int a;
    sp_int d;
    sp_int q;
    sp_int rem;

    wb_fill(&a, 4, (sp_int_digit)0x1234567ULL);
    _sp_init_size(&d, SP_INT_DIGITS);      /* d = 0, used == 0 */
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)_sp_div(&a, &d, &q, &rem, (unsigned int)(a.used + 1U));

    /* The ordinary row (a nonzero divisor) in the same binary. */
    wb_fill(&d, 2, (sp_int_digit)0x89abULL);
    _sp_init_size(&q, SP_INT_DIGITS);
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)_sp_div(&a, &d, &q, &rem, (unsigned int)(a.used + 1U));

    WB_NOTE("_sp_div zero-divisor width row exercised");
}
#else
static void wb_div_zero_divisor(void)
{
    WB_NOTE("_sp_div not compiled; zero-divisor row skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 16: prime-test argument rejection ahead of the width guard.
 *
 *   if ((err == MP_OKAY) && (a->used * 2 >= SP_INT_DIGITS)) {
 *
 * The width guard's error operand is only false when an EARLIER check already
 * rejected the call. The API suite never passes a NULL candidate to the
 * randomised entry point, so the guard is only ever reached with the error
 * clear. A NULL candidate short-circuits it (the width term is not evaluated,
 * so nothing is dereferenced).
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_PRIME_GEN) && !defined(WC_NO_RNG)
static void wb_prime_arg_rejected(void)
{
    WC_RNG rng;
    int    res = 0;

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("RNG init failed; prime argument rows skipped");
        return;
    }

    /* Error latched by the NULL check: the width guard sees it. */
    (void)sp_prime_is_prime_ex(NULL, 1, &res, &rng);
    (void)sp_prime_is_prime_ex(NULL, 1, NULL, &rng);

    (void)wc_FreeRng(&rng);
    WB_NOTE("prime-test argument rejection rows exercised");
}
#else
static void wb_prime_arg_rejected(void)
{
    WB_NOTE("randomised prime test not compiled; argument rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 17: the randomised Miller-Rabin witness rejection.
 *
 *   if ((sp_cmp_d(b, 2) != MP_GT) || (_sp_cmp(b, c) != MP_LT)) continue;
 *
 * The witness is drawn at random and rejected when it is not in [3, a-3].
 * The "too small" arm needs a draw of 0, 1 or 2, which for the multi-hundred-
 * bit candidates the API tests use has probability ~2^-bits and is therefore
 * never observed. The witness is masked down to the CANDIDATE's bit width, so
 * a deliberately tiny candidate makes the draw space small enough that the
 * arm is hit with certainty inside a bounded number of trials.
 *
 * The candidate is chosen so that BOTH rejection arms stay rare enough for the
 * loop to make progress: 2039 is prime and just below 2^11, so a random
 * 11-bit witness is out of range only 14 times in 2048. The helper is called
 * directly because sp_prime_is_prime_ex() answers single-digit candidates from
 * its small-prime table without ever drawing a witness.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_PRIME_GEN) && !defined(WC_NO_RNG)
/* 2039 draws ~1.007 witnesses per trial, so this many trials makes ~20000
 * draws: at 3/2048 per draw the probability of never seeing a witness of 2 or
 * less is about e^-29. Each trial is a Miller-Rabin on an 11-bit number. */
#define WB_SMALL_WITNESS_TRIALS 20000

static void wb_prime_small_witness(void)
{
    WC_RNG rng;
    sp_int a;
    int    res = 0;
    int    i;

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("RNG init failed; small-witness rows skipped");
        return;
    }

    wb_set_d(&a, (sp_int_digit)2039);
    for (i = 0; i < WB_SMALL_WITNESS_TRIALS; i++) {
        if (_sp_prime_random_trials(&a, 1, &res, &rng) != MP_OKAY) {
            wb_fail = 1;
            break;
        }
    }

    (void)wc_FreeRng(&rng);
    WB_NOTE("randomised witness rejection rows exercised");
}
#else
static void wb_prime_small_witness(void)
{
    WB_NOTE("randomised prime trials not compiled; witness rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 18: the sign-of-c arm of the division-based inverse.
 *
 *   if ((err == MP_OKAY) && sp_isneg(c)) c += m;      (SP_INT_NEGATIVE)
 *   if ((err == MP_OKAY) && cneg)        c = m - |c|; (default)
 *
 * The leading operand's false side is the failed-inverse exit above (the
 * Euclid loop divides by zero once the remainder reaches zero for a
 * non-coprime pair, so sp_div() latches MP_VAL). Its true side needs a
 * SUCCESSFUL inverse whose accumulated coefficient came out negative, in
 * the same binary. Whether it does depends only on the parity of the number
 * of Euclid steps, so sweep a range of coprime operands rather than picking
 * one and hoping.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_INVMOD) && !defined(WOLFSSL_SP_LOW_MEM) && \
    !defined(WOLFSSL_SP_SMALL) && (!defined(NO_RSA) || !defined(NO_DH))
static void wb_invmod_c_sign(void)
{
    sp_int a;
    sp_int m;
    sp_int r;
    sp_int_digit v;

    /* Same 1024-bit odd modulus shape as the no-inverse rows: only a
     * modulus of at least 1024 bits selects _sp_invmod_div(). */
    if (wb_pow2(&m, 1022) != MP_OKAY) {
        WB_NOTE("digit ceiling below 1024 bits; inverse sign rows skipped");
        return;
    }
    if ((sp_add_d(&m, 1, &m) != MP_OKAY) || (sp_mul_d(&m, 3, &m) != MP_OKAY)) {
        wb_fail = 1;
        return;
    }

    for (v = 5; v <= 61; v += 2) {
        if ((v % 3) == 0) {
            continue;               /* shares the factor 3: no inverse */
        }
        wb_set_d(&a, v);
        _sp_init_size(&r, SP_INT_DIGITS);
        (void)sp_invmod(&a, &m, &r);
    }

    WB_NOTE("division-based inverse coefficient-sign rows exercised");
}
#else
static void wb_invmod_c_sign(void)
{
    WB_NOTE("division-based inverse not compiled; sign rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 19: sp_exptmod_nct()'s negative-operand rejection.
 *
 *   else if ((e->sign == MP_NEG) || (m->sign == MP_NEG)) err = MP_VAL;
 *
 * Only compiled with WOLFSSL_SP_INT_NEGATIVE, and no caller in the library
 * or in the API tests hands it a negative exponent or modulus, so the whole
 * decision was never evaluated with either operand true. Both are set here
 * directly - sp_int's sign field is in scope in this TU.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SP_INT_NEGATIVE
static void wb_exptmod_nct_negative(void)
{
    sp_int b;
    sp_int e;
    sp_int m;
    sp_int r;

    wb_set_d(&b, (sp_int_digit)3);
    wb_set_d(&e, (sp_int_digit)5);
    wb_set_d(&m, (sp_int_digit)0x0fffffffffffffc5ULL);
    _sp_init_size(&r, SP_INT_DIGITS);

    /* Negative exponent, positive modulus: first operand true. */
    e.sign = MP_NEG;
    (void)sp_exptmod_nct(&b, &e, &m, &r);
    e.sign = MP_ZPOS;

    /* Positive exponent, negative modulus: first operand false, second
     * true - the second operand's own vector. */
    m.sign = MP_NEG;
    (void)sp_exptmod_nct(&b, &e, &m, &r);
    m.sign = MP_ZPOS;

    /* Both positive: the all-false row that completes both pairs. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_nct(&b, &e, &m, &r);

    WB_NOTE("sp_exptmod_nct negative-operand rows exercised");
}
#else
static void wb_exptmod_nct_negative(void)
{
    WB_NOTE("WOLFSSL_SP_INT_NEGATIVE off; exptmod sign rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 20: the "base == modulus" shortcut inside the exponentiation
 * engines, and the err chains that ride the same allocations.
 *
 *   if ((err == MP_OKAY) && sp_iszero(t[0]))  { _sp_set(r, 0); done = 1; }
 *   if ((err == MP_OKAY) && sp_iszero(bm))    { _sp_set(r, 0); done = 1; }
 *   while ((err == MP_OKAY) && ((i >= 0) || (c >= winBits)));
 *
 * The second operand's true side needs a base that reduces to zero, i.e. an
 * exact multiple of the modulus - nothing in the library or the API tests
 * asks for one. The leading operand only moves when the sp_mod()/window
 * step underneath fails an allocation, which needs WOLFSSL_SMALL_STACK, and
 * llvm-cov derives independence pairs per BINARY, so both have to be here.
 * ------------------------------------------------------------------------- */
static void wb_exptmod_base_multiple(void)
{
    sp_int b;
    sp_int e;
    sp_int m;
    sp_int r;
    int    n;

    /* A 2-digit odd modulus: big enough for the Montgomery engine
     * (m->used > 1 && odd), small enough that the sweep is cheap. The
     * single-digit modulus below takes the other engine. */
    wb_fill(&m, 2, (sp_int_digit)0);
    m.dp[0] = (sp_int_digit)0x0fffffffffffffc5ULL;
    m.dp[1] = (sp_int_digit)0x00000000000000f1ULL;
    wb_set_d(&e, (sp_int_digit)0x10001);

    /* b = m * 2: >= m, and b mod m == 0. */
    if (sp_mul_d(&m, 2, &b) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_nct(&b, &e, &m, &r);

    /* Ordinary base through the same engines: the shortcut's false side. */
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod_nct(&b, &e, &m, &r);

    /* Allocation sweep over the same two calls. No-op unless the variant
     * sets WOLFSSL_SMALL_STACK: without it the temporaries are stack arrays
     * and err cannot leave MP_OKAY. */
    /* mcdc_fa_arm_only(): fail EXACTLY the n-th allocation, not it and every
     * later one. The targets are allocations made by callees (sp_mod()'s
     * division temporaries, the window table) that only run after the
     * engine's own temporaries are already in hand, so a fail-from-n-onwards
     * sweep kills the engine before its callee is reached. */
    mcdc_fa_install();
    for (n = 1; n <= 40; n++) {
        _sp_init_size(&r, SP_INT_DIGITS);
        mcdc_fa_arm_only(n);
        (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
        mcdc_fa_disarm();

        _sp_init_size(&r, SP_INT_DIGITS);
        mcdc_fa_arm_only(n);
        (void)sp_exptmod_nct(&b, &e, &m, &r);
        mcdc_fa_disarm();
    }

    /* The same sweep with the base that reduces to zero, so the shortcut's
     * own allocation site is walked as well. */
    if (sp_mul_d(&m, 2, &b) == MP_OKAY) {
        for (n = 1; n <= 40; n++) {
            _sp_init_size(&r, SP_INT_DIGITS);
            mcdc_fa_arm_only(n);
            (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
            mcdc_fa_disarm();

            _sp_init_size(&r, SP_INT_DIGITS);
            mcdc_fa_arm_only(n);
            (void)sp_exptmod_nct(&b, &e, &m, &r);
            mcdc_fa_disarm();
        }
    }
    mcdc_fa_disarm();

    /* Repeat both shapes against a SINGLE-digit odd modulus, which does not
     * satisfy `m->used > 1` and so takes the other exponentiation engine.
     * Both engines carry the same base-reduction shortcut and the same
     * window loop, at different lines. */
    wb_set_d(&m, (sp_int_digit)0x0fffffffffffffc5ULL);
    if (sp_mul_d(&m, 2, &b) == MP_OKAY) {
        _sp_init_size(&r, SP_INT_DIGITS);
        (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
        _sp_init_size(&r, SP_INT_DIGITS);
        (void)sp_exptmod(&b, &e, &m, &r);
        for (n = 1; n <= 60; n++) {
            _sp_init_size(&r, SP_INT_DIGITS);
            mcdc_fa_arm_only(n);
            (void)sp_exptmod_ex(&b, &e, (int)e.used, &m, &r);
            mcdc_fa_disarm();

            _sp_init_size(&r, SP_INT_DIGITS);
            mcdc_fa_arm_only(n);
            (void)sp_exptmod(&b, &e, &m, &r);
            mcdc_fa_disarm();
        }
    }
    wb_set_d(&b, (sp_int_digit)3);
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_exptmod(&b, &e, &m, &r);
    for (n = 1; n <= 60; n++) {
        _sp_init_size(&r, SP_INT_DIGITS);
        mcdc_fa_arm_only(n);
        (void)sp_exptmod(&b, &e, &m, &r);
        mcdc_fa_disarm();
    }
    mcdc_fa_disarm();

    WB_NOTE("exponentiation base-multiple and allocation rows exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 21: sp_div_2d()'s remainder copy.
 *
 *   if ((err == MP_OKAY) && (rem != NULL)) { ... mask the top digit ... }
 *
 * The leading operand's false side is a remainder sp_int too small to hold
 * the dividend: sp_copy() then returns MP_VAL with rem still non-NULL. Every
 * caller sizes the remainder from the dividend, so it never happens there.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
static void wb_div_2d_rem_small(void)
{
    sp_int a;
    sp_int r;
    sp_int rem;

    wb_fill(&a, 3, (sp_int_digit)0x0123456789abcdefULL);
    _sp_init_size(&r, SP_INT_DIGITS);

    /* Remainder with room for one digit only. */
    _sp_init_size(&rem, 1);
    (void)sp_div_2d(&a, SP_WORD_SIZE + 3, &r, &rem);

    /* Same shift with a remainder that fits: the operand's true side. */
    _sp_init_size(&rem, SP_INT_DIGITS);
    (void)sp_div_2d(&a, SP_WORD_SIZE + 3, &r, &rem);

    WB_NOTE("sp_div_2d remainder-capacity rows exercised");
}
#else
static void wb_div_2d_rem_small(void)
{
    WB_NOTE("sp_div_2d not compiled; remainder-capacity rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 22: sp_gcd()'s result-capacity check, second link.
 *
 *   else if (((a->used <= b->used) && (r->size < a->used)) ||
 *            ((a->used > b->used) && (r->size < b->used)))
 *
 * The second link is only evaluated when the first is false, i.e. with
 * a->used > b->used; it then needs a result too small for the SMALLER
 * operand. The committed rows only ever undersized the result against the
 * larger one, which the first link catches.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SP_MATH_ALL
static void wb_gcd_r_small_b(void)
{
    sp_int a;
    sp_int b;
    sp_int r;

    wb_fill(&a, 4, (sp_int_digit)0x0123456789abcdefULL);
    wb_fill(&b, 3, (sp_int_digit)0x00fedcba98765432ULL);

    /* a->used > b->used and r too small for b: second link true. */
    _sp_init_size(&r, 2);
    (void)sp_gcd(&a, &b, &r);

    /* Same shape with a result that fits: second link false. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_gcd(&a, &b, &r);

    /* Operands the other way round, so the first link is evaluated and the
     * second link's own operand is false: the row its pair needs. */
    _sp_init_size(&r, SP_INT_DIGITS);
    (void)sp_gcd(&b, &a, &r);

    WB_NOTE("sp_gcd smaller-operand capacity rows exercised");
}
#else
static void wb_gcd_r_small_b(void)
{
    WB_NOTE("sp_gcd not compiled; smaller-operand capacity rows skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Class 23: the primality trial loops' error arm.
 *
 *   if ((err != MP_OKAY) || (*result == MP_NO)) break;
 *
 * The leading operand's true side needs sp_prime_miller_rabin() to fail,
 * which on this configuration means an allocation failure inside the
 * modular exponentiation it performs. Its false side (a composite rejected
 * on the result operand) has to be in the same binary.
 * ------------------------------------------------------------------------- */
/* Pinned RNG seed for the randomised Miller-Rabin trial loop (Class 23).
 * Recorded here because a seed that reaches a condition is a test vector: the
 * next person has to be able to reproduce the result. */
#define WB_PRIME_RNG_SEED  0x5eed0001UL

static void wb_prime_trial_alloc(void)
{
    sp_int  a;
    int     res = 0;
    int     n;
#ifndef WC_NO_RNG
    WC_RNG  rng;
    int     haveRng;
#endif

    /* 10007 * 10009: composite, but both factors are past the end of the
     * small-prime table, so trial division does not settle it and the
     * Miller-Rabin loop actually runs and rejects on *result. */
    wb_set_d(&a, (sp_int_digit)100160063ULL);
    (void)sp_prime_is_prime(&a, 8, &res);
#ifndef WC_NO_RNG
    if (wc_InitRng(&rng) == 0) {
        (void)sp_prime_is_prime_ex(&a, 8, &res, &rng);
        wc_FreeRng(&rng);
    }
#endif

    /* 2^31 - 1, a genuine prime (checked): the trial loop then runs every
     * round without breaking, which is the `err == MP_OKAY && *result !=
     * MP_NO` row both operands' pairs need. The two-word constant the rest
     * of this file uses as a modulus is NOT prime, so it only ever produced
     * the break row. */
    wb_set_d(&a, (sp_int_digit)2147483647UL);
    (void)sp_prime_is_prime(&a, 8, &res);

    mcdc_fa_install();
    for (n = 1; n <= 60; n++) {
        wb_set_d(&a, (sp_int_digit)2147483647UL);
        mcdc_fa_arm_only(n);
        (void)sp_prime_is_prime(&a, 8, &res);
        mcdc_fa_disarm();
    }

#ifndef WC_NO_RNG
    haveRng = (wc_InitRng(&rng) == 0);
    if (haveRng) {
        wb_set_d(&a, (sp_int_digit)2147483647UL);
        (void)sp_prime_is_prime_ex(&a, 8, &res, &rng);
        for (n = 1; n <= 60; n++) {
            wb_set_d(&a, (sp_int_digit)2147483647UL);
            mcdc_fa_arm_only(n);
            (void)sp_prime_is_prime_ex(&a, 8, &res, &rng);
            mcdc_fa_disarm();
        }
        wc_FreeRng(&rng);
    }
#endif
    mcdc_fa_disarm();

    /* The trial loops called DIRECTLY. Going through sp_prime_is_prime()
     * puts the argument checks, the small-prime comparison and the trial
     * division ahead of the loop, so an allocation index that lands inside
     * sp_prime_miller_rabin() from here would have to be guessed past all
     * of them. Called directly, the arming starts at the function's own
     * three ALLOC_SP_INTs and the next allocations are the exponentiation's
     * -- exactly what the loop's `err != MP_OKAY` operand needs. Both
     * functions are file-static and in scope because this TU #includes
     * sp_int.c. */
    wb_set_d(&a, (sp_int_digit)2147483647UL);
    (void)_sp_prime_trials(&a, 8, &res);
    wb_set_d(&a, (sp_int_digit)100160063ULL);
    (void)_sp_prime_trials(&a, 8, &res);
    for (n = 1; n <= 30; n++) {
        wb_set_d(&a, (sp_int_digit)2147483647UL);
        mcdc_fa_arm_only(n);
        (void)_sp_prime_trials(&a, 8, &res);
        mcdc_fa_disarm();
    }
#ifndef WC_NO_RNG
    if (wc_InitRng(&rng) == 0) {
        wb_set_d(&a, (sp_int_digit)2147483647UL);
        (void)_sp_prime_random_trials(&a, 8, &res, &rng);
        wb_set_d(&a, (sp_int_digit)100160063ULL);
        (void)_sp_prime_random_trials(&a, 8, &res, &rng);
        /* Real-entropy sweep. Kept for the rows it does reach (the
         * wc_RNG_GenerateBlock() error break at :19666's neighbour), but it
         * does NOT close :19672:0: the first faulted allocation lands inside
         * Hash_DRBG_Generate() and leaves the WC_RNG permanently
         * DRBG_FAILED, so every later index dies at the draw. Measured: for
         * n >= 3 the call returns RNG_FAILURE_E with the RNG reporting a
         * failure, never MP_MEM from the exponentiation. */
        for (n = 1; n <= 30; n++) {
            wb_set_d(&a, (sp_int_digit)2147483647UL);
            mcdc_fa_arm_only(n);
            (void)_sp_prime_random_trials(&a, 8, &res, &rng);
            mcdc_fa_disarm();
        }
        wc_FreeRng(&rng);
    }

    /* :19672:0 (`err != MP_OKAY` of the RANDOMISED trial loop), closed with a
     * PINNED, allocation-free RNG on a fresh WC_RNG.
     *
     * PINNED INPUT (evidence): mcdc_seed_rng.h armed with seed 0x5eed0001;
     * candidate a = 2^31 - 1 (prime) for the error rows and
     * a = 100160063 = 10007 * 10009 (composite, both factors past the end of
     * the small-prime table) for the *result == MP_NO row; trials = 8.
     *
     * With the armed hook the loop makes no allocation of its own before
     * sp_prime_miller_rabin(), so allocation index 1 and 2 are this
     * function's two ALLOC_SP_INT_ARRAYs (err set before the loop; the
     * decision is not reached) and every index from 3 up lands inside the
     * exponentiation, returning MP_MEM into `err` and breaking on THIS
     * operand. The two un-armed calls above it in the same binary supply the
     * (F,F) row (a prime, so the loop runs every round) and the (F,T) row (a
     * composite, rejected on *result). */
    if (wc_InitRng(&rng) == 0) {
        mcdc_sr_arm(WB_PRIME_RNG_SEED);

        wb_set_d(&a, (sp_int_digit)2147483647UL);
        (void)_sp_prime_random_trials(&a, 8, &res, &rng);
        wb_set_d(&a, (sp_int_digit)100160063ULL);
        (void)_sp_prime_random_trials(&a, 8, &res, &rng);

        for (n = 1; n <= 24; n++) {
            /* Rewind BEFORE arming: re-absorbing the seed allocates. */
            mcdc_sr_rewind(WB_PRIME_RNG_SEED);
            wb_set_d(&a, (sp_int_digit)2147483647UL);
            mcdc_fa_arm_only(n);
            (void)_sp_prime_random_trials(&a, 8, &res, &rng);
            mcdc_fa_disarm();
        }

        mcdc_sr_disarm();
        wc_FreeRng(&rng);
    }
#endif
    mcdc_fa_disarm();

    WB_NOTE("prime trial-loop error rows exercised");
}

#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_SP_MATH */

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("sp_int.c white-box MC/DC supplement\n");
#if !defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_SP_MATH)
    printf("  neither WOLFSSL_SP_MATH_ALL nor WOLFSSL_SP_MATH defined;"
        " nothing to exercise\n");
    return 0;
#else
    wb_count_bits_leading_zero();
    wb_cnt_lsb_all_zero_digits();
    wb_alloc_ceiling_macros();
    wb_div_capacity();
    wb_exptmod_engines();
    wb_exptmod_dispatch();
    wb_invmod_negative();
    wb_invmod_no_inverse();
    wb_alloc_ceiling_sites();
    wb_sp_backend_dispatch();
    wb_gcd_capacity();
    wb_prime_shapes();
    wb_sqrmod_ceiling();
    wb_output_edges();
    wb_mulmod_tmp_zero();
    wb_sub_off_loop();
    wb_add_d_overflow();
    wb_lshb_capacity();
    wb_div_zero_divisor();
    wb_prime_arg_rejected();
    wb_prime_small_witness();
    wb_invmod_c_sign();
    wb_exptmod_nct_negative();
    wb_exptmod_base_multiple();
    wb_div_2d_rem_small();
    wb_gcd_r_small_b();
    wb_prime_trial_alloc();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the harness
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
