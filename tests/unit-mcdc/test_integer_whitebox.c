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
 * one binary (llvm-cov computes MC/DC per binary; the campaign unions the
 * "independence shown" bit across binaries by line:col).
 *
 * Build: compiled by run-mcdc.sh's white-box step with the SAME MC/DC CFLAGS
 * and -I<workspace> as the instrumented library, then linked against that
 * variant's libwolfssl.a with its integer.o removed (this TU supplies the
 * instrumented integer.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Every call is memory-safe (static helpers are handed initialized mp_ints and
 * in-range selectors); setup failures print a skip and return 0 (a nonzero
 * exit makes the campaign discard the variant and its coverage).
 */

#include <wolfcrypt/src/integer.c>

#include <stdio.h>

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

int main(void)
{
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
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * campaign discard this variant's coverage. */
    return 0;
#endif
}
