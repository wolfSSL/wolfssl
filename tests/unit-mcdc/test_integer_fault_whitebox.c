/* test_integer_fault_whitebox.c
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

/*
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/integer.c (the
 * HEAPMATH big-integer backend, bigint-integer module).
 *
 * integer.c is the USE_INTEGER_HEAP_MATH multi-precision engine: every mp_*
 * op allocates through XMALLOC/XREALLOC. Its one uncovered class of decisions
 * that neither the tests/api DecisionCoverage suite nor the static-helper
 * white-box (test_integer_whitebox.c) can reach is the FALSE (short-circuit)
 * half of the allocation success-chains inside mp_div's binary long-division:
 *
 *   if (((res = mp_abs(a, &ta))    != MP_OKAY) ||     -- 1592:*:0
 *       ((res = mp_abs(b, &tb))    != MP_OKAY) ||     -- 1592:*:1
 *       ((res = mp_mul_2d(&tb, n, &tb)) != MP_OKAY) ||-- 1592:*:2
 *       ((res = mp_mul_2d(&tq, n, &tq)) != MP_OKAY))  -- 1592:*:3
 *   ...
 *       if (((res = mp_sub(&ta, &tb, &ta)) != MP_OKAY) ||  -- 1601:*:0
 *           ((res = mp_add(&q,  &tq, &q))  != MP_OKAY))     -- 1601:*:1
 *   ...
 *       if (((res = mp_div_2d(&tb, 1, &tb, NULL)) != MP_OKAY) || -- 1606:*:0
 *           ((res = mp_div_2d(&tq, 1, &tq, NULL)) != MP_OKAY))   -- 1606:*:1
 *
 * In normal execution every allocation succeeds, so `res` stays MP_OKAY and
 * each operand's TRUE (failure) side is never shown; and because these are OR
 * chains where each operand's independence pair REQUIRES that specific operand
 * to be TRUE (the whole chain otherwise runs to completion with every operand
 * FALSE), no ordinary call can close them. The only way to drive operand k's
 * TRUE side is to make the k-th allocation-bearing mp_* op in the chain fail
 * while the earlier ones succeed.
 *
 * This white-box installs the generic heap-fault injector (mcdc_fault_alloc.h)
 * and sweeps the fail-index across mp_div's allocation sites: for each index
 * exactly one earlier op returns MP_MEM, so exactly one operand of one chain is
 * driven TRUE (short-circuiting the rest) per call. The unarmed baseline call
 * supplies the all-FALSE half of every pair in the SAME binary (llvm-cov
 * computes MC/DC per binary; the harness unions the "independence shown" bit
 * across binaries by line:col).
 *
 * Which operands are alloc-closable: mp_abs (grows a fresh temp from NULL),
 * mp_mul_2d (left-shift grows the temp), and mp_add (grows q from its
 * never-grown NULL dp on the first loop iteration) all allocate, so 1592:0-3
 * and 1601:1 are closable.
 *
 * mp_sub (1601:0) and both mp_div_2d (1606:0 and 1606:1) are EXCLUDED. Their
 * TRUE sides are not merely hard to reach with an allocation fault; on this
 * call site the callee has no failing return at all:
 *
 *   mp_div_2d(&x, 1, &x, NULL) with c == a and d == NULL executes, in order,
 *   the b<=0 early-out (not taken, b == 1), mp_init(&t) at :431 -- which
 *   :128 implements as "defer allocation until mp_grow", so it assigns
 *   dp=NULL/used=0/alloc=0 and returns MP_OKAY unconditionally -- then skips
 *   mp_mod_2d because d == NULL, then mp_copy(a, c) at :445, which returns
 *   MP_OKAY at :345 on the "if (a == b)" identity check before it can grow
 *   anything, then void mp_rshd/mp_rshb/mp_clamp/mp_clear and "return
 *   MP_OKAY". No XMALLOC/XREALLOC is issued and no fallible call is made, so
 *   res is MP_OKAY on every iteration for every input.
 *
 *   mp_sub(&ta, &tb, &ta): ta and tb are both MP_ZPOS (mp_abs results;
 *   mp_mul_2d, s_mp_sub and mp_clamp all preserve/reassert MP_ZPOS), so
 *   mp_sub takes the sa == sb arm at :1977; the loop guard at :1600
 *   (mp_cmp(&tb,&ta) != MP_GT, which for two MP_ZPOS values is
 *   mp_cmp_mag) guarantees mp_cmp_mag(ta,tb) != MP_LT, so it dispatches to
 *   s_mp_sub(ta, tb, ta) at :1993. There c == a, so "c->alloc < max_a"
 *   (:1900) is "ta->alloc < ta->used", false under the mp_int invariant
 *   alloc >= used -- mp_grow is never called. The two sanity returns cannot
 *   fire either: ta->dp is non-NULL because mp_abs -> mp_copy -> mp_grow
 *   always allocates into a zero-alloc destination (:350, :392), and tb->dp
 *   is non-NULL for the same reason whenever min_b = tb->used > 0.
 *   s_mp_sub therefore returns MP_OKAY at :1965 unconditionally.
 *
 * The allocation injector cannot change this: the only allocation-bearing op
 * inside the loop is the mp_add at :1602, and its failure goes straight to
 * LBL_ERR, so no faulted iteration ever falls through to a subsequent mp_sub
 * or mp_div_2d with damaged temporaries.
 *
 * A second, small section closes a handful of API-reachable ARGUMENT residuals
 * (NOT allocation-related) that the existing suites simply never pass the
 * deciding value for: mp_exptmod zero-modulus, mp_prime_is_prime t<=0, mp_lcm
 * zero operands, and the mp_radix_size / mp_toradix radix<MP_RADIX_BIN guards,
 * plus mp_add_d's negative multi-digit inner operand. These are deterministic
 * direct calls (no injection) providing both halves of each pair in-binary.
 *
 * A third section covers mp_addmod_ct, mp_submod_ct and mp_div_2_mod_ct. Each
 * grows only its output, or a temporary when c == d, and that grow is failed;
 * NULL and negative-operand rows drive each argument guard operand TRUE.
 *
 * Crash-safety: every armed call fails an allocation that mp_div's own
 * goto-LBL_ERR cleanup absorbs (that cleanup is what is under test); operands
 * are (re)built while DISARMED each iteration and mp_div does not mutate its
 * a/b inputs. The harness never dereferences a faulted call's output. Runs
 * clean under -fsanitize=address.
 *
 * It #includes integer.c directly (like the other unit-mcdc white-boxes) to be
 * the single instrumented definition; the library's integer.o is trimmed from
 * the archive at link time.
 *
 * Invocation:
 *   ./test_integer_fault_whitebox           default: full fault sweep + args
 *   ./test_integer_fault_whitebox baseline  unarmed valid ops only (delta base)
 *   ./test_integer_fault_whitebox probe      print mp_div allocation count
 */

#include <wolfcrypt/src/integer.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

#ifndef HEAP_HINT
#define HEAP_HINT NULL
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(USE_FAST_MATH) || !defined(USE_INTEGER_HEAP_MATH) || \
    defined(WOLFSSL_SP_MATH) || defined(NO_BIG_INT)

int main(void)
{
    printf("integer.c fault white-box: heapmath (integer.c) not the selected"
           " backend, nothing to do\n");
    return 0;
}

#else

/* Build the two mp_div operands DISARMED: a huge dividend (2^220 + 12345) and a
 * small odd divisor (65537). mp_count_bits(a) >> mp_count_bits(b) forces n > 0
 * (so both mp_mul_2d sites allocate) and mp_cmp_mag(a,b) != MP_LT (so the fast
 * "a < b" early-out is skipped and the binary long-division loop runs, reaching
 * the mp_sub/mp_add and mp_div_2d chains). Returns 0 on success. */
static int build_div_operands(mp_int* a, mp_int* b)
{
    if (mp_init(a) != MP_OKAY) return -1;
    if (mp_init(b) != MP_OKAY) { mp_clear(a); return -1; }
    if (mp_set(a, 1) != MP_OKAY) goto fail;
    if (mp_mul_2d(a, 220, a) != MP_OKAY) goto fail;   /* a = 2^220 */
    if (mp_add_d(a, 12345, a) != MP_OKAY) goto fail;  /* a = 2^220 + 12345 */
    if (mp_set(b, 65537) != MP_OKAY) goto fail;       /* b = 65537 (17 bits) */
    return 0;
fail:
    mp_clear(a); mp_clear(b);
    return -1;
}

/* One full mp_div over the prepared operands. c/d receive quotient/remainder. */
static int one_div(void)
{
    mp_int a, b, c, d;
    int r;

    if (build_div_operands(&a, &b) != 0)
        return -1;
    if (mp_init(&c) != MP_OKAY) { mp_clear(&a); mp_clear(&b); return -1; }
    if (mp_init(&d) != MP_OKAY) { mp_clear(&a); mp_clear(&b); mp_clear(&c);
        return -1; }

    r = mp_div(&a, &b, &c, &d);

    mp_clear(&a); mp_clear(&b); mp_clear(&c); mp_clear(&d);
    return r;
}

/* ---- API-reachable ARGUMENT residuals (deterministic, no fault injection).
 * Each provides BOTH halves of its MC/DC pair within this binary. ---- */
static void wb_argument_residuals(void)
{
    mp_int a, b, c, y, zero;
    int res = 0;
    int size = 0;
    char buf[64];

    XMEMSET(&a, 0, sizeof(a));   XMEMSET(&b, 0, sizeof(b));
    XMEMSET(&c, 0, sizeof(c));   XMEMSET(&y, 0, sizeof(y));
    XMEMSET(&zero, 0, sizeof(zero));

    if (mp_init_multi(&a, &b, &c, &y, &zero, NULL) != MP_OKAY) {
        WB_NOTE("argument residuals: init failed, skipped");
        wb_fail = 1;
        return;
    }

    /* mp_exptmod: "mp_iszero(P) || P->sign == MP_NEG" 940:*:0 -- the iszero
     * half. P == 0 (T) returns MP_VAL; a positive modulus (both operands F)
     * runs the real exponentiation. */
    (void)mp_set(&a, 3);
    (void)mp_set(&b, 5);
    (void)mp_set(&c, 7);          /* positive modulus */
    (void)mp_exptmod(&a, &b, &zero, &y);  /* mp_iszero(P) == YES: cond0 T */
    (void)mp_exptmod(&a, &b, &c, &y);     /* positive P: both F */

    /* mp_prime_is_prime: "t <= 0 || t > PRIME_SIZE" 5065:*:0 -- the t<=0 half.
     * t == 0 (T) returns MP_VAL; t == 8 (both operands F) runs the test. */
    (void)mp_set(&a, 17);
    (void)mp_prime_is_prime(&a, 0, &res);   /* t <= 0: cond0 T */
    (void)mp_prime_is_prime(&a, 8, &res);   /* both F */

    /* mp_lcm: "mp_iszero(a) == MP_YES || mp_iszero(b) == MP_YES" 5312:*:0/1.
     * lcm(0,b): cond0 T. lcm(a,0): cond0 F, cond1 T. lcm(a,b): both F. */
    (void)mp_set(&a, 6);
    (void)mp_set(&b, 8);
    (void)mp_lcm(&zero, &b, &c);   /* iszero(a) T: cond0 T */
    (void)mp_lcm(&a, &zero, &c);   /* iszero(a) F, iszero(b) T: cond1 T */
    (void)mp_lcm(&a, &b, &c);      /* both F */

    /* mp_radix_size: "radix < MP_RADIX_BIN || radix > MP_RADIX_MAX" 5549:*:0 --
     * the radix<BIN half. radix 1 (< 2): cond0 T. radix 65 (> MAX): cond0 F,
     * cond1 T. radix 10 (valid): both F. */
    (void)mp_set(&a, 0x1234);
    (void)mp_radix_size(&a, 1, &size);              /* radix<BIN: cond0 T */
    (void)mp_radix_size(&a, 65, &size);             /* radix>MAX: cond1 T */
    (void)mp_radix_size(&a, MP_RADIX_DEC, &size);   /* both F */

    /* mp_toradix: same guard, its own copy 5610:*:0. */
    XMEMSET(buf, 0, sizeof(buf));
    (void)mp_toradix(&a, buf, 1);                   /* radix<BIN: cond0 T */
    (void)mp_toradix(&a, buf, 65);                  /* radix>MAX: cond1 T */
    XMEMSET(buf, 0, sizeof(buf));
    (void)mp_toradix(&a, buf, MP_RADIX_DEC);        /* both F */

    /* mp_add_d: "a->sign == MP_NEG && (a->used > 1 || a->dp[0] >= b)" 4549:*:1
     * -- the "a->used > 1" inner-OR operand. A negative TWO-digit value drives
     * used>1 T (inner OR T -> outer AND T, the |a|-b subtraction path). A
     * negative ONE-digit value with dp[0] < b drives used>1 F AND dp[0]>=b F
     * (inner OR F -> outer AND F), completing that operand's pair in-binary. */
    (void)mp_set(&a, 1);
    (void)mp_mul_2d(&a, (int)DIGIT_BIT, &a);  /* a = 2^DIGIT_BIT, used == 2 */
    a.sign = MP_NEG;
    (void)mp_add_d(&a, 1, &c);                /* NEG && used>1: cond1 T */
    (void)mp_set(&a, 5);
    a.sign = MP_NEG;                          /* a = -5, used == 1, dp[0]==5 */
    (void)mp_add_d(&a, 10, &c);               /* NEG, used>1 F, dp[0](5)>=10 F */

    mp_clear(&a); mp_clear(&b); mp_clear(&c); mp_clear(&y); mp_clear(&zero);
    WB_NOTE("argument residuals (exptmod/prime/lcm/radix/add_d) exercised");
}

/* ---- Constant-time modular helpers: mp_addmod_ct / mp_submod_ct /
 * mp_div_2_mod_ct. Each grows its output (or, when c == d, a temporary) to
 * the modulus size before the branchless loops, and that grow can return
 * MP_MEM; the inputs are only read. The NULL and negative rows give each
 * argument guard operand its TRUE side. ---- */
#define WB_CT_ADD   0
#define WB_CT_SUB   1
#define WB_CT_DIV2  2

/* Build the operands DISARMED; m is the P-256 prime. With fresh set, a, b and
 * d keep the dp == NULL that mp_init() leaves, so the inputs are read with no
 * allocation behind them. Otherwise a = 5 and b = 7, grown to m.used. Either
 * way the output's (or the c == d temporary's) grow is the only allocation.
 * Returns 0 on success. */
static int wb_ct_setup(mp_int* m, mp_int* a, mp_int* b, mp_int* d, int fresh)
{
    if (mp_init_multi(m, a, b, d, NULL, NULL) != MP_OKAY)
        return -1;
    if (mp_read_radix(m, "FFFFFFFF00000001000000000000000000000000FFFFFFFF"
            "FFFFFFFFFFFFFFFF", MP_RADIX_HEX) != MP_OKAY)
        goto fail;
    if (!fresh) {
        if ((mp_set(a, 5) != MP_OKAY) || (mp_set(b, 7) != MP_OKAY) ||
                (mp_grow(a, m->used) != MP_OKAY) ||
                (mp_grow(b, m->used) != MP_OKAY))
            goto fail;
    }
    return 0;
fail:
    mp_clear(m); mp_clear(a); mp_clear(b); mp_clear(d);
    return -1;
}

#ifndef MCDC_FA_UNAVAILABLE
static const char* const wb_ct_name[3] = {
    "mp_addmod_ct", "mp_submod_ct", "mp_div_2_mod_ct"
};

/* mp_div_2_mod_ct() has no d, so alias applies to add and sub only. */
static int wb_ct_call(int op, mp_int* a, mp_int* b, mp_int* m, mp_int* d,
    int alias)
{
    mp_int* out = alias ? m : d;

    if (op == WB_CT_ADD)
        return mp_addmod_ct(a, b, m, out);
    if (op == WB_CT_SUB)
        return mp_submod_ct(a, b, m, out);
    return mp_div_2_mod_ct(a, m, d);
}

/* Count the call's allocations unarmed, then fail each one in turn and
 * require MP_MEM; one past the count must succeed. The fresh case fails the
 * grow of d (c for mp_div_2_mod_ct); the c == d case fails the temporary's
 * grow, whose error path clears it. */
static void wb_ct_alloc_sweep(int op, int alias)
{
    mp_int m, a, b, d;
    unsigned long allocs;
    unsigned long want;
    unsigned long n;
    int r;

    want = 1;

    if (wb_ct_setup(&m, &a, &b, &d, !alias) != 0) {
        WB_NOTE("ct alloc sweep: setup failed, skipped");
        wb_fail = 1;
        return;
    }
    mcdc_fa_arm(1000000);
    r = wb_ct_call(op, &a, &b, &m, &d, alias);
    allocs = mcdc_fa_count;
    mcdc_fa_disarm();
    mp_clear(&m); mp_clear(&a); mp_clear(&b); mp_clear(&d);
    if ((r != MP_OKAY) || (allocs != want)) {
        printf("  [wb] %s alias %d: r %d, %lu allocations, expected %lu\n",
               wb_ct_name[op], alias, r, allocs, want);
        wb_fail = 1;
        return;
    }

    for (n = 1; n <= allocs + 1; n++) {
        if (wb_ct_setup(&m, &a, &b, &d, !alias) != 0) {
            wb_fail = 1;
            continue;
        }
        mcdc_fa_arm(n);
        r = wb_ct_call(op, &a, &b, &m, &d, alias);
        mcdc_fa_disarm();
        if (r != ((n <= allocs) ? WC_NO_ERR_TRACE(MP_MEM) : MP_OKAY)) {
            printf("  [wb] %s alias %d: fail-index %lu -> %d\n",
                   wb_ct_name[op], alias, n, r);
            wb_fail = 1;
        }
        mp_clear(&m); mp_clear(&a); mp_clear(&b); mp_clear(&d);
    }
    printf("  [wb] %s%s: %lu allocations, each failed in turn\n",
           wb_ct_name[op], alias ? " (c == d)" : "", allocs);
}
#endif

/* Each NULL, then each negative operand, in turn must return MP_VAL; the
 * sweep's successful calls give the all-FALSE row. */
static void wb_ct_null_args(void)
{
    mp_int m, a, b, d;
    mp_int* p[4];
    int k;

    if (wb_ct_setup(&m, &a, &b, &d, 0) != 0) {
        WB_NOTE("ct NULL args: setup failed, skipped");
        wb_fail = 1;
        return;
    }
    for (k = 0; k < 4; k++) {
        p[0] = &a; p[1] = &b; p[2] = &m; p[3] = &d;
        p[k] = NULL;
        if ((mp_addmod_ct(p[0], p[1], p[2], p[3]) !=
                WC_NO_ERR_TRACE(MP_VAL)) ||
                (mp_submod_ct(p[0], p[1], p[2], p[3]) !=
                WC_NO_ERR_TRACE(MP_VAL))) {
            printf("  [wb] ct add/sub NULL arg %d not rejected\n", k);
            wb_fail = 1;
        }
    }
    for (k = 0; k < 3; k++) {
        p[0] = &a; p[1] = &m; p[2] = &d;
        p[k] = NULL;
        if (mp_div_2_mod_ct(p[0], p[1], p[2]) != WC_NO_ERR_TRACE(MP_VAL)) {
            printf("  [wb] mp_div_2_mod_ct NULL arg %d not rejected\n", k);
            wb_fail = 1;
        }
    }
    for (k = 0; k < 2; k++) {
        p[0] = &a; p[1] = &b;
        p[k]->sign = MP_NEG;
        if ((mp_addmod_ct(&a, &b, &m, &d) != WC_NO_ERR_TRACE(MP_VAL)) ||
                (mp_submod_ct(&a, &b, &m, &d) != WC_NO_ERR_TRACE(MP_VAL))) {
            printf("  [wb] ct add/sub negative arg %d not rejected\n", k);
            wb_fail = 1;
        }
        p[k]->sign = MP_ZPOS;
    }
    a.sign = MP_NEG;
    if (mp_div_2_mod_ct(&a, &m, &d) != WC_NO_ERR_TRACE(MP_VAL)) {
        WB_NOTE("mp_div_2_mod_ct negative arg not rejected");
        wb_fail = 1;
    }
    a.sign = MP_ZPOS;
    mp_clear(&m); mp_clear(&a); mp_clear(&b); mp_clear(&d);
    WB_NOTE("ct NULL and sign argument guards exercised");
}

int main(int argc, char** argv)
{
    int do_sweep   = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    int do_probe   =  (argc > 1 && strcmp(argv[1], "probe") == 0);
    int n;
    int K = 24;   /* mp_div performs well under 24 allocations; over-sweep is
                   * harmless (indices past the last site run to completion). */

    printf("integer.c fault white-box (%s)\n",
           do_probe ? "probe" : (do_sweep ? "sweep" : "baseline"));

    mcdc_fa_install();

    /* ---- baseline: one unarmed successful mp_div supplies the all-FALSE half
     *      of every OR-chain operand's pair, plus the whole success body. ---- */
    if (one_div() != MP_OKAY) {
        printf("  baseline mp_div failed; skipping\n");
        mcdc_fa_restore();
        return 0;
    }

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Count mp_div's allocations without failing any (arm a huge index so
         * the counter advances but never trips). Sizes the sweep's K. */
        mp_int a, b, c, d;
        if (build_div_operands(&a, &b) == 0 &&
                mp_init(&c) == MP_OKAY && mp_init(&d) == MP_OKAY) {
            mcdc_fa_arm(1000000);
            (void)mp_div(&a, &b, &c, &d);
            printf("  PROBE mp_div allocs = %lu\n", mcdc_fa_count);
            mcdc_fa_disarm();
            mp_clear(&a); mp_clear(&b); mp_clear(&c); mp_clear(&d);
        }
        mcdc_fa_disarm();
        mcdc_fa_restore();
        return 0;
    }
#endif

    if (do_sweep) {
        /* --- mp_div fault-index sweep. Operands are rebuilt DISARMED each
         * iteration (a faulted mp_div may leave c/d partially built and its own
         * temps freed; the a/b inputs are untouched but rebuilt anyway for a
         * clean, independent trial). Fail-index n selects which allocation-
         * bearing op in the chain returns MP_MEM: as n walks 1..K it lands, in
         * turn, on the mp_abs(a)/mp_abs(b)/mp_mul_2d(tb)/mp_mul_2d(tq) setup
         * temps (1611:0-3) and the first-iteration mp_add(q) grow (1620:1),
         * driving each operand's TRUE side once. --- */
        for (n = 1; n <= K; n++) {
            mp_int a, b, c, d;

            if (build_div_operands(&a, &b) != 0) {
                wb_fail = 1;
                continue;
            }
            if (mp_init(&c) != MP_OKAY || mp_init(&d) != MP_OKAY) {
                mp_clear(&a); mp_clear(&b); mp_clear(&c); mp_clear(&d);
                wb_fail = 1;
                continue;
            }
            mcdc_fa_arm(n);
            (void)mp_div(&a, &b, &c, &d);
            mcdc_fa_disarm();
            mp_clear(&a); mp_clear(&b); mp_clear(&c); mp_clear(&d);
        }
        WB_NOTE("mp_div fault-index sweep done");

#ifndef MCDC_FA_UNAVAILABLE
        wb_ct_alloc_sweep(WB_CT_ADD, 0);
        wb_ct_alloc_sweep(WB_CT_ADD, 1);
        wb_ct_alloc_sweep(WB_CT_SUB, 0);
        wb_ct_alloc_sweep(WB_CT_SUB, 1);
        wb_ct_alloc_sweep(WB_CT_DIV2, 0);
#endif

        wb_argument_residuals();
        wb_ct_null_args();
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* heapmath backend selected */
