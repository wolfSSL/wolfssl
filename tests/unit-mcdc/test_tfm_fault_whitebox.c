/* test_tfm_fault_whitebox.c
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
 * Second MC/DC white-box supplement for wolfcrypt/src/tfm.c (FASTMATH
 * big-integer engine, bigint-tfm module). It complements
 * test_tfm_whitebox.c, which reaches the file-static helpers; this TU targets
 * the seven conditions that survived that driver, the tests/api
 * DecisionCoverage extensions and the four native build variants, and which
 * step 7 relabelled away from the (retired) "32-bit axis" residual class.
 *
 * Every section supplies BOTH halves of the targeted independence pair inside
 * THIS binary - llvm-cov computes MC/DC per binary and the campaign only
 * unions the "independence shown" bit by source line:col, so a rejection
 * vector without its accepting partner in the same binary proves nothing.
 *
 * ---------------------------------------------------------------------------
 * 1. fp_exptmod / fp_exptmod_ex / fp_exptmod_nct, negative-exponent branch
 *    2927:0, 3022:0, 3120:0   `if ((err == 0) && (P->sign == FP_NEG))`
 *
 *    The recorded recipe for these ("an mcdc_fault_alloc.h row hugging
 *    fp_exptmod_ex") and the model in test_tfm_whitebox.c's
 *    wb_TfmExptModDecisionCoverage ("call C: invmod fails (gcd=7), err==0 F")
 *    are BOTH wrong about where `err` comes from. The decision sits INSIDE
 *
 *        err = fp_invmod(&tmp[0], &tmp[1], &tmp[0]);
 *        if (err == FP_OKAY) {
 *           ...
 *           err = _fp_exptmod_ct/_nct(...);
 *           if ((err == 0) && (P->sign == FP_NEG)) { err = fp_add(Y, P, Y); }
 *        }
 *
 *    so an fp_invmod failure never REACHES line 2927 - it skips the whole
 *    block. The only `err` the decision can see is the exponentiation
 *    engine's, and that engine must fail with the invmod having SUCCEEDED.
 *
 *    No injector is needed. Both engines open with
 *        if ((err = fp_montgomery_setup(P, &mp)) != FP_OKAY) return err;
 *    and fp_montgomery_setup rejects an even modulus outright
 *    (tfm.c:3480 `b = a->dp[0]; if ((b & 1) == 0) return FP_VAL;`). A
 *    negative modulus with an EVEN magnitude therefore reaches the engine and
 *    fails it, while fp_invmod - which for an even modulus dispatches to
 *    fp_invmod_slow (tfm.c:1284) - still succeeds whenever gcd(G,|P|) == 1.
 *    G = 3, X = -3, P = -14: invmod(3,14) = 5, montgomery_setup(14) = FP_VAL,
 *    so `err == 0` is FALSE with the decision reached. P = -7 (odd) is the
 *    accepting partner: engine succeeds, P->sign == FP_NEG, decision TRUE.
 *
 * 2. fp_to_unsigned_bin_len trailing-significance check
 *    3988:0   `if ((i == a->used - 1) && ((a->dp[i] >> j) != 0))`
 *
 *    Crafted input, no injector. `i` is the digit cursor the copy loop stopped
 *    at. Its three reachable shapes are selected purely by the requested
 *    output length c against a->used:
 *      c == DIGIT_BIT/8 with used == 1: the loop consumes the whole digit and
 *        exits on `i < a->used`, leaving i == a->used, so `i == a->used - 1`
 *        is FALSE (cond0 F, cond1 unevaluated - the rejecting half);
 *      c == 2 with used == 1 and a < 2^16: loop exits on x < 0 with i == 0 ==
 *        used-1 and no significant bits left (cond0 T, cond1 F);
 *      c == DIGIT_BIT/8 with used == 2: i stops one digit short and the top
 *        digit is nonzero (cond0 T, cond1 T -> FP_VAL).
 *
 * 3. fp_isprime_ex Miller-Rabin error propagation
 *    5200:0   `if ((err != FP_OKAY) || (res == FP_NO))`
 *
 *    Crafted input, no injector. fp_prime_miller_rabin() forwards the return
 *    of fp_exptmod(b, r, a, y), whose modulus is the CANDIDATE a; fp_exptmod
 *    rejects `P->used > (FP_SIZE/2)` at tfm.c:2857. A candidate wider than
 *    FP_SIZE/2 digits that still survives the 256-entry trial-division loop
 *    above therefore makes the very first Miller-Rabin round return FP_VAL.
 *    A power of 1621 (the first prime ABOVE primes[FP_PRIME_SIZE-1] == 1619)
 *    is coprime to every table entry by construction, so it passes trial
 *    division for free. The accepting partners are ordinary calls on 1621
 *    (prime: err FP_OKAY, res FP_YES) and on 1621*1627 (composite that also
 *    survives trial division: err FP_OKAY, res FP_NO -> cond1's own pair).
 *
 * 4. fp_isprime_ex trial-division error propagation
 *    5188:0   `if (res != MP_OKAY || d == 0)`
 *
 *    fp_mod_d() is fp_div_d(), whose only non-FP_OKAY returns are FP_VAL for a
 *    zero divisor (primes[] contains none) and FP_MEM from its
 *    WC_ALLOC_VAR_EX scratch. That allocation exists ONLY under
 *    WOLFSSL_SMALL_STACK (types.h:983), so this operand is closable in the
 *    small_stack variant and there alone: mcdc_fault_alloc.h + a one-shot
 *    fail-index sweep. Under the other variants the sweep is inert (no
 *    allocation is issued inside fp_isprime_ex) and the calls simply run to
 *    completion, which is harmless. The all-FALSE partner is the unarmed call
 *    in section 3.
 *
 * 5. mp_prime_is_prime_ex random-base rejection
 *    5319:0   `if (fp_cmp_d(b, 2) != FP_GT || fp_cmp(b, c) != FP_LT)`
 *
 *    The base b is read from wc_RNG_GenerateBlock(), so `b <= 2` is a lottery
 *    - for the smallest candidate this loop will accept (11 bits, baseSz 2,
 *    top byte masked to 3 bits) it is a 3-in-2048 draw, and ASIL-D evidence
 *    cannot rest on a lottery. This TU interposes wc_RNG_GenerateBlock with a
 *    SCRIPTED byte stream (the mcdc_seed_rng.h macro trick, but with a chosen
 *    script rather than a SHAKE squeeze, because the target range is too
 *    narrow to hit by seed search and a script is reproducible by
 *    inspection):
 *        draw 1 -> b = 1     (cond0 TRUE  via fp_cmp_d == FP_LT)
 *        draw 2 -> b = 2     (cond0 TRUE  via fp_cmp_d == FP_EQ)
 *        draw 3 -> b = 2047  (cond0 FALSE, cond1 TRUE: b >= c == 1619)
 *        draw 4+ -> b = 5    (both FALSE: a real Miller-Rabin round, t--)
 *    The post-script filler is a valid base, so the `continue` loop always
 *    terminates. Disarmed, the hook is a straight pass-through to the real
 *    wc_RNG_GenerateBlock.
 * ---------------------------------------------------------------------------
 *
 * Crash safety: the crafted vectors are ordinary fp_int values built through
 * the fp_* API; the faulted vectors fail a single allocation whose caller
 * returns FP_MEM before initialising anything (WC_ALLOC_VAR_EX and
 * fp_prime_miller_rabin's XMALLOC both return immediately on NULL), and the
 * harness never dereferences a faulted call's output. Operands are rebuilt
 * while DISARMED on every iteration.
 *
 * Determinism: no wall clock, no live entropy on any measured path - the RNG
 * hook replaces the only randomness tfm.c consumes.
 *
 * It #includes tfm.c directly (like every other unit-mcdc white-box) to be the
 * single instrumented definition; the library's tfm.o is trimmed from the
 * archive at link time. main() always returns 0 - a nonzero exit makes the
 * campaign discard the whole variant.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/random.h>

/* Scripted RNG hook, declared while wc_RNG_GenerateBlock still means the real
 * thing (random.h is already in above, so its prototype is not rewritten). */
#ifndef WC_NO_RNG
static int mcdc_tfm_rng_block(WC_RNG* rng, byte* out, word32 sz);
#define wc_RNG_GenerateBlock(rng, out, sz) mcdc_tfm_rng_block((rng), (out), (sz))
#endif

#include <wolfcrypt/src/tfm.c>

#ifndef WC_NO_RNG
#undef wc_RNG_GenerateBlock
#endif

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
    #define WB_MAYBE_UNUSED __attribute__((unused))
#else
    #define WB_MAYBE_UNUSED
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* ------------------------------------------------------------------------ */
/* scripted RNG (section 5)                                                  */
/* ------------------------------------------------------------------------ */
#ifndef WC_NO_RNG

static int  mcdc_tfm_rng_armed = 0;
static word32 mcdc_tfm_rng_pos = 0;

/* Two bytes per draw; see section 5 of the header comment. */
static const byte mcdc_tfm_rng_script[] = {
    0x00, 0x01,   /* b = 1    */
    0x00, 0x02,   /* b = 2    */
    0x07, 0xff    /* b = 2047 */
};

WB_MAYBE_UNUSED static void mcdc_tfm_rng_arm(void)
{
    mcdc_tfm_rng_armed = 1;
    mcdc_tfm_rng_pos   = 0;
}

WB_MAYBE_UNUSED static void mcdc_tfm_rng_disarm(void)
{
    mcdc_tfm_rng_armed = 0;
    mcdc_tfm_rng_pos   = 0;
}

static int mcdc_tfm_rng_block(WC_RNG* rng, byte* out, word32 sz)
{
    word32 i;

    if (!mcdc_tfm_rng_armed)
        return wc_RNG_GenerateBlock(rng, out, sz);

    for (i = 0; i < sz; i++) {
        if (mcdc_tfm_rng_pos < (word32)sizeof(mcdc_tfm_rng_script)) {
            out[i] = mcdc_tfm_rng_script[mcdc_tfm_rng_pos++];
        }
        else {
            /* filler: a valid base (0x0005 big-endian) so the loop ends */
            out[i] = (byte)((i + 1 == sz) ? 0x05 : 0x00);
        }
    }
    return 0;
}

#endif /* !WC_NO_RNG */

#if !defined(USE_FAST_MATH)

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tfm.c fault white-box: USE_FAST_MATH not defined, nothing to do\n");
    (void)wb_fail;
    return 0;
}

#else /* USE_FAST_MATH */

/* ------------------------------------------------------------------------ */
/* 1. negative-exponent chain: err from the exponentiation engine (2927/3022/  */
/*    3120 cond 0)                                                            */
/* ------------------------------------------------------------------------ */
#ifndef POSITIVE_EXP_ONLY
static void wb_exptmod_engine_failure(void)
{
    fp_int g, x, p, y;

    XMEMSET(&g, 0, sizeof(g));
    XMEMSET(&x, 0, sizeof(x));
    XMEMSET(&p, 0, sizeof(p));
    XMEMSET(&y, 0, sizeof(y));

    /* --- accepting half: engine succeeds (err == 0 TRUE) and the modulus is
     * negative (cond1 TRUE) -> the fp_add(Y, P, Y) fixup runs. --- */
    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 7); fp_setneg(&p);
    printf("  [wb] fp_exptmod     G=3 X=-3 P=-7  -> %d (expect 0)\n",
           fp_exptmod(&g, &x, &p, &y));

    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 7); fp_setneg(&p);
    printf("  [wb] fp_exptmod_ex  G=3 X=-3 P=-7  -> %d (expect 0)\n",
           fp_exptmod_ex(&g, &x, x.used, &p, &y));

    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 7); fp_setneg(&p);
    printf("  [wb] fp_exptmod_nct G=3 X=-3 P=-7  -> %d (expect 0)\n",
           fp_exptmod_nct(&g, &x, &p, &y));

    /* --- rejecting half: |P| even, so fp_invmod still succeeds through
     * fp_invmod_slow (gcd(3,14) == 1) but fp_montgomery_setup rejects the
     * modulus inside _fp_exptmod_ct/_nct -> err == FP_VAL, cond0 FALSE. --- */
    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 14); fp_setneg(&p);
    printf("  [wb] fp_exptmod     G=3 X=-3 P=-14 -> %d (expect FP_VAL)\n",
           fp_exptmod(&g, &x, &p, &y));

    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 14); fp_setneg(&p);
    printf("  [wb] fp_exptmod_ex  G=3 X=-3 P=-14 -> %d (expect FP_VAL)\n",
           fp_exptmod_ex(&g, &x, x.used, &p, &y));

    fp_set(&g, 3); fp_set(&x, 3); fp_setneg(&x);
    fp_set(&p, 14); fp_setneg(&p);
    printf("  [wb] fp_exptmod_nct G=3 X=-3 P=-14 -> %d (expect FP_VAL)\n",
           fp_exptmod_nct(&g, &x, &p, &y));

    WB_NOTE("exptmod negative-exponent chain: engine-failure half exercised");
}
#endif /* !POSITIVE_EXP_ONLY */

/* ------------------------------------------------------------------------ */
/* 2. fp_to_unsigned_bin_len trailing check (3988 cond 0)                     */
/* ------------------------------------------------------------------------ */
#if DIGIT_BIT == 64 || DIGIT_BIT == 32 || DIGIT_BIT == 16
static void wb_to_unsigned_bin_len_tail(void)
{
    fp_int a;
    unsigned char buf[32];
    const int dbytes = (int)(DIGIT_BIT / 8);

    XMEMSET(&a, 0, sizeof(a));
    XMEMSET(buf, 0, sizeof(buf));

    /* cond0 FALSE: the copy loop consumes every digit and stops on
     * `i < a->used`, so i == a->used, one past `a->used - 1`. */
    fp_set(&a, 0x1234);
    printf("  [wb] to_unsigned_bin_len(0x1234, %d) -> %d (expect 0, cond0 F)\n",
           dbytes, fp_to_unsigned_bin_len(&a, buf, dbytes));

    /* cond0 TRUE, cond1 FALSE: the loop stops on x < 0 with i == a->used - 1
     * and the remaining high bits of the current digit are zero. */
    fp_set(&a, 0x1234);
    printf("  [wb] to_unsigned_bin_len(0x1234, 2) -> %d (expect 0, cond0 T"
           " cond1 F)\n", fp_to_unsigned_bin_len(&a, buf, 2));

    /* cond0 TRUE, cond1 TRUE: same stop, but a significant digit is left
     * unwritten -> FP_VAL. */
    fp_set(&a, 1);
    if (fp_mul_2d(&a, (int)DIGIT_BIT, &a) == FP_OKAY)
        printf("  [wb] to_unsigned_bin_len(2^DIGIT_BIT, %d) -> %d (expect"
               " FP_VAL, cond0 T cond1 T)\n", dbytes,
               fp_to_unsigned_bin_len(&a, buf, dbytes));
    else
        wb_fail = 1;

    WB_NOTE("fp_to_unsigned_bin_len trailing-significance vectors exercised");
}
#endif /* DIGIT_BIT in {64,32,16} */

/* ------------------------------------------------------------------------ */
/* 3./4. fp_isprime_ex (5200 cond 0, 5188 cond 0)                             */
/* ------------------------------------------------------------------------ */
#if !defined(NO_DH) || !defined(NO_DSA) || !defined(NO_RSA) || \
    defined(WOLFSSL_KEY_GEN)

/* First prime strictly above primes[FP_PRIME_SIZE-1] (0x0653 == 1619), so any
 * power of it survives the whole trial-division loop untouched. */
#define WB_TFM_BIG_PRIME  1621
#define WB_TFM_BIG_PRIME2 1627

/* a = WB_TFM_BIG_PRIME ^ k, k the smallest exponent with used > FP_SIZE/2.
 * Returns 0 on success. */
static int wb_build_oversized_candidate(fp_int* a)
{
    int guard = 0;

    fp_set(a, WB_TFM_BIG_PRIME);
    while (a->used <= (FP_SIZE / 2)) {
        if (fp_mul_d(a, WB_TFM_BIG_PRIME, a) != FP_OKAY)
            return -1;
        if (++guard > (FP_SIZE * DIGIT_BIT))   /* cannot loop forever */
            return -1;
    }
    return 0;
}

static void wb_isprime_ex_vectors(void)
{
    fp_int a;
    int    res = 0;
    int    rc;
    int    n;

    XMEMSET(&a, 0, sizeof(a));

    /* accepting half of BOTH decisions: a prime above the table. Every
     * fp_mod_d returns MP_OKAY with d != 0 (5188 F,F) and every Miller-Rabin
     * round returns FP_OKAY with res == FP_YES (5200 F,F). */
    fp_set(&a, WB_TFM_BIG_PRIME);
    rc = fp_isprime_ex(&a, 8, &res);
    printf("  [wb] fp_isprime_ex(1621) -> %d res %d (expect 0 / FP_YES)\n",
           rc, res);

    /* 5188 cond1 TRUE: divisible by a table prime -> d == 0. */
    fp_set(&a, WB_TFM_BIG_PRIME);
    if (fp_mul_d(&a, 3, &a) == FP_OKAY)
        (void)fp_isprime_ex(&a, 8, &res);

    /* 5200 cond1 TRUE: composite that still survives trial division, so a
     * Miller-Rabin round reports FP_NO with err == FP_OKAY. */
    fp_set(&a, WB_TFM_BIG_PRIME);
    if (fp_mul_d(&a, WB_TFM_BIG_PRIME2, &a) == FP_OKAY) {
        rc = fp_isprime_ex(&a, 8, &res);
        printf("  [wb] fp_isprime_ex(1621*1627) -> %d res %d (expect 0 /"
               " FP_NO)\n", rc, res);
    }

    /* 5200 cond0 TRUE: candidate wider than FP_SIZE/2 digits. fp_exptmod
     * inside the first Miller-Rabin round rejects it at tfm.c:2857 and
     * fp_prime_miller_rabin forwards FP_VAL. */
    if (wb_build_oversized_candidate(&a) == 0) {
        printf("  [wb] fp_isprime_ex(1621^k, used %d > FP_SIZE/2 %d) -> %d"
               " (expect FP_VAL)\n", a.used, (int)(FP_SIZE / 2),
               fp_isprime_ex(&a, 8, &res));
    }
    else
        wb_fail = 1;

    /* 5188 cond0 TRUE: the only failing return fp_mod_d has on this call site
     * is FP_MEM out of fp_div_d's WC_ALLOC_VAR_EX, which exists only under
     * WOLFSSL_SMALL_STACK. One-shot sweep so exactly one allocation fails per
     * call and the rest of the run stays healthy; inert (a plain successful
     * run) in variants where fp_isprime_ex allocates nothing. */
#ifndef MCDC_FA_UNAVAILABLE
    mcdc_fa_install();
    for (n = 1; n <= 4; n++) {
        fp_set(&a, WB_TFM_BIG_PRIME);
        mcdc_fa_arm_only(n);
        (void)fp_isprime_ex(&a, 8, &res);
        mcdc_fa_disarm();
    }
    /* indices past the 256-entry trial-division loop land on fp_isprime_ex's
     * own scratch and on fp_prime_miller_rabin's XMALLOC, a second (small
     * stack only) route to 5200 cond0. */
    for (n = 255; n <= 262; n++) {
        fp_set(&a, WB_TFM_BIG_PRIME);
        mcdc_fa_arm_only(n);
        (void)fp_isprime_ex(&a, 8, &res);
        mcdc_fa_disarm();
    }
    mcdc_fa_restore();
#else
    (void)n;
    WB_NOTE("allocation lever unavailable; 5188:0 not attempted");
#endif

    WB_NOTE("fp_isprime_ex trial-division / Miller-Rabin vectors exercised");
}

/* ------------------------------------------------------------------------ */
/* 5. mp_prime_is_prime_ex random-base rejection (5319 cond 0)                */
/* ------------------------------------------------------------------------ */
#if !defined(WC_NO_RNG) && !defined(FREESCALE_LTC_TFM)
static void wb_prime_is_prime_ex_base(void)
{
    WC_RNG rng;
    mp_int a;
    int    res = 0;
    int    rc;

    XMEMSET(&a, 0, sizeof(a));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; 5319:0 skipped");
        wb_fail = 1;
        return;
    }

    /* 1621: 11 bits -> baseSz 2, bitSz 3 (base[0] &= 7), c = a - 2 = 1619.
     * The scripted stream walks b = 1, 2, 2047 and then a run of valid
     * bases, so both operands of the base filter get both halves here. */
    fp_set(&a, WB_TFM_BIG_PRIME);
    mcdc_tfm_rng_arm();
    rc = mp_prime_is_prime_ex(&a, 2, &res, &rng);
    printf("  [wb] mp_prime_is_prime_ex(1621, scripted bases) -> %d res %d"
           " (expect 0 / FP_YES)\n", rc, res);
    mcdc_tfm_rng_disarm();

    wc_FreeRng(&rng);
    WB_NOTE("mp_prime_is_prime_ex scripted-base filter exercised");
}
#endif /* !WC_NO_RNG && !FREESCALE_LTC_TFM */

#endif /* prime helpers compiled */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tfm.c fault white-box MC/DC supplement\n");

    if (wolfCrypt_Init() != 0) {
        printf("  wolfCrypt_Init failed; nothing measured\n");
        return 0;
    }

#ifndef POSITIVE_EXP_ONLY
    wb_exptmod_engine_failure();
#endif
#if DIGIT_BIT == 64 || DIGIT_BIT == 32 || DIGIT_BIT == 16
    wb_to_unsigned_bin_len_tail();
#endif
#if !defined(NO_DH) || !defined(NO_DSA) || !defined(NO_RSA) || \
    defined(WOLFSSL_KEY_GEN)
    wb_isprime_ex_vectors();
#if !defined(WC_NO_RNG) && !defined(FREESCALE_LTC_TFM)
    wb_prime_is_prime_ex_base();
#endif
#endif

    (void)wolfCrypt_Cleanup();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures surface as skips, not failures: a nonzero exit makes the
     * campaign discard this variant's coverage. */
    return 0;
}

#endif /* USE_FAST_MATH */
