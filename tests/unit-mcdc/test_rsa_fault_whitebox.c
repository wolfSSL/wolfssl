/* test_rsa_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/rsa.c.
 *
 * rsa.c's dominant uncovered class (127 of 283 conditions before this file) is
 * the FALSE/failure half of allocation success chains that only diverge when an
 * EARLIER heap allocation fails, e.g.
 *
 *   RsaFunctionPrivate:  if ((rnd == NULL) || (rndi == NULL)) return MEMORY_E;
 *                        if (ret == 0 && mp_exptmod(tmp,&dQ,&q,tmpb) != MP_OKAY)
 *                        if ((ret == 0) && (mp_montgomery_setup(&n,&mp)!=MP_OKAY))
 *   RsaFunctionCheckIn:  if (ret == 0 && INIT_MP_INT_SIZE(c,..) != MP_OKAY)
 *   wc_CompareDiffPQ:    if (((c=XMALLOC..)==NULL) || ((d=XMALLOC..)==NULL))
 *   _CheckProbablePrime: if (((tmp1=XMALLOC..)==NULL) || ((tmp2=XMALLOC..)==NULL))
 *   wc_CheckProbablePrime_ex: if (((p=..)==NULL)||((q=..)==NULL)||((e=..)==NULL))
 *   wc_MakeRsaKey:       if ((p==NULL)||(q==NULL)||(tmp1==NULL)||(tmp2==NULL)||
 *                            (tmp3==NULL))
 *
 * In normal execution every allocation succeeds, so these decisions never take
 * the failure branch and neither the NULL-guard operands nor the "ret==0 &&
 * mp_op != MP_OKAY" cleanup halves are exercised. This white-box installs the
 * generic heap-fault injector (mcdc_fault_alloc.h) and sweeps the fail-index
 * across each entry point's allocation sites: for each index exactly one
 * earlier allocation returns NULL (or an mp_* op's internal scratch alloc
 * returns NULL, making the op return MEMORY_E), driving the failure operand at
 * that site and, in a following guard, the ret!=0 short-circuit half.
 *
 * These allocation sites only exist under WOLFSSL_SMALL_STACK (the mp_int/byte
 * temporaries are otherwise on the stack, and the mp scratch is stack when
 * WOLFSSL_SP_NO_MALLOC), so this supplement is only productive in the
 * small_stack variant; under the other variants it still builds and runs (the
 * sweep simply finds fewer heap sites to fault and the targets run to
 * completion), which is why it is safe to wire as a normal whitebox entry that
 * every variant compiles.  ==> wire it with the small_stack -D (see the
 * the module registry note at the end of this file's commit message).
 *
 * It #includes rsa.c directly (like the sibling test_rsa_whitebox.c and the
 * other unit-mcdc white-boxes) to reach the file-static wc_CompareDiffPQ /
 * _CheckProbablePrime / wc_CheckProbablePrime_ex and the SMALL_STACK cleanup.
 *
 * Crash-safety: every armed call either returns MEMORY_E before building any
 * mp_int, or fails a deeper allocation whose error the target's own cleanup
 * absorbs (that cleanup is exactly what is under test). The key/inputs are
 * prepared while DISARMED, and the harness never dereferences a value a faulted
 * call returned. Runs clean under -fsanitize=address.
 *
 * NOT alloc-related, therefore deliberately NOT targeted here (left to the
 * tests/api DecisionCoverage cases, reported out of scope in RESIDUALS.md):
 * the PKCS#1 v1.5 / OAEP / PSS pad+unpad data-path decisions (rsa.c ~1038,
 * 1530, 1731, 1796, 1939, 2045, 2058, 2150, 4524, 4554, 4594, 4655, 4715),
 * the async WC_PENDING_E dispatch decisions (3347/3368/3830/3849/4051/4156),
 * the RSA verify-decrypt padding comparisons (3584/3595/3631/4071/4074) and the
 * *_KeyDecodeRaw / CheckProbablePrime_ex argument guards (5293/5914/5996/6004).
 *
 * STRUCTURALLY UNSATISFIABLE (recorded in the exclusion record; line
 * numbers are rsa.c's). None of these is "hard to reach" -- each is an
 * argument that the missing row does not exist:
 *
 *   3356:1 3377:0 3640:1 (both records) 3846:1 3865:0 4074:1 4179:0
 *          the WC_PENDING_E sentinel. It can enter these `ret`s only from
 *          wc_RsaFunctionAsync() (3234, inside #if defined(WOLFSSL_ASYNC_
 *          CRYPT) && defined(WC_ASYNC_ENABLE_RSA)) or from wc_CryptoCb_Rsa()
 *          / wc_CryptoCb_RsaPad() (3571, inside #ifdef WOLF_CRYPTO_CB);
 *          5568 assigns it to wc_MakeRsaKey's own err, a different function,
 *          and no other callee on the path (RsaFunctionSync,
 *          wc_RsaFunctionNonBlock, which yields FP_WOULDBLOCK, and the
 *          mp_ / sp_ backends) produces the code. Neither macro is set by
 *          configs/rsa/user_settings.base.h or any variant's cppflags, and
 *          settings.h derives WOLF_CRYPTO_CB only from WOLF_CRYPTO_DEV.
 *          Confirmed against the measurement: no llvm-cov region exists for
 *          rsa.c:3557-3585 or rsa.c:3216-3300 in any variant or white-box.
 *
 *   5632:2 5642:0/1 5695:0/2 5698:0/1
 *          the FIPS 186-4 prime search. `i` is incremented only under
 *          HAVE_FIPS, so in this build it stays 0 while failCount is
 *          5 * (size / 2) > 0: `i >= failCount` / `i < failCount` never
 *          change value, and neither the p for(;;) nor the q do/while can
 *          exit with err == MP_OKAY && !isPrime, so both `if (err == MP_OKAY
 *          && !isPrime)` decisions are never true. 5695:0 is additionally
 *          preceded by `err = WC_CHECK_FOR_INTR_SIGNALS(); if (err != 0)
 *          break;`, so err is known zero where it is evaluated.
 *
 *   5677:0/1
 *          both operands need the (TRUE,TRUE) row. The Fermat block only
 *          runs with isPrime set, which _CheckProbablePrime() grants only
 *          after wc_CompareDiffPQ() showed |p-q| > 2^((size/2)-100), while
 *          the test needs |p-q| < 2^((size/4)+32). (size/2)-100 exceeds
 *          (size/4)+32 for every size > 528 and RsaSizeCheck() admits
 *          nothing below RSA_MIN_SIZE -- 2048 by default, 1024 in the
 *          min_size_1024 variant.
 *
 *   1036:1 `(word32)hLen > sizeof(tmpA)`: hLen is wc_HashGetDigestSize()'s
 *          result with the negative case already returned, so at most
 *          WC_MAX_DIGEST_SIZE (64), against tmpA[WC_MAX_DIGEST_SIZE + 4].
 *   4577:0 `WC_SAFE_SUM_WORD32(inSz, saltLen, totalSz) == 0`: inSz is pinned
 *          to digSz <= 64 by the argument check and every path leaves
 *          saltLen a non-negative int, so the word32 sum is at most
 *          64 + 2^31-1 and cannot wrap.
 *   5333:2 `qRaw == NULL` is the exact negation of the leading `qRaw !=
 *          NULL`, so no vector pair varies it alone.
 *   4097:1 `pad != NULL` cannot be false while ret >= 0: all four arms of
 *          wc_RsaUnPad_ex() set *out before returning a non-negative value.
 *
 * Invocation:
 *   ./test_rsa_fault_whitebox            default: full fault-index sweep
 *   ./test_rsa_fault_whitebox baseline   only the unarmed valid ops (delta base)
 *   ./test_rsa_fault_whitebox probe      per-entry-point allocation counts
 * (Default is the sweep so the run_whitebox harness -- which runs the
 * binary with NO arguments -- gets full coverage.)
 */

/* SECOND LEVER -- BIG-INTEGER FAULTS (mcdc_fault_mp.h)
 * ----------------------------------------------------
 * The heap sweep above cannot reach rsa.c's LARGEST residual class, the
 * RsaFunctionPrivate / RsaFunctionSync big-integer success chains:
 *
 *   if (ret == 0 && mp_exptmod(tmp, &key->dQ, &key->q, tmpb) != MP_OKAY)
 *   if (ret == 0 && mp_submod(tmpa, tmpb, &key->p, tmp) != MP_OKAY)
 *   if ((ret == 0) && (mp_montgomery_setup(&key->n, &mp) != MP_OKAY))
 *   if (ret == 0 && mp_read_unsigned_bin(tmp, in, inLen) != MP_OKAY)
 *   ... and the same shape all through wc_MakeRsaKey / _CheckProbablePrime
 *
 * On a healthy machine no mp_* call ever fails, so the `mp_xxx(..) != MP_OKAY`
 * operand is never TRUE and the `ret == 0` operand is never FALSE. The heap
 * lever cannot substitute: with the base config's SP backend the mp scratch is
 * not always heap, and even where it is, only the ALLOCATION can be failed,
 * never the computation. mcdc_fault_mp.h macro-interposes the value-returning
 * mp_* API for this translation unit only (installed BEFORE rsa.c is
 * #included) and mcdc_fm_arm(n) makes the n-th mp_* call -- and every later
 * one -- return MP_VAL. One sweep over n therefore drives BOTH operands of
 * every guard in the chain. Predicates (mp_iszero / mp_cmp / mp_count_bits)
 * and teardown (mp_clear / mp_forcezero) are NOT interposed, so cleanup keeps
 * working and every armed call stays crash-safe; mp_init / mp_init_multi are
 * likewise left alone (MCDC_FM_WITH_INIT is not defined) because rsa.c's
 * INIT_MP_INT_SIZE failure path still runs mp_forcezero() over the
 * unconstructed scratch.
 */
#include "mcdc_fault_mp.h"

/* mp_montgomery_reduce_ct is the one computation in RsaFunctionPrivate's
 * blinding-invert tail that mcdc_fault_mp.h does not interpose (it is a macro
 * in every backend rather than an entry point of its own). Wrapping it here,
 * on the shared mcdc_fm counter, keeps 3041's pair inside the same sweep. */
#ifdef mp_montgomery_reduce_ct
MCDC_FM_MAYBE_UNUSED static int mcdc_rsa_mont_red_ct(mp_int* a, mp_int* m,
    mp_digit rho)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_montgomery_reduce_ct(a, m, rho);
}
#undef  mp_montgomery_reduce_ct
#define mp_montgomery_reduce_ct(a, m, rho) mcdc_rsa_mont_red_ct((a), (m), (rho))
#endif

/* THIRD LEVER -- SCRATCH-mp_int LIFECYCLE (mcdc_fault_mpint.h)
 * -----------------------------------------------------------
 * Neither of the two levers above can make NEW_MP_INT_SIZE() or
 * INIT_MP_INT_SIZE() fail, and rsa.c hangs a success chain off each of them:
 *
 *   2890/2898  RsaFunctionPrivate  rnd / rndi   (blinding)
 *   2963/2968  RsaFunctionPrivate  tmpb         (CRT, no-blinding build)
 *   2981       RsaFunctionPrivate  first CRT exptmod behind that ret
 *   3071/3078  RsaFunctionSync     tmp
 *   3084       RsaFunctionSync     mp_read_unsigned_bin behind that ret
 *   3503/3508  RsaFunctionCheckIn  c
 *
 * INIT_MP_INT_SIZE resolves to mp_init_size()/mp_init() on storage the caller
 * already owns and cannot fail; NEW_MP_INT_SIZE is a real allocation only
 * under WOLFSSL_SMALL_STACK, and in every other build the NULL guard behind it
 * is not even compiled. So the failure operand of each of those guards is
 * never TRUE and the `ret == 0` operand of the guard that follows is never
 * FALSE. mcdc_fault_mpint.h interposes both macros for this translation unit
 * (installed BEFORE rsa.c is #included) and, where the build declares the
 * scratch on the stack, also compiles the NULL guard the SMALL_STACK builds
 * have. See its header comment for the availability table. */
#include "mcdc_fault_mpint.h"

/* mp_2expt is called from exactly one place in rsa.c: wc_CompareDiffPQ(), which
 * _CheckProbablePrime() only calls when its `q` argument is non-NULL -- that is,
 * from the SECOND (q) prime-search loop of wc_MakeRsaKey and never from the
 * first (p) one. A ONE-SHOT failure of it is therefore a phase-exact way to put
 * a rejected candidate into the q loop, which is what 5669 idx0
 * (`err == MP_OKAY` FALSE at the Fermat check) needs and nothing else can
 * supply: the loop is entered only after the p search has succeeded, so any
 * monotone injector fails the p search instead and the q loop is never reached.
 *
 * It must be one-shot for a second reason. The q loop overwrites `err` with
 * WC_CHECK_FOR_INTR_SIGNALS() before re-testing it, so a persistent failure
 * inside the loop body never terminates it -- the candidate is rejected, err is
 * reset to 0, and the loop runs again forever. Disarming on the first hit lets
 * the next candidate succeed and the key generation complete normally. */
static int mcdc_rsa_2expt_armed = 0;

MCDC_FM_MAYBE_UNUSED static int mcdc_rsa_2expt(mp_int* a, int b)
{
    if (mcdc_rsa_2expt_armed) {
        mcdc_rsa_2expt_armed = 0;
        return MCDC_FM_ERR;
    }
    return mp_2expt(a, b);
}
#undef  mp_2expt
#define mp_2expt(a, b) mcdc_rsa_2expt((a), (b))

#include <wolfcrypt/src/rsa.c>

#include "mcdc_fault_alloc.h"
#include <time.h>

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(NO_RSA) || !defined(WOLFSSL_KEY_GEN) || defined(WC_NO_RNG)

int main(void)
{
    printf("rsa.c fault white-box: NO_RSA / !WOLFSSL_KEY_GEN / WC_NO_RNG, "
           "nothing to do\n");
    return 0;
}

#else

#define WB_RSA_BITS   2048              /* RSA_MIN_SIZE in a non-wolfEngine build */
#define WB_RSA_BYTES  (WB_RSA_BITS / 8)

/* Sweep bound for the shallow entry points (public encrypt/verify, key export,
 * DER decode): a generous over-sweep past their deepest allocation site
 * (public encrypt probes at ~34 sites; over-sweeping is harmless -- once the
 * fail index is beyond the site count the target simply runs to completion). */
#define WB_SWEEP_K    64

/* The private path (RsaFunctionPrivate: blinding invmod/exptmod + CRT
 * dP/dQ/u exptmods + montgomery blinding-invert) drives ~5.8k internal sp_int
 * scratch allocations at 2048-bit under SMALL_STACK, and each guarded mp op's
 * failure half is only reached by faulting one of ITS scratch allocations. So
 * the private sweep must span the whole allocation depth to place a fault
 * inside every op's range (the deep montgomery guards 3013..3032 sit near the
 * very end). */
#define WB_PRIV_K     6200
/* Blinding draws a fresh RNG value each call, so the per-op allocation-index
 * boundaries drift run to run; a couple of reps lets the union reach the small
 * (few-alloc) submod/mul/add ops whose narrow index window a single pass with
 * drifting boundaries can skip. */
#define WB_PRIV_REP   2

/* ------------------------------------------------------------------------- *
 * Direct file-static targets: XMALLOC NULL-guards only reachable under
 * WOLFSSL_SMALL_STACK, whose callers always pass valid pointers so the failure
 * halves are white-box + fault-injection only.
 *
 * The XMALLOC NULL-guards in wc_CompareDiffPQ / _CheckProbablePrime /
 * wc_CheckProbablePrime_ex are fault-injection-only (callers always pass valid
 * pointers). Each operand is swept: idx0 by arm(1), idx1 by arm(2), idx2 by
 * arm(3). Faulting a later operand is crash-safe since PR 10973 fixed the
 * partial-OOM cleanup that had freed an allocated-but-uninitialized temp.
 * ------------------------------------------------------------------------- */
static void wb_static_compare_diff_pq(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* if (((c=XMALLOC..)==NULL) || ((d=XMALLOC..)==NULL)) ret = MEMORY_E; */
    mp_int p, q;
    int    valid = 0;

    if (mp_init(&p) != MP_OKAY) { WB_NOTE("mp_init(p) failed"); wb_fail = 1; return; }
    if (mp_init(&q) != MP_OKAY) { mp_clear(&p); WB_NOTE("mp_init(q) failed");
                                  wb_fail = 1; return; }
    (void)mp_set(&p, 3);
    (void)mp_set(&q, 5);

    mcdc_fa_arm(1);
    (void)wc_CompareDiffPQ(&p, &q, WB_RSA_BITS, &valid);   /* c==NULL: idx0 true */
    mcdc_fa_disarm();
    mcdc_fa_arm(2);
    (void)wc_CompareDiffPQ(&p, &q, WB_RSA_BITS, &valid);   /* d==NULL, c!=NULL: idx1 true */
    mcdc_fa_disarm();
    (void)wc_CompareDiffPQ(&p, &q, WB_RSA_BITS, &valid);   /* all-false */

    mp_clear(&p);
    mp_clear(&q);
    WB_NOTE("wc_CompareDiffPQ XMALLOC guard idx0+idx1 done");
#else
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; wc_CompareDiffPQ skipped");
#endif
}

static void wb_static_check_probable_prime(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* if (((tmp1=XMALLOC..)==NULL) || ((tmp2=XMALLOC..)==NULL)) goto notOkay; */
    mp_int p, e;
    int    isPrime = 0;

    if (mp_init(&p) != MP_OKAY) { WB_NOTE("mp_init(p) failed"); wb_fail = 1; return; }
    if (mp_init(&e) != MP_OKAY) { mp_clear(&p); WB_NOTE("mp_init(e) failed");
                                  wb_fail = 1; return; }
    (void)mp_set(&p, 101);
    (void)mp_set(&e, 65537);

    mcdc_fa_arm(1);
    (void)_CheckProbablePrime(&p, NULL, &e, 2048, &isPrime, NULL); /* tmp1==NULL: idx0 */
    mcdc_fa_disarm();
    mcdc_fa_arm(2);
    (void)_CheckProbablePrime(&p, NULL, &e, 2048, &isPrime, NULL); /* tmp2==NULL: idx1 */
    mcdc_fa_disarm();
    (void)_CheckProbablePrime(&p, NULL, &e, 2048, &isPrime, NULL); /* all-false */

    mp_clear(&p);
    mp_clear(&e);
    WB_NOTE("_CheckProbablePrime XMALLOC guard idx0+idx1 done");
#else
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; _CheckProbablePrime skipped");
#endif
}

static void wb_static_check_probable_prime_ex(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* if (((p=..)==NULL)||((q=..)==NULL)||((e=..)==NULL)) ret = MEMORY_E; */
    byte pRaw[8] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x65 };
    byte eRaw[3] = { 0x01,0x00,0x01 };
    int  isPrime = 0;

    mcdc_fa_arm(1);
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL); /* p==NULL: idx0 */
    mcdc_fa_disarm();
    mcdc_fa_arm(2);
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL); /* q==NULL: idx1 */
    mcdc_fa_disarm();
    mcdc_fa_arm(3);
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL); /* e==NULL: idx2 */
    mcdc_fa_disarm();
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL); /* all-false */
    WB_NOTE("wc_CheckProbablePrime_ex XMALLOC guard idx0+idx1+idx2 done");
#else
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; wc_CheckProbablePrime_ex skipped");
#endif
}

/* wc_MakeRsaKey line ~5456: the 5-way p/q/tmp1/tmp2/tmp3 XMALLOC NULL guard.
 * Failing alloc n (n<=5) selects exactly the n-th temp NULL -> MEMORY_E before
 * any prime search runs (cheap, no RNG draw). n=6..8 lets all five succeed
 * (all-false side of the guard) then faults the following mp_init_multi/buf so
 * keygen still aborts early rather than running the full slow generation. */
static void wb_makersakey_alloc_guard(WC_RNG* rng)
{
    RsaKey k2;
    int    n;

    for (n = 1; n <= 8; n++) {
        if (wc_InitRsaKey(&k2, NULL) != 0) { wb_fail = 1; continue; }
        mcdc_fa_arm(n);
        (void)wc_MakeRsaKey(&k2, 2048, 65537, rng);
        mcdc_fa_disarm();
        wc_FreeRsaKey(&k2);
    }
    WB_NOTE("wc_MakeRsaKey p/q/tmp* NULL-guard swept (n=1..8)");
}

/* ---------------------------------------------------------------------------
 * wc_RsaPSS_CheckPadding_ex2() long-salt scratch buffer (WOLFSSL_PSS_LONG_SALT)
 *
 *   4586:  if ((ret == 0) && (sizeof(sigCheckBuf) < (RSA_PSS_PAD_SZ + inSz +
 *                                                    (word32)saltLen)))
 *   4617:  if (sigCheck != NULL && sigCheck != sigCheckBuf)
 *
 * sigCheck starts as the on-stack sigCheckBuf (WC_MAX_DIGEST_SIZE*2 +
 * RSA_PSS_PAD_SZ = 136 bytes) and is only replaced by an XMALLOC'd buffer when
 * the salt pushes 8 + inSz + saltLen past that. Three same-binary vectors:
 *
 *   short salt      -> sigCheck == sigCheckBuf     4617 (T,F) -> F
 *   long salt, OK   -> sigCheck == heap buffer     4617 (T,T) -> T
 *   long salt, OOM  -> sigCheck == NULL            4617 (F,-) -> F
 *
 * and for 4586 the same calls give (T,F)/(T,T) plus a pre-rejected call
 * (in==NULL sets ret=BAD_FUNC_ARG upstream) for the (F,-) half.
 *
 * Sizing: SHA-512 digest (inSz 64) with saltLen 70 -> 8+64+70 = 142 > 136, so
 * the heap path is taken; sigSz must equal inSz+saltLen = 134, and the code
 * reads sig[saltLen .. saltLen+inSz), so the sig buffer is 134 bytes. The
 * padding never verifies (the input is not a real PSS block) -- BAD_PADDING_E
 * is the expected, harmless outcome; only the buffer-selection decisions
 * matter here. The OOM vector is armed around this ONE call with everything
 * else built while disarmed.
 * ------------------------------------------------------------------------ */
#if defined(WOLFSSL_PSS_LONG_SALT) && defined(WC_RSA_PSS)
static void wb_pss_checkpadding_sigcheck(void)
{
    byte in[WC_MAX_DIGEST_SIZE];
    byte sig[WC_MAX_DIGEST_SIZE * 2 + 16];
    int  digSz;

#ifdef WOLFSSL_SHA512
    const enum wc_HashType ht = WC_HASH_TYPE_SHA512;
    const int longSalt = 70;
#else
    const enum wc_HashType ht = WC_HASH_TYPE_SHA256;
    const int longSalt = 110;   /* 8 + 32 + 110 = 150 > 136 */
#endif

    XMEMSET(in, 0x5a, sizeof(in));
    XMEMSET(sig, 0xa5, sizeof(sig));

    digSz = wc_HashGetDigestSize(ht);
    if (digSz <= 0 || (word32)(digSz + longSalt) > (word32)sizeof(sig)) {
        WB_NOTE("PSS long-salt sizing unavailable; sigCheck check skipped");
        return;
    }

    /* (F,-) half of 4586: rejected upstream, ret != 0 at the size test. */
    (void)wc_RsaPSS_CheckPadding_ex2(NULL, (word32)digSz, sig,
        (word32)digSz * 2, ht, digSz, 0, NULL);

    /* short salt: stack buffer, 4586 (T,F) / 4617 (T,F). */
    (void)wc_RsaPSS_CheckPadding_ex2(in, (word32)digSz, sig,
        (word32)(digSz * 2), ht, digSz, 0, NULL);

    /* long salt, allocation succeeds: 4586 (T,T) / 4617 (T,T). */
    (void)wc_RsaPSS_CheckPadding_ex2(in, (word32)digSz, sig,
        (word32)(digSz + longSalt), ht, longSalt, 0, NULL);

#ifndef MCDC_FA_UNAVAILABLE
    /* long salt, allocation fails: sigCheck == NULL -> 4617 (F,-). Armed
     * around this single call only; nothing built here needs the heap. */
    mcdc_fa_arm(1);
    (void)wc_RsaPSS_CheckPadding_ex2(in, (word32)digSz, sig,
        (word32)(digSz + longSalt), ht, longSalt, 0, NULL);
    mcdc_fa_disarm();
#endif

    WB_NOTE("wc_RsaPSS_CheckPadding_ex2 sigCheck stack/heap/NULL pairs done");
}
#else
static void wb_pss_checkpadding_sigcheck(void)
{ WB_NOTE("WOLFSSL_PSS_LONG_SALT/WC_RSA_PSS off; sigCheck check skipped"); }
#endif

/* ---------------------------------------------------------------------------
 * FIPS 186-4 section 5.5 item (e): the default PSS salt length is the hash
 * length EXCEPT for a 1024-bit modulus with SHA-512, where it is clamped to
 * RSA_PSS_SALT_MAX_SZ. The guard
 *
 *     if (bits == 1024 && hLen == WC_SHA512_DIGEST_SIZE)
 *
 * appears in RsaUnPad_PSS and in both wc_RsaPSS_VerifyCheck* entry points,
 * and every one of them is residual because the suite only ever signs with a
 * 2048-bit key: the first operand is never TRUE. Three vectors give both
 * operands their independence pair:
 *
 *     1024-bit key + SHA-512  -> (T,T)
 *     1024-bit key + SHA-256  -> (T,F)
 *     2048-bit key + SHA-512  -> (F,-)
 *
 * A 1024-bit key is only accepted where RSA_MIN_SIZE allows it (the
 * min_size_1024 variant), which is enough: a condition counts as covered in
 * the union as soon as ONE build that compiles it demonstrates the pair.
 * ------------------------------------------------------------------------- */
#if defined(WC_RSA_PSS) && defined(WOLFSSL_SHA512) && \
    defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && (RSA_MIN_SIZE <= 1024)
static void wb_pss_saltlen_1024_sha512(RsaKey* key2048, WC_RNG* rng)
{
    RsaKey k1024;
    byte   sig[256];
    byte   out[256];
    byte   dig[WC_SHA512_DIGEST_SIZE];
    int    sz;
    int    inited = 0;

    XMEMSET(&k1024, 0, sizeof(k1024));
    XMEMSET(dig, 0x5c, sizeof(dig));

    if (wc_InitRsaKey(&k1024, NULL) != 0) {
        wb_fail = 1;
        return;
    }
    inited = 1;
    if (wc_MakeRsaKey(&k1024, 1024, 65537, rng) != 0) {
        WB_NOTE("1024-bit keygen refused; PSS salt-length vectors skipped");
        wb_fail = 1;
        goto out;
    }

    /* (T,T): 1024-bit modulus, SHA-512 digest -> clamped salt length */
    sz = wc_RsaPSS_Sign(dig, WC_SHA512_DIGEST_SIZE, sig, sizeof(sig),
                        WC_HASH_TYPE_SHA512, WC_MGF1SHA512, &k1024, rng);
    if (sz > 0) {
        (void)wc_RsaPSS_VerifyCheck(sig, (word32)sz, out, sizeof(out),
                                    dig, WC_SHA512_DIGEST_SIZE,
                                    WC_HASH_TYPE_SHA512, WC_MGF1SHA512,
                                    &k1024);
        {   /* the Inline form carries its own copy of the same guard */
            byte  in2[256];
            byte* p = NULL;
            XMEMCPY(in2, sig, (size_t)sz);
            (void)wc_RsaPSS_VerifyCheckInline(in2, (word32)sz, &p,
                                              dig, WC_SHA512_DIGEST_SIZE,
                                              WC_HASH_TYPE_SHA512,
                                              WC_MGF1SHA512, &k1024);
        }
    }
    else {
        wb_fail = 1;
    }

    /* (T,F): same 1024-bit modulus, SHA-256 digest -> salt stays hLen */
    sz = wc_RsaPSS_Sign(dig, WC_SHA256_DIGEST_SIZE, sig, sizeof(sig),
                        WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &k1024, rng);
    if (sz > 0) {
        (void)wc_RsaPSS_VerifyCheck(sig, (word32)sz, out, sizeof(out),
                                    dig, WC_SHA256_DIGEST_SIZE,
                                    WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                    &k1024);
        {
            byte  in2[256];
            byte* p = NULL;
            XMEMCPY(in2, sig, (size_t)sz);
            (void)wc_RsaPSS_VerifyCheckInline(in2, (word32)sz, &p,
                                              dig, WC_SHA256_DIGEST_SIZE,
                                              WC_HASH_TYPE_SHA256,
                                              WC_MGF1SHA256, &k1024);
        }
    }
    else {
        wb_fail = 1;
    }

    /* (F,-): the 2048-bit key already built by main, SHA-512 digest */
    sz = wc_RsaPSS_Sign(dig, WC_SHA512_DIGEST_SIZE, sig, sizeof(sig),
                        WC_HASH_TYPE_SHA512, WC_MGF1SHA512, key2048, rng);
    if (sz > 0) {
        (void)wc_RsaPSS_VerifyCheck(sig, (word32)sz, out, sizeof(out),
                                    dig, WC_SHA512_DIGEST_SIZE,
                                    WC_HASH_TYPE_SHA512, WC_MGF1SHA512,
                                    key2048);
        {
            byte  in2[256];
            byte* p = NULL;
            XMEMCPY(in2, sig, (size_t)sz);
            (void)wc_RsaPSS_VerifyCheckInline(in2, (word32)sz, &p,
                                              dig, WC_SHA512_DIGEST_SIZE,
                                              WC_HASH_TYPE_SHA512,
                                              WC_MGF1SHA512, key2048);
        }
    }

    WB_NOTE("PSS FIPS 5.5(e) 1024-bit/SHA-512 salt-length vectors done");

out:
    if (inited)
        wc_FreeRsaKey(&k1024);
}
#else
static void wb_pss_saltlen_1024_sha512(RsaKey* key2048, WC_RNG* rng)
{
    (void)key2048; (void)rng;
    WB_NOTE("PSS/SHA-512/keygen off or RSA_MIN_SIZE > 1024; 5.5(e) skipped");
}
#endif

/* ---------------------------------------------------------------------------
 * RsaFunctionPrivate 2946: the five mp_iszero() CRT-component operands
 *
 *   if (ret == 0 && (mp_iszero(&key->p) || mp_iszero(&key->q) ||
 *           mp_iszero(&key->dP) || mp_iszero(&key->dQ) || mp_iszero(&key->u)))
 *
 * Every key the API can produce carries a complete CRT set, so operands 1..5
 * are all-FALSE forever and the non-CRT fallback exptmod is dead code from the
 * public surface. A white-box can build the missing halves directly: five
 * scratch keys, each a copy of the good key with exactly ONE component left at
 * its post-wc_InitRsaKey zero, so in key i the i-th mp_iszero is the FIRST
 * TRUE operand of the chain (every earlier one FALSE) -- the exact
 * independence vector for that operand, with the all-FALSE partner supplied by
 * every ordinary private op in this same binary.
 *
 * Scratch keys, never the shared one: the mutation is destructive, and the
 * blinding/CRT ops that follow would be wrong for every later case.
 * RsaFunctionPrivate is called directly (it is file-static, and the public
 * entry points reject a key with a zero p before reaching it).
 * ------------------------------------------------------------------------ */
#if !defined(WOLFSSL_SP_MATH) && !defined(RSA_LOW_MEM) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
static void wb_priv_zero_crt_components(RsaKey* key, WC_RNG* rng)
{
    int i;

    for (i = 0; i < 5; i++) {
        RsaKey zk;
        mp_int tmp;

        if (wc_InitRsaKey(&zk, NULL) != 0) { wb_fail = 1; continue; }
        if ((mp_copy(&key->n, &zk.n) != MP_OKAY) ||
            (mp_copy(&key->e, &zk.e) != MP_OKAY) ||
            (mp_copy(&key->d, &zk.d) != MP_OKAY)) {
            wc_FreeRsaKey(&zk);
            wb_fail = 1;
            continue;
        }
        /* everything but the i-th component; the i-th stays zero */
        if (i != 0) (void)mp_copy(&key->p,  &zk.p);
        if (i != 1) (void)mp_copy(&key->q,  &zk.q);
        if (i != 2) (void)mp_copy(&key->dP, &zk.dP);
        if (i != 3) (void)mp_copy(&key->dQ, &zk.dQ);
        if (i != 4) (void)mp_copy(&key->u,  &zk.u);

        if (mp_init(&tmp) == MP_OKAY) {
            /* any residue < n; the fallback path is a plain tmp^d mod n */
            (void)mp_set(&tmp, 42);
            (void)RsaFunctionPrivate(&tmp, &zk, rng);
            mp_forcezero(&tmp);
        }
        wc_FreeRsaKey(&zk);
    }
    WB_NOTE("RsaFunctionPrivate zero-p/q/dP/dQ/u vectors done");
}
#else
static void wb_priv_zero_crt_components(RsaKey* key, WC_RNG* rng)
{
    (void)key; (void)rng;
    WB_NOTE("SP_MATH / LOW_MEM / reduced-surface build; zero-CRT vectors n/a");
}
#endif

/* ---------------------------------------------------------------------------
 * Padding-helper data vectors (no fault injection needed -- these operands are
 * simply never produced by a well-formed block or a well-formed argument set,
 * and the helpers are file-static or take the deciding value as a plain
 * parameter, so only a white-box can supply them).
 *
 *   2043 idx1  pkcsBlock[1] != RSA_BLOCK_TYPE_1 with pkcsBlock[0] == 0
 *   2056 idx0  separator found before RSA_MIN_PAD_SZ bytes of padding
 *   2056 idx1  >= RSA_MIN_PAD_SZ bytes but the byte before the run end != 0
 *   1794 idx0  RsaUnPad_OAEP with an unusable hash type (digest size < 0)
 *   1794 idx1  usable hash, but pkcsBlockLen < 2*hLen + 2
 *   1729 idx0/1  wc_RsaPad_ex(WC_RSA_NO_PAD) with bits <= 0 / a length mismatch
 *   2148 idx0/1  the same pair on the un-pad side
 *   4547 idx0/1  wc_RsaPSS_CheckPadding_ex2's FIPS 186-4 5.5(e) salt reduction:
 *                `bits` is a plain parameter here, so the 1024-bit half needs
 *                no 1024-bit key and no RSA_MIN_SIZE override
 *   1528 idx1 / 1937 idx1  the same 5.5(e) test inside RsaPad_PSS /
 *                RsaUnPad_PSS, both file-static and both taking `bits`
 *                directly: hLen is varied (SHA-512 vs SHA-256) with bits
 *                pinned at 1024 to flip operand 1 alone.
 *
 * Every vector's accepting partner is produced by the ordinary sign / verify /
 * encrypt / decrypt traffic earlier in this same binary.
 * ------------------------------------------------------------------------ */
static void wb_pad_unpad_vectors(WC_RNG* rng)
{
    byte blk[512];
    byte out[512];
    const byte* cp = NULL;
    byte*  op = NULL;

    XMEMSET(blk, 0, sizeof(blk));
    XMEMSET(out, 0, sizeof(out));

#ifndef WOLFSSL_RSA_VERIFY_ONLY
    /* --- RsaUnPad block-type-1 formatting guards ------------------------- */
    blk[0] = 0x00; blk[1] = 0x02;          /* 2043: idx0 F, idx1 T */
    (void)RsaUnPad(blk, 64, &cp, RSA_BLOCK_TYPE_1);

    blk[0] = 0x00; blk[1] = 0x01; blk[2] = 0x00;
    (void)RsaUnPad(blk, 64, &cp, RSA_BLOCK_TYPE_1);   /* 2056: idx0 T */

    XMEMSET(blk, 0, sizeof(blk));
    blk[0] = 0x00; blk[1] = 0x01;
    XMEMSET(blk + 2, 0xFF, 9);             /* indices 2..10 */
    blk[11] = 0xAA;                        /* run ends at i=12, blk[11] != 0 */
    (void)RsaUnPad(blk, 64, &cp, RSA_BLOCK_TYPE_1);   /* 2056: idx0 F, idx1 T */
#endif

#if !defined(WC_NO_RSA_OAEP) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    /* --- RsaUnPad_OAEP digest-size / block-length guard ------------------- */
    XMEMSET(blk, 0, sizeof(blk));
    /* idx0 T: wc_HashGetDigestSize(WC_HASH_TYPE_NONE) is negative */
    (void)RsaUnPad_OAEP(blk, 64, &op, WC_HASH_TYPE_NONE, WC_MGF1SHA256,
                        NULL, 0, NULL);
    /* idx0 F, idx1 T: SHA-256 needs at least 2*32+2 = 66 bytes */
    (void)RsaUnPad_OAEP(blk, 8, &op, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                        NULL, 0, NULL);
#endif

#ifdef WC_RSA_NO_PADDING
    /* --- the no-padding exact-length guards, pad and un-pad side ---------- */
    XMEMSET(blk, 0x5a, sizeof(blk));
    /* 1729 idx0 T (bits <= 0) */
    (void)wc_RsaPad_ex(blk, 256, out, sizeof(out), RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_NO_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                       NULL, 0, 0, 0, NULL);
    /* 1729 idx0 F, idx1 T (2048 bits wants exactly 256 input bytes) */
    (void)wc_RsaPad_ex(blk, 128, out, sizeof(out), RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_NO_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                       NULL, 0, 0, 2048, NULL);
    /* 1729 all-false partner */
    (void)wc_RsaPad_ex(blk, 256, out, sizeof(out), RSA_BLOCK_TYPE_2, rng,
                       WC_RSA_NO_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                       NULL, 0, 0, 2048, NULL);

    op = NULL;
    /* 2148 idx0 T */
    (void)wc_RsaUnPad_ex(blk, 256, &op, RSA_BLOCK_TYPE_2, WC_RSA_NO_PAD,
                         WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0, 0, 0,
                         NULL);
    /* 2148 idx0 F, idx1 T */
    (void)wc_RsaUnPad_ex(blk, 128, &op, RSA_BLOCK_TYPE_2, WC_RSA_NO_PAD,
                         WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0, 0, 2048,
                         NULL);
    /* 2148 all-false partner */
    (void)wc_RsaUnPad_ex(blk, 256, &op, RSA_BLOCK_TYPE_2, WC_RSA_NO_PAD,
                         WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0, 0, 2048,
                         NULL);
#endif /* WC_RSA_NO_PADDING */

#if defined(WC_RSA_PSS) && defined(WOLFSSL_SHA512)
    {
        byte  in512[WC_SHA512_DIGEST_SIZE];
        byte  in256[WC_SHA256_DIGEST_SIZE];
        byte  sig[WC_SHA512_DIGEST_SIZE * 2];

        XMEMSET(in512, 0x5a, sizeof(in512));
        XMEMSET(in256, 0x5a, sizeof(in256));
        XMEMSET(sig,   0xa5, sizeof(sig));

        /* 4547 (T,T): bits == 1024 AND inSz == SHA-512 digest size. */
        (void)wc_RsaPSS_CheckPadding_ex2(in512, sizeof(in512), sig,
            (word32)(RSA_PSS_SALT_MAX_SZ + (int)sizeof(in512)),
            WC_HASH_TYPE_SHA512, RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);
        /* 4547 (F,-): same call at 2048 bits. */
        (void)wc_RsaPSS_CheckPadding_ex2(in512, sizeof(in512), sig,
            (word32)(2 * sizeof(in512)), WC_HASH_TYPE_SHA512,
            RSA_PSS_SALT_LEN_DEFAULT, 2048, NULL);
        /* 4547 (T,F): 1024 bits but a SHA-256 digest. */
        (void)wc_RsaPSS_CheckPadding_ex2(in256, sizeof(in256), sig,
            (word32)(2 * sizeof(in256)), WC_HASH_TYPE_SHA256,
            RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);

#ifndef WC_NO_RNG
        /* 1528 idx1: RsaPad_PSS's own copy of the 5.5(e) test. bits pinned at
         * 1024 for both calls so ONLY hLen differs -- that is the operand-1
         * independence pair. The block never has to verify; the salt-length
         * selection happens before any of that. */
        (void)RsaPad_PSS(in512, sizeof(in512), out, 128, rng,
                         WC_HASH_TYPE_SHA512, WC_MGF1SHA512,
                         RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);
        (void)RsaPad_PSS(in256, sizeof(in256), out, 128, rng,
                         WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                         RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);
#endif
        /* 1937 idx1: the same test inside RsaUnPad_PSS. */
        XMEMSET(blk, 0xbc, 128);
        op = NULL;
        (void)RsaUnPad_PSS(blk, 128, &op, WC_HASH_TYPE_SHA512, WC_MGF1SHA512,
                           RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);
        op = NULL;
        (void)RsaUnPad_PSS(blk, 128, &op, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                           RSA_PSS_SALT_LEN_DEFAULT, 1024, NULL);
    }
#endif /* WC_RSA_PSS && WOLFSSL_SHA512 */

    (void)rng; (void)cp; (void)op;
    WB_NOTE("pad/un-pad formatting + FIPS 5.5(e) salt vectors done");
}

/* ---------------------------------------------------------------------------
 * RsaPublicEncryptEx 3707 idx0: `sz < RSA_MIN_PAD_SZ`.
 *
 * sz is wc_RsaEncryptSize(key) = the byte length of n, and every key the API
 * can build is at least RSA_MIN_SIZE bits, so the guard is dead from outside.
 * A scratch key whose n is a single byte makes sz == 1 and drives operand 0
 * TRUE; the FALSE-FALSE partner is every real encrypt in this binary. (The
 * upper operand `sz > RSA_MAX_SIZE/8` is NOT attempted: n would have to exceed
 * the math backend's own maximum bit width, so mp_read cannot build one --
 * recorded as a residual rather than a gap.)
 * ------------------------------------------------------------------------ */
static void wb_encryptsize_lower_bound(WC_RNG* rng)
{
#ifndef WOLFSSL_RSA_VERIFY_ONLY
    RsaKey sk;
    byte   in[4];
    byte   out[64];

    XMEMSET(in, 0x11, sizeof(in));
    XMEMSET(out, 0, sizeof(out));

    if (wc_InitRsaKey(&sk, NULL) != 0) { wb_fail = 1; return; }
    if ((mp_set(&sk.n, 0x0b) == MP_OKAY) && (mp_set(&sk.e, 3) == MP_OKAY)) {
        sk.type = RSA_PUBLIC;
        (void)wc_RsaPublicEncrypt(in, 1, out, sizeof(out), &sk, rng);
    }
    else {
        wb_fail = 1;
    }
    wc_FreeRsaKey(&sk);
    WB_NOTE("RsaPublicEncryptEx sz < RSA_MIN_PAD_SZ vector done");
#else
    (void)rng;
#endif
}

/* ---------------------------------------------------------------------------
 * SCRATCH-mp_int LIFECYCLE SWEEPS (mcdc_fault_mpint.h)
 *
 *   2890 idx0/idx1  (rnd == NULL) || (rndi == NULL)
 *   2898 idx0/idx1  (INIT(rnd) not MP_OKAY) || (INIT(rndi) not MP_OKAY)
 *   2968 idx0/idx1  (ret == 0) && INIT(tmpb) not MP_OKAY      (no-blinding)
 *   2981 idx0       ret == 0 && mp_exptmod(..,tmpb) not MP_OKAY
 *   3084 idx0       ret == 0 && mp_read_unsigned_bin(tmp,..) not MP_OKAY
 *   3508 idx0/idx1  ret == 0 && INIT(c) not MP_OKAY
 *
 * Each entry point is run DISARMED first: that supplies the accepting half of
 * every one of those guards IN THIS BINARY and, at the same time, MEASURES how
 * many lifecycle calls the entry point makes, which is the exact sweep length
 * (no over-sweep, no wall clock -- the bound is a counted property of the code
 * under test, so the same source always measures the same).
 *
 * Then the fail index is swept over [1..K] in both flavours:
 *   - monotone (fail from n on): index n drives the failure operand at the n-th
 *     site and the `ret == 0` operand FALSE at every guard downstream of it;
 *   - one-shot (fail ONLY n): needed where the monotone arm would null an
 *     EARLIER pointer of the same guard and short-circuit it -- 2890's
 *     (rnd == NULL) || (rndi == NULL) is exactly that shape, since the arm that
 *     nulls rndi also nulls rnd.
 *
 * Every armed call is crash-safe: a faulted INIT leaves the object zeroed
 * (which is what teardown expects) and the caller skips every operation on it,
 * and a faulted NEW leaves a NULL the caller must test before use.
 * ------------------------------------------------------------------------ */
#define WB_FMI_SWEEP(lbl, ...)                                            \
    do {                                                                  \
        long k_, i_;                                                      \
        mcdc_fmi_disarm();                                                \
        { __VA_ARGS__; }                                                  \
        k_ = mcdc_fmi_init_seen();                                        \
        for (i_ = 1; i_ <= k_; i_++) {                                    \
            mcdc_fmi_arm_init(i_);                                        \
            { __VA_ARGS__; }                                              \
            mcdc_fmi_disarm();                                            \
            mcdc_fmi_arm_init_only(i_);                                   \
            { __VA_ARGS__; }                                              \
            mcdc_fmi_disarm();                                            \
        }                                                                 \
        printf("  [wb] mpint INIT sweep %s: K=%ld\n", (lbl), k_);         \
        mcdc_fmi_disarm();                                                \
        { __VA_ARGS__; }                                                  \
        k_ = mcdc_fmi_new_seen();                                         \
        for (i_ = 1; i_ <= k_; i_++) {                                    \
            mcdc_fmi_arm_new(i_);                                         \
            { __VA_ARGS__; }                                              \
            mcdc_fmi_disarm();                                            \
            mcdc_fmi_arm_new_only(i_);                                    \
            { __VA_ARGS__; }                                              \
            mcdc_fmi_disarm();                                            \
        }                                                                 \
        printf("  [wb] mpint NEW  sweep %s: K=%ld\n", (lbl), k_);         \
        mcdc_fmi_disarm();                                                \
    } while (0)

static void wb_mpint_lifecycle(RsaKey* key, WC_RNG* rng, const byte* msg,
                               word32 msgLen, const byte* ct, int ctLen,
                               const byte* sig, int sigLen)
{
    byte o[WB_RSA_BYTES];

    printf("  [wb] mpint lever: INIT %s, NEW %s\n",
           mcdc_fmi_init_available() ? "armable" : "inert",
           mcdc_fmi_new_available()  ? "armable" : "inert (heap lever covers "
                                                   "the small-stack builds)");

    /* RsaFunctionSync public path: tmp NEW + INIT, then 3084's read-in. */
    XMEMSET(o, 0, sizeof(o));
    WB_FMI_SWEEP("RsaPublicEncrypt",
        (void)wc_RsaPublicEncrypt(msg, msgLen, o, sizeof(o), key, rng));

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY)
    /* RsaFunctionPrivate: rnd/rndi (blinding builds) or tmpb (2963/2968/2981
     * in the no-blinding build), reached through RsaFunctionSync's own tmp. */
    WB_FMI_SWEEP("RsaSSL_Sign",
        { byte s2[WB_RSA_BYTES];
          XMEMSET(s2, 0, sizeof(s2));
          (void)wc_RsaSSL_Sign(msg, msgLen, s2, sizeof(s2), key, rng); });

    /* RsaFunctionCheckIn's c (3503/3508) sits in FRONT of all of the above on
     * the private-decrypt path, so this sweep covers it and everything the
     * sign sweep does. */
    if (ctLen > 0) {
        WB_FMI_SWEEP("RsaPrivateDecrypt",
            { byte d2[WB_RSA_BYTES];
              XMEMSET(d2, 0, sizeof(d2));
              (void)wc_RsaPrivateDecrypt(ct, (word32)ctLen, d2, sizeof(d2),
                                         key); });
    }
#else
    (void)ct; (void)ctLen;
#endif

    /* Public-decrypt path: a second route into RsaFunctionCheckIn, for the
     * reduced-surface builds that compile out the private one. */
    if (sigLen > 0) {
        WB_FMI_SWEEP("RsaSSL_Verify",
            { byte v2[WB_RSA_BYTES];
              XMEMSET(v2, 0, sizeof(v2));
              (void)wc_RsaSSL_Verify(sig, (word32)sigLen, v2, sizeof(v2),
                                     key); });
    }

    mcdc_fmi_disarm();
    WB_NOTE("scratch-mp_int NEW/INIT lifecycle sweeps done");
}

/* ---------------------------------------------------------------------------
 * wc_MakeRsaKey 5669 idx0: `err == MP_OKAY` FALSE at the Fermat guard of the
 * q prime-search loop.
 *
 * The q loop is only entered once the p search has already succeeded, so no
 * monotone injector reaches it -- it fails the p search first and wc_MakeRsaKey
 * gives up before the loop exists. The one place the two loops differ is that
 * the q loop passes a non-NULL q to _CheckProbablePrime(), which makes it call
 * wc_CompareDiffPQ(), the sole caller of mp_2expt() in the file. A one-shot
 * mp_2expt failure is therefore phase-exact: it rejects the FIRST q candidate
 * with a non-MP_OKAY err and nothing else in the run is touched. The next
 * candidate is evaluated normally and the key completes, which is also what
 * keeps the loop terminating (see the note at the wrapper).
 *
 * The reachability of the vector does not depend on the random stream: the
 * fault fires at a fixed STRUCTURAL point (the first candidate of the q loop),
 * whichever candidates the entropy happens to produce.
 * ------------------------------------------------------------------------ */
static void wb_makekey_qloop_err(WC_RNG* rng)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    RsaKey mk;

    if (wc_InitRsaKey(&mk, NULL) != 0) { wb_fail = 1; return; }
    mcdc_rsa_2expt_armed = 1;
    (void)wc_MakeRsaKey(&mk, WB_RSA_BITS, 65537, rng);
    mcdc_rsa_2expt_armed = 0;
    wc_FreeRsaKey(&mk);
    WB_NOTE("wc_MakeRsaKey q-loop rejected-candidate vector done");
#else
    (void)rng;
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; q-loop vector skipped");
#endif
}

/* ---------------------------------------------------------------------------
 * wc_RsaFunction 3593 idx1 / 3604 idx1: the bounds-check dispatch
 *
 *   if (type == RSA_PRIVATE_DECRYPT && key->state == RSA_STATE_DECRYPT_EXPTMOD)
 *   if (type == RSA_PUBLIC_DECRYPT  && key->state == RSA_STATE_DECRYPT_EXPTMOD)
 *
 * Reached from wc_RsaPrivateDecrypt / wc_RsaSSL_Verify the state operand is
 * always TRUE when the type operand is, so operand 1's FALSE half needs a
 * direct call with the key parked in another state -- which is exactly what a
 * caller driving wc_RsaFunction itself (the documented public entry point)
 * does. Uses a scratch key so the shared key's state machine is untouched.
 * ------------------------------------------------------------------------ */

/* The sweeps below are already capped deterministically by WB_MP_MAX. The wall
 * clock is a second, load-dependent truncation on top of that: if it fires
 * first, the sweep is shorter on a busy machine than on an idle one and the
 * same source measures differently run to run (proved on wc_lms_impl.c,
 * 2026-08-11). Keep it as a backstop against TEST_TIMEOUT, but make it say so,
 * so a load-dependent result is never mistaken for a stable one. */
static int wb_mp_backstop = 0;

static int wb_mp_over(int elapsed)
{
    if (elapsed && !wb_mp_backstop) {
        wb_mp_backstop = 1;
        printf("  [wb] WALL-CLOCK BACKSTOP truncated the sweep before "
               "WB_MP_MAX -- coverage is load-dependent for this run\n");
    }
    return elapsed;
}

static void wb_rsafunction_state_operand(RsaKey* key, WC_RNG* rng,
                                         const byte* ct, int ctLen)
{
#if !defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(TEST_UNPAD_CONSTANT_TIME) && \
    !defined(NO_RSA_BOUNDS_CHECK) && !defined(WOLF_CRYPTO_CB_ONLY_RSA)
    byte   out[WB_RSA_BYTES];
    word32 outLen = sizeof(out);

    if (ctLen <= 0)
        return;
    XMEMSET(out, 0, sizeof(out));

    key->state = RSA_STATE_NONE;
    (void)wc_RsaFunction(ct, (word32)ctLen, out, &outLen, RSA_PRIVATE_DECRYPT,
                         key, rng);
    key->state = RSA_STATE_NONE;
    outLen = sizeof(out);
    (void)wc_RsaFunction(ct, (word32)ctLen, out, &outLen, RSA_PUBLIC_DECRYPT,
                         key, rng);
    key->state = RSA_STATE_NONE;
    WB_NOTE("wc_RsaFunction type/state dispatch operand-1 vectors done");
#else
    (void)key; (void)rng; (void)ct; (void)ctLen;
#endif
}

int main(int argc, char** argv)
{
    int      do_baseline = (argc > 1 && strcmp(argv[1], "baseline") == 0);
    int      do_probe    = (argc > 1 && strcmp(argv[1], "probe")    == 0);
    int      do_sweep    = !do_baseline && !do_probe;
    /* Optional section selector (debugging): a sweep-mode argv[1] naming one
     * section runs only that section. NULL (no argv) runs them all. */
    const char* only     = (do_sweep && argc > 1) ? argv[1] : NULL;
#define WANT(s) (only == NULL || strcmp(only, (s)) == 0)
    WC_RNG   rng;

    /* Unbuffered: if a fault-injected path dies, whatever ran so far must
     * still be in the log. */
    setvbuf(stdout, NULL, _IONBF, 0);
    RsaKey   key;
    byte     msg[32];
    byte     ct[WB_RSA_BYTES];
    byte     dec[WB_RSA_BYTES];
    byte     sig[WB_RSA_BYTES];
    byte     der[WB_RSA_BYTES * 4];
    int      ctLen = 0, derLen = 0;
    int      n, rep, ret;
    time_t   heap_t0 = 0;

    printf("rsa.c fault white-box (%s)\n",
           do_baseline ? "baseline" : (do_probe ? "probe" : "sweep"));

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(msg, 0x2b, sizeof(msg));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(dec, 0, sizeof(dec));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(der, 0, sizeof(der));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }
    if (wc_InitRsaKey(&key, NULL) != 0) {
        printf("  wc_InitRsaKey failed; skipping\n");
        wc_FreeRng(&rng);
        return 0;
    }

    mcdc_fa_install();

    /* ---- build a valid CRT key ONCE while DISARMED (allocations succeed) ---- */
    ret = wc_MakeRsaKey(&key, WB_RSA_BITS, 65537, &rng);
    if (ret != 0) {
        printf("  wc_MakeRsaKey failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return 0;
    }
#ifndef WC_NO_RNG
    /* Associate the RNG so wc_RsaPrivateDecrypt blinds (WC_RSA_BLINDING). */
    (void)wc_RsaSetRNG(&key, &rng);
#endif

    /* one unarmed public encrypt -> a valid ciphertext for the decrypt sweep */
    ret = wc_RsaPublicEncrypt(msg, sizeof(msg), ct, sizeof(ct), &key, &rng);
    if (ret > 0) ctLen = ret;

    /* ---- baseline: unarmed valid operations supply every all-false NULL guard
     *      operand and the err==0 true chains / MP_OKAY cleanup halves. ---- */
    (void)wc_RsaSSL_Sign(msg, sizeof(msg), sig, sizeof(sig), &key, &rng);
    if (ctLen > 0)
        (void)wc_RsaPrivateDecrypt(ct, (word32)ctLen, dec, sizeof(dec), &key);
#ifdef WOLFSSL_RSA_KEY_CHECK
    (void)wc_CheckRsaKey(&key);
#endif
#ifdef WOLFSSL_KEY_TO_DER
    ret = wc_RsaKeyToDer(&key, der, sizeof(der));
    if (ret > 0) derLen = ret;
#endif

    /* Cheap and independent of the fault sweeps below, so run it here rather
     * than after them: the RSA_LOW_MEM variant's sweep can hit the harness
     * wall-clock limit, and anything queued behind it would be lost with the
     * whole run. */
    wb_pss_checkpadding_sigcheck();
    wb_pss_saltlen_1024_sha512(&key, &rng);

    /* Data-only white-box vectors: no injector, microseconds each, and they
     * must not sit behind the heap sweeps (whose RSA_LOW_MEM instance can hit
     * the harness wall-clock limit and take the whole run's profile with it). */
    wb_pad_unpad_vectors(&rng);
    wb_encryptsize_lower_bound(&rng);
    wb_priv_zero_crt_components(&key, &rng);
    if (ctLen > 0)
        wb_rsafunction_state_operand(&key, &rng, ct, ctLen);

    /* Scratch-mp_int lifecycle sweeps and the q-loop vector. Counted sweeps,
     * no wall clock, and every armed call aborts its entry point within a
     * handful of big-int operations, so they are cheap -- but they still go
     * BEFORE the deadline-bounded sweeps below, which under RSA_LOW_MEM run
     * close to the harness limit. */
    wb_mpint_lifecycle(&key, &rng, msg, (word32)sizeof(msg), ct, ctLen,
                       sig, (int)sizeof(sig));
    wb_makekey_qloop_err(&rng);

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Diagnostic: count the allocations each entry point performs WITHOUT
         * failing any (arm a huge index so the counter advances but never
         * trips). Sizes each sweep's K. Exits without sweeping. */
        byte o[WB_RSA_BYTES];
        XMEMSET(o, 0, sizeof(o));
        mcdc_fa_arm(1000000);
        (void)wc_RsaPublicEncrypt(msg, sizeof(msg), o, sizeof(o), &key, &rng);
        printf("  PROBE pub-encrypt allocs = %lu\n", mcdc_fa_count);
        mcdc_fa_arm(1000000);
        (void)wc_RsaSSL_Sign(msg, sizeof(msg), sig, sizeof(sig), &key, &rng);
        printf("  PROBE sign allocs        = %lu\n", mcdc_fa_count);
        if (ctLen > 0) {
            mcdc_fa_arm(1000000);
            (void)wc_RsaPrivateDecrypt(ct, (word32)ctLen, dec, sizeof(dec), &key);
            printf("  PROBE priv-decrypt allocs= %lu\n", mcdc_fa_count);
        }
#ifdef WOLFSSL_RSA_KEY_CHECK
        mcdc_fa_arm(1000000);
        (void)wc_CheckRsaKey(&key);
        printf("  PROBE checkkey allocs    = %lu\n", mcdc_fa_count);
#endif
#ifdef WOLFSSL_KEY_TO_DER
        mcdc_fa_arm(1000000);
        (void)wc_RsaKeyToDer(&key, der, sizeof(der));
        printf("  PROBE keytoder allocs    = %lu\n", mcdc_fa_count);
#endif
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
        return 0;
    }
#endif

    if (do_sweep) {
        /* ---- big-integer fault sweeps (mcdc_fault_mp.h) -------------------
         * FIRST, deliberately: these are the cheapest sweeps in the file (an
         * armed mp_* call aborts its entry point within a handful of big-int
         * operations) and they carry the largest single block of residuals in
         * rsa.c, so they must not be queued behind the multi-thousand-index
         * heap sweeps below -- under RSA_LOW_MEM those can reach the harness
         * wall-clock limit, and a timed-out white-box contributes nothing.
         *
         * Each target is first run DISARMED: that supplies the all-TRUE
         * (ret==0, every mp op OK) row of every guard in the chain IN THIS
         * BINARY -- the accepting half without which the rejecting vectors
         * below prove no independence pair -- and measures the sweep length K.
         * Then the fail index is swept over [1..K]: index n drives operand 1
         * TRUE at the n-th call site and operand 0 FALSE at every guard
         * downstream of it. Inputs are rebuilt (or are read-only) while
         * disarmed, so every armed call starts from the same known-good
         * state. */
        {
            time_t t0 = time(NULL);
            long   k, i;

#define WB_MP_MAX      600
#define WB_MP_DEADLINE 150
#define WB_MP_EXPIRED() wb_mp_over(difftime(time(NULL), t0) > (double)WB_MP_DEADLINE)
#define WB_MP_SWEEP(lbl, ...)                                             \
    do {                                                                  \
        mcdc_fm_disarm();                                                 \
        { __VA_ARGS__; }                                                  \
        k = mcdc_fm_seen();                                               \
        if (k > WB_MP_MAX)                                                \
            k = WB_MP_MAX;                                                \
        for (i = 1; (i <= k) && !WB_MP_EXPIRED(); i++) {                  \
            mcdc_fm_arm(i);                                               \
            { __VA_ARGS__; }                                              \
            mcdc_fm_disarm();                                             \
        }                                                                 \
        printf("  [wb] mp sweep %s: K=%ld\n", (lbl), k);                  \
    } while (0)

            if (WANT("mp")) {
                byte o[WB_RSA_BYTES];

                /* RsaFunctionSync public path: tmp read-in + exptmod. */
                XMEMSET(o, 0, sizeof(o));
                WB_MP_SWEEP("RsaPublicEncrypt",
                    (void)wc_RsaPublicEncrypt(msg, sizeof(msg), o, sizeof(o),
                                              &key, &rng));

                /* RsaFunctionPrivate: the blinding invmod/exptmod/mulmod
                 * chain, the CRT dP/dQ/u chain and the montgomery
                 * blinding-invert tail -- the single largest residual block
                 * in the file. */
                WB_MP_SWEEP("RsaSSL_Sign",
                    { byte s2[WB_RSA_BYTES];
                      XMEMSET(s2, 0, sizeof(s2));
                      (void)wc_RsaSSL_Sign(msg, sizeof(msg), s2, sizeof(s2),
                                           &key, &rng); });

                if (ctLen > 0) {
                    WB_MP_SWEEP("RsaPrivateDecrypt",
                        { byte d2[WB_RSA_BYTES];
                          XMEMSET(d2, 0, sizeof(d2));
                          (void)wc_RsaPrivateDecrypt(ct, (word32)ctLen, d2,
                                                     sizeof(d2), &key); });
                }

                WB_MP_SWEEP("RsaSSL_Verify",
                    { byte v2[WB_RSA_BYTES];
                      XMEMSET(v2, 0, sizeof(v2));
                      (void)wc_RsaSSL_Verify(sig, sizeof(sig), v2, sizeof(v2),
                                             &key); });

#ifdef WOLFSSL_RSA_KEY_CHECK
                WB_MP_SWEEP("CheckRsaKey", (void)wc_CheckRsaKey(&key));
#endif
#ifdef WOLFSSL_KEY_TO_DER
                WB_MP_SWEEP("RsaKeyToDer",
                    (void)wc_RsaKeyToDer(&key, der, sizeof(der)));
#endif
                if (derLen > 0) {
                    WB_MP_SWEEP("RsaPrivateKeyDecode",
                        { RsaKey dk; word32 idx = 0;
                          if (wc_InitRsaKey(&dk, NULL) == 0) {
                              (void)wc_RsaPrivateKeyDecode(der, &idx, &dk,
                                                           (word32)derLen);
                              wc_FreeRsaKey(&dk);
                          } });
                }
                mcdc_fm_disarm();
            }

            /* Prime-search err == MP_OKAY chains. Deliberately shallow: an
             * armed wc_MakeRsaKey aborts as soon as the injected failure is
             * reached, so a LOW fail index costs only the few prime
             * candidates evaluated before it, while a high one would pay for
             * a full 1024-bit prime search per iteration. WB_MAKEKEY_K is
             * therefore small on purpose -- this white-box already carries
             * the multi-thousand-index heap sweeps below, and under
             * RSA_LOW_MEM the binary as a whole runs close to the harness
             * wall-clock limit (a timed-out run yields NO profile at all, so
             * "shallow but finished" strictly beats "deep but killed"). */
#define WB_MAKEKEY_K 12
            if (WANT("mpkeygen")) {
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
                int isPrime = 0;

                /* 5249 idx1: |p-q| below the FIPS 186 bound with
                 * wc_CompareDiffPQ itself succeeding -- q == p makes the
                 * difference zero. The sweep right after supplies idx0 by
                 * failing that same call. Real 1024-bit primes (the key built
                 * at the top of main) so the whole function body runs, not
                 * just its lower-bound rejection. */
                (void)_CheckProbablePrime(&key.p, &key.p, &key.e,
                                          WB_RSA_BITS, &isPrime, &rng);
                WB_MP_SWEEP("CheckProbablePrime(q)",
                    { int ip = 0;
                      (void)_CheckProbablePrime(&key.p, &key.q, &key.e,
                                                WB_RSA_BITS, &ip, &rng); });
                WB_MP_SWEEP("CheckProbablePrime(p)",
                    { int ip = 0;
                      (void)_CheckProbablePrime(&key.p, NULL, &key.e,
                                                WB_RSA_BITS, &ip, &rng); });

                for (i = 1; (i <= WB_MAKEKEY_K) && !WB_MP_EXPIRED(); i++) {
                    RsaKey mk;
                    if (wc_InitRsaKey(&mk, NULL) != 0) { wb_fail = 1; continue; }
                    mcdc_fm_arm(i);
                    (void)wc_MakeRsaKey(&mk, WB_RSA_BITS, 65537, &rng);
                    mcdc_fm_disarm();
                    wc_FreeRsaKey(&mk);
                }
                printf("  [wb] mp sweep MakeRsaKey: K=%d\n", WB_MAKEKEY_K);
#endif
                mcdc_fm_disarm();
            }
            mcdc_fm_disarm();
            WB_NOTE("big-integer fault sweeps done");
        }

        /* --- wc_RsaPublicEncrypt: RsaFunctionSync public path -- tmp NEW/INIT,
         * mp_read_unsigned_bin (line 3075), mp_exptmod_nct. Faulting the n-th
         * alloc drives the tmp NULL/INIT-fail and the ret==0 && mp_*!=MP_OKAY
         * halves at 3075 and in RsaFunctionCheckIn (3499). --- */
        heap_t0 = time(NULL);
        if (WANT("pub"))
        for (n = 1; n <= WB_SWEEP_K; n++) {
            byte o[WB_RSA_BYTES];
            XMEMSET(o, 0, sizeof(o));
            mcdc_fa_arm(n);
            (void)wc_RsaPublicEncrypt(msg, sizeof(msg), o, sizeof(o), &key, &rng);
            mcdc_fa_disarm();
        }

        /* --- wc_RsaSSL_Sign + wc_RsaPrivateDecrypt: RsaFunctionPrivate. These
         * drive the blinding rnd/rndi NULL guard (2882), the ret==0 && CRT
         * mp_exptmod/submod/mulmod/mul/add halves (2937..2996) and the
         * montgomery blinding-invert chain (3013..3032). Blinding draws a fresh
         * RNG value each call so the deeper mp scratch alloc counts drift;
         * repeat the sweep so the union reaches every op despite the drift.
         * The key is reused (private ops do not mutate it); output is fresh. --- */
        /* Wall-clock guard. The harness kills a white-box at TEST_TIMEOUT and
         * a killed run yields NO profile at all, so every vector before the
         * kill is lost too -- "shallow but finished" strictly beats "deep but
         * killed". RSA_LOW_MEM (non-CRT: one full-width private exptmod per
         * iteration instead of two half-width ones) is several times slower
         * per vector than the CRT variants, which is exactly the build that
         * ran into the limit. The deadline is checked between vectors, so it
         * truncates the sweep instead of aborting it. */
#define WB_HEAP_DEADLINE 330
#define WB_HEAP_EXPIRED() (difftime(time(NULL), heap_t0) > (double)WB_HEAP_DEADLINE)
        if (WANT("priv"))
        for (rep = 0; rep < WB_PRIV_REP; rep++) {
            for (n = 1; n <= WB_PRIV_K && !WB_HEAP_EXPIRED(); n++) {
                byte s2[WB_RSA_BYTES];
                XMEMSET(s2, 0, sizeof(s2));
                mcdc_fa_arm(n);
                (void)wc_RsaSSL_Sign(msg, sizeof(msg), s2, sizeof(s2), &key, &rng);
                mcdc_fa_disarm();
            }
            if (ctLen > 0) {
                for (n = 1; n <= WB_PRIV_K && !WB_HEAP_EXPIRED(); n++) {
                    byte d2[WB_RSA_BYTES];
                    XMEMSET(d2, 0, sizeof(d2));
                    mcdc_fa_arm(n);
                    (void)wc_RsaPrivateDecrypt(ct, (word32)ctLen, d2,
                                               sizeof(d2), &key);
                    mcdc_fa_disarm();
                }
            }
        }

        /* --- wc_RsaSSL_Verify: public RsaFunctionSync path against the valid
         * baseline signature (a second public path exerciser). --- */
        if (WANT("verify"))
        for (n = 1; n <= WB_SWEEP_K; n++) {
            byte o[WB_RSA_BYTES];
            XMEMSET(o, 0, sizeof(o));
            mcdc_fa_arm(n);
            (void)wc_RsaSSL_Verify(sig, sizeof(sig), o, sizeof(o), &key);
            mcdc_fa_disarm();
        }

        /* --- wc_CheckRsaKey: allocates tmp mp_int(s) then runs mp verify ops;
         * faulting each drives its ret==0 && mp_*!=MP_OKAY halves. Only present
         * when WOLFSSL_RSA_KEY_CHECK is enabled (not in the base config). --- */
#ifdef WOLFSSL_RSA_KEY_CHECK
        for (n = 1; n <= WB_SWEEP_K; n++) {
            mcdc_fa_arm(n);
            (void)wc_CheckRsaKey(&key);
            mcdc_fa_disarm();
        }
#endif

#ifdef WOLFSSL_KEY_TO_DER
        /* --- wc_RsaKeyToDer: SetRsaPublicKey/SetRsaPrivateKey temp allocs. --- */
        if (WANT("der"))
        for (n = 1; n <= WB_SWEEP_K; n++) {
            mcdc_fa_arm(n);
            (void)wc_RsaKeyToDer(&key, der, sizeof(der));
            mcdc_fa_disarm();
        }
#endif

        /* --- wc_RsaPublicKeyDecode / wc_RsaPrivateKeyDecode on the exported
         * DER: faults the decode-time mp temp allocations. --- */
        if (WANT("decode") && derLen > 0) {
            for (n = 1; n <= WB_SWEEP_K; n++) {
                RsaKey  dk;
                word32  idx = 0;
                if (wc_InitRsaKey(&dk, NULL) != 0) { wb_fail = 1; continue; }
                mcdc_fa_arm(n);
                (void)wc_RsaPrivateKeyDecode(der, &idx, &dk, (word32)derLen);
                mcdc_fa_disarm();
                wc_FreeRsaKey(&dk);
            }
        }

        /* --- file-static XMALLOC NULL guards + wc_MakeRsaKey 5-way guard --- */
        if (WANT("static")) {
            wb_static_compare_diff_pq();
            wb_static_check_probable_prime();
            wb_static_check_probable_prime_ex();
        }
        if (WANT("makekey"))
            wb_makersakey_alloc_guard(&rng);

        WB_NOTE("fault-index sweeps over public/private/check/der + helpers done");
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    mcdc_fm_disarm();
    mcdc_fmi_disarm();
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* !NO_RSA && WOLFSSL_KEY_GEN && !WC_NO_RNG */
