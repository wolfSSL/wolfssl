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
 * modules.json note at the end of this file's commit message).
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
 * Invocation:
 *   ./test_rsa_fault_whitebox            default: full fault-index sweep
 *   ./test_rsa_fault_whitebox baseline   only the unarmed valid ops (delta base)
 *   ./test_rsa_fault_whitebox probe      per-entry-point allocation counts
 * (Default is the sweep so the campaign's run_whitebox harness -- which runs the
 * binary with NO arguments -- gets full coverage.)
 */

#include <wolfcrypt/src/rsa.c>

#include "mcdc_fault_alloc.h"

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
 * IMPORTANT -- library double-free-on-partial-OOM defect (DEATHNOTE): in each
 * of wc_CompareDiffPQ / _CheckProbablePrime / wc_CheckProbablePrime_ex the temp
 * mp_ints are XMALLOC'd in a short-circuit "|| " chain and mp_init_multi() is
 * then SKIPPED when any XMALLOC in the chain returned NULL (ret = MEMORY_E).
 * The cleanup nonetheless calls mp_clear()/mp_forcezero() on the *already
 * allocated but never initialized* earlier struct(s); sp_clear() loops
 * `for (i=0; i<a->used; i++)` over a garbage `used` field and ForceZero()s a
 * garbage `size`, writing far past the struct -> heap corruption / abort.
 *
 * Consequently only the FIRST operand of each XMALLOC chain can be faulted
 * crash-safely (fail alloc #1 -> every temp still NULL -> cleanup skips them
 * all), which covers the idx0 operand. Faulting a LATER operand (idx1/idx2)
 * would leave an earlier struct allocated-but-uninitialized and trip the
 * library bug, so those halves stay JUSTIFIED RESIDUALS (blocked by the defect,
 * not by the injector) -- reported to the campaign DEATHNOTE, NOT swept here.
 * ------------------------------------------------------------------------- */
static void wb_static_compare_diff_pq(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* wc_CompareDiffPQ line ~5051:
     *   if (((c=XMALLOC..)==NULL) || ((d=XMALLOC..)==NULL)) ret = MEMORY_E;
     * arm(1): c==NULL (idx0 true), d untouched(NULL) -> cleanup clean. The
     * all-false side is produced by the unarmed baseline call. idx1 (d==NULL,
     * c!=NULL) hits the uninit-cleanup defect above -> residual. */
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
    (void)wc_CompareDiffPQ(&p, &q, WB_RSA_BITS, &valid);   /* all-false */

    mp_clear(&p);
    mp_clear(&q);
    WB_NOTE("wc_CompareDiffPQ XMALLOC guard idx0 done (idx1 = library-bug residual)");
#else
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; wc_CompareDiffPQ skipped");
#endif
}

static void wb_static_check_probable_prime(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* _CheckProbablePrime line ~5194:
     *   if (((tmp1=XMALLOC..)==NULL) || ((tmp2=XMALLOC..)==NULL)) goto notOkay;
     * arm(1): tmp1==NULL (idx0 true). idx1 = uninit-cleanup residual. */
    mp_int p, e;
    int    isPrime = 0;

    if (mp_init(&p) != MP_OKAY) { WB_NOTE("mp_init(p) failed"); wb_fail = 1; return; }
    if (mp_init(&e) != MP_OKAY) { mp_clear(&p); WB_NOTE("mp_init(e) failed");
                                  wb_fail = 1; return; }
    (void)mp_set(&p, 101);
    (void)mp_set(&e, 65537);

    mcdc_fa_arm(1);
    (void)_CheckProbablePrime(&p, NULL, &e, 2048, &isPrime, NULL); /* idx0 true */
    mcdc_fa_disarm();
    (void)_CheckProbablePrime(&p, NULL, &e, 2048, &isPrime, NULL); /* all-false */

    mp_clear(&p);
    mp_clear(&e);
    WB_NOTE("_CheckProbablePrime XMALLOC guard idx0 done (idx1 = library-bug residual)");
#else
    WB_NOTE("KEY_GEN off / PUBLIC_ONLY; _CheckProbablePrime skipped");
#endif
}

static void wb_static_check_probable_prime_ex(void)
{
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    /* wc_CheckProbablePrime_ex line ~5298:
     *   if (((p=..)==NULL)||((q=..)==NULL)||((e=..)==NULL)) ret = MEMORY_E;
     * arm(1): p==NULL (idx0 true). idx1/idx2 = uninit-cleanup residuals. */
    byte pRaw[8] = { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x65 };
    byte eRaw[3] = { 0x01,0x00,0x01 };
    int  isPrime = 0;

    mcdc_fa_arm(1);
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL);
    mcdc_fa_disarm();
    (void)wc_CheckProbablePrime_ex(pRaw, sizeof(pRaw), NULL, 0,
                                   eRaw, sizeof(eRaw), 2048, &isPrime, NULL);
    WB_NOTE("wc_CheckProbablePrime_ex XMALLOC guard idx0 done (idx1/2 = library-bug residual)");
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
    RsaKey   key;
    byte     msg[32];
    byte     ct[WB_RSA_BYTES];
    byte     dec[WB_RSA_BYTES];
    byte     sig[WB_RSA_BYTES];
    byte     der[WB_RSA_BYTES * 4];
    int      ctLen = 0, derLen = 0;
    int      n, rep, ret;

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
        /* --- wc_RsaPublicEncrypt: RsaFunctionSync public path -- tmp NEW/INIT,
         * mp_read_unsigned_bin (line 3075), mp_exptmod_nct. Faulting the n-th
         * alloc drives the tmp NULL/INIT-fail and the ret==0 && mp_*!=MP_OKAY
         * halves at 3075 and in RsaFunctionCheckIn (3499). --- */
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
        if (WANT("priv"))
        for (rep = 0; rep < WB_PRIV_REP; rep++) {
            for (n = 1; n <= WB_PRIV_K; n++) {
                byte s2[WB_RSA_BYTES];
                XMEMSET(s2, 0, sizeof(s2));
                mcdc_fa_arm(n);
                (void)wc_RsaSSL_Sign(msg, sizeof(msg), s2, sizeof(s2), &key, &rng);
                mcdc_fa_disarm();
            }
            if (ctLen > 0) {
                for (n = 1; n <= WB_PRIV_K; n++) {
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

        WB_NOTE("fault-index sweeps over public/private/check/der + statics done");
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* !NO_RSA && WOLFSSL_KEY_GEN && !WC_NO_RNG */
