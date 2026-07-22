/* test_sakke_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/sakke.c.
 *
 * tests/api/test_sakke.c and tests/unit-mcdc/test_sakke_whitebox.c together
 * drive every public entry point and file-static helper of sakke.c, but a
 * residual class of decisions cannot be reached that way: the FALSE half of
 * the success-chain guards shaped
 *
 *     if   ((err == 0) && <next step>) ...
 *     while((err == 0) && mp_iszero(...))
 *     for  (...; (err == 0) && (i >= 0); ...)
 *
 * In normal execution every allocation succeeds, so err stays 0 (MP_OKAY) and
 * the "err == 0" operand is always true -- its independence pair (a case where
 * err != 0 makes it false and that decides the branch) is never shown. The
 * only way to drive err != 0 partway through these chains is to make an
 * EARLIER heap allocation fail so the running operation returns MEMORY_E.
 *
 * This white-box installs the generic heap-fault injector (mcdc_fault_alloc.h)
 * and sweeps the fail-index across each entry point's allocation sites: for
 * each index exactly one earlier allocation returns NULL, breaking the success
 * chain with err != 0 at a different depth, so the "err == 0" false half of
 * one guard (or loop check) is exercised per position.
 *
 * It #includes sakke.c directly (like test_sakke_whitebox.c) so the file-static
 * helpers sakke_mulmod_base_add / sakke_addmod / sakke_tplmod /
 * sakke_compute_point_r are reachable for direct armed calls, and so
 * llvm-cov attributes the coverage to sakke.c's own decisions.
 *
 * Targeted GAPS.md residuals (err==0 FALSE half unless noted):
 *   411  sakke_mulmod_base_add "(err==0) && map"      (non-SP build only)
 *   536  wc_MakeSakkeKey       "(err==0) && mp_iszero(..)"  cond 0 only;
 *        cond 1 (mp_iszero true, random scalar == 0) is crypto-unreachable.
 *   1483 sakke_addmod          "(err==0) && (mp_cmp!=MP_LT)"
 *   1505/1508/1511 sakke_tplmod  three sequential reductions, same shape
 *   2282 sakke_pairing loop    "(err==0) && (i>=0)"
 *   2302 sakke_pairing         "(err==0) && (i>0) && mp_is_bit_set(..)"
 *   2454 wc_ValidateSakkeRsk   "(err==0) && (idSz<=SAKKE_ID_MAX_SIZE)"
 *   2646 sakke_modexp_loop     "(err==0) && (i>=0)"
 *   6289 sakke_hash_to_range   "(err==0) && (i<n)"
 *   6657 sakke_compute_point_r "(err==0) && (idSz<=SAKKE_ID_MAX_SIZE)"
 *
 * Crash-safety: all key/point/mp inputs are prepared while DISARMED; every
 * armed call either returns an error before building anything, or fails a
 * deeper allocation whose error the target's own cleanup absorbs (that cleanup
 * is what is under test). The harness never dereferences a value an armed call
 * returned. sakke_compute_point_i() (reached via ValidateSakkeRsk /
 * compute_point_r) repurposes the ecc private-key mp_int as scratch, so a
 * FRESH fully-prepared key is (re)built while disarmed before each sweep group
 * that needs genuine key state, and the key that a sweep may leave partially
 * mutated is never reused across groups. Runs clean under -fsanitize=address.
 *
 * Invocation:
 *   ./test_sakke_fault_whitebox            default: full fault-index sweeps
 *   ./test_sakke_fault_whitebox baseline   unarmed valid ops only (delta base)
 *   ./test_sakke_fault_whitebox probe      print per-target allocation counts
 * The campaign run_whitebox harness runs the binary with NO arguments, so the
 * default is the productive full sweep.
 */

#include <wolfcrypt/src/sakke.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFCRYPT_HAVE_SAKKE)

int main(void)
{
    printf("sakke.c fault white-box: WOLFCRYPT_HAVE_SAKKE not defined\n");
    return 0;
}

#else

/* Small (numerically tiny) identity: only its byte length matters for the
 * idSz guards; a small magnitude keeps sakke_compute_point_i()'s scalar in
 * range so the guard, not an ECC range error, is what err reflects. */
static byte gId[4] = { 0x00, 0x00, 0x00, 0x01 };
static const word16 gIdSz = (word16)sizeof(gId);

/* Per-target fault-index sweep upper bounds, sized from the "probe" run (each
 * over-sweeps the target's allocation count by a margin; over-sweeping is
 * harmless). Tunable via -D at compile time. The heavy pairing/precompute
 * targets (validate/encap/derive) are swept far enough to reach past
 * sakke_compute_point_i() into the pairing and modexp loops. */
/* Cold allocation counts (measured by the "probe" run with the FP fixed-point
 * cache freed): a single cold ECC base-point multiply builds the FP windowed
 * cache in ~261 heap allocations; encap/derive perform two cold muls (~522).
 * These allocations, inside the FIRST wc_ecc_mulmod of sakke_compute_point_i(),
 * are the only faultable sites reachable before each targeted err-chain guard
 * in the base (non-SMALL_STACK, fixed sp_int) config -- the pairing / modexp /
 * hash loops that follow perform no heap allocation, so their mid-loop err!=0
 * halves stay justified residuals here (they open only under WOLFSSL_SMALL_STACK
 * for the pairing accumulate-line helpers; see the module report). */
#ifndef SAKKE_K_MAKEKEY
#define SAKKE_K_MAKEKEY   280
#endif
#ifndef SAKKE_K_MAKERSK
#define SAKKE_K_MAKERSK   280
#endif
#ifndef SAKKE_K_MULADD
#define SAKKE_K_MULADD    280
#endif
#ifndef SAKKE_K_SMALLMP
#define SAKKE_K_SMALLMP   8
#endif
#ifndef SAKKE_K_VALIDATE
#define SAKKE_K_VALIDATE  340   /* past the 261-alloc FP build into pairing,
                                 * so under WOLFSSL_SMALL_STACK the pairing
                                 * accumulate-line faults flip 2282/2302 */
#endif
#ifndef SAKKE_K_ENCAP
#define SAKKE_K_ENCAP     540
#endif
#ifndef SAKKE_K_DERIVE
#define SAKKE_K_DERIVE    540
#endif
#ifndef SAKKE_K_POINTR
#define SAKKE_K_POINTR    280
#endif

/* Build a fully prepared SAKKE key: master secret + public key + RSK +
 * identity + set RSK. MUST be called DISARMED. rsk is caller-owned. */
static int build_prepared(SakkeKey* key, WC_RNG* rng, ecc_point* rsk)
{
    int ret = wc_InitSakkeKey_ex(key, 128, ECC_SAKKE_1, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_MakeSakkeKey(key, rng);
    if (ret == 0)
        ret = wc_MakeSakkeRsk(key, gId, gIdSz, rsk);
    if (ret == 0)
        ret = wc_SetSakkeIdentity(key, gId, gIdSz);
    if (ret == 0)
        ret = wc_SetSakkeRsk(key, rsk, NULL, 0);
    return ret;
}

#ifndef MCDC_FA_UNAVAILABLE
/* Count the allocations a nullary lambda-ish call performs without failing any
 * (arm a huge index so the counter advances but never trips). */
#define PROBE(label, callexpr) do {                                          \
        wc_ecc_fp_free();  /* force cold: rebuild FP fixed-point cache */    \
        key.i.idSz = 0;    /* force point-I recompute where cached */        \
        mcdc_fa_arm(1000000);                                               \
        (void)(callexpr);                                                   \
        printf("  PROBE %-28s allocs = %lu\n", (label), mcdc_fa_count);     \
        mcdc_fa_disarm();                                                   \
    } while (0)
#endif

int main(int argc, char** argv)
{
    int    do_baseline = (argc > 1 && strcmp(argv[1], "baseline") == 0);
    int    do_probe    = (argc > 1 && strcmp(argv[1], "probe") == 0);
    WC_RNG rng;
    SakkeKey key;
    ecc_point* rsk = NULL;
    byte   ssv[128];
    byte   auth[257];
    word16 authSz;
    int    valid;
    int    n;
    int    ret;

    printf("sakke.c fault white-box (%s)\n",
           do_baseline ? "baseline" : (do_probe ? "probe" : "sweep"));

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(ssv,  0, sizeof(ssv));
    XMEMSET(auth, 0, sizeof(auth));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    rsk = wc_ecc_new_point();
    if (rsk == NULL) {
        printf("  wc_ecc_new_point failed; skipping\n");
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }

    /* ---- baseline: one unarmed success of each target (all err==0 TRUE
     *      chains, all-false NULL guards, the idSz<=MAX true halves). ---- */
    ret = build_prepared(&key, &rng, rsk);
    if (ret != 0) {
        printf("  build_prepared failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_ecc_del_point(rsk);
        wc_FreeRng(&rng);
        return 0;
    }

    valid = -1;
    (void)wc_ValidateSakkeRsk(&key, gId, gIdSz, rsk, &valid);
    authSz = sizeof(auth);
    (void)wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16,
                                      auth, &authSz);
    (void)wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16, auth, authSz);

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Per-target allocation counts, used to size each sweep's K. Each
         * PROBE rebuilds/uses fresh state as the sweep will. Exits after. */
        SakkeKey k2;
        ecc_point* rsk2 = wc_ecc_new_point();

        XMEMSET(&k2, 0, sizeof(k2));

        /* MakeSakkeKey: fresh init'd (only) key. */
        if (wc_InitSakkeKey_ex(&k2, 128, ECC_SAKKE_1, NULL, INVALID_DEVID)
                == 0) {
            PROBE("wc_MakeSakkeKey", wc_MakeSakkeKey(&k2, &rng));
            wc_FreeSakkeKey(&k2);
        }
        /* MakeSakkeRsk on the prepared key. */
        if (rsk2 != NULL)
            PROBE("wc_MakeSakkeRsk", wc_MakeSakkeRsk(&key, gId, gIdSz, rsk2));
        /* ValidateSakkeRsk. */
        { int a = 0;
          PROBE("wc_ValidateSakkeRsk",
                wc_ValidateSakkeRsk(&key, gId, gIdSz, rsk, &a)); }
        /* Encapsulate. */
        { word16 az = sizeof(auth);
          PROBE("wc_MakeSakkeEncapsulatedSSV",
                wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16,
                                            auth, &az)); }
        /* Derive. */
        PROBE("wc_DeriveSakkeSSV",
              wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16, auth,
                                (word16)257));
#ifndef WOLFSSL_HAVE_SP_ECC
        { mp_int sN; ecc_point* ar = wc_ecc_new_point();
          mp_init(&sN); mp_set(&sN, 7);
          if (ar != NULL) {
              PROBE("sakke_mulmod_base_add",
                    sakke_mulmod_base_add(&key, &sN, &key.ecc.pubkey, ar, 1));
              wc_ecc_del_point(ar);
          }
          mp_free(&sN); }
#endif
        if (rsk2 != NULL) { wc_ecc_forcezero_point(rsk2);
                            wc_ecc_del_point(rsk2); }
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_FreeSakkeKey(&key);
        wc_ecc_forcezero_point(rsk); wc_ecc_del_point(rsk);
        wc_FreeRng(&rng);
        return 0;
    }
#endif /* !MCDC_FA_UNAVAILABLE */

    if (!do_baseline) {
#ifndef MCDC_FA_UNAVAILABLE
        /* ============================================================
         * Fault-index sweeps. K values sized from the probe run (see the
         * modules.json note); each K over-sweeps its target's allocation
         * count by a margin (over-sweeping is harmless -- once n exceeds the
         * site count the target simply runs to completion). Fresh key state
         * is (re)built while DISARMED for every group whose target mutates
         * key internals.
         * ============================================================ */

        /* --- wc_MakeSakkeKey (536:0): the master-secret loop's mp_rand /
         * mp_mod allocate; failing one sets err != 0 so the while's
         * "(err==0) && mp_iszero(..)" exits on the err==0 false half. Also
         * drives the earlier "(err==0) && ..." chain in key generation.
         * Fresh init'd key per iteration (MakeSakkeKey overwrites state and a
         * faulted call may leave it partial). --- */
        for (n = 1; n <= SAKKE_K_MAKEKEY; n++) {
            SakkeKey mk;
            XMEMSET(&mk, 0, sizeof(mk));
            if (wc_InitSakkeKey_ex(&mk, 128, ECC_SAKKE_1, NULL, INVALID_DEVID)
                    == 0) {
                wc_ecc_fp_free();  /* cold base mul so its FP-build allocates */
                mcdc_fa_arm(n);
                (void)wc_MakeSakkeKey(&mk, &rng);
                mcdc_fa_disarm();
                wc_FreeSakkeKey(&mk);
            }
        }
        WB_NOTE("wc_MakeSakkeKey fault sweep done");

        /* --- wc_MakeSakkeRsk: sweeps its own success chain. rsk output only;
         * key state (public key + master secret) untouched, so reuse key.
         * Fresh rsk point per iteration. --- */
        for (n = 1; n <= SAKKE_K_MAKERSK; n++) {
            ecc_point* rp = wc_ecc_new_point();
            if (rp != NULL) {
                wc_ecc_fp_free();  /* cold RSK-extraction mul */
                mcdc_fa_arm(n);
                (void)wc_MakeSakkeRsk(&key, gId, gIdSz, rp);
                mcdc_fa_disarm();
                wc_ecc_forcezero_point(rp);
                wc_ecc_del_point(rp);
            }
        }
        WB_NOTE("wc_MakeSakkeRsk fault sweep done");

#ifndef WOLFSSL_HAVE_SP_ECC
        /* --- sakke_mulmod_base_add (411): its wc_ecc_mulmod /
         * mp_montgomery_setup / ecc_projective_add_point each allocate;
         * failing one sets err != 0 so "(err==0) && map" takes the err==0
         * false half. map fixed at 1 (the value the existing whitebox could
         * not pair with err!=0). Uses the real public key. --- */
        {
            mp_int sN;
            mp_init(&sN);
            mp_set(&sN, 7);
            for (n = 1; n <= SAKKE_K_MULADD; n++) {
                ecc_point* ar = wc_ecc_new_point();
                if (ar != NULL) {
                    wc_ecc_fp_free();  /* cold: FP-build inside wc_ecc_mulmod */
                    mcdc_fa_arm(n);
                    (void)sakke_mulmod_base_add(&key, &sN, &key.ecc.pubkey,
                                                ar, 1);
                    mcdc_fa_disarm();
                    wc_ecc_del_point(ar);
                }
            }
            mp_free(&sN);
            WB_NOTE("sakke_mulmod_base_add fault sweep done");
        }

        /* --- sakke_addmod (1483) / sakke_tplmod (1505/1508/1511): pure
         * mp_int helpers. Their leading mp_add / mp_mul_d only allocate under
         * a heap-backed math backend; where they do, a fault sets err != 0 so
         * each "(err==0) && (mp_cmp != MP_LT)" reduction check takes its
         * err==0 false half. Where mp_add/mp_mul_d never allocate (fixed
         * sp_int), the sweep is a no-op and these stay justified residuals. */
        {
            for (n = 1; n <= SAKKE_K_SMALLMP; n++) {
                mp_int a, b, m, r;
                mp_init(&a); mp_init(&b); mp_init(&m); mp_init(&r);
                mp_set(&a, 60); mp_set(&b, 70); mp_set(&m, 100);
                mcdc_fa_arm(n);
                (void)sakke_addmod(&a, &b, &m, &r);
                mcdc_fa_disarm();
                mp_set(&a, 40); mp_set(&m, 100);
                mcdc_fa_arm(n);
                (void)sakke_tplmod(&a, &m, &r);
                mcdc_fa_disarm();
                mp_free(&a); mp_free(&b); mp_free(&m); mp_free(&r);
            }
            WB_NOTE("sakke_addmod / sakke_tplmod fault sweep done");
        }
#endif /* !WOLFSSL_HAVE_SP_ECC */

        /* --- wc_ValidateSakkeRsk (2454, and 2282/2302 in sakke_pairing):
         * sakke_compute_point_i() runs first (heavy ECC precompute) -- a fault
         * there sets err != 0 before the 2454 idSz guard, driving its err==0
         * false half. Faults deeper in the run land inside sakke_pairing's
         * accumulate-line loop, setting err != 0 so the 2282 loop check and
         * 2302 inner guard take their err==0 false halves on the next
         * iteration. Validate does not need the master secret (only the public
         * key + params), and resets key->i.table = NULL on recompute, so the
         * shared prepared key is reused; a fault leaves key->i partial but
         * every subsequent validate call recomputes it. --- */
        for (n = 1; n <= SAKKE_K_VALIDATE; n++) {
            int a = 0;
            wc_ecc_fp_free();   /* cold sakke_compute_point_i mul (FP build) */
            key.i.idSz = 0;     /* force point-I recompute */
            mcdc_fa_arm(n);
            (void)wc_ValidateSakkeRsk(&key, gId, gIdSz, rsk, &a);
            mcdc_fa_disarm();
        }
        WB_NOTE("wc_ValidateSakkeRsk fault sweep done");

        /* --- wc_MakeSakkeEncapsulatedSSV (6289 in sakke_hash_to_range, plus
         * the pairing/modexp loops it drives): sakke_calc_a ->
         * sakke_hash_to_range runs the "(err==0) && (i<n)" digest loop; a
         * fault inside sakke_calc_h_v sets err != 0 so the loop check takes
         * its err==0 false half. Deeper faults drive sakke_modexp_loop's 2646
         * check. Encapsulate uses the public key + identity, not the master
         * secret; reuse key. --- */
        for (n = 1; n <= SAKKE_K_ENCAP; n++) {
            word16 az = sizeof(auth);
            byte   s2[128];
            XMEMSET(s2, 0, sizeof(s2));
            wc_ecc_fp_free();   /* cold muls (FP build) */
            key.i.idSz = 0;
            mcdc_fa_arm(n);
            (void)wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, s2, 16,
                                              auth, &az);
            mcdc_fa_disarm();
        }
        WB_NOTE("wc_MakeSakkeEncapsulatedSSV fault sweep done");

        /* --- wc_DeriveSakkeSSV (6657 in sakke_compute_point_r, 6289, 2646):
         * sakke_compute_point_r() runs sakke_compute_point_i() then the r
         * scalar multiply; a fault in compute_point_i sets err != 0 before the
         * 6657 idSz guard (err==0 false half). Derive uses the RSK; reuse key.
         * A valid auth/authSz pair is not required for the fault paths (the
         * failure occurs before the SSV is checked). --- */
        for (n = 1; n <= SAKKE_K_DERIVE; n++) {
            byte s2[128];
            XMEMSET(s2, 0, sizeof(s2));
            wc_ecc_fp_free();   /* cold muls (FP build) */
            key.i.idSz = 0;
            mcdc_fa_arm(n);
            (void)wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, s2, 16, auth,
                                    (word16)257);
            mcdc_fa_disarm();
        }
        WB_NOTE("wc_DeriveSakkeSSV fault sweep done");

        /* --- sakke_compute_point_r (6657) direct: force the recompute branch
         * (key->i.idSz = 0) with idSz > SAKKE_ID_MAX_SIZE while faulting
         * compute_point_i, isolating the 6657 idSz operand with err both 0
         * (unarmed, from the baseline above) and != 0 (armed here). --- */
        {
            mp_int rS;
            byte   out[257];
            byte   idBig[SAKKE_ID_MAX_SIZE + 1];
            XMEMSET(idBig, 0, sizeof(idBig));
            idBig[sizeof(idBig) - 1] = 0x5A;
            XMEMSET(out, 0, sizeof(out));
            mp_init(&rS);
            mp_set(&rS, 5);
            for (n = 1; n <= SAKKE_K_POINTR; n++) {
                wc_ecc_fp_free();   /* cold compute_point_i mul (FP build) */
                key.i.idSz = 0;
                mcdc_fa_arm(n);
                (void)sakke_compute_point_r(&key, idBig, (word16)sizeof(idBig),
                                            &rS, 128, out);
                mcdc_fa_disarm();
            }
            key.i.idSz = 0;
            mp_free(&rS);
            WB_NOTE("sakke_compute_point_r idSz-guard fault sweep done");
        }
#else
        WB_NOTE("MCDC_FA_UNAVAILABLE: static/debug allocator signature -- "
                "fault injection compiled out; err-chain residuals unclosed "
                "in this variant");
#endif /* !MCDC_FA_UNAVAILABLE */
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_FreeSakkeKey(&key);
    wc_ecc_forcezero_point(rsk);
    wc_ecc_del_point(rsk);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */
