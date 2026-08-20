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

/* Installed BEFORE sakke.c so its mp_* calls resolve to the fault wrappers.
 * sakke.c's residuals are the `(err == 0) && <next step>` halves of its
 * big-integer chains (1490/1512/1515/1518 mp_cmp range checks, the 2653
 * bit-scan loop, the 543 key-generation retry). No mp_* call fails on a
 * healthy machine and the mp scratch is on the stack, so neither the ordinary
 * tests nor the heap-fault sweep below can drive `err == 0` FALSE there.
 * mcdc_fault_mp.h interposes the value-returning mp_* API for this TU only;
 * mcdc_fm_arm(n) fails the n-th mp_* call and every later one. Predicates
 * (mp_iszero/mp_cmp/mp_count_bits) and teardown (mp_free/mp_forcezero) are NOT
 * interposed, so cleanup keeps working and armed calls stay crash-safe. */
#include "mcdc_fault_mp.h"

/* --------------------------------------------------------------------------
 * Value-forcing mp_rand() interposer for the 543 master-secret retry loop.
 *
 *     do { ... err = mp_rand(priv, digits, rng);
 *              err = mp_mod(priv, &key->params.q, priv); }
 *     while ((err == 0) && mp_iszero(wc_ecc_key_get_priv(&key->ecc)));
 *
 * Both conditions need the loop to actually RETRY, which only happens when the
 * drawn scalar reduces to zero -- a ~2^-1024 event under real entropy, and one
 * a seeded RNG cannot force either, because mp_rand() is served by the sp_int
 * layer in a different TU (the seeded-RNG macro only rewrites call sites in the
 * TU it is included in). Interposing mp_rand() here is the one lever that
 * reaches it: sakke.c has exactly ONE mp_rand() call site (line 536), so no
 * disambiguation is needed.
 *
 * Modes are ONE-SHOT, so the loop's second iteration draws a genuine random
 * scalar and the loop terminates on real data -- there is no retry loop here
 * whose termination depends on a random draw going a particular way.
 *
 * Ordering is the same load-bearing trick as mcdc_fault_mp.h: the wrapper is
 * compiled while mp_rand still names the real entry point, and only then is the
 * name redefined. sakke.c must be #included AFTER this block.
 * ----------------------------------------------------------------------- */
#define WB_SR_OFF   0   /* pass through */
#define WB_SR_ZERO  1   /* succeed, but hand back the scalar 0 */
#define WB_SR_FAIL  2   /* fail the draw */

static int wb_sr_mode = WB_SR_OFF;

MCDC_FM_MAYBE_UNUSED static int wb_sr_rand(mp_int* a, int digits, WC_RNG* rng)
{
    int mode = wb_sr_mode;

    if (mode != WB_SR_OFF) {
        wb_sr_mode = WB_SR_OFF;   /* one-shot */
    }
    if (mode == WB_SR_FAIL) {
        return MCDC_FM_ERR;
    }
    if (mode == WB_SR_ZERO) {
        mp_zero(a);
        return 0;
    }
    return mp_rand(a, digits, rng);
}

#undef  mp_rand
#define mp_rand(a, d, r)    wb_sr_rand((a), (d), (r))

#include <wolfcrypt/src/sakke.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

/* ---- big-integer fault sweeps (mcdc_fault_mp.h) ------------------------- */
#define WB_MP_DEADLINE  90

static time_t wb_mp_t0;

/* Budget by VECTOR COUNT, not elapsed time: a wall-clock budget makes coverage
 * a function of machine load, so the same source measures differently run to
 * run (proved on wc_lms_impl.c, 2026-08-11). The wall clock is kept only as a
 * backstop against TEST_TIMEOUT, and announces itself if it fires. */
#ifndef WB_MAX_VECTORS
    #define WB_MAX_VECTORS 20000
#endif

static long wb_mp_vectors = 0;
static int  wb_mp_backstop = 0;

static int wb_mp_expired(void)
{
    if (++wb_mp_vectors > (long)WB_MAX_VECTORS) {
        return 1;
    }
    if (difftime(time(NULL), wb_mp_t0) > (double)WB_MP_DEADLINE) {
        if (!wb_mp_backstop) {
            wb_mp_backstop = 1;
            printf("  [wb] WALL-CLOCK BACKSTOP fired after %ld "
                   "vectors; lower WB_MAX_VECTORS\n", wb_mp_vectors);
        }
        return 1;
    }
    return 0;
}

/* Run the statement once DISARMED -- the all-true baseline row for every guard
 * it touches, in THIS binary, and the sweep length K -- then sweep the fail
 * index over [1..min(K, cap)]. */
#define WB_MP_SWEEP(lbl, cap, ...)                                        \
    do {                                                                  \
        long k_, i_;                                                      \
        mcdc_fm_disarm();                                                 \
        { __VA_ARGS__; }                                                  \
        k_ = mcdc_fm_seen();                                              \
        if (k_ > (long)(cap))                                             \
            k_ = (long)(cap);                                             \
        for (i_ = 1; (i_ <= k_) && !wb_mp_expired(); i_++) {              \
            mcdc_fm_arm(i_);                                              \
            { __VA_ARGS__; }                                              \
            mcdc_fm_disarm();                                             \
        }                                                                 \
        printf("  [wb] mp sweep %s: K=%ld\n", (lbl), k_);                 \
    } while (0)

static void wb_mp_sweeps(SakkeKey* key, WC_RNG* rng, ecc_point* rsk)
{
    byte   ssv2[128];
    byte   auth2[257];
    word16 aSz;

    wb_mp_t0 = time(NULL);
    mcdc_fm_disarm();
    XMEMSET(ssv2, 0x5a, sizeof(ssv2));
    XMEMSET(auth2, 0, sizeof(auth2));

    /* Fresh key per iteration: MakeSakkeKey mutates it, and its retry loop
     * (543) plus the point-I/RSK derivation chains are what the sweep is for. */
    WB_MP_SWEEP("MakeSakkeKey", 150,
        {
            SakkeKey k2;
            if (wc_InitSakkeKey_ex(&k2, 128, ECC_SAKKE_1, NULL,
                    INVALID_DEVID) == 0) {
                (void)wc_MakeSakkeKey(&k2, rng);
                wc_FreeSakkeKey(&k2);
            }
        });

    WB_MP_SWEEP("MakeSakkeRsk", 200,
        {
            ecc_point* r2 = wc_ecc_new_point();
            if (r2 != NULL) {
                (void)wc_MakeSakkeRsk(key, gId, gIdSz, r2);
                wc_ecc_del_point(r2);
            }
        });

    WB_MP_SWEEP("ValidateSakkeRsk", 250,
        {
            int v = -1;
            (void)wc_ValidateSakkeRsk(key, gId, gIdSz, rsk, &v);
        });

    WB_MP_SWEEP("MakeSakkeEncapsulatedSSV", 250,
        {
            byte   s2[128];
            byte   a2[257];
            word16 z = (word16)sizeof(a2);
            XMEMSET(s2, 0x5a, sizeof(s2));
            (void)wc_MakeSakkeEncapsulatedSSV(key, WC_HASH_TYPE_SHA256, s2, 16,
                a2, &z);
        });

    /* One valid encapsulation, produced DISARMED, for the derive sweep. */
    mcdc_fm_disarm();
    aSz = (word16)sizeof(auth2);
    if (wc_MakeSakkeEncapsulatedSSV(key, WC_HASH_TYPE_SHA256, ssv2, 16, auth2,
            &aSz) == 0) {
        WB_MP_SWEEP("DeriveSakkeSSV", 250,
            {
                byte s3[128];
                XMEMCPY(s3, ssv2, 16);
                (void)wc_DeriveSakkeSSV(key, WC_HASH_TYPE_SHA256, s3, 16,
                    auth2, aSz);
            });
    }

    mcdc_fm_disarm();
    WB_NOTE("big-integer fault sweeps done");
}

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

    /* Unbuffered: if an armed call ever crashes, the notes printed so far
     * must survive to say WHICH sweep it died in. */
    setvbuf(stdout, NULL, _IONBF, 0);
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

        /* --- wc_MakeSakkeKey 543: the master-secret retry loop
         *       while ((err == 0) && mp_iszero(wc_ecc_key_get_priv(..)))
         * Both conditions need the loop to actually RETRY, i.e. a drawn scalar
         * that reduces to zero -- a ~2^-1024 event that no heap fault and no
         * seeded RNG can produce (mp_rand() is served from another TU, so the
         * seeded-RNG macro never reaches it). The value-forcing mp_rand()
         * interposer at the top of this file is the lever; sakke.c has exactly
         * one mp_rand() call site, and both modes are ONE-SHOT so the second
         * iteration draws real entropy and the loop terminates on real data.
         *
         *   WB_SR_ZERO -> (T,T) decision TRUE, retries; the retry supplies the
         *                 accepting (T,F) row -> closes idx1 and gives idx0
         *                 the TRUE-decision partner it needs
         *   WB_SR_FAIL -> (F,-) decision FALSE                 -> closes idx0
         * Both rows land in THIS binary alongside the ordinary (T,F). --- */
        {
            int mode;
            for (mode = WB_SR_ZERO; mode <= WB_SR_FAIL; mode++) {
                SakkeKey zk;
                XMEMSET(&zk, 0, sizeof(zk));
                if (wc_InitSakkeKey_ex(&zk, 128, ECC_SAKKE_1, NULL,
                        INVALID_DEVID) == 0) {
                    int e2;
                    wb_sr_mode = mode;
                    e2 = wc_MakeSakkeKey(&zk, &rng);
                    wb_sr_mode = WB_SR_OFF;
                    printf("  [wb] MakeSakkeKey rand mode %d -> %d\n",
                           mode, e2);
                    wc_FreeSakkeKey(&zk);
                }
            }
        }

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
            /* sakke_tplmod 1518 idx0 (`err == 0` FALSE) -- the THIRD of the
             * helper's three sequential reductions:
             *
             *     err = mp_mul_d(a, 3, r);                          (1511)
             *     if ((err == 0) && (mp_cmp(r,m) != MP_LT)) sub;    (1512)
             *     if ((err == 0) && (mp_cmp(r,m) != MP_LT)) sub;    (1515)
             *     if ((err == 0) && (mp_cmp(r,m) != MP_LT)) sub;    (1518)
             *
             * 1512 and 1515 get their err!=0 halves for free -- an earlier
             * mp_sub failing carries err forward -- but 1518 needs the mp_sub
             * at 1516 to have RUN and FAILED, which needs an input where the
             * first two reductions both fire. Every in-product caller passes
             * a < m, so 3a < 3m and the third check is only ever reached with
             * err == 0; a direct call on the file-static helper with a == m
             * makes all three fire (300 -> 200 -> 100 -> 0).
             *
             * The heap lever cannot do it: under a fixed sp_int backend
             * mp_sub() never allocates, so it never fails. mcdc_fault_mp.h's
             * lever can -- interposed mp_* call 1 is the mp_mul_d, 2 is the
             * mp_sub at 1513 and 3 is the mp_sub at 1516, so arming index 3
             * fails exactly that one and 1518 is reached with err != 0.
             *
             * The accepting (T,T) row at 1518 is the unarmed a == m call right
             * before it; the (T,F) row comes from the a=40,m=100 tplmod calls
             * in the sweep below (300 -> 200 -> 100 -> stop). */
            {
                mp_int a, m, r;
                int e0, e1;
                mp_init(&a); mp_init(&m); mp_init(&r);
                mp_set(&a, 100); mp_set(&m, 100);
                e1 = sakke_tplmod(&a, &m, &r);              /* 1518 (T,T) */
                mcdc_fm_arm(3);
                e0 = sakke_tplmod(&a, &m, &r);              /* 1518 (F,-) */
                mcdc_fm_disarm();
                printf("  [wb] sakke_tplmod 1518 vectors: (T,T)=%d armed=%d\n",
                       e1, e0);
                mp_free(&a); mp_free(&m); mp_free(&r);
            }

            /* sakke_addmod 1490 idx0, same shape but one reduction: a direct
             * armed call is the only way to reach it with err != 0. */
            {
                mp_int a, b, m, r;
                int e0;
                mp_init(&a); mp_init(&b); mp_init(&m); mp_init(&r);
                mp_set(&a, 60); mp_set(&b, 70); mp_set(&m, 100);
                mcdc_fm_arm(1);
                e0 = sakke_addmod(&a, &b, &m, &r);          /* 1490 (F,-) */
                mcdc_fm_disarm();
                (void)sakke_addmod(&a, &b, &m, &r);         /* 1490 (T,T) */
                mp_set(&a, 10); mp_set(&b, 20);
                (void)sakke_addmod(&a, &b, &m, &r);         /* 1490 (T,F) */
                printf("  [wb] sakke_addmod 1490 armed=%d\n", e0);
                mp_free(&a); mp_free(&b); mp_free(&m); mp_free(&r);
            }

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
    if (!do_baseline && !do_probe)
        wb_mp_sweeps(&key, &rng, rsk);
    mcdc_fm_disarm();
    wc_FreeSakkeKey(&key);
    wc_ecc_forcezero_point(rsk);
    wc_ecc_del_point(rsk);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* WOLFCRYPT_HAVE_SAKKE */
