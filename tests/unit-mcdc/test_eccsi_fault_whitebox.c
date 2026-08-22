/* test_eccsi_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/eccsi.c.
 *
 * The tests/api eccsi suite plus tests/unit-mcdc/test_eccsi_whitebox.c drive
 * eccsi.c to 129/140 conditions. The two file-static "map" guards
 *
 *     eccsi_mulmod_base_add():   if ((err == 0) && map)   (line ~1358)
 *     eccsi_mulmod_point_add():  if ((err == 0) && map)   (line ~1449)
 *
 * still have the FALSE half of their `err == 0` condition uncovered: every
 * caller (and the existing whitebox) reaches these guards with err == 0, so the
 * err-non-zero branch is only taken when an EARLIER step in the helper
 * (wc_ecc_mulmod / ecc_projective_add_point) fails. Under the default sp-math
 * build those steps allocate heap scratch, so making one of their allocations
 * return NULL forces err = MEMORY_E and drives the `err == 0` FALSE half while
 * `map` is held TRUE -- exactly the MC/DC independence case for `err == 0`.
 *
 * This white-box installs the generic heap-fault injector (mcdc_fault_alloc.h)
 * and, for each helper, sweeps the fail-index across the allocation sites of the
 * mulmod/point-add so that for some index an earlier allocation returns NULL and
 * the map guard sees err != 0. It #includes eccsi.c directly (like the sibling
 * test_eccsi_whitebox.c) so the file-static helpers are in scope.
 *
 * Not driven here (justified, documented in test_eccsi_whitebox.c and the uncovered-condition report):
 *   - eccsi_load_ecc_params() 196/202/208 `err == 0` FALSE halves: reaching them
 *     requires eccsi_load_order() / the a/b radix reads to fail. Those are
 *     mp_read_radix() calls on fixed, static, in-struct sp_int members of known-
 *     good curve constants; under WOLFSSL_SP_MATH_ALL they perform NO heap
 *     allocation (confirmed by the PROBE mode below reporting 0 allocs), so a
 *     pass-through heap-fault allocator cannot make them fail and the reads
 *     cannot fail on the valid static hex strings either. Defensive residuals.
 *   - eccsi_make_pair() (916) and eccsi_gen_sig() (1926) retry-loop conditions:
 *     the mp_iszero / mp_cmp collision only triggers on a cryptographically
 *     negligible (~2^-256) random draw, not on allocation failure. Left as
 *     defensive residuals (see test_eccsi_whitebox.c).
 *
 * Crash-safety: the key/base/params are prepared while DISARMED. Every armed
 * call either fails an allocation inside wc_ecc_mulmod / ecc_projective_add_point
 * (whose own cleanup frees the partial state and returns MEMORY_E, which is
 * exactly what the map guard then observes) or runs to completion. The harness
 * never dereferences a value a faulted call produced. Runs clean under
 * -fsanitize=address.
 *
 * Invocation:
 *   ./test_eccsi_fault_whitebox            default: full fault sweep (used by the
 *                                          suite run_whitebox, no args)
 *   ./test_eccsi_fault_whitebox baseline   unarmed valid ops only (delta baseline)
 *   ./test_eccsi_fault_whitebox probe      per-target allocation-site counts
 */

/* Installed BEFORE eccsi.c so its mp_* calls resolve to the fault wrappers.
 * eccsi.c's residuals are the `(err == 0) && <next step>` halves of its
 * big-integer success chains (196/202/208 params->haveA/haveB/havePrime, the
 * 924/1934 retry loops). No mp_* call ever fails on a healthy machine and the
 * mp scratch is on the stack, so neither the ordinary tests nor the heap-fault
 * sweep below can drive `err == 0` FALSE there. mcdc_fault_mp.h interposes the
 * value-returning mp_* API for this TU only; mcdc_fm_arm(n) fails the n-th
 * mp_* call and every later one. Predicates (mp_iszero/mp_cmp) and teardown
 * (mp_free/mp_forcezero) are NOT interposed, so cleanup keeps working. */
#include "mcdc_fault_mp.h"

/* --------------------------------------------------------------------------
 * Value-forcing mp_addmod() interposer for eccsi_gen_sig()'s rejection loop
 * (eccsi.c:1934):
 *
 *     do { ... err = mp_mulmod(r, &key->ssk, &key->params.order, s);
 *              err = mp_addmod(he, s, &key->params.order, s); }
 *     while ((err == 0) && (mp_iszero(s) || (mp_cmp(s, he) == MP_EQ)));
 *
 * RFC 6507 step 4 rejects the candidate when s == 0 or s == HE. Both are
 * ~2^-256 events on real entropy, so no amount of API driving reaches them,
 * and a seeded RNG cannot force them either: s is the output of a modular
 * multiply-and-add over an ephemeral scalar, not a value the generator hands
 * out. Without one of the two rejecting draws the decision only ever records
 * (T,F,F), which is a single vector -- that is why ALL THREE conditions were
 * open, including `err == 0`, whose independence pair needs a vector where the
 * loop actually REPEATS.
 *
 * eccsi.c has exactly two mp_addmod() call sites -- eccsi_make_pair() at 920
 * and this one at 1931 -- and only the second is reached from
 * wc_SignEccsiHash(), so a one-shot armed immediately around a sign call needs
 * no disambiguation.
 *
 * The modes are ONE-SHOT, so the loop's SECOND iteration computes a genuine s
 * and terminates on real data: no retry loop here depends on a random draw
 * going a particular way, and the accepting (T,F,F) row is produced by that
 * same iteration in the same binary as the rejecting rows.
 *
 * Ordering is the load-bearing trick from mcdc_fault_mp.h: the wrapper is
 * compiled while mp_addmod still names the (already interposed) real thing,
 * and only then is the name redefined. eccsi.c is #included AFTER this block.
 * ----------------------------------------------------------------------- */
#define WB_EA_OFF   0   /* pass through */
#define WB_EA_ZERO  1   /* succeed, but hand back s == 0        -> 1934 idx1 */
#define WB_EA_EQ    2   /* succeed, but hand back s == he       -> 1934 idx2 */
#define WB_EA_FAIL  3   /* fail the add                         -> 1934 idx0 */

static int wb_ea_mode = WB_EA_OFF;

MCDC_FM_MAYBE_UNUSED static int wb_ea_addmod(const mp_int* a, const mp_int* b,
    const mp_int* m, mp_int* r)
{
    int mode = wb_ea_mode;
    int err;

    if (mode != WB_EA_OFF) {
        wb_ea_mode = WB_EA_OFF;   /* one-shot */
    }
    if (mode == WB_EA_FAIL) {
        return MCDC_FM_ERR;
    }

    err = mp_addmod(a, b, m, r);
    if (err == 0) {
        if (mode == WB_EA_ZERO) {
            /* s = 0: RFC 6507's first rejection test. */
            mp_zero(r);
        }
        else if (mode == WB_EA_EQ) {
            /* s = HE: the second rejection test. `a` IS he at the 1931 call
             * site, so this needs no extra handle on the key. */
            err = mp_copy(a, r);
        }
    }
    return err;
}

#undef  mp_addmod
#define mp_addmod(a, b, c, d)   wb_ea_addmod((a), (b), (c), (d))

#include <wolfcrypt/src/eccsi.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFCRYPT_HAVE_ECCSI) || !defined(WOLFCRYPT_ECCSI_CLIENT)

int main(void)
{
    printf("eccsi.c fault white-box: ECCSI/ECCSI_CLIENT not enabled, "
           "nothing to do\n");
    return 0;
}

#else

/* Reload the base point coordinates into params->base (eccsi_mulmod_base_add
 * mutates params->base in place and clears haveBase). Must be DISARMED. */
static int reload_base(EccsiKey* key)
{
    key->params.haveBase = 0;
    return eccsi_load_base(key);
}

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

/* ---- eccsi_gen_sig() 1934 rejection loop -------------------------------
 *      while ((err == 0) && (mp_iszero(s) || (mp_cmp(s, he) == MP_EQ)));
 *
 * Three conditions, and before this vector set ALL THREE were open, because
 * the loop had only ever been observed taking the single (T,F,F) exit: the two
 * RFC 6507 step-4 rejections (s == 0, s == HE) are ~2^-256 draws, and `err==0`
 * cannot show independence without a partner vector in which the decision is
 * TRUE -- i.e. in which the loop actually repeats.
 *
 * The one-shot mp_addmod modes at the top of this file supply all of it:
 *   WB_EA_ZERO -> (T,T,-) TRUE, retries; the retry is the accepting (T,F,F)
 *   WB_EA_EQ   -> (T,F,T) TRUE, likewise
 *   WB_EA_FAIL -> (F,-,-) FALSE
 *
 * Self-contained fixture on purpose: the shared fixture in wb_mp_sweeps() is
 * driven through armed sweeps before the sign path is reached, and one of them
 * currently leaves the key in a state wc_SetEccsiPair rejects (see the note
 * there). A fresh key here means these vectors cannot be lost to that.
 */
static void wb_gen_sig_reject(WC_RNG* rng)
{
    EccsiKey   k;
    ecc_point* pvt = NULL;
    mp_int     ssk;
    byte       id[] = "eccsi-gensig@wolfssl.com";
    byte       hash[WC_MAX_DIGEST_SIZE];
    byte       hashSz = 0;
    int        ready = 0;
    int        mode;

    mcdc_fm_disarm();
    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&ssk, 0, sizeof(ssk));
    XMEMSET(hash, 0, sizeof(hash));

    if (wc_InitEccsiKey(&k, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("gen_sig fixture: wc_InitEccsiKey failed; 1934 skipped");
        return;
    }
    pvt = wc_ecc_new_point_h(NULL);
    if ((pvt != NULL) && (mp_init(&ssk) == 0) &&
            (wc_MakeEccsiKey(&k, rng) == 0) &&
            (wc_MakeEccsiPair(&k, rng, WC_HASH_TYPE_SHA256, id,
                (word32)sizeof(id), &ssk, pvt) == 0) &&
            (wc_SetEccsiPair(&k, &ssk, pvt) == 0) &&
            (wc_HashEccsiId(&k, WC_HASH_TYPE_SHA256, id, (word32)sizeof(id),
                pvt, hash, &hashSz) == 0) &&
            (wc_SetEccsiHash(&k, hash, hashSz) == 0)) {
        ready = 1;
    }
    if (!ready) {
        WB_NOTE("gen_sig fixture setup failed; 1934 skipped");
        wb_fail = 1;
    }
    else {
        for (mode = WB_EA_ZERO; mode <= WB_EA_FAIL; mode++) {
            byte   sg[257];
            word32 z = (word32)sizeof(sg);
            int    e;

            XMEMSET(sg, 0, sizeof(sg));
            wb_ea_mode = mode;
            e = wc_SignEccsiHash(&k, rng, WC_HASH_TYPE_SHA256, hash,
                    WC_SHA256_DIGEST_SIZE, sg, &z);
            wb_ea_mode = WB_EA_OFF;
            printf("  [wb] gen_sig reject mode %d -> %d\n", mode, e);
        }
    }

    mp_free(&ssk);
    if (pvt != NULL)
        wc_ecc_del_point_h(pvt, NULL);
    wc_FreeEccsiKey(&k);
}

static void wb_mp_sweeps(WC_RNG* rng)
{
    EccsiKey  k;
    ecc_point* pvt = NULL;
    mp_int     ssk;
    byte       id[] = "eccsi-mp-fault@wolfssl.com";
    byte       hash[WC_MAX_DIGEST_SIZE];
    byte       hashSz = 0;
    byte       sig[257];
    word32     sigSz;
    int        verified = 0;
    int        ready = 0;

    wb_mp_t0 = time(NULL);
    mcdc_fm_disarm();

    /* Runs first, on its own fixture: see wb_gen_sig_reject(). */
    wb_gen_sig_reject(rng);
    mcdc_fm_disarm();

    XMEMSET(&k, 0, sizeof(k));
    XMEMSET(&ssk, 0, sizeof(ssk));
    XMEMSET(hash, 0x5a, sizeof(hash));
    XMEMSET(sig, 0, sizeof(sig));

    if (wc_InitEccsiKey(&k, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitEccsiKey failed; mp sweeps skipped");
        return;
    }
    pvt = wc_ecc_new_point_h(NULL);
    if ((pvt != NULL) && (mp_init(&ssk) == 0) &&
            (wc_MakeEccsiKey(&k, rng) == 0)) {
        ready = 1;
    }
    if (!ready) {
        WB_NOTE("eccsi fixture setup failed; mp sweeps skipped");
        goto done;
    }

    /* Order matters: everything that needs a VALID (ssk, pvt) pair is driven
     * first, because the MakeEccsiPair sweep leaves the key in whatever state
     * a faulted call produced. */
    mcdc_fm_disarm();
    if (wc_MakeEccsiPair(&k, rng, WC_HASH_TYPE_SHA256, id, (word32)sizeof(id),
            &ssk, pvt) != 0) {
        WB_NOTE("wc_MakeEccsiPair baseline failed; mp sweeps skipped");
        goto done;
    }

    WB_MP_SWEEP("ValidateEccsiPair", 200,
        {
            int v = 0;
            (void)wc_ValidateEccsiPair(&k, WC_HASH_TYPE_SHA256, id,
                (word32)sizeof(id), &ssk, pvt, &v);
        });

    mcdc_fm_disarm();
    if ((wc_SetEccsiPair(&k, &ssk, pvt) == 0) &&
            (wc_HashEccsiId(&k, WC_HASH_TYPE_SHA256, id, (word32)sizeof(id),
                pvt, hash, &hashSz) == 0) &&
            (wc_SetEccsiHash(&k, hash, hashSz) == 0)) {
        WB_MP_SWEEP("SignEccsiHash", 200,
            {
                byte   s2[257];
                word32 z = (word32)sizeof(s2);
                (void)wc_SignEccsiHash(&k, rng, WC_HASH_TYPE_SHA256, hash,
                    WC_SHA256_DIGEST_SIZE, s2, &z);
            });

        mcdc_fm_disarm();
        sigSz = (word32)sizeof(sig);
        if (wc_SignEccsiHash(&k, rng, WC_HASH_TYPE_SHA256, hash,
                WC_SHA256_DIGEST_SIZE, sig, &sigSz) == 0) {
            WB_MP_SWEEP("VerifyEccsiHash", 200,
                (void)wc_VerifyEccsiHash(&k, WC_HASH_TYPE_SHA256, hash,
                    WC_SHA256_DIGEST_SIZE, sig, sigSz, &verified));
        }
        else {
            WB_NOTE("wc_SignEccsiHash baseline failed; verify sweep skipped");
        }
    }
    else {
        /* Print WHICH step refused, so this never has to be bisected again:
         * the original spelling passed hashSz = NULL to wc_HashEccsiId(),
         * which rejects it with BAD_FUNC_ARG, and the SignEccsiHash /
         * VerifyEccsiHash sweeps below were silently skipped on every run. */
        int e1 = wc_SetEccsiPair(&k, &ssk, pvt);
        int e2 = wc_HashEccsiId(&k, WC_HASH_TYPE_SHA256, id,
                     (word32)sizeof(id), pvt, hash, &hashSz);
        int e3 = wc_SetEccsiHash(&k, hash, hashSz);
        printf("  [wb] SetEccsiPair=%d HashEccsiId=%d SetEccsiHash=%d; "
               "sign+verify sweeps skipped\n", e1, e2, e3);
    }

    /* 196/202/208 eccsi_load_ecc_params():
     *     if ((err == 0) && (!params->haveA))     (and haveB / havePrime)
     * The FALSE half of the err operand needs an earlier step in the SAME call
     * to fail, with the second operand still true -- i.e. a key whose haveA/
     * haveB/havePrime are still 0. Those flags latch on first use, and the
     * public API caches them, so the only way to present a fresh key is to
     * call the file-static helper directly (in scope via the #include at the
     * top) on a key that has never loaded its parameters, with the fail index
     * landing on eccsi_load_order()'s / this function's own mp_read_radix.
     * The all-true row comes from the unarmed fixture setup above. */
    {
        long n;

        for (n = 1; (n <= 6) && !wb_mp_expired(); n++) {
            EccsiKey k2;

            XMEMSET(&k2, 0, sizeof(k2));
            if (wc_InitEccsiKey(&k2, NULL, INVALID_DEVID) == 0) {
                mcdc_fm_disarm();
                if (wc_MakeEccsiKey(&k2, rng) == 0) {
                    /* Clear the latches so every guard's second operand is
                     * true again for this armed call. */
                    k2.params.haveA     = 0;
                    k2.params.haveB     = 0;
                    k2.params.havePrime = 0;
                    mcdc_fm_arm(n);
                    (void)eccsi_load_ecc_params(&k2);
                    mcdc_fm_disarm();
                }
                wc_FreeEccsiKey(&k2);
            }
        }
        printf("  [wb] mp sweep eccsi_load_ecc_params: 6 points\n");
    }

    /* Destructive sweeps last: each faulted call may leave the key or the
     * pair unusable, so nothing above may depend on them. */
    WB_MP_SWEEP("MakeEccsiPair", 200,
        (void)wc_MakeEccsiPair(&k, rng, WC_HASH_TYPE_SHA256, id,
            (word32)sizeof(id), &ssk, pvt));

    WB_MP_SWEEP("MakeEccsiKey", 120,
        {
            EccsiKey k2;
            XMEMSET(&k2, 0, sizeof(k2));
            if (wc_InitEccsiKey(&k2, NULL, INVALID_DEVID) == 0) {
                (void)wc_MakeEccsiKey(&k2, rng);
                wc_FreeEccsiKey(&k2);
            }
        });

done:
    mcdc_fm_disarm();
    mp_free(&ssk);
    if (pvt != NULL)
        wc_ecc_del_point_h(pvt, NULL);
    wc_FreeEccsiKey(&k);
    WB_NOTE("big-integer fault sweeps done");
}

int main(int argc, char** argv)
{
    int      do_sweep   = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    int      do_probe   = (argc > 1 && strcmp(argv[1], "probe") == 0);
    WC_RNG   rng;
    EccsiKey key;
    ecc_point* ptA = NULL;
    ecc_point* ptB = NULL;
    ecc_point* res = NULL;
    mp_int   n;
    mp_digit mp = 0;
    int      ret;
    int      n_idx;
    const int K = 60; /* over-sweep past the mulmod/point-add allocation sites */

    /* Unbuffered: if an armed call ever crashes, the notes printed so far
     * must survive to say WHICH sweep it died in. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("eccsi.c fault white-box (%s)\n",
           do_probe ? "probe" : (do_sweep ? "sweep" : "baseline"));

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&n, 0, sizeof(n));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    /* ---- prepare a valid KMS key with base/params/mp loaded (DISARMED) ---- */
    ret = wc_InitEccsiKey(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("  wc_InitEccsiKey failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
    ret = wc_MakeEccsiKey(&key, &rng);
    if (ret == 0)
        ret = eccsi_load_base(&key);
    if (ret == 0)
        ret = eccsi_load_ecc_params(&key);
    if (ret == 0)
        ret = mp_montgomery_setup(&key.params.prime, &mp);
    if (ret == 0)
        ret = mp_init(&n);
    if (ret == 0)
        ret = mp_set(&n, 3);
    if (ret == 0) {
        ptA = wc_ecc_new_point_h(NULL);
        ptB = wc_ecc_new_point_h(NULL);
        res = wc_ecc_new_point_h(NULL);
        if ((ptA == NULL) || (ptB == NULL) || (res == NULL))
            ret = MEMORY_E;
    }
    if (ret == 0)
        ret = wc_ecc_copy_point(key.params.base, ptA);
    if (ret == 0)
        ret = wc_ecc_copy_point(key.params.base, ptB);
    if (ret != 0) {
        printf("  key/base preparation failed (%d); skipping\n", ret);
        wb_fail = 1;
        goto cleanup;
    }

    /* ---- baseline: one unarmed success of each targeted helper (err==0
     *      TRUE side of the map guard, both map polarities). ---- */
    (void)reload_base(&key);
    (void)eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 1);
    (void)reload_base(&key);
    (void)eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 0);
    (void)eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp, 1);
    (void)eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp, 0);

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Diagnostic: allocation-site counts, faulting nothing. Also confirms
         * the eccsi_load_* radix reads do NOT allocate (hence 196/202/208 are
         * not heap-fault closable -- see the file header). */
        unsigned long c_order, c_params, c_base_add, c_point_add;

        key.params.haveOrder = 0;
        mcdc_fa_arm(1000000);
        (void)eccsi_load_order(&key);
        c_order = mcdc_fa_count;

        key.params.haveOrder = key.params.haveA = key.params.haveB =
            key.params.havePrime = 0;
        mcdc_fa_arm(1000000);
        (void)eccsi_load_ecc_params(&key);
        c_params = mcdc_fa_count;

        (void)reload_base(&key);
        mcdc_fa_arm(1000000);
        (void)eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 1);
        c_base_add = mcdc_fa_count;

        mcdc_fa_arm(1000000);
        (void)eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp, 1);
        c_point_add = mcdc_fa_count;

        mcdc_fa_disarm();
        printf("  PROBE eccsi_load_order      allocs = %lu\n", c_order);
        printf("  PROBE eccsi_load_ecc_params allocs = %lu\n", c_params);
        printf("  PROBE eccsi_mulmod_base_add allocs = %lu\n", c_base_add);
        printf("  PROBE eccsi_mulmod_point_add allocs = %lu\n", c_point_add);
        goto cleanup;
    }
#endif

    if (do_sweep) {
#ifndef MCDC_FA_UNAVAILABLE
        /* --- eccsi_mulmod_base_add: fault an allocation inside wc_ecc_mulmod /
         * ecc_projective_add_point so err = MEMORY_E before the `(err==0)&&map`
         * guard -> drives the 1358 `err == 0` FALSE half (map held TRUE). Fresh
         * base per iteration (the helper mutates params->base). --- */
        for (n_idx = 1; n_idx <= K; n_idx++) {
            (void)reload_base(&key);      /* DISARMED: base valid again */
            mcdc_fa_arm(n_idx);
            (void)eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 1);
            mcdc_fa_disarm();
        }
        /* Restore a clean base for the point-add sweep. */
        (void)reload_base(&key);

        /* --- eccsi_mulmod_point_add: same idea; wc_ecc_mulmod allocation
         * failure drives the 1449 `err == 0` FALSE half (map held TRUE).
         * point-add does not mutate params->base, so ptA/ptB are reused. --- */
        for (n_idx = 1; n_idx <= K; n_idx++) {
            mcdc_fa_arm(n_idx);
            (void)eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp, 1);
            mcdc_fa_disarm();
        }
        WB_NOTE("fault-index sweeps over mulmod_base_add / mulmod_point_add "
                "done (1358/1449 err==0 FALSE halves)");
#else
        WB_NOTE("fault injector unavailable in this variant; nothing swept");
#endif
    }

cleanup:
    mcdc_fa_disarm();
    mcdc_fa_restore();
    if (do_sweep)
        wb_mp_sweeps(&rng);
    if (ptA != NULL) wc_ecc_del_point_h(ptA, NULL);
    if (ptB != NULL) wc_ecc_del_point_h(ptB, NULL);
    if (res != NULL) wc_ecc_del_point_h(res, NULL);
    mp_free(&n);
    wc_FreeEccsiKey(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* WOLFCRYPT_HAVE_ECCSI && WOLFCRYPT_ECCSI_CLIENT */
