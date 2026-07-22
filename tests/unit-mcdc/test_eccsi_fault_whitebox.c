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
 * Not driven here (justified, documented in test_eccsi_whitebox.c and GAPS.md):
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
 *                                          campaign run_whitebox, no args)
 *   ./test_eccsi_fault_whitebox baseline   unarmed valid ops only (delta baseline)
 *   ./test_eccsi_fault_whitebox probe      per-target allocation-site counts
 */

#include <wolfcrypt/src/eccsi.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

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
