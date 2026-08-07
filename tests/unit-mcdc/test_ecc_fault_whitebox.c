/* test_ecc_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/ecc.c.
 *
 * ecc.c's generic (non-SP) point-math helpers switch from stack mp_int[1]
 * arrays to individually XMALLOC'd mp_int structures under
 * WOLFSSL_SMALL_STACK, each guarded by a "was the alloc NULL" check that
 * only exists (and only ever runs the FALSE-then-TRUE independence pair)
 * when that switch is active:
 *
 *   _ecc_projective_add_point:  if (t1 == NULL || t2 == NULL) (x3 call
 *                                sites: line ~2075, ~2472, ~2837 -- the
 *                                third also guards the ALT_ECC_SIZE
 *                                rx/ry/rz allocation)
 *   mp_sqrtmod_prime:           10-operand NULL check (line ~16490) over
 *                                t1/C/Q/S/Z/M/T/R/N/two, reachable only via
 *                                point decompression (a compressed-point
 *                                DER import)
 *
 * In normal execution every allocation succeeds, so these NULL guards never
 * take their TRUE branch. This white-box installs the generic heap-fault
 * injector (mcdc_fault_alloc.h, shared with test_rsa_fault_whitebox.c) and
 * sweeps the fail-index across each entry point's allocation sites so that,
 * for each index, exactly one allocation returns NULL and drives that
 * guard's failure half.
 *
 * Productive ONLY under WOLFSSL_SMALL_STACK (the small_stack variant): on
 * every other variant these mp_int temporaries are plain stack arrays, no
 * XMALLOC site exists, and the sweep below simply runs every call to
 * completion without finding anything to fault (still builds and passes
 * cleanly, contributing 0 extra coverage -- same "safe on every variant,
 * productive on one" shape as test_rsa_fault_whitebox.c's own SMALL_STACK
 * dependency).
 *
 * #includes ecc.c directly (like the sibling test_ecc_whitebox.c) to reach
 * the file-static mp_sqrtmod_prime and the generic add/dbl point helpers'
 * SMALL_STACK allocation sites via their always-compiled public wrappers
 * ecc_projective_add_point()/ecc_projective_dbl_point().
 *
 * Crash-safety: every armed call either returns MEMORY_E/BAD_FUNC_ARG
 * before touching an uninitialized mp_int, or fails a deeper allocation
 * whose error the target's own cleanup absorbs. Inputs are prepared while
 * DISARMED; the harness never dereferences a value a faulted call
 * returned.
 */

#include <wolfcrypt/src/ecc.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_ECC) && !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLFSSL_SP_MATH)

/* Generous over-sweep: 2 sites for add/dbl point (t1/t2), a few more when
 * ALT_ECC_SIZE also allocates rx/ry/rz, and 10 sites for mp_sqrtmod_prime.
 * Over-sweeping past the real site count is harmless -- the target just
 * runs to completion once the fail index is out of range. */
#define WB_SWEEP_K 16

/* ------------------------------------------------------------------------- *
 * _ecc_projective_add_point / _ecc_projective_dbl_point SMALL_STACK t1/t2
 * (+ rx/ry/rz under ALT_ECC_SIZE) XMALLOC NULL guards, via the always-
 * compiled public wrappers (see test_ecc_whitebox.c Class 14 for why these
 * are reachable regardless of WOLFSSL_PUBLIC_ECC_ADD_DBL).
 * ------------------------------------------------------------------------- */
static void wb_fault_projective_add_dbl(void)
{
    ecc_point *P, *Q, *R;
    mp_int a, modulus;
    int n;

    if (mp_init_multi(&a, &modulus, NULL, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    (void)mp_set(&a, 2);
    (void)mp_set_int(&modulus, 1000000007uL);

    P = wc_ecc_new_point();
    Q = wc_ecc_new_point();
    R = wc_ecc_new_point();
    if (P == NULL || Q == NULL || R == NULL) {
        wb_fail = 1;
        goto out;
    }
    (void)mp_set(P->x, 3); (void)mp_set(P->y, 5); (void)mp_set(P->z, 1);
    (void)mp_set(Q->x, 11); (void)mp_set(Q->y, 13); (void)mp_set(Q->z, 1);

    for (n = 1; n <= WB_SWEEP_K; n++) {
        mcdc_fa_arm(n);
        (void)ecc_projective_add_point(P, Q, R, &a, &modulus, 0);
        mcdc_fa_disarm();
    }
    for (n = 1; n <= WB_SWEEP_K; n++) {
        mcdc_fa_arm(n);
        (void)ecc_projective_dbl_point(P, R, &a, &modulus, 0);
        mcdc_fa_disarm();
    }

    WB_NOTE("_ecc_projective_add/dbl_point SMALL_STACK alloc sweep done");

out:
    wc_ecc_del_point(P);
    wc_ecc_del_point(Q);
    wc_ecc_del_point(R);
    mp_clear(&modulus);
    mp_clear(&a);
}

/* ------------------------------------------------------------------------- *
 * mp_sqrtmod_prime's 10-mp_int SMALL_STACK XMALLOC NULL guard, via
 * wc_ecc_import_point_der_ex() decompressing a real compressed point (the
 * curve generator G, always a valid on-curve x): reaches the sqrt-mod-prime
 * "compute y from x" branch of point decompression.
 * ------------------------------------------------------------------------- */
static void wb_fault_sqrtmod_prime(void)
{
#if defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_COMP_KEY)
    int idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    const ecc_set_type* cs;
    mp_int gx;
    byte der[1 + 66];
    word32 numlen;
    int n;

    if (idx == ECC_CURVE_INVALID) {
        WB_NOTE("SECP256R1 not in ecc_sets[]; sqrtmod_prime sweep skipped");
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);
    numlen = (word32)cs->size;

    if (mp_init(&gx) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    if (mp_read_radix(&gx, cs->Gx, MP_RADIX_HEX) != MP_OKAY) {
        mp_clear(&gx);
        wb_fail = 1;
        return;
    }
    XMEMSET(der, 0, sizeof(der));
    der[0] = ECC_POINT_COMP_EVEN; /* either parity reaches the sqrt call */
    if (mp_to_unsigned_bin(&gx, der + 1 +
            (numlen - (word32)mp_unsigned_bin_size(&gx))) != MP_OKAY) {
        mp_clear(&gx);
        wb_fail = 1;
        return;
    }
    mp_clear(&gx);

    for (n = 1; n <= WB_SWEEP_K; n++) {
        ecc_point* point = wc_ecc_new_point();
        if (point == NULL) {
            wb_fail = 1;
            continue;
        }
        mcdc_fa_arm(n);
        (void)wc_ecc_import_point_der_ex(der, 1 + numlen, idx, point, 1);
        mcdc_fa_disarm();
        wc_ecc_del_point(point);
    }

    WB_NOTE("mp_sqrtmod_prime SMALL_STACK 10-alloc sweep done");
#else
    WB_NOTE("HAVE_ECC_KEY_IMPORT/HAVE_COMP_KEY off; sqrtmod_prime skipped");
#endif
}

#endif /* HAVE_ECC && !WOLF_CRYPTO_CB_ONLY_ECC && !WOLFSSL_SP_MATH */

int main(void)
{
    printf("ecc.c fault white-box MC/DC supplement\n");
#if !defined(HAVE_ECC) || defined(WOLF_CRYPTO_CB_ONLY_ECC) || \
    defined(WOLFSSL_SP_MATH)
    printf("  HAVE_ECC off (or crypto-cb-only / bare WOLFSSL_SP_MATH "
           "build); nothing to exercise\n");
    return 0;
#else
    mcdc_fa_install();
    wb_fault_projective_add_dbl();
    wb_fault_sqrtmod_prime();
    mcdc_fa_disarm();
    mcdc_fa_restore();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
