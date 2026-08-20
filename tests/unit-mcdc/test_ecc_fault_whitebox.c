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

/* SECOND LEVER -- BIG-INTEGER FAULTS (mcdc_fault_mp.h)
 * ----------------------------------------------------
 * ecc.c's fixed-point (FP_ECC) cache helpers and mp_sqrtmod_prime are written
 * as big-integer success chains:
 *
 *     if ((mp_copy(g->x, ...) != MP_OKAY) ||
 *         (mp_copy(g->y, ...) != MP_OKAY) || ...)
 *     if (err == MP_OKAY && idx >= 0 && ...)
 *     while (res == MP_OKAY && done == 0)
 *
 * On a healthy machine no mp_* call ever fails, so the "!= MP_OKAY" operands
 * are never TRUE and the "err == MP_OKAY" operands are never FALSE. The heap
 * lever cannot reach them: it can only make an ALLOCATION fail, never a
 * computation. mcdc_fault_mp.h macro-interposes the value-returning mp_* API,
 * so mcdc_fm_arm(n) makes the n-th mp_* call -- and every later one -- return
 * MP_VAL. This header must come BEFORE ecc.c so the wrappers are compiled
 * while the mp_* names still mean the real entry points.
 *
 * mp_init / mp_init_multi are deliberately NOT interposed (MCDC_FM_WITH_INIT
 * stays undefined): mp_sqrtmod_prime's own cleanup mp_clear()s its ten
 * temporaries after an init failure, which on the non-small-stack variants
 * are uninitialised stack mp_ints. Faulting only the COMPUTATION calls drives
 * the same residual operands and never leaves an mp_int unconstructed. */
#include "mcdc_fault_mp.h"

/* Two extra interposers, local to this TU (they are not in the shared header
 * because adding them there would shift the fault index of every other
 * module's mp sweeps). mp_mod_d supplies the res==MP_OKAY FALSE half of
 * mp_sqrtmod_prime's "prime mod 4 == 3" fast-path guard; mp_jacobi supplies
 * it for the Legendre-symbol guard inside the Z search. Both wrappers are
 * compiled while the names still mean the real functions. */
#if defined(HAVE_COMP_KEY) && !defined(WOLFSSL_ATECC508A) && \
    !defined(WOLFSSL_ATECC608A) && !defined(WOLFSSL_CRYPTOCELL) && \
    !defined(WOLFSSL_SP_MATH) && !defined(SQRTMOD_USE_MOD_EXP)
    #define MCDC_ECC_SQRTMOD_INTERPOSE
#endif

#ifdef MCDC_ECC_SQRTMOD_INTERPOSE
MCDC_FM_MAYBE_UNUSED static int mcdc_ecc_mod_d(const mp_int* a, mp_digit b,
    mp_digit* c)
{
    if (mcdc_fm_hit())
        return MCDC_FM_ERR;
    return mp_mod_d((mp_int*)a, b, c);
}
#undef  mp_mod_d
#define mp_mod_d(a, b, c)   mcdc_ecc_mod_d((a), (b), (c))
#endif /* MCDC_ECC_SQRTMOD_INTERPOSE */

#include <wolfcrypt/src/ecc.c>

#include "mcdc_fault_alloc.h"

#include <limits.h>
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

/* The same ten-operand NULL guard, driven DIRECTLY instead of through point
 * decompression. Going in via wc_ecc_import_point_der_ex means the ten
 * XMALLOCs sit behind every allocation the import itself performs, so the
 * fail index that isolates operand k is both deep and build-dependent.
 * mp_sqrtmod_prime is file-static and reachable from this TU, so calling it
 * with the injector armed at 1..10 puts exactly one of its own allocations at
 * the fail index -- operand k TRUE with operands 0..k-1 FALSE -- and the
 * disarmed call beside it is the all-FALSE row. A no-op on the variants where
 * the ten temporaries are stack mp_ints and no XMALLOC site exists. */
static void wb_fault_sqrtmod_prime_direct(void)
{
#ifdef MCDC_ECC_SQRTMOD_INTERPOSE
    mp_int p, n, r;
    int    i;

    if (mp_init_multi(&p, &n, &r, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    if (mp_set_int(&p, 17UL) != MP_OKAY || mp_set_int(&n, 2UL) != MP_OKAY) {
        wb_fail = 1;
        goto out;
    }

    (void)mp_sqrtmod_prime(&n, &p, &r);     /* all-FALSE row */
    for (i = 1; i <= 12; i++) {
        (void)mp_set_int(&p, 17UL);
        (void)mp_set_int(&n, 2UL);
        mcdc_fa_arm(i);
        (void)mp_sqrtmod_prime(&n, &p, &r);
        mcdc_fa_disarm();
    }

    WB_NOTE("mp_sqrtmod_prime direct 10-operand NULL-guard sweep done");
out:
    mcdc_fa_disarm();
    mp_clear(&p);
    mp_clear(&n);
    mp_clear(&r);
#else
    WB_NOTE("sqrtmod_prime not compiled; direct NULL-guard sweep skipped");
#endif
}

/* =========================================================================
 * FP_ECC fixed-point cache (find_hole / find_base / add_entry / build_lut /
 * accel_fp_mul / accel_fp_mul2add and the three public entry points that
 * drive them: wc_ecc_mulmod_ex, wc_ecc_mulmod_ex2, ecc_mul2add).
 *
 * Why these residuals exist and how each is closed:
 *
 *  - The "(mp_copy(..) != MP_OKAY) || .." OR-chains in add_entry / build_lut /
 *    accel_fp_mul are unreachable without a computation fault: mcdc_fm_arm(n)
 *    supplies operand n-1 TRUE with every earlier operand FALSE, and the
 *    disarmed call right beside it supplies the all-FALSE row IN THE SAME
 *    BINARY.
 *
 *  - The "err == MP_OKAY && idx >= 0 && lru_count < INT_MAX-1" chains need
 *    three different cache states, none of which a normal API call produces:
 *      operand 0 FALSE  -> add_entry must fail   (mp fault, index 1 / 4)
 *      operand 1 FALSE  -> no cache slot at all  (every entry .lock = 1, so
 *                          find_base misses and find_hole returns -1)
 *      operand 2 FALSE  -> lru_count saturated   (set to INT_MAX by hand)
 *    The same locked-cache state is what drives find_hole's own "z >= 0"
 *    operand FALSE and the "idx >= 0" operands of the LUT-build and
 *    LUT-use guards further down each entry point.
 *
 *  - find_base's per-coordinate comparison chain only ever sees "all three
 *    match" or "x differs"; a cache entry whose x matches but whose y (then
 *    z) differs is built by hand to supply the two missing rows.
 *
 * fp_cache, and every helper above, is file-static -- reachable only because
 * this TU #includes ecc.c. All crafted state is torn down with
 * wc_ecc_fp_free() before the next scenario, so a rejection vector can never
 * leave a poisoned cache behind for the vector after it.
 * ========================================================================= */
#if defined(FP_ECC) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLFSSL_NO_MALLOC)

typedef struct wb_fp_ctx {
    mp_int      a;
    mp_int      prime;
    mp_int      order;
    mp_int      mu;
    mp_int      k;
    mp_int      k1;
    ecc_point*  G;
    ecc_point*  B;
    ecc_point*  R;
    int         inited;
} wb_fp_ctx;

static int wb_fp_setup(wb_fp_ctx* c)
{
    int idx;
    const ecc_set_type* cs;

    XMEMSET(c, 0, sizeof(*c));

    idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    if (idx == ECC_CURVE_INVALID)
        return 0;
    cs = wc_ecc_get_curve_params(idx);
    if (cs == NULL)
        return 0;

    if (mp_init_multi(&c->a, &c->prime, &c->order, &c->mu, &c->k, &c->k1)
            != MP_OKAY)
        return 0;
    c->inited = 1;

    c->G = wc_ecc_new_point();
    c->B = wc_ecc_new_point();
    c->R = wc_ecc_new_point();
    if (c->G == NULL || c->B == NULL || c->R == NULL)
        return 0;

    if (mp_read_radix(&c->a,     cs->Af,    MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(&c->prime, cs->prime, MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(&c->order, cs->order, MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(c->G->x,   cs->Gx,    MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(c->G->y,   cs->Gy,    MP_RADIX_HEX) != MP_OKAY ||
        mp_set(c->G->z, 1) != MP_OKAY)
        return 0;

    /* B = -G: a second, distinct, genuinely on-curve base point, so the
     * two-base Shamir path caches two different entries. */
    if (mp_copy(c->G->x, c->B->x) != MP_OKAY ||
        mp_sub(&c->prime, c->G->y, c->B->y) != MP_OKAY ||
        mp_set(c->B->z, 1) != MP_OKAY)
        return 0;

    /* two scalars: k has set bits high enough to walk every lut_gap
     * iteration, k1 is 1 so only the very last iteration of the Shamir loop
     * sees a non-zero digit for it. Pairing them makes the "this base's digit
     * is non-zero while the accumulator is still empty" case happen for
     * exactly one of the two bases. */
    if (mp_set_int(&c->k, 0x9E3779B9UL) != MP_OKAY ||
        mp_set(&c->k1, 1) != MP_OKAY)
        return 0;

    return 1;
}

static void wb_fp_teardown(wb_fp_ctx* c)
{
    wc_ecc_del_point(c->G);
    wc_ecc_del_point(c->B);
    wc_ecc_del_point(c->R);
    if (c->inited) {
        mp_clear(&c->a);
        mp_clear(&c->prime);
        mp_clear(&c->order);
        mp_clear(&c->mu);
        mp_clear(&c->k);
        mp_clear(&c->k1);
    }
    XMEMSET(c, 0, sizeof(*c));
}

/* every entry locked -> find_base misses, find_hole finds no hole */
static void wb_fp_lock_all(int on)
{
    int x;
    for (x = 0; x < FP_ENTRIES; x++)
        fp_cache[x].lock = on ? 1 : 0;
}

/* find_hole "z >= 0" FALSE, plus the "idx == -1 / idx >= 0 FALSE" rows of
 * wc_ecc_mulmod_ex, wc_ecc_mulmod_ex2 and ecc_mul2add. With no slot the three
 * entry points fall back to their normal (non-cached) mulmod, so each call is
 * an ordinary, fully successful scalar multiply -- the accepting side of the
 * surrounding err == MP_OKAY operands comes for free. */
static void wb_fp_no_slot(wb_fp_ctx* c)
{
    int x;

    /* find_hole "z >= 0" TRUE-determining row: entry 0 holds a base and is
     * the only unlocked (so lowest-lru) slot, which makes find_hole choose it
     * and free it -- the eviction path a fresh cache never reaches. */
    wc_ecc_fp_free();
    wb_fp_lock_all(0);
    if (add_entry(0, c->G) == MP_OKAY) {
        for (x = 1; x < FP_ENTRIES; x++)
            fp_cache[x].lock = 1;
        (void)find_hole();
        wb_fp_lock_all(0);
    }
    else {
        wb_fail = 1;
    }

    wc_ecc_fp_free();
    wb_fp_lock_all(1);

    (void)find_hole();

    (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, &c->a, &c->prime, 1, NULL);
    (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, &c->a, &c->prime, &c->order,
                            NULL, 1, NULL);
#ifdef ECC_SHAMIR
    (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime, NULL);
#endif

    wb_fp_lock_all(0);
    wc_ecc_fp_free();
    WB_NOTE("FP_ECC locked-cache (no slot) vectors done");
}

/* find_base: x matches but y differs, then x+y match but z differs. */
static void wb_fp_find_base_partial(wb_fp_ctx* c)
{
    wc_ecc_fp_free();
    wb_fp_lock_all(0);

    fp_cache[0].g = wc_ecc_new_point();
    if (fp_cache[0].g == NULL) {
        wb_fail = 1;
        return;
    }
    (void)mp_copy(c->G->x, fp_cache[0].g->x);
    (void)mp_set(fp_cache[0].g->y, 7);
    (void)mp_copy(c->G->z, fp_cache[0].g->z);
    (void)find_base(c->G);                    /* y comparison FALSE */

    (void)mp_copy(c->G->y, fp_cache[0].g->y);
    (void)mp_set(fp_cache[0].g->z, 9);
    (void)find_base(c->G);                    /* z comparison FALSE */

    (void)mp_copy(c->G->z, fp_cache[0].g->z);
    (void)find_base(c->G);                    /* all three match */

    wc_ecc_del_point(fp_cache[0].g);
    fp_cache[0].g = NULL;
    WB_NOTE("find_base partial-match vectors done");
}

/* add_entry's three-mp_copy OR-chain: arm 1/2/3, then the all-FALSE row. */
static void wb_fp_add_entry_faults(wb_fp_ctx* c)
{
    long n;

    for (n = 1; n <= 3; n++) {
        wc_ecc_fp_free();
        mcdc_fm_arm(n);
        (void)add_entry(0, c->G);
        mcdc_fm_disarm();
    }
    wc_ecc_fp_free();
    (void)add_entry(0, c->G);
    wc_ecc_fp_free();
    WB_NOTE("add_entry mp_copy chain arm(1..3) + accept done");
}

/* build_lut's two OR-chains and accel_fp_mul's LUT-copy chain.
 *
 * build_lut's interposed call order is fixed: three mp_mulmod (the "copy
 * base" chain) then three mp_copy (the "single bit entries" chain), so
 * arm(1..3) walks the first chain operand by operand and arm(4..6) the
 * second. mp_init / mp_init_copy are not interposed, so the indices do not
 * drift between variants.
 *
 * The one full (disarmed) build_lut is what makes accel_fp_mul reachable at
 * all -- it is the only expensive call in this file, so it runs exactly once
 * and its LUT is then reused by every later scenario. */
static void wb_fp_build_lut_and_mul(wb_fp_ctx* c)
{
    long     n;
    mp_digit mp = 0;

    wc_ecc_fp_free();
    if (mp_montgomery_setup(&c->prime, &mp) != MP_OKAY ||
        mp_montgomery_calc_normalization(&c->mu, &c->prime) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    for (n = 1; n <= 6; n++) {
        wc_ecc_fp_free();
        if (add_entry(0, c->G) != MP_OKAY) {
            wb_fail = 1;
            continue;
        }
        mcdc_fm_arm(n);
        (void)build_lut(0, &c->a, &c->prime, mp, &c->mu);
        mcdc_fm_disarm();
    }

    wc_ecc_fp_free();
    if (add_entry(0, c->G) == MP_OKAY &&
        build_lut(0, &c->a, &c->prime, mp, &c->mu) == MP_OKAY) {
        /* accepting row first, then the fault sweep over the LUT-copy chain */
        (void)accel_fp_mul(0, &c->k, c->R, &c->a, &c->prime, mp, 1);
        for (n = 1; n <= 8; n++) {
            mcdc_fm_arm(n);
            (void)accel_fp_mul(0, &c->k, c->R, &c->a, &c->prime, mp, 1);
            mcdc_fm_disarm();
        }
    }
    else {
        wb_fail = 1;
    }
    wc_ecc_fp_free();
    WB_NOTE("build_lut mp chains arm(1..6) + accel_fp_mul sweep done");
}

/* The lru_count / LUT_set guards of the three public entry points.
 *
 * A cache warmed by two ordinary calls leaves LUT_set == 1, so the saturated
 * lru_count vectors below cost no second LUT build. The err == MP_OKAY FALSE
 * halves come from an armed add_entry: index 1 fails the first base's copy,
 * index 4 lets the first base through and fails the second's. */
static void wb_fp_lru_and_lutset(wb_fp_ctx* c)
{
    int  i;
    long n;

    /* Each entry point warms its OWN cache: the "lru_count >= 2 but the LUT
     * is not built yet" row of its build-the-LUT guard only happens on the
     * second call THROUGH THAT ENTRY POINT, and a cache warmed through a
     * sibling would arrive with LUT_set already 1 and skip it. Three calls
     * per entry point give lru 1 (guard FALSE on lru), lru 2 with no LUT
     * (guard TRUE, builds it) and lru 3 with the LUT set (guard FALSE on
     * LUT_set). */

    /* --- wc_ecc_mulmod_ex --- */
    wc_ecc_fp_free();
    for (i = 0; i < 3; i++)
        (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, &c->a, &c->prime, 1, NULL);
    i = find_base(c->G);
    if (i >= 0) {
        fp_cache[i].lru_count = INT_MAX;
        (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, &c->a, &c->prime, 1, NULL);
    }
    else {
        wb_fail = 1;
    }

    /* --- wc_ecc_mulmod_ex2 --- */
    wc_ecc_fp_free();
    for (i = 0; i < 3; i++)
        (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, &c->a, &c->prime,
                                &c->order, NULL, 1, NULL);
    i = find_base(c->G);
    if (i >= 0) {
        fp_cache[i].lru_count = INT_MAX;
        (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, &c->a, &c->prime,
                                &c->order, NULL, 1, NULL);
    }
    else {
        wb_fail = 1;
    }

#ifdef ECC_SHAMIR
    /* --- ecc_mul2add: warmed through itself, so both LUT-build guards see
     * their TRUE row, then accel_fp_mul2add runs for real. --- */
    wc_ecc_fp_free();
    for (i = 0; i < 3; i++)
        (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime,
                          NULL);

    /* one base's digit non-zero while the accumulator is still empty: k1 == 1
     * puts B's only set bit in the final iteration, so every earlier
     * iteration has zA non-zero with zB zero (and the mirrored call gives the
     * opposite). */
    (void)ecc_mul2add(c->G, &c->k, c->B, &c->k1, c->R, &c->a, &c->prime, NULL);
    (void)ecc_mul2add(c->G, &c->k1, c->B, &c->k, c->R, &c->a, &c->prime, NULL);

    /* accel_fp_mul2add's own LUT-copy chains: the LUTs are built, so an armed
     * mp_* aborts inside the Shamir loop instead of before it. */
    for (n = 1; n <= 14; n++) {
        mcdc_fm_arm(n);
        (void)ecc_mul2add(c->G, &c->k, c->B, &c->k1, c->R, &c->a, &c->prime,
                          NULL);
        mcdc_fm_disarm();
        mcdc_fm_arm(n);
        /* mirrored scalars: the second base is the one whose digit is
         * non-zero while the accumulator is still empty, so this sweep walks
         * the OTHER copy-chain of the Shamir loop. */
        (void)ecc_mul2add(c->G, &c->k1, c->B, &c->k, c->R, &c->a, &c->prime,
                          NULL);
        mcdc_fm_disarm();
    }

    i = find_base(c->G);
    if (i >= 0)
        fp_cache[i].lru_count = INT_MAX;
    i = find_base(c->B);
    if (i >= 0)
        fp_cache[i].lru_count = INT_MAX;
    (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime, NULL);

    /* idx1 cached but no slot left for idx2: entry for G stays resolvable by
     * find_base (which ignores .lock) while find_hole has nothing to give. */
    wc_ecc_fp_free();
    if (add_entry(0, c->G) == MP_OKAY) {
        wb_fp_lock_all(1);
        (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime,
                          NULL);
        wb_fp_lock_all(0);
    }
    else {
        wb_fail = 1;
    }
#else
    (void)n;
#endif

    /* --- err == MP_OKAY FALSE halves (armed add_entry) --- */
    wc_ecc_fp_free();
    mcdc_fm_arm(1);
    (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, &c->a, &c->prime, 1, NULL);
    mcdc_fm_disarm();

    wc_ecc_fp_free();
    mcdc_fm_arm(1);
    (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, &c->a, &c->prime, &c->order,
                            NULL, 1, NULL);
    mcdc_fm_disarm();

#ifdef ECC_SHAMIR
    wc_ecc_fp_free();
    mcdc_fm_arm(1);
    (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime, NULL);
    mcdc_fm_disarm();

    wc_ecc_fp_free();
    mcdc_fm_arm(4);     /* first base's three copies pass, second base fails */
    (void)ecc_mul2add(c->G, &c->k, c->B, &c->k, c->R, &c->a, &c->prime, NULL);
    mcdc_fm_disarm();
#endif

    wc_ecc_fp_free();
    WB_NOTE("FP_ECC lru_count / LUT_set / add_entry-failure vectors done");
}

/* wc_ecc_mulmod_ex / wc_ecc_mulmod_ex2 argument guards: the residual operands
 * are the ones no caller in the library ever violates (a == NULL, and
 * order == NULL on the _ex2 form). The valid call right after is the
 * all-FALSE row of the same chain, in the same binary. */
static void wb_fp_argguards(wb_fp_ctx* c)
{
    (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, NULL, &c->prime, 1, NULL);
    (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, NULL, &c->prime, &c->order,
                            NULL, 1, NULL);
    (void)wc_ecc_mulmod_ex2(&c->k, c->G, c->R, &c->a, &c->prime, NULL,
                            NULL, 1, NULL);
    wc_ecc_fp_free();
    (void)wc_ecc_mulmod_ex(&c->k, c->G, c->R, &c->a, &c->prime, 1, NULL);
    wc_ecc_fp_free();
    WB_NOTE("wc_ecc_mulmod_ex/_ex2 NULL-argument operands done");
}

static void wb_fp_cache_suite(void)
{
    wb_fp_ctx c;

    if (!wb_fp_setup(&c)) {
        wb_fail = 1;
        wb_fp_teardown(&c);
        WB_NOTE("FP_ECC suite setup failed; skipped");
        return;
    }

    wb_fp_build_lut_and_mul(&c);   /* heaviest first */
    wb_fp_lru_and_lutset(&c);
    wb_fp_add_entry_faults(&c);
    wb_fp_find_base_partial(&c);
    wb_fp_no_slot(&c);
    wb_fp_argguards(&c);

    wc_ecc_fp_free();
    wb_fp_lock_all(0);
    wb_fp_teardown(&c);
}
#else
static void wb_fp_cache_suite(void)
{
    WB_NOTE("FP_ECC off (or no-malloc build); fixed-point cache suite skipped");
}
#endif /* FP_ECC && !WOLFSSL_SP_MATH && !WOLFSSL_NO_MALLOC */

/* =========================================================================
 * Degenerate point operands.
 *
 * _ecc_projective_add_point's "should we double instead?" test and both
 * _safe wrappers' infinity handling only fire for operand shapes a scalar
 * multiply never produces: P and Q the same point, P and Q negatives of each
 * other, a zero Z (a point already at infinity in Jacobian form), and a zero
 * curve coefficient. Each is built by hand here and fed to the file-static
 * primitives directly. The mp_set chains that follow those tests are error
 * propagation, so their "err == MP_OKAY" operands need an armed mp_* as well.
 * ========================================================================= */
#if defined(HAVE_ECC) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_CRYPTOCELL)
static void wb_degenerate_points(void)
{
    mp_int      a, zero, prime;
    ecc_point  *P = NULL, *Q = NULL, *R = NULL;
    mp_digit    mp = 0;
    int         idx, inf = 0;
    long        n;
    const ecc_set_type* cs;

    idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
    if (idx == ECC_CURVE_INVALID) {
        wb_fail = 1;
        return;
    }
    cs = wc_ecc_get_curve_params(idx);
    if (cs == NULL) {
        wb_fail = 1;
        return;
    }
    if (mp_init_multi(&a, &zero, &prime, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }
    P = wc_ecc_new_point();
    Q = wc_ecc_new_point();
    R = wc_ecc_new_point();
    if (P == NULL || Q == NULL || R == NULL) {
        wb_fail = 1;
        goto out;
    }
    if (mp_read_radix(&a, cs->Af, MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(&prime, cs->prime, MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(P->x, cs->Gx, MP_RADIX_HEX) != MP_OKAY ||
        mp_read_radix(P->y, cs->Gy, MP_RADIX_HEX) != MP_OKAY ||
        mp_set(P->z, 1) != MP_OKAY ||
        mp_set(&zero, 0) != MP_OKAY ||
        mp_montgomery_setup(&prime, &mp) != MP_OKAY) {
        wb_fail = 1;
        goto out;
    }

    /* Q = P: x, z and y all compare equal -> the whole chain TRUE */
    if (wc_ecc_copy_point(P, Q) != MP_OKAY) {
        wb_fail = 1;
        goto out;
    }
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* Q = -P: x and z equal, y differs but equals modulus - P->y */
    (void)mp_sub(&prime, P->y, Q->y);
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* Q->z == 0: the digit-count operand FALSE with x still equal */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->z, 0);
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* Q->z differs (non-zero): the z comparison FALSE */
    (void)mp_set(Q->z, 2);
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* Q->x differs: the first operand FALSE */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->x, 3);
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* y differs and is NOT the negation either: the last operand FALSE */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->y, 5);
    (void)_ecc_projective_add_point(P, Q, R, &a, &prime, mp);

    /* curve coefficient zero -> "modulus - a is zero" TRUE in the doubling
     * formula's coefficient selection; the real a gives the FALSE row. */
    (void)_ecc_projective_dbl_point(P, R, &zero, &prime, mp);
    (void)_ecc_projective_dbl_point(P, R, &a, &prime, mp);
    for (n = 1; n <= 10; n++) {
        mcdc_fm_arm(n);
        (void)_ecc_projective_dbl_point(P, R, &zero, &prime, mp);
        mcdc_fm_disarm();
    }

    /* --- the _safe wrappers --- */

    /* A = -B: the wrapper's own set-to-infinity chain, with and without an
     * infinity out-pointer, and with the chain faulted. */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_sub(&prime, P->y, Q->y);
    inf = 0;
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, NULL);
    for (n = 1; n <= 6; n++) {
        mcdc_fm_arm(n);
        (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
        mcdc_fm_disarm();
    }

    /* B with a zero Z and a different X: the add itself returns Z == 0, so
     * the wrapper's "result is infinity" tail runs. */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->x, 3);
    (void)mp_set(Q->z, 0);
    inf = 0;
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, NULL);
    (void)ecc_projective_add_point_safe(Q, P, R, &a, &prime, mp, &inf);
    /* The set-to-infinity chain sits behind the whole add, so its
     * "err == MP_OKAY" operand only goes FALSE when the armed index lands
     * exactly on one of those mp_set calls -- hence a sweep long enough to
     * walk past every mp_* the add itself performs. */
    /* Negatives of each other on DIFFERENT projective representatives:
     * B = (x*L^2, -y*L^3, z*L). The wrapper's x/z equality test misses it, so
     * the raw add runs and returns Z == 0 with X and Y non-zero -- the
     * "only Z zero -> result is infinity" arm, which the all-zero shape above
     * never reaches. */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(&zero, 4);
    (void)mp_mulmod(P->x, &zero, &prime, Q->x);
    (void)mp_sub(&prime, P->y, Q->y);
    (void)mp_set(&zero, 8);
    (void)mp_mulmod(Q->y, &zero, &prime, Q->y);
    (void)mp_set(&zero, 2);
    (void)mp_mulmod(P->z, &zero, &prime, Q->z);
    (void)mp_set(&zero, 0);
    inf = 0;
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, NULL);
    for (n = 1; n <= 40; n++) {
        mcdc_fm_arm(n);
        (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
        mcdc_fm_disarm();
    }

    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->x, 3);
    (void)mp_set(Q->z, 0);
    for (n = 1; n <= 40; n++) {
        mcdc_fm_arm(n);
        (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
        mcdc_fm_disarm();
    }

    /* B is the SAME affine point as A but on a different projective
     * representative: (x*L^2, y*L^3, z*L) for L = 2. The wrapper's x/z
     * equality test therefore misses it, the raw add detects the degeneracy
     * and returns X == Y == Z == 0, and the "all zero -> should have doubled"
     * recovery path runs -- the one shape a scalar multiply never feeds in.
     * The scaling survives Montgomery form because both sides of the
     * comparison pick up the same R factor. */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_mulmod(P->x, P->x, &prime, &zero);      /* scratch: unused value */
    (void)mp_set(&zero, 4);
    (void)mp_mulmod(P->x, &zero, &prime, Q->x);      /* x * 4  */
    (void)mp_set(&zero, 8);
    (void)mp_mulmod(P->y, &zero, &prime, Q->y);      /* y * 8  */
    (void)mp_set(&zero, 2);
    (void)mp_mulmod(P->z, &zero, &prime, Q->z);      /* z * 2  */
    inf = 0;
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, NULL);
    /* same shape with B->z already zero: the recovery takes its other arm */
    (void)mp_set(Q->z, 0);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)mp_set(&zero, 0);

    /* A already at infinity (x == y == 0) on either side */
    (void)mp_set(Q->x, 0);
    (void)mp_set(Q->y, 0);
    (void)mp_set(Q->z, 1);
    (void)ecc_projective_add_point_safe(Q, P, R, &a, &prime, mp, &inf);
    (void)ecc_projective_add_point_safe(P, Q, R, &a, &prime, mp, &inf);
    (void)ecc_projective_dbl_point_safe(Q, R, &a, &prime, mp);

    /* P->z == 0 -> doubling yields Z == 0, so the dbl wrapper's own
     * set-to-infinity chain runs (and is then faulted). */
    (void)wc_ecc_copy_point(P, Q);
    (void)mp_set(Q->z, 0);
    (void)ecc_projective_dbl_point_safe(Q, R, &a, &prime, mp);
    for (n = 1; n <= 20; n++) {
        mcdc_fm_arm(n);
        (void)ecc_projective_dbl_point_safe(Q, R, &a, &prime, mp);
        mcdc_fm_disarm();
    }

    WB_NOTE("degenerate point-operand vectors done");

out:
    mcdc_fm_disarm();
    wc_ecc_del_point(P);
    wc_ecc_del_point(Q);
    wc_ecc_del_point(R);
    mp_clear(&a);
    mp_clear(&zero);
    mp_clear(&prime);
}
#else
static void wb_degenerate_points(void)
{
    WB_NOTE("generic point math not compiled; degenerate operands skipped");
}
#endif

/* =========================================================================
 * mp_sqrtmod_prime: the Tonelli-Shanks "res == MP_OKAY && .." chain.
 *
 * Called directly (it is file-static) rather than through point
 * decompression, so the prime can be chosen to select each branch:
 *
 *   P-256's prime         == 3 (mod 4) -> the mp_exptmod fast path;
 *   17                    == 1 (mod 4) -> full Tonelli-Shanks;
 *   9 and 21 are NOT prime -> the two "clamp the loop in case 'prime' is not
 *                             really prime" guards, which are the only way to
 *                             drive mp_cmp(Z,prime)==MP_EQ and
 *                             mp_cmp_d(M,i)==MP_EQ TRUE. 9 admits no Z with
 *                             Legendre -1 at all (every Jacobi symbol mod a
 *                             square is 0 or 1), so the Z search runs up to
 *                             Z == prime; 21 does admit one, so the search
 *                             succeeds and the failure surfaces in the inner
 *                             reduce-to-one loop instead.
 *
 * Each prime is first run DISARMED (the accepting row of every guard in the
 * chain, same binary) and then swept: arm(n) makes the n-th mp_* call fail,
 * which is the only way to drive the res == MP_OKAY operands FALSE.
 * ========================================================================= */
#ifdef MCDC_ECC_SQRTMOD_INTERPOSE
static void wb_sqrtmod_prime_cases(void)
{
    static const struct { unsigned long p; unsigned long n; } cases[] = {
        { 17UL,  2UL },     /* real prime, 1 mod 4: Tonelli-Shanks */
        { 13UL,  3UL },     /* real prime, 1 mod 4 */
        {  9UL,  5UL },     /* composite: Z search exhausts to Z == prime */
        { 21UL,  5UL },     /* composite: inner reduce-to-one loop clamps */
        { 23UL,  2UL },     /* real prime, 3 mod 4: mp_exptmod fast path */
    };
    mp_int p, n, r;
    size_t ci;
    long   k, i;

    if (mp_init_multi(&p, &n, &r, NULL, NULL, NULL) != MP_OKAY) {
        wb_fail = 1;
        return;
    }

    for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
        if (mp_set_int(&p, cases[ci].p) != MP_OKAY ||
            mp_set_int(&n, cases[ci].n) != MP_OKAY) {
            wb_fail = 1;
            continue;
        }

        mcdc_fm_disarm();
        (void)mp_sqrtmod_prime(&n, &p, &r);
        k = mcdc_fm_seen();
        if (k > 40)
            k = 40;

        for (i = 1; i <= k; i++) {
            if (mp_set_int(&p, cases[ci].p) != MP_OKAY ||
                mp_set_int(&n, cases[ci].n) != MP_OKAY)
                continue;
            mcdc_fm_arm(i);
            (void)mp_sqrtmod_prime(&n, &p, &r);
            mcdc_fm_disarm();
        }
    }

    mcdc_fm_disarm();
    mp_clear(&p);
    mp_clear(&n);
    mp_clear(&r);
    WB_NOTE("mp_sqrtmod_prime branch + mp-fault sweep done");
}
#else
static void wb_sqrtmod_prime_cases(void)
{
    WB_NOTE("HAVE_COMP_KEY off (or mod-exp sqrt); sqrtmod_prime cases skipped");
}
#endif /* MCDC_ECC_SQRTMOD_INTERPOSE */

/* ------------------------------------------------------------------------- *
 * COMPUTATION-failure residuals in the point-multiply / sign / verify /
 * on-curve chains.
 *
 * Each of these decisions is `err == MP_OKAY && <something>` sitting AFTER a
 * run of big-integer steps that never fail on a healthy machine, so the
 * `err == MP_OKAY` operand is never FALSE:
 *
 *   3296  ecc_mulmod          first z-randomization, after the R[] copies
 *   3859  wc_ecc_mulmod_ex    the `&& map` guard after the multiply
 *   7810  wc_ecc_sign_hash_ex the digest-truncation guard after reading e
 *   9576  ecc_verify_hash     the same guard on the verify side
 *  10744  _ecc_is_point       the "is a == -3" guard after the y^2-x^3 steps
 *
 * Each sweep also has to be run on inputs for which the guard's OTHER operand
 * is TRUE, or every row -- faulted and unfaulted alike -- comes out FALSE and
 * no two of them form an independence pair:
 *   7810 / 9576  need an order whose bit length is not a byte multiple and a
 *                digest longer than it, so that after the truncation to the
 *                order's BYTE length 8*inlen is still above the order's BIT
 *                length. prime239v1's order is 239 bits, so a 32-byte digest
 *                truncates to 30 bytes and 240 > 239 holds; the NIST prime
 *                curves in this table all have byte-multiple orders, and
 *                secp521r1 cannot be used because ecc.c caps a digest at
 *                WC_MAX_DIGEST_SIZE = 64 bytes, already shorter than its
 *                521-bit order;
 *   10744        needs a curve whose a is not -3 (a Koblitz curve), so the
 *                "use a in the calculation" arm is the one taken.
 *
 * The mp lever is the only one that reaches them: no allocation fault can make
 * a COMPUTATION fail, and every input that would (a malformed curve) is
 * rejected further up. Sweeping the fail index across each entry point walks
 * the failure position through the whole chain, so for some index the failure
 * lands just before the guard.
 *
 * The sweeps are deliberately generous: past the real call count the target
 * simply runs to completion. Every armed call is crash-safe -- the target
 * propagates the MP_VAL to its own cleanup, and nothing the call produced is
 * read back here.
 * ------------------------------------------------------------------------- */
#define WB_MP_SWEEP_K 90

static void wb_fault_mulmod_chain(void)
{
    DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);
    ecc_key    key;
    ecc_point* G = NULL;
    ecc_point* R = NULL;
    WC_RNG     rng;
    mp_int     k[1];
    int        err = MP_OKAY;
    int        haveRng = 0;
    int        n;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(k, 0, sizeof(k));
    if (wc_ecc_init(&key) != 0)
        return;
    if (wc_ecc_set_curve(&key, 0, ECC_SECP256R1) != 0) {
        wc_ecc_free(&key);
        return;
    }
    ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT, err);
    if (err == MP_OKAY)
        err = wc_ecc_curve_load(key.dp, &curve, ECC_CURVE_FIELD_ALL);
    if (err == MP_OKAY)
        err = mp_init(k);
    G = wc_ecc_new_point();
    R = wc_ecc_new_point();

    if ((err == MP_OKAY) && (G != NULL) && (R != NULL) &&
        (mp_copy(curve->Gx, G->x) == MP_OKAY) &&
        (mp_copy(curve->Gy, G->y) == MP_OKAY) &&
        (mp_set(G->z, 1) == MP_OKAY) && (mp_set(k, 5) == MP_OKAY)) {
        haveRng = (wc_InitRng(&rng) == 0);

        /* With a live RNG the z-randomization runs, which is the branch whose
         * `err == MP_OKAY` operand (3296) is otherwise unreachable. */
        for (n = 1; n <= WB_MP_SWEEP_K; n++) {
            mcdc_fm_arm(n);
            (void)wc_ecc_mulmod_ex2(k, G, R, curve->Af, curve->prime,
                                    curve->order, haveRng ? &rng : NULL, 1,
                                    NULL);
            mcdc_fm_disarm();
        }
        for (n = 1; n <= WB_MP_SWEEP_K; n++) {
            mcdc_fm_arm(n);
            (void)wc_ecc_mulmod_ex(k, G, R, curve->Af, curve->prime, 1, NULL);
            mcdc_fm_disarm();
        }
    }

    mcdc_fm_disarm();
    if (haveRng)
        wc_FreeRng(&rng);
    if (R != NULL)
        wc_ecc_del_point(R);
    if (G != NULL)
        wc_ecc_del_point(G);
    mp_free(k);
    if (err == MP_OKAY)
        wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    wc_ecc_free(&key);
    WB_NOTE("mulmod / is-point mp-fault sweep done");
}

/* 10744 needs a curve whose "a" is NOT p-3: on every NIST prime curve the
 * `mp_cmp_d(t2, 3) != MP_EQ` operand is permanently FALSE, so the decision is
 * FALSE both with and without a fault and the two rows never differ in
 * outcome. A Koblitz curve (a == 0) makes the unfaulted row TRUE. */
static void wb_fault_is_point_koblitz(void)
{
    DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);
    ecc_key    key;
    ecc_point* G = NULL;
    int        err = MP_OKAY;
    int        n;

    XMEMSET(&key, 0, sizeof(key));
    if (wc_ecc_get_curve_idx(ECC_SECP256K1) < 0) {
        WB_NOTE("SECP256K1 absent; is-point mp sweep skipped");
        return;
    }
    if (wc_ecc_init(&key) != 0)
        return;
    if (wc_ecc_set_curve(&key, 0, ECC_SECP256K1) != 0) {
        wc_ecc_free(&key);
        return;
    }
    ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT, err);
    if (err == MP_OKAY)
        err = wc_ecc_curve_load(key.dp, &curve, ECC_CURVE_FIELD_ALL);
    G = wc_ecc_new_point();
    if ((err == MP_OKAY) && (G != NULL) &&
        (mp_copy(curve->Gx, G->x) == MP_OKAY) &&
        (mp_copy(curve->Gy, G->y) == MP_OKAY) &&
        (mp_set(G->z, 1) == MP_OKAY)) {
        for (n = 1; n <= 24; n++) {
            mcdc_fm_arm(n);
            (void)wc_ecc_is_point(G, curve->Af, curve->Bf, curve->prime);
            mcdc_fm_disarm();
        }
    }
    mcdc_fm_disarm();
    if (G != NULL)
        wc_ecc_del_point(G);
    if (err == MP_OKAY)
        wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    wc_ecc_free(&key);
    WB_NOTE("is-point (Koblitz) mp-fault sweep done");
}

static void wb_fault_sign_verify_chain(void)
{
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
    WC_RNG  rng;
    ecc_key key;
    byte    digest[32];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigSz = (word32)sizeof(sig);
    int     haveKey = 0;
    int     n;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(digest, 0x3b, sizeof(digest));
    XMEMSET(sig, 0, sizeof(sig));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; sign/verify mp sweep skipped");
        return;
    }
    if (wc_ecc_init(&key) == 0)
        haveKey = (wc_ecc_make_key_ex(&rng, 0, &key, ECC_PRIME239V1) == 0);

    if (haveKey) {
#ifdef HAVE_ECC_SIGN
        int haveSig = (wc_ecc_sign_hash(digest, (word32)sizeof(digest), sig,
                                        &sigSz, &rng, &key) == 0);
        for (n = 1; n <= WB_MP_SWEEP_K; n++) {
            word32 tmpSz = (word32)sizeof(sig);
            byte   tmp[ECC_MAX_SIG_SIZE];
            XMEMSET(tmp, 0, sizeof(tmp));
            mcdc_fm_arm(n);
            (void)wc_ecc_sign_hash(digest, (word32)sizeof(digest), tmp, &tmpSz,
                                   &rng, &key);
            mcdc_fm_disarm();
        }
#else
        int haveSig = 0;
#endif
#ifdef HAVE_ECC_VERIFY
        if (haveSig) {
            for (n = 1; n <= WB_MP_SWEEP_K; n++) {
                int res = 0;
                mcdc_fm_arm(n);
                (void)wc_ecc_verify_hash(sig, sigSz, digest,
                                         (word32)sizeof(digest), &res, &key);
                mcdc_fm_disarm();
            }
        }
#else
        (void)haveSig;
#endif
    }
    else {
        WB_NOTE("sign/verify mp sweep: key setup failed");
    }

    mcdc_fm_disarm();
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    WB_NOTE("sign/verify mp-fault sweep done");
#else
    WB_NOTE("sign/verify not compiled in; mp sweep skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * Heap-fault sites reached only by calling the file-static owner directly.
 *
 *   2839  ecc_map_ex        the t1/t2 NEW_MP_INT_SIZE NULL guard. Every public
 *                           caller allocates a great many other things first,
 *                           so a fail index that lands exactly on t1 or t2 is
 *                           not reachable by sweeping an outer entry point.
 *   7314  ecc_sign_hash_sw  the custom-curve fixup guard, reached with err
 *                           already set only when the function's OWN first
 *                           allocation (the blinding value b) returns NULL.
 *
 * Both are productive under WOLFSSL_SMALL_STACK only; elsewhere the storage is
 * a stack array, the arm finds nothing to fail, and the calls simply succeed.
 * ------------------------------------------------------------------------- */
static void wb_fault_map_and_sign_sw(void)
{
    DECLARE_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);
    ecc_key    key;
    ecc_point* P = NULL;
    mp_digit   mp = 0;
    int        err = MP_OKAY;
    int        n;

    XMEMSET(&key, 0, sizeof(key));
    if (wc_ecc_init(&key) != 0)
        return;
    if (wc_ecc_set_curve(&key, 0, ECC_SECP256R1) != 0) {
        wc_ecc_free(&key);
        return;
    }
    ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT, err);
    if (err == MP_OKAY)
        err = wc_ecc_curve_load(key.dp, &curve, ECC_CURVE_FIELD_ALL);
    P = wc_ecc_new_point();

    if ((err == MP_OKAY) && (P != NULL) &&
        (mp_copy(curve->Gx, P->x) == MP_OKAY) &&
        (mp_copy(curve->Gy, P->y) == MP_OKAY) &&
        (mp_set(P->z, 1) == MP_OKAY) &&
        (mp_montgomery_setup(curve->prime, &mp) == MP_OKAY)) {
        /* Prepared while DISARMED; only the map itself runs armed. */
        for (n = 1; n <= 4; n++) {
            mcdc_fa_arm(n);
            (void)ecc_map_ex(P, curve->prime, mp, 1);
            mcdc_fa_disarm();
            (void)mp_copy(curve->Gx, P->x);
            (void)mp_copy(curve->Gy, P->y);
            (void)mp_set(P->z, 1);
        }
    }

#if defined(HAVE_ECC_SIGN) && defined(WOLFSSL_CUSTOM_CURVES) && \
    !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_MICROCHIP_TA100) && !defined(WOLFSSL_CRYPTOCELL) && \
    !defined(WOLFSSL_KCAPI_ECC)
    if (err == MP_OKAY) {
        WC_RNG rng;
        mp_int ers[3];
        int    haveRng;

        XMEMSET(&rng, 0, sizeof(rng));
        XMEMSET(ers, 0, sizeof(ers));
        haveRng = (wc_InitRng(&rng) == 0);
        if (haveRng &&
            (mp_init_multi(&ers[0], &ers[1], &ers[2], NULL, NULL, NULL)
                                                                == MP_OKAY)) {
            if ((mp_set(ecc_get_k(&key), 3) == MP_OKAY) &&
                (mp_set(&ers[0], 0x2a) == MP_OKAY)) {
                key.type = ECC_PRIVATEKEY;
                /* CUSTOM index so the unfaulted run takes the guard's TRUE
                 * branch: with a table index the decision is FALSE whether or
                 * not the allocation failed, and no pair of rows differs in
                 * outcome. dp still points at a real curve. */
                key.idx = ECC_CUSTOM_IDX;
                for (n = 1; n <= 4; n++) {
                    ecc_key eph;
                    XMEMSET(&eph, 0, sizeof(eph));
                    if (wc_ecc_init(&eph) != 0)
                        break;
                    mcdc_fa_arm(n);
                    (void)ecc_sign_hash_sw(&key, &eph, &rng, curve, &ers[0],
                                           &ers[1], &ers[2]);
                    mcdc_fa_disarm();
                    wc_ecc_free(&eph);
                }
            }
            mp_free(&ers[2]);
            mp_free(&ers[1]);
            mp_free(&ers[0]);
        }
        if (haveRng)
            wc_FreeRng(&rng);
    }
#endif

    mcdc_fa_disarm();
    if (P != NULL)
        wc_ecc_del_point(P);
    if (err == MP_OKAY)
        wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    wc_ecc_free(&key);
    WB_NOTE("ecc_map_ex / ecc_sign_hash_sw heap-fault sweep done");
}

#endif /* HAVE_ECC && !WOLF_CRYPTO_CB_ONLY_ECC && !WOLFSSL_SP_MATH */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("ecc.c fault white-box MC/DC supplement\n");
#if !defined(HAVE_ECC) || defined(WOLF_CRYPTO_CB_ONLY_ECC) || \
    defined(WOLFSSL_SP_MATH)
    printf("  HAVE_ECC off (or crypto-cb-only / bare WOLFSSL_SP_MATH "
           "build); nothing to exercise\n");
    return 0;
#else
    /* mp-fault work first: it is bounded and cheap, while the heap sweeps
     * below walk a long fail index. */
    wb_fp_cache_suite();
    wb_degenerate_points();
    wb_sqrtmod_prime_cases();
    wb_fault_mulmod_chain();
    wb_fault_is_point_koblitz();
    wb_fault_sign_verify_chain();
    mcdc_fm_disarm();

    mcdc_fa_install();
    wb_fault_projective_add_dbl();
    wb_fault_sqrtmod_prime();
    wb_fault_sqrtmod_prime_direct();
    wb_fault_map_and_sign_sw();
    mcdc_fa_disarm();
    mcdc_fa_restore();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the harness
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
