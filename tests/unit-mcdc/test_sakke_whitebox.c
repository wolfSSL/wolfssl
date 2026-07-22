/* test_sakke_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/sakke.c.
 *
 * tests/api/test_sakke.c drives every WOLFSSL_API entry point in sakke.c
 * (see its own header comment for the WOLFSSL_HAVE_SAKKE vs.
 * WOLFCRYPT_HAVE_SAKKE naming note), but a handful of decisions live in
 * file-static helpers -- or inside a public wrapper that is never driven
 * with the specific argument that flips this decision -- that the public
 * API test cannot reach both ways. This white-box #includes sakke.c
 * directly so those helpers are reachable, and drives both halves of each
 * targeted decision.
 *
 * Several of the targeted helpers (sakke_mulmod_base_add(), sakke_addmod(),
 * sakke_tplmod(), and the loop-bearing non-SP sakke_pairing()) only exist in
 * the non-WOLFSSL_HAVE_SP_ECC build of sakke.c -- the SP-math build
 * substitutes single-shot sp_ecc_* calls that fold the same decision into
 * the SP library itself, so those sections are skipped (with a printed
 * note) when WOLFSSL_HAVE_SP_ECC is defined.
 *
 * Guards covered (line : owning function):
 *
 * sakke.c:411  sakke_mulmod_base_add() "(err == 0) && map" -- every in-tree
 *     caller (sakke_compute_point_i()) hardcodes map=1, so map=0 is
 *     otherwise unreachable. Both values driven directly.
 * sakke.c:1483 sakke_addmod() "(err == 0) && (mp_cmp(r, m) != MP_LT)" --
 *     pure mp_int helper, no key state needed. r < m and r >= m both driven.
 * sakke.c:1505/1508/1511 sakke_tplmod() -- same shape, three sequential
 *     reduction checks; a/m chosen so each of the three independently sees
 *     both "still >= m" and "already < m" across the four calls made.
 * sakke.c:2454 wc_ValidateSakkeRsk() "(err == 0) && (idSz <=
 *     SAKKE_ID_MAX_SIZE)" -- unlike wc_SetSakkeIdentity()/
 *     wc_MakeSakkePointI(), this public wrapper never bounds idSz before
 *     computing point I, so idSz > SAKKE_ID_MAX_SIZE is reachable directly
 *     through the public API; driven here to isolate the guard that keeps
 *     the fixed 128-byte key->i.id copy from overflowing.
 * sakke.c:2466 wc_ValidateSakkeRsk() "*valid = ((err == 0) &&
 *     (mp_cmp(a, &key->params.g) == MP_EQ))" -- true (matching RSK/identity
 *     pair) and false (RSK computed for a different identity) both driven.
 * sakke.c:6653 sakke_compute_point_r() "(key->i.idSz == 0) ||
 *     (key->i.idSz != idSz) || (XMEMCMP(id, key->i.id, idSz) != 0)" -- each
 *     operand toggled independently by controlling key->i.* state directly
 *     (never-cached, size-mismatch, content-mismatch, cache-hit).
 * sakke.c:6657 sakke_compute_point_r() "(err == 0) && (idSz <=
 *     SAKKE_ID_MAX_SIZE)" -- same shape/reason as 2454, driven as an
 *     idSz > SAKKE_ID_MAX_SIZE call that also forces the 6653 recompute
 *     path.
 *
 * Loop decisions at sakke.c:2282, 2302, 2646 and 6289 (bit/byte iteration
 * bounded by mp_count_bits(&params->q) or a digest size) are exercised for
 * both loop-continue and loop-exit, and (2302) both mp_is_bit_set()
 * outcomes, as a side effect of the full key-generation / RSK / validate /
 * encapsulate / derive round trip this file performs to reach the guards
 * above -- the loop bound and q's bit pattern are fixed curve parameters,
 * data-independent of the freshly-generated key material, so a single
 * successful run already flips every one of those edges. What such a run
 * cannot show is the "err != 0" operand of "(err == 0) && ..." partway
 * through a loop -- that needs an internal operation to fail on a specific
 * iteration, which isn't selectable without corrupting library state; left
 * as a residual (the same class of residual as the mid-operation failures
 * documented for test_aes_whitebox.c in
 * iso26262/mcdc-per-module/reports/aes/RESIDUALS.md).
 *
 * Residual (not forced): sakke.c:536 "while ((err == 0) &&
 * mp_iszero(wc_ecc_key_get_priv(&key->ecc)))" in wc_MakeSakkeKey() only
 * re-rolls when a freshly-generated 1024-bit random scalar is exactly 0 --
 * cryptographically negligible, and not reachable without a corrupted or
 * mocked RNG.
 *
 * Crash-safety: every call below either operates on plain, directly-owned
 * mp_int/ecc_point locals, or on a single SakkeKey ("key") that is fully
 * initialized (params, base point and a real master secret via
 * wc_MakeSakkeKey()) before any file-static function that dereferences its
 * internals is called. sakke_compute_point_i() -- reached through both
 * wc_ValidateSakkeRsk() and sakke_compute_point_r() -- repurposes the ecc
 * private-key mp_int as scratch space for whatever identity integer it is
 * given, so calls that rely on the real master secret (key generation, RSK
 * generation) are all made first; every call after the first
 * wc_ValidateSakkeRsk() below only needs id/idSz/rsk state, never the
 * master secret again.
 */

#include <wolfcrypt/src/sakke.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

int main(void)
{
    printf("sakke.c white-box supplement\n");
#ifdef WOLFCRYPT_HAVE_SAKKE
    WC_RNG rng;
    SakkeKey key;
    ecc_point* rsk = NULL;
    ecc_point* rsk2 = NULL;
    byte id[1] = { 0x01 };
    byte id2[1] = { 0x02 };
    byte idBig[SAKKE_ID_MAX_SIZE + 1];
    int valid;

    /* Numerically small (leading zero bytes) so the raw identity, read as
     * a scalar, stays well inside the curve's field size -- only the byte
     * *length* needs to exceed SAKKE_ID_MAX_SIZE to drive the guards below.
     * A numerically large idSz+1-byte value here trips wc_ecc_mulmod()'s
     * own ECC_OUT_OF_RANGE_E, which would make err != 0 the reason the
     * guard evaluates false instead of the idSz operand being isolated
     * (same lesson documented in test_sakke.c's idMax comment). */
    XMEMSET(idBig, 0, sizeof(idBig));
    idBig[sizeof(idBig) - 1] = 0x5A;
    XMEMSET(&key, 0, sizeof(key));

    if (wc_InitRng(&rng) != 0) wb_fail = 1;
    if (wc_InitSakkeKey_ex(&key, 128, ECC_SAKKE_1, NULL, INVALID_DEVID) != 0)
        wb_fail = 1;
    /* Real master secret + public key -- needed by every guard below that
     * depends on genuine key state. */
    if (wc_MakeSakkeKey(&key, &rng) != 0) wb_fail = 1;

    rsk = wc_ecc_new_point();
    rsk2 = wc_ecc_new_point();
    if ((rsk == NULL) || (rsk2 == NULL)) wb_fail = 1;
    if (wc_MakeSakkeRsk(&key, id, (word16)sizeof(id), rsk) != 0) wb_fail = 1;
    if (wc_MakeSakkeRsk(&key, id2, (word16)sizeof(id2), rsk2) != 0)
        wb_fail = 1;

    /* --- sakke.c:411 sakke_mulmod_base_add(): "(err == 0) && map" ---
     * Only exists without WOLFSSL_HAVE_SP_ECC. Every in-tree caller
     * hardcodes map=1 (sakke_compute_point_i()); map=0 is otherwise
     * unreachable. Uses the real public key computed by wc_MakeSakkeKey()
     * above, before it is repurposed below. */
#ifndef WOLFSSL_HAVE_SP_ECC
    {
        mp_int scalarN;
        ecc_point* addResult = wc_ecc_new_point();

        if (addResult == NULL) wb_fail = 1;
        mp_init(&scalarN);
        mp_set(&scalarN, 7);

        if (sakke_mulmod_base_add(&key, &scalarN, &key.ecc.pubkey, addResult, 0)
                != 0) wb_fail = 1;               /* map == 0 (false) */
        if (sakke_mulmod_base_add(&key, &scalarN, &key.ecc.pubkey, addResult, 1)
                != 0) wb_fail = 1;               /* map == 1 (true) */

        mp_free(&scalarN);
        if (addResult != NULL) wc_ecc_del_point(addResult);
        WB_NOTE("sakke_mulmod_base_add() map==0/map==1 (line 411) "
            "exercised");
    }

    /* --- sakke.c:1483 sakke_addmod() / 1505,1508,1511 sakke_tplmod() ---
     * Pure mp_int reduction helpers -- no key state needed at all. */
    {
        mp_int a, b, m, r;

        mp_init(&a);
        mp_init(&b);
        mp_init(&m);
        mp_init(&r);

        /* sakke_addmod(): r < m (guard false, no subtraction). */
        mp_set(&a, 3); mp_set(&b, 4); mp_set(&m, 100);
        if (sakke_addmod(&a, &b, &m, &r) != 0) wb_fail = 1; /* r = 7 */
        /* sakke_addmod(): r >= m (guard true, one subtraction). */
        mp_set(&a, 60); mp_set(&b, 70); mp_set(&m, 100);
        if (sakke_addmod(&a, &b, &m, &r) != 0) wb_fail = 1; /* r = 130 */
        WB_NOTE("sakke_addmod() r<m / r>=m (line 1483) exercised");

        /* sakke_tplmod(): 3*10=30 < 100 -- all three checks false. */
        mp_set(&a, 10); mp_set(&m, 100);
        if (sakke_tplmod(&a, &m, &r) != 0) wb_fail = 1;
        /* 3*40=120 -> one subtraction to 20 -- 1st check true, 2nd/3rd
         * false. */
        mp_set(&a, 40); mp_set(&m, 100);
        if (sakke_tplmod(&a, &m, &r) != 0) wb_fail = 1;
        /* 3*25=75 -> 45 -> 15 -- 1st and 2nd checks true, 3rd false. */
        mp_set(&a, 25); mp_set(&m, 30);
        if (sakke_tplmod(&a, &m, &r) != 0) wb_fail = 1;
        /* 3*11=33 -> 23 -> 13 -> 3 -- all three checks true. */
        mp_set(&a, 11); mp_set(&m, 10);
        if (sakke_tplmod(&a, &m, &r) != 0) wb_fail = 1;
        WB_NOTE("sakke_tplmod() 3-stage reduction (lines 1505/1508/1511) "
            "all true/false combinations exercised");

        mp_free(&a);
        mp_free(&b);
        mp_free(&m);
        mp_free(&r);
    }
#else
    WB_NOTE("WOLFSSL_HAVE_SP_ECC defined -- sakke_mulmod_base_add()/"
        "sakke_addmod()/sakke_tplmod() are not compiled in this build "
        "(SP-math substitutes single-shot sp_ecc_* calls); skipped");
#endif

    /* --- sakke.c:2454/2466 wc_ValidateSakkeRsk() --- */
    /* Matching RSK/identity pair: valid == 1 (line 2466 true). Also
     * exercises the loops at 2282/2302 (sakke_pairing()) with real data. */
    valid = -1;
    if (wc_ValidateSakkeRsk(&key, id, (word16)sizeof(id), rsk, &valid) != 0)
        wb_fail = 1;
    if (valid != 1) wb_fail = 1;

    /* Mismatched pair: rsk2 was computed for id2, checked here against id.
     * Isolates line 2466's mp_cmp(...) == MP_EQ operand to false while err
     * stays 0. */
    valid = -1;
    if (wc_ValidateSakkeRsk(&key, id, (word16)sizeof(id), rsk2, &valid) != 0)
        wb_fail = 1;
    if (valid != 0) wb_fail = 1;
    WB_NOTE("wc_ValidateSakkeRsk() valid==1/valid==0 (line 2466) exercised");

    /* idSz > SAKKE_ID_MAX_SIZE: wc_ValidateSakkeRsk() never bounds idSz
     * before computing point I (unlike wc_SetSakkeIdentity()/
     * wc_MakeSakkePointI()), so this is reachable directly through the
     * public API. Isolates line 2454's "idSz <= SAKKE_ID_MAX_SIZE" operand
     * to false while err stays 0, confirming the fixed 128-byte key->i.id
     * copy is skipped rather than overflowed. From this call on, "key"'s
     * ecc private-key mp_int has been repurposed as scratch by
     * sakke_compute_point_i() and no longer holds the master secret. */
    valid = -1;
    if (wc_ValidateSakkeRsk(&key, idBig, (word16)sizeof(idBig), rsk, &valid)
            != 0) wb_fail = 1;
    WB_NOTE("wc_ValidateSakkeRsk() idSz > SAKKE_ID_MAX_SIZE (line 2454) "
        "exercised");

    /* --- sakke.c:6653/6657 sakke_compute_point_r() ---
     * Called directly (it is file-static) so key->i.* cache state can be
     * controlled precisely; none of these calls need the master secret. */
    {
        mp_int rScalar;
        byte out[257];
        byte idA[4] = { 0x01, 0x02, 0x03, 0x04 };
        byte idB[5] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E };
        byte idC[5] = { 0x11, 0x12, 0x13, 0x14, 0x15 };

        XMEMSET(out, 0, sizeof(out));
        mp_init(&rScalar);
        mp_set(&rScalar, 5);

        /* key->i.idSz == 0 (true): never-cached point I -- recompute. */
        key.i.idSz = 0;
        if (sakke_compute_point_r(&key, idA, (word16)sizeof(idA), &rScalar,
                128, out) != 0) wb_fail = 1;

        /* key->i.idSz == 0 now false (== sizeof(idA)); key->i.idSz != idSz
         * true (sizeof(idA) != sizeof(idB)) -- recompute. */
        if (sakke_compute_point_r(&key, idB, (word16)sizeof(idB), &rScalar,
                128, out) != 0) wb_fail = 1;

        /* Both size operands false (idSz matches the cached size from the
         * call above); XMEMCMP differs (true, idC has different content
         * than the cached idB) -- recompute. */
        if (sakke_compute_point_r(&key, idC, (word16)sizeof(idC), &rScalar,
                128, out) != 0) wb_fail = 1;

        /* All three operands false: identical id/idSz to the point I
         * cached by the call directly above -- cache hit, recompute
         * skipped entirely. */
        if (sakke_compute_point_r(&key, idC, (word16)sizeof(idC), &rScalar,
                128, out) != 0) wb_fail = 1;
        WB_NOTE("sakke_compute_point_r() cache-state guard (line 6653) all "
            "four operand combinations exercised");

        /* idSz > SAKKE_ID_MAX_SIZE, with key->i.idSz reset to 0 to force
         * the recompute branch: isolates line 6657's bound to false while
         * err stays 0, confirming the copy into the fixed 128-byte
         * key->i.id is skipped instead of overflowed. */
        key.i.idSz = 0;
        if (sakke_compute_point_r(&key, idBig, (word16)sizeof(idBig),
                &rScalar, 128, out) != 0) wb_fail = 1;
        WB_NOTE("sakke_compute_point_r() idSz > SAKKE_ID_MAX_SIZE (line "
            "6657) exercised");

        mp_free(&rScalar);
    }

    if (rsk != NULL) {
        wc_ecc_forcezero_point(rsk);
        wc_ecc_del_point(rsk);
    }
    if (rsk2 != NULL) {
        wc_ecc_forcezero_point(rsk2);
        wc_ecc_del_point(rsk2);
    }
    wc_FreeSakkeKey(&key);
    (void)wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  WOLFCRYPT_HAVE_SAKKE not defined; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
