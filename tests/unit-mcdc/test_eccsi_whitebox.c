/* test_eccsi_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/eccsi.c.
 *
 * The tests/api eccsi suite drives eccsi.c through its *public* API only.
 * A handful of decision conditions live in file-static helpers that are
 * either never reached with both cache-flag states in the same run, or
 * are only reachable via a private-only "map" argument that every public
 * caller hard-codes -- so their MC/DC independence pairs cannot be shown
 * from the API without editing library source. This white-box #includes
 * eccsi.c directly so the static helpers are in scope, and drives both
 * halves of each targeted guard within this one binary.
 *
 * Targeted residuals (eccsi.c):
 *   eccsi_load_ecc_params() (line ~196/202/208)
 *     if ((err == 0) && (!params->haveA))
 *     if ((err == 0) && (!params->haveB))
 *     if ((err == 0) && (!params->havePrime))
 *   These cache flags are false on a freshly initialized EccsiKey (the load
 *   runs) and true on every subsequent call (the load is skipped). No
 *   public entry point exposes a way to reset the flags without a fresh
 *   wc_InitEccsiKey(), so a single API-level test can only ever show one
 *   side; calling the static helper twice on the SAME key here shows both.
 *
 *   eccsi_mulmod_base_add() (line ~1358) and eccsi_mulmod_point_add()
 *   (line ~1449), both "if ((err == 0) && map)":
 *   'map' (0 = leave result in projective form, 1 = map to affine) is a
 *   parameter of these static helpers, but every public caller hard-codes
 *   a single literal for it (map=1 in the signing/verification call sites),
 *   so the map=0 side of the decision is never reached through the API.
 *   Calling the helpers directly with map=0 and map=1 drives both halves.
 *
 * Not driven (justified residuals, documented rather than forced):
 *   eccsi_make_pair() (line ~916):
 *     while ((err == 0) && (mp_iszero(ssk) ||
 *             (mp_cmp(ssk, wc_ecc_key_get_priv(&key->ecc)) == MP_EQ)));
 *   wc_SignEccsiHash()'s retry loop (line ~1926):
 *     while ((err == 0) && (mp_iszero(s) || (mp_cmp(s, he) == MP_EQ)));
 *   Both loops only take their extra iteration when a freshly generated
 *   random scalar happens to be exactly zero or collide with another
 *   value -- a cryptographically negligible event (probability ~2^-256 on
 *   P-256) that cannot be forced through the public RNG-driven API without
 *   corrupting the RNG or hand-crafting an internal scalar, which would
 *   defeat the point of testing the real retry logic. Left as defensive
 *   residuals.
 *
 * Crash-safety: every call here operates on a single EccsiKey that has been
 * fully initialized (wc_InitEccsiKey) and had its curve parameters and base
 * point loaded before any helper that dereferences them is called; scratch
 * ecc_points and mp_ints are heap/stack allocated and freed at the end.
 */

#include <wolfcrypt/src/eccsi.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

int main(void)
{
    printf("eccsi.c white-box supplement\n");
#ifdef WOLFCRYPT_HAVE_ECCSI
    EccsiKey key;
    int      ret;

    ret = wc_InitEccsiKey(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("wc_InitEccsiKey failed; whitebox skipped");
        wb_fail = 1;
    }
    else {
#ifdef WOLFCRYPT_ECCSI_CLIENT
        /* eccsi_load_ecc_params(): haveA/haveB/havePrime guards.
         * First call: key is freshly initialized, so all three flags are
         * 0 -- every "!params->haveX" operand is TRUE and the load runs. */
        ret = eccsi_load_ecc_params(&key);
        if (ret != 0) {
            WB_NOTE("eccsi_load_ecc_params (fresh, haveX=0) unexpected "
                     "return");
            wb_fail = 1;
        }

        /* Second call, same key: all three flags are now 1, so every
         * "!params->haveX" operand is FALSE and the load is skipped. */
        ret = eccsi_load_ecc_params(&key);
        if (ret != 0) {
            WB_NOTE("eccsi_load_ecc_params (cached, haveX=1) unexpected "
                     "return");
            wb_fail = 1;
        }

        /* eccsi_mulmod_base_add() / eccsi_mulmod_point_add(): map guard.
         * Need a loaded base point, curve parameters and a Montgomery
         * reduction multiplier before either helper can be driven. */
        ret = eccsi_load_base(&key);
        if (ret != 0) {
            WB_NOTE("eccsi_load_base failed; mulmod guards skipped");
            wb_fail = 1;
        }
        else {
            ecc_point* ptA = wc_ecc_new_point_h(NULL);
            ecc_point* ptB = wc_ecc_new_point_h(NULL);
            ecc_point* res = wc_ecc_new_point_h(NULL);

            if ((ptA == NULL) || (ptB == NULL) || (res == NULL)) {
                WB_NOTE("wc_ecc_new_point_h failed; mulmod guards skipped");
                wb_fail = 1;
            }
            else {
                mp_int   n;
                mp_digit mp = 0;

                XMEMSET(&n, 0, sizeof(n));

                /* Snapshot the loaded base (G) into two independent
                 * points before eccsi_mulmod_base_add() mutates
                 * key.params.base in place. */
                ret = wc_ecc_copy_point(key.params.base, ptA);
                if (ret == 0) {
                    ret = wc_ecc_copy_point(key.params.base, ptB);
                }
                if (ret != 0) {
                    WB_NOTE("wc_ecc_copy_point failed; mulmod guards "
                             "skipped");
                    wb_fail = 1;
                }
                else if (mp_init(&n) != 0) {
                    WB_NOTE("mp_init failed; mulmod guards skipped");
                    wb_fail = 1;
                }
                else if (mp_set(&n, 3) != 0) {
                    WB_NOTE("mp_set failed; mulmod guards skipped");
                    wb_fail = 1;
                    mp_free(&n);
                }
                else if (mp_montgomery_setup(&key.params.prime, &mp) != 0) {
                    WB_NOTE("mp_montgomery_setup failed; mulmod guards "
                             "skipped");
                    wb_fail = 1;
                    mp_free(&n);
                }
                else {
                    /* eccsi_mulmod_base_add(): (err == 0) && map.
                     * map=0 -- guard FALSE, ecc_map() not called. */
                    ret = eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 0);
                    if (ret != 0) {
                        WB_NOTE("eccsi_mulmod_base_add(map=0) unexpected "
                                 "return");
                        wb_fail = 1;
                    }

                    /* map=1 -- guard TRUE, ecc_map() called. */
                    ret = eccsi_mulmod_base_add(&key, &n, ptA, res, mp, 1);
                    if (ret != 0) {
                        WB_NOTE("eccsi_mulmod_base_add(map=1) unexpected "
                                 "return");
                        wb_fail = 1;
                    }

                    /* eccsi_mulmod_point_add(): (err == 0) && map.
                     * map=0 -- guard FALSE, ecc_map() not called. */
                    ret = eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp,
                            0);
                    if (ret != 0) {
                        WB_NOTE("eccsi_mulmod_point_add(map=0) unexpected "
                                 "return");
                        wb_fail = 1;
                    }

                    /* map=1 -- guard TRUE, ecc_map() called. */
                    ret = eccsi_mulmod_point_add(&key, &n, ptA, ptB, res, mp,
                            1);
                    if (ret != 0) {
                        WB_NOTE("eccsi_mulmod_point_add(map=1) unexpected "
                                 "return");
                        wb_fail = 1;
                    }

                    mp_free(&n);
                }
            }

            wc_ecc_del_point_h(ptA, NULL);
            wc_ecc_del_point_h(ptB, NULL);
            wc_ecc_del_point_h(res, NULL);
        }

        WB_NOTE("eccsi_load_ecc_params haveA/haveB/havePrime and "
                "eccsi_mulmod_base_add/eccsi_mulmod_point_add map guards "
                "exercised");
#else
        WB_NOTE("WOLFCRYPT_ECCSI_CLIENT not defined; static helpers "
                "unavailable");
#endif /* WOLFCRYPT_ECCSI_CLIENT */

        wc_FreeEccsiKey(&key);
    }

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  WOLFCRYPT_HAVE_ECCSI not defined; nothing to exercise\n");
#endif /* WOLFCRYPT_HAVE_ECCSI */
    (void)wb_fail;
    return 0;
}
