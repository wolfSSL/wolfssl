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
 *   The two rejection-sampling retry loops (924 and 1934), all three
 *   conditions each:
 *     eccsi_make_pair()  (924)
 *       while ((err == 0) && (mp_iszero(ssk) ||
 *               (mp_cmp(ssk, wc_ecc_key_get_priv(&key->ecc)) == MP_EQ)));
 *     eccsi_gen_sig()    (1934)
 *       while ((err == 0) && (mp_iszero(s) || (mp_cmp(s, he) == MP_EQ)));
 *   Both loops re-sample when the derived scalar comes out zero or collides
 *   with the value it is compared against. Neither scalar is a raw random
 *   draw: ssk = (KSAK + HS*v) mod q and s = (HE + r*SSK) mod q, and HS/HE
 *   are hashes of the freshly generated ephemeral point, so no choice of RNG
 *   stream (seeded or not) can steer either to a chosen value -- that would
 *   be a hash preimage. What CAN be steered is the last arithmetic step of
 *   each loop body: both scalars are produced by the loop's final
 *   mp_addmod(), which this file interposes (wb_am_addmod, installed before
 *   eccsi.c so eccsi.c's call sites bind to it). The interposer is a
 *   ONE-SHOT keyed on the destination mp_int pointer, so it tampers with
 *   exactly one iteration and the retry then runs the genuine arithmetic --
 *   the loop terminates on real data, not on a second injected value.
 *
 *   Four vectors per loop, all in this one binary, which is what llvm-cov
 *   needs to derive the independence pairs:
 *     (d) OFF   -> scalar non-zero and != comparand : (T,F,F), decision FALSE
 *     (b) ZERO  -> mp_iszero() TRUE on pass 1       : (T,T),   decision TRUE
 *     (c) COPY  -> mp_cmp() == MP_EQ on pass 1      : (T,F,T), decision TRUE
 *               (the copied value is the addmod operand the loop then
 *                compares against: operand b at 920, operand a at 1931)
 *     (a) FAIL  -> mp_addmod returns MP_VAL         : (F),     decision FALSE
 *   (a)+(b) is the independence pair for cond 0 (err == 0); (b)+(d) for
 *   cond 1 (mp_iszero); (c)+(d) for cond 2 (mp_cmp == MP_EQ). A rejection
 *   vector on its own would prove nothing, so all four always run.
 *
 *   924 is driven through the public wc_MakeEccsiPair() (ssk is the caller's
 *   mp_int, so the pointer key is unambiguous). 1934 is driven by calling the
 *   file-static eccsi_gen_sig() directly with caller-owned r/s, after
 *   replicating exactly the state wc_SignEccsiHash() sets up before it
 *   (pair set, id hash set, order loaded); wc_SignEccsiHash() itself aliases
 *   r/s onto key->pubkey.pubkey.y/z, and owning them here makes the pointer
 *   key exact.
 *
 * Crash-safety: every call here operates on a single EccsiKey that has been
 * fully initialized (wc_InitEccsiKey) and had its curve parameters and base
 * point loaded before any helper that dereferences them is called; scratch
 * ecc_points and mp_ints are heap/stack allocated and freed at the end. The
 * FAIL vectors make the loop's last mp_addmod return MP_VAL, which the loop
 * body's own "if (err == 0)" chain absorbs; the tampered/failed ssk, r and s
 * are never read afterwards, and the destructive 924 vectors run last, with a
 * clean pair regenerated before the signing fixture is built.
 */

/* --------------------------------------------------------------------------
 * Value-forcing mp_addmod interposer.
 *
 * Same macro-interposition ordering as mcdc_fault_mp.h: the wrapper is
 * compiled while mp_addmod still means the real (sp_addmod / integer.c / tfm.c)
 * entry point, and only then is the name redefined, so the wrapper reaches the
 * genuine operation. eccsi.c must be #included AFTER this block.
 *
 * Unlike the fault injectors this does not only fail a call, it can also
 * substitute the RESULT -- which is what the two retry loops need, since their
 * loop condition is a predicate on the value, not on an error code. Both
 * eccsi.c call sites (920 in eccsi_make_pair, 1931 in eccsi_gen_sig) are
 * targets; the destination-pointer key selects which one is affected.
 * ----------------------------------------------------------------------- */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

#if defined(__GNUC__) || defined(__clang__)
    #define WB_MAYBE_UNUSED __attribute__((unused))
#else
    #define WB_MAYBE_UNUSED
#endif

#ifdef WOLFCRYPT_HAVE_ECCSI

#define WB_AM_OFF     0   /* pass through */
#define WB_AM_ZERO    1   /* succeed, then force the result to zero */
#define WB_AM_COPY_A  2   /* succeed, then force the result to operand a */
#define WB_AM_COPY_B  3   /* succeed, then force the result to operand b */
#define WB_AM_FAIL    4   /* return MP_VAL without touching the result */

/* The COPY modes take the operand the call was given rather than a pointer
 * cached by the driver: wc_ecc_key_get_priv() is a function under
 * WOLFSSL_ECC_BLIND_K, so a pointer captured before the call is not
 * guaranteed to still name the private key during it. Only the operand that
 * does NOT alias the destination is ever copied (eccsi.c's 920 site writes
 * over operand a, its 1931 site over operand b), so the copy is always of a
 * live value. */
static int     wb_am_mode = WB_AM_OFF;
static mp_int* wb_am_dst  = NULL;

/* const-in / non-const-out signature: sp_int.h declares the operands const
 * while integer.h and tfm.h do not, and this is the one shape that binds under
 * every math backend without a qualifier warning at eccsi.c's call sites. */
WB_MAYBE_UNUSED static int wb_am_addmod(const mp_int* a, const mp_int* b,
    const mp_int* m, mp_int* r)
{
    int mode = WB_AM_OFF;
    int ret;

    if ((wb_am_mode != WB_AM_OFF) && (r == wb_am_dst)) {
        mode = wb_am_mode;
        /* One-shot: the loop's retry iteration runs untampered, so the loop
         * terminates on genuine arithmetic rather than a second injection. */
        wb_am_mode = WB_AM_OFF;
    }
    if (mode == WB_AM_FAIL) {
        return MP_VAL;
    }
    ret = mp_addmod((mp_int*)a, (mp_int*)b, (mp_int*)m, r);
    if (ret == 0) {
        if (mode == WB_AM_ZERO) {
            mp_zero(r);
        }
        else if (mode == WB_AM_COPY_A) {
            ret = mp_copy((mp_int*)a, r);
        }
        else if (mode == WB_AM_COPY_B) {
            ret = mp_copy((mp_int*)b, r);
        }
    }
    return ret;
}

#undef  mp_addmod
#define mp_addmod(a, b, m, r)   wb_am_addmod((a), (b), (m), (r))

#endif /* WOLFCRYPT_HAVE_ECCSI */

#include <wolfcrypt/src/eccsi.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* --------------------------------------------------------------------------
 * 924 / 1934: the two rejection-sampling retry loops.
 *
 * Vector map (see the file header for the independence-pair argument):
 *   eccsi_make_pair()  924, ssk = (KSAK + HS*v) mod q
 *     OFF -> (T,F,F)  ZERO -> (T,T)  COPY_B(KSAK) -> (T,F,T)  FAIL -> (F)
 *   eccsi_gen_sig()   1934, s   = (HE + r*SSK) mod q
 *     OFF -> (T,F,F)  ZERO -> (T,T)  COPY_A(he)   -> (T,F,T)  FAIL -> (F)
 * ----------------------------------------------------------------------- */
#if defined(WOLFCRYPT_HAVE_ECCSI) && defined(WOLFCRYPT_ECCSI_KMS) && \
    defined(WOLFCRYPT_ECCSI_CLIENT) && !defined(NO_SHA256)
static void wb_eccsi_retry_loops(void)
{
    WC_RNG     rng;
    EccsiKey   key;
    ecc_point* pvt = NULL;
    mp_int     ssk;
    mp_int     r;
    mp_int     s;
    byte       id[] = "eccsi-retry@wolfssl.com";
    byte       msg[32];
    byte       hash[WC_MAX_DIGEST_SIZE];
    int        ready = 0;
    int        ret;

    XMEMSET(&rng,  0, sizeof(rng));
    XMEMSET(&key,  0, sizeof(key));
    XMEMSET(&ssk,  0, sizeof(ssk));
    XMEMSET(&r,    0, sizeof(r));
    XMEMSET(&s,    0, sizeof(s));
    XMEMSET(msg,   0x3c, sizeof(msg));
    XMEMSET(hash,  0, sizeof(hash));

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; retry-loop vectors skipped");
        wb_fail = 1;
        return;
    }
    if (wc_InitEccsiKey(&key, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitEccsiKey failed; retry-loop vectors skipped");
        wb_fail = 1;
        wc_FreeRng(&rng);
        return;
    }

    pvt = wc_ecc_new_point_h(NULL);
    if (pvt != NULL) {
        (void)mp_init(&ssk);
        (void)mp_init(&r);
        (void)mp_init(&s);
        if (wc_MakeEccsiKey(&key, &rng) == 0) {
            ready = 1;
        }
    }
    if (!ready) {
        WB_NOTE("eccsi retry-loop fixture setup failed; vectors skipped");
        wb_fail = 1;
        goto done;
    }

    /* ---- 924: eccsi_make_pair() via the public wc_MakeEccsiPair(). ------ */

    /* (d) all-false single-pass exit. */
    wb_am_mode = WB_AM_OFF;
    ret = wc_MakeEccsiPair(&key, &rng, WC_HASH_TYPE_SHA256, id,
        (word32)sizeof(id), &ssk, pvt);
    if (ret != 0) {
        WB_NOTE("wc_MakeEccsiPair baseline (924 all-false) failed");
        wb_fail = 1;
        goto done;
    }

    /* (b) mp_iszero(ssk) TRUE on pass 1, retry, then normal exit. */
    wb_am_dst  = &ssk;
    wb_am_mode = WB_AM_ZERO;
    ret = wc_MakeEccsiPair(&key, &rng, WC_HASH_TYPE_SHA256, id,
        (word32)sizeof(id), &ssk, pvt);
    wb_am_mode = WB_AM_OFF;
    if (ret != 0) {
        WB_NOTE("wc_MakeEccsiPair zero-ssk retry vector failed");
        wb_fail = 1;
    }

    /* (c) mp_cmp(ssk, KSAK) == MP_EQ on pass 1, retry, then normal exit.
     * Operand b of the 920 mp_addmod IS wc_ecc_key_get_priv(&key->ecc). */
    wb_am_dst  = &ssk;
    wb_am_mode = WB_AM_COPY_B;
    ret = wc_MakeEccsiPair(&key, &rng, WC_HASH_TYPE_SHA256, id,
        (word32)sizeof(id), &ssk, pvt);
    wb_am_mode = WB_AM_OFF;
    if (ret != 0) {
        WB_NOTE("wc_MakeEccsiPair ssk==KSAK retry vector failed");
        wb_fail = 1;
    }

    /* (a) err != 0 on loop exit. ssk is not read after this. */
    wb_am_dst  = &ssk;
    wb_am_mode = WB_AM_FAIL;
    (void)wc_MakeEccsiPair(&key, &rng, WC_HASH_TYPE_SHA256, id,
        (word32)sizeof(id), &ssk, pvt);
    wb_am_mode = WB_AM_OFF;

    /* Regenerate a valid pair: the FAIL vector left ssk holding a partial
     * product, and the signing fixture below needs a genuine (ssk, pvt). */
    ret = wc_MakeEccsiPair(&key, &rng, WC_HASH_TYPE_SHA256, id,
        (word32)sizeof(id), &ssk, pvt);
    if (ret != 0) {
        WB_NOTE("wc_MakeEccsiPair restore failed; 1934 vectors skipped");
        wb_fail = 1;
        goto done;
    }
    WB_NOTE("eccsi_make_pair 924 retry-loop pairs exercised");

    /* ---- 1934: eccsi_gen_sig() called directly with caller-owned r/s. ---
     * Same state wc_SignEccsiHash() establishes before it: pair set, identity
     * hash set, curve order loaded. */
    if ((wc_SetEccsiPair(&key, &ssk, pvt) != 0) ||
            (wc_HashEccsiId(&key, WC_HASH_TYPE_SHA256, id,
                (word32)sizeof(id), pvt, hash, NULL) != 0) ||
            (wc_SetEccsiHash(&key, hash, WC_SHA256_DIGEST_SIZE) != 0) ||
            (eccsi_load_order(&key) != 0)) {
        WB_NOTE("eccsi signing fixture setup failed; 1934 vectors skipped");
        wb_fail = 1;
        goto done;
    }

    /* (d) all-false single-pass exit. */
    wb_am_mode = WB_AM_OFF;
    ret = eccsi_gen_sig(&key, &rng, WC_HASH_TYPE_SHA256, msg,
        (word32)sizeof(msg), &r, &s);
    if (ret != 0) {
        WB_NOTE("eccsi_gen_sig baseline (1934 all-false) failed");
        wb_fail = 1;
    }

    /* (b) mp_iszero(s) TRUE on pass 1, retry, then normal exit. */
    wb_am_dst  = &s;
    wb_am_mode = WB_AM_ZERO;
    ret = eccsi_gen_sig(&key, &rng, WC_HASH_TYPE_SHA256, msg,
        (word32)sizeof(msg), &r, &s);
    wb_am_mode = WB_AM_OFF;
    if (ret != 0) {
        WB_NOTE("eccsi_gen_sig zero-s retry vector failed");
        wb_fail = 1;
    }

    /* (c) mp_cmp(s, he) == MP_EQ on pass 1, retry, then normal exit.
     * Operand a of the 1931 mp_addmod IS he (== &key->tmp), which
     * eccsi_gen_sig() reloads from the digest on every iteration. */
    wb_am_dst  = &s;
    wb_am_mode = WB_AM_COPY_A;
    ret = eccsi_gen_sig(&key, &rng, WC_HASH_TYPE_SHA256, msg,
        (word32)sizeof(msg), &r, &s);
    wb_am_mode = WB_AM_OFF;
    if (ret != 0) {
        WB_NOTE("eccsi_gen_sig s==he retry vector failed");
        wb_fail = 1;
    }

    /* (a) err != 0 on loop exit. r/s are not read after this. */
    wb_am_dst  = &s;
    wb_am_mode = WB_AM_FAIL;
    (void)eccsi_gen_sig(&key, &rng, WC_HASH_TYPE_SHA256, msg,
        (word32)sizeof(msg), &r, &s);
    wb_am_mode = WB_AM_OFF;

    WB_NOTE("eccsi_gen_sig 1934 retry-loop pairs exercised");

done:
    wb_am_mode = WB_AM_OFF;
    wb_am_dst  = NULL;
    mp_free(&s);
    mp_free(&r);
    mp_forcezero(&ssk);
    mp_free(&ssk);
    if (pvt != NULL) {
        wc_ecc_del_point_h(pvt, NULL);
    }
    wc_FreeEccsiKey(&key);
    wc_FreeRng(&rng);
}
#else
static void wb_eccsi_retry_loops(void)
{ WB_NOTE("ECCSI KMS/CLIENT or SHA-256 unavailable; 924/1934 retry-loop "
          "vectors skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
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

    /* 924 / 1934 retry loops, on their own key/RNG fixture. */
    wb_eccsi_retry_loops();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    wb_eccsi_retry_loops();
    printf("  WOLFCRYPT_HAVE_ECCSI not defined; nothing to exercise\n");
#endif /* WOLFCRYPT_HAVE_ECCSI */
    (void)wb_fail;
    return 0;
}
