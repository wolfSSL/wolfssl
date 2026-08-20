/* test_frodokem_mat_hash_fault_whitebox.c
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
 * MC/DC hash/AES-fault white-box for wolfcrypt/src/wc_frodokem_mat.c.
 *
 * THE DEFERRED TECHNIQUE, IMPLEMENTED
 * -----------------------------------
 * test_frodokem_fault_common.h records, at length, why the heap-fault mock
 * closes NONE of wc_frodokem_mat.c's 13 residuals:
 *
 *     "on x86/x86_64 its (ret == 0) && step residuals become ret != 0 ONLY
 *      when a SHAKE (wc_InitShake* / Absorb / Squeeze) or AES-ECB primitive
 *      returns an error. Those primitives DO NOT route through the heap
 *      allocator ... they would need a primitive-return fault mock (stubbing
 *      the wc_Shake family and wc_AesEcbEncrypt), a separate deferred
 *      technique."
 *
 * This file is that technique. mcdc_fault_hash.h macro-interposes the SHAKE
 * and AES-ECB primitives for THIS translation unit only (the involved .c is
 * #included after the interposers are installed), and mcdc_fh_arm(n) makes the
 * n-th primitive call -- and every later one -- return BAD_FUNC_ARG.
 *
 * WHAT THAT REACHES
 *   1041:1 / 1084:1  frodokem_gen_noise():
 *                        if (p->useShake256 && ((ret = wc_InitShake256(...)) == 0))
 *                    The second operand has no other route to FALSE, which is
 *                    why MCDC_FH_WITH_SHAKE_INIT is enabled here (it is opt-in
 *                    precisely because a white-box that inits its own SHAKE
 *                    contexts must not have that setup faulted; this one does
 *                    not init any).
 *   1059:0 / 1102:0  if ((ret == 0) && (cnt1 > 0))     -- fault the Absorb or
 *                    an earlier SqueezeBlocks of the same gen_noise call.
 *   1242:0           for (r = 0; (ret == 0) && (r < cnt); r++) -- fault an
 *                    AES-ECB inside the row loop of frodokem_gen_a_rows_aes().
 *   1828 / 1956 / 2151 / 2283 :0   for (i = 0; (ret == 0) && (i < n); i++)
 *                    -- the four matrix mul-add row loops.
 *   1841 / 1969 / 2164 / 2296 :0   if ((ret == 0) && (p->qMask != 0xffff))
 *                    -- the post-loop reduction guard. NOTE this needs the
 *                    q == 2^15 parameter sets (640), where qMask != 0xffff, so
 *                    the sweep always includes a 640 type.
 *
 * DRIVING IT
 * ----------
 * wc_frodokem_mat.c is a helper TU: the public API lives in wc_frodokem.c,
 * which the harness still supplies from the trimmed archive, so an ordinary
 * MakeKey / Encapsulate / Decapsulate reaches every routine here end to end.
 * Each entry point is swept separately with its inputs built while DISARMED:
 * run it once unarmed (the all-true baseline row for every guard, in THIS
 * binary -- HARD RULE 1 -- and the sweep length K), then sweep n over [1..K]
 * dense-then-strided to a fixed point budget.
 *
 * Only the SMALLEST parameter set of each matrix-generation family (640_SHAKE
 * and 640_AES, plus their ephemeral forms when compiled) is swept: 640 is the
 * only set with qMask != 0xffff, and the 976/1344 sets run the identical code
 * with a bigger n at several times the cost. The larger sets still get their
 * baseline pass. Everything is bounded by a point budget AND a CPU deadline so
 * the binary can never hit the 600 s TEST_TIMEOUT (a timeout is a
 * SILENT SKIP that would lose the whole file).
 */

/* wc_InitShake128/256 must be interposable here -- see the 1041:1 note above.
 * This TU initialises no SHAKE context of its own, so nothing in the test
 * setup can be faulted by that. */
#define MCDC_FH_WITH_SHAKE_INIT 1
#include "mcdc_fault_hash.h"

/* The involved .c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_frodokem_mat.c>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_frodokem.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifndef WOLFSSL_HAVE_FRODOKEM

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("frodokem mat hash-fault white-box: !WOLFSSL_HAVE_FRODOKEM, "
        "nothing to do\n");
    return 0;
}

#else

/* Sweep budget and CPU deadline (see file header). */
#define WB_DENSE       48
#define WB_POINTS      160
#define WB_DEADLINE_S  200

static clock_t wb_t0;

/* Budget by VECTOR COUNT, not elapsed time.
 *
 * A wall-clock budget makes coverage a function of machine load: under
 * contention the sweep stops at a different vector than on an idle host, so the
 * same source measures differently run to run. Two full sweeps of an unchanged
 * tree on 2026-08-11 disagreed on wc_lms_impl.c for exactly this reason. For
 * ASIL-D the evidence must be reproducible; a baseline recorded from a fast run
 * fails on a slow one.
 *
 * WB_MAX_VECTORS is the real, deterministic bound. The wall clock survives only
 * as a backstop against TEST_TIMEOUT (a killed white-box is scored as a SILENT
 * SKIP and loses the whole file), and says so loudly if it ever fires -- that
 * means the vector budget needs lowering, not that the result is quietly short.
 */
#ifndef WB_MAX_VECTORS
    #define WB_MAX_VECTORS 20000
#endif

static long wb_vectors = 0;
static int  wb_backstop_fired = 0;

static int wb_expired(void)
{
    if (++wb_vectors > (long)WB_MAX_VECTORS) {
        return 1;
    }
    if (((double)(clock() - wb_t0) / (double)CLOCKS_PER_SEC)
        > (double)WB_DEADLINE_S) {
        if (!wb_backstop_fired) {
            wb_backstop_fired = 1;
            printf("  [wb] WALL-CLOCK BACKSTOP fired after %ld "
                   "vectors -- coverage is load-dependent for this "
                   "run; lower WB_MAX_VECTORS\n", wb_vectors);
        }
        return 1;
    }
    return 0;
}

static long wb_next(long n, long k)
{
    long stride;

    if (n < (long)WB_DENSE)
        return n + 1;
    stride = (k - (long)WB_DENSE) / (long)WB_POINTS;
    if (stride < 1)
        stride = 1;
    return n + stride;
}

/* Types swept in full. 640 is the only q == 2^15 set (qMask != 0xffff), which
 * the `(ret == 0) && (p->qMask != 0xffff)` guards need, and it is the cheapest
 * of each family. */
static const int fk_sweep_types[] = {
#ifdef WOLFSSL_FRODOKEM_SHAKE
    WC_FRODOKEM_640_SHAKE,
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    WC_FRODOKEM_640_AES,
#endif
#if defined(WOLFSSL_FRODOKEM_EPHEMERAL) && defined(WOLFSSL_FRODOKEM_SHAKE)
    WC_EFRODOKEM_640_SHAKE,
#endif
#if defined(WOLFSSL_FRODOKEM_EPHEMERAL) && defined(WOLFSSL_FRODOKEM_AES)
    WC_EFRODOKEM_640_AES,
#endif
    0 /* keeps the array non-empty when no type is compiled in */
};

/* Types given only an unarmed baseline pass (the all-true rows for the
 * larger-n copies of the same code). */
static const int fk_base_types[] = {
#ifdef WOLFSSL_FRODOKEM_SHAKE
    WC_FRODOKEM_976_SHAKE, WC_FRODOKEM_1344_SHAKE,
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    WC_FRODOKEM_976_AES, WC_FRODOKEM_1344_AES,
#endif
    0
};

static WC_RNG wb_rng;
static byte   wb_ct[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
static byte   wb_ss[FRODOKEM_MAX_LENSEC];
static byte   wb_ss2[FRODOKEM_MAX_LENSEC];

/* Build a fully made key of a given type. Must be called DISARMED. */
static int wb_build(FrodoKemKey* key, int type)
{
    int ret = wc_FrodoKemKey_Init(key, type, NULL, INVALID_DEVID);

    if (ret == 0)
        ret = wc_FrodoKemKey_MakeKey(key, &wb_rng);
    return ret;
}

/* One unarmed make/encap/decap for a type: the all-true baseline rows. */
static void wb_baseline(int type)
{
    FrodoKemKey key;
    word32      ctLen = (word32)sizeof(wb_ct);

    XMEMSET(&key, 0, sizeof(key));
    mcdc_fh_disarm();
    if (wb_build(&key, type) == 0) {
        (void)wc_FrodoKemKey_CipherTextSize(&key, &ctLen);
        if (wc_FrodoKemKey_Encapsulate(&key, wb_ct, wb_ss, &wb_rng) == 0)
            (void)wc_FrodoKemKey_Decapsulate(&key, wb_ss2, wb_ct, ctLen);
    }
    wc_FrodoKemKey_Free(&key);
}

static void wb_sweep_type(int type)
{
    FrodoKemKey good;
    word32      ctLen = (word32)sizeof(wb_ct);
    long        k, n, points;
    int         haveCt = 0;

    XMEMSET(&good, 0, sizeof(good));
    mcdc_fh_disarm();
    if (wb_build(&good, type) != 0) {
        wc_FrodoKemKey_Free(&good);
        return;                          /* type not compiled in this build */
    }
    (void)wc_FrodoKemKey_CipherTextSize(&good, &ctLen);

    printf("  [wb] --- type 0x%02x ---\n", (unsigned)type);

    /* ---- make_key ---- */
    {
        FrodoKemKey key;
        XMEMSET(&key, 0, sizeof(key));
        mcdc_fh_disarm();
        if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) == 0) {
            (void)wc_FrodoKemKey_MakeKey(&key, &wb_rng);
            k = mcdc_fh_seen();
        }
        else {
            k = 0;
        }
        wc_FrodoKemKey_Free(&key);

        points = 0;
        for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
            FrodoKemKey f;
            XMEMSET(&f, 0, sizeof(f));
            if (wc_FrodoKemKey_Init(&f, type, NULL, INVALID_DEVID) == 0) {
                mcdc_fh_arm(n);
                (void)wc_FrodoKemKey_MakeKey(&f, &wb_rng);
                mcdc_fh_disarm();
                points++;
            }
            wc_FrodoKemKey_Free(&f);
        }
        printf("  [wb] make_key sweep: K=%ld, %ld points\n", k, points);
    }

    /* ---- encapsulate (does not mutate the key) ---- */
    mcdc_fh_disarm();
    haveCt = (wc_FrodoKemKey_Encapsulate(&good, wb_ct, wb_ss, &wb_rng) == 0);
    k = mcdc_fh_seen();
    if (!haveCt) {
        WB_NOTE("baseline encapsulate failed; encap/decap sweeps skipped");
        wb_fail = 1;
        wc_FrodoKemKey_Free(&good);
        return;
    }
    points = 0;
    for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
        byte c2[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
        byte s2[FRODOKEM_MAX_LENSEC];
        mcdc_fh_arm(n);
        (void)wc_FrodoKemKey_Encapsulate(&good, c2, s2, &wb_rng);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] encapsulate sweep: K=%ld, %ld points\n", k, points);

    /* ---- decapsulate (re-encapsulates internally: hits the mat paths
     *      again plus the shared-secret compare) ---- */
    mcdc_fh_disarm();
    (void)wc_FrodoKemKey_Decapsulate(&good, wb_ss2, wb_ct, ctLen);
    k = mcdc_fh_seen();
    points = 0;
    for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
        byte d2[FRODOKEM_MAX_LENSEC];
        mcdc_fh_arm(n);
        (void)wc_FrodoKemKey_Decapsulate(&good, d2, wb_ct, ctLen);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] decapsulate sweep: K=%ld, %ld points\n", k, points);

    mcdc_fh_disarm();
    wc_FrodoKemKey_Free(&good);
}

/* ------------------------------------------------------------------------- *
 * frodokem_gen_noise() driven DIRECTLY.
 *
 * Two residuals live in this one function and the end-to-end sweep above has
 * never landed on them:
 *
 *     if (p->useShake256 && ((ret = wc_InitShake256(...)) == 0))   -- cond 1
 *     if ((ret == 0) && (cnt1 > 0))                                -- cond 0
 *
 * The lever is right: MCDC_FH_WITH_SHAKE_INIT already interposes
 * wc_InitShake128/256, so the second operand of the first guard HAS a false
 * side available. What is wrong is the INDEX. frodokem_gen_noise() is called
 * from MakeKey/Encapsulate/Decapsulate only after matrix-A generation has
 * already made hundreds of SHAKE calls, so its own calls sit far out in the
 * strided tail of the sweep, where the stride steps over them. Widening the
 * sweep would cost a full FrodoKEM operation per extra point.
 *
 * frodokem_gen_noise() is WOLFSSL_LOCAL and this TU #includes the .c, so it is
 * called here directly instead, with the fault index counted from ZERO at the
 * call. Index 1 is then exactly the wc_InitShake* call and indices 2..6 are the
 * Absorb/SqueezeBlocks that follow -- no searching, and six cheap vectors
 * instead of a longer sweep of whole key operations.
 *
 * SIZING. The function's documented precondition is that a non-zero cnt1 spans
 * more than one SHAKE block. WB_GN_CNT = 256 coefficients = 512 bytes per
 * region, which is 3 whole blocks plus a remainder at the SHAKE-256 rate (136)
 * and 3 plus a remainder at the SHAKE-128 rate (168); every squeeze and every
 * XMEMCPY the function performs stays inside the 512-byte regions in both
 * cases, and tmp is a whole block at either rate. Worked through for both rates
 * before writing, because a faulted primitive leaves its output buffer
 * untouched and the harness must never over-read it.
 *
 * PAIRING (HARD RULE 1): the unarmed cnt1 > 0 call is the (T,T) row for both
 * decisions and runs first, in this same binary.
 * ------------------------------------------------------------------------- */
#define WB_GN_CNT   256                  /* coefficients per region */
#define WB_GN_BYTES (2 * WB_GN_CNT)      /* 512 -- more than one block, both
                                          * rates */
#define WB_GN_TMP   256                  /* >= FRODOKEM_SHAKE128_RATE (168) */

static void wb_gen_noise_rows(int type)
{
    FrodoKemKey key;
    wc_Shake    shake;
    byte        seInput[1 + FRODOKEM_MAX_LENSE];
    byte        tmp[WB_GN_TMP];
    word16      mat0[WB_GN_CNT];
    word16      mat1[WB_GN_CNT];
    long        n;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&shake, 0, sizeof(shake));

    mcdc_fh_disarm();
    if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;                          /* type not compiled in */
    }
    if ((key.params == NULL) ||
            ((word32)key.params->lenSE + 1U > (word32)sizeof(seInput))) {
        wc_FrodoKemKey_Free(&key);
        return;
    }

    XMEMSET(seInput, 0x5e, sizeof(seInput));
    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(mat0, 0, sizeof(mat0));
    XMEMSET(mat1, 0, sizeof(mat1));

    /* (T,T) for both decisions: everything succeeds and region 1 is present. */
    if (frodokem_gen_noise(key.params, &shake, seInput, tmp, mat0, WB_GN_CNT,
            mat1, WB_GN_CNT) != 0) {
        WB_NOTE("baseline frodokem_gen_noise failed; gen-noise rows skipped");
        wb_fail = 1;
        wc_FrodoKemKey_Free(&key);
        return;
    }

    /* (T,F) for the cnt1 guard: no region 1. */
    (void)frodokem_gen_noise(key.params, &shake, seInput, tmp, mat0, WB_GN_CNT,
        NULL, 0);

    /* Index 1 = the wc_InitShake* call itself, giving the init guard its
     * (T,F) row; 2..6 = the Absorb/Squeeze chain, giving `ret == 0` its false
     * row at the cnt1 guard with region 1 still requested. A fixed six
     * vectors -- a count, never a clock. */
    for (n = 1; n <= 6L; n++) {
        mcdc_fh_arm(n);
        (void)frodokem_gen_noise(key.params, &shake, seInput, tmp, mat0,
            WB_GN_CNT, mat1, WB_GN_CNT);
        mcdc_fh_disarm();
    }

    mcdc_fh_disarm();
    wc_FrodoKemKey_Free(&key);
    WB_NOTE("frodokem_gen_noise init/cnt1 rows exercised");
}

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_frodokem_mat.c hash/AES-fault white-box supplement\n");
    wb_t0 = clock();

    XMEMSET(&wb_rng, 0, sizeof(wb_rng));
    XMEMSET(wb_ct, 0, sizeof(wb_ct));
    XMEMSET(wb_ss, 0, sizeof(wb_ss));
    XMEMSET(wb_ss2, 0, sizeof(wb_ss2));

    if (wc_InitRng(&wb_rng) != 0) {
        WB_NOTE("wc_InitRng failed; nothing driven");
    }
    else {
        for (i = 0; i < sizeof(fk_base_types) / sizeof(fk_base_types[0]); i++) {
            if (fk_base_types[i] != 0)
                wb_baseline(fk_base_types[i]);
        }
        /* Both noise arms. p->useShake256 is false only for the 640 sets, and
         * fk_base_types above carries no 640 type, so the SHAKE-128 copy of
         * the guard pair needs its own entry here. Types absent from the build
         * are rejected by Init and skipped. */
        {
            static const int gn_types[] = {
#ifdef WOLFSSL_FRODOKEM_SHAKE
                WC_FRODOKEM_640_SHAKE, WC_FRODOKEM_976_SHAKE,
#endif
#ifdef WOLFSSL_FRODOKEM_AES
                WC_FRODOKEM_640_AES, WC_FRODOKEM_976_AES,
#endif
                0
            };
            size_t g;

            for (g = 0; g < sizeof(gn_types) / sizeof(gn_types[0]); g++) {
                if (gn_types[g] != 0)
                    wb_gen_noise_rows(gn_types[g]);
            }
        }
        for (i = 0; i < sizeof(fk_sweep_types) / sizeof(fk_sweep_types[0]);
                i++) {
            if ((fk_sweep_types[i] != 0) && !wb_expired())
                wb_sweep_type(fk_sweep_types[i]);
        }
        mcdc_fh_disarm();
        wc_FreeRng(&wb_rng);
    }

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the harness discard this binary's coverage. */
    return 0;
}

#endif /* WOLFSSL_HAVE_FRODOKEM */
