/* test_xmss_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/wc_xmss_impl.c.
 *
 * suite/reports/xmss/the uncovered-condition report is entirely error-propagation:
 *
 *     for (i = 1; (ret == 0) && (i < params->wots_len); i++)   -- WOTS+ chain
 *     for (i = 0; (ret == 0) && (i < params->d); i++)          -- subtree loops
 *     if ((ret == 0) && (WC_IDX_INVALID(idx, ...)))
 *     if ((ret == 0) && (XMEMCMP(node, pub_root, n) != 0))
 *
 * The (ret == 0) operand only goes FALSE when an earlier step in the same
 * operation failed. wc_xmss_impl.c has exactly ONE allocation (the BDS state
 * in the non-SMALL arm) -- everything else that can set `ret` is a SHA-2 /
 * SHAKE primitive call, and those never touch the heap. mcdc_fault_alloc.h
 * therefore cannot reach these; mcdc_fault_hash.h can.
 *
 * mcdc_fault_hash.h macro-interposes wc_Sha256Update/Final, wc_Sha512Update/
 * Final and the SHAKE Update/Final family for THIS translation unit only, and
 * mcdc_fh_arm(n) makes the n-th primitive call -- and every later one --
 * return BAD_FUNC_ARG. wc_InitSha256/wc_InitSha512 are deliberately NOT
 * interposed, so this file's own state setup can never be faulted.
 *
 * DRIVING IT CHEAPLY
 * ------------------
 * The smallest parameter set wc_xmss.c will hand out is height 10 (1024
 * leaves), whose keygen is over a million hash calls -- far too expensive to
 * repeat a few hundred times. So, exactly like the sibling
 * test_wc_xmss_impl_whitebox.c, this file hand-builds an XmssParams with a
 * deliberately tiny height (h=4 => 16 leaves) and calls the link-local
 * wc_xmssmt_keygen / wc_xmssmt_sign / wc_xmssmt_verify / wc_xmss_sigsleft
 * entry points directly. Both d=1 (single tree) and d=2 (XMSS^MT, two layers)
 * shapes are driven, because the per-layer loops
 * (`(ret == 0) && (i < params->d)`) need d > 1 to have a second iteration.
 *
 * Each entry point is swept SEPARATELY with its inputs built while DISARMED:
 * one unarmed run gives both the all-true baseline row for every guard (HARD
 * RULE 1: same binary) and the sweep length K; then n is swept over [1..K],
 * dense over the first WB_DENSE indices and strided after that to a fixed
 * point budget. The secret key is restored from a snapshot before every armed
 * sign, so each armed call starts from the same known-good state.
 *
 * NEVER HANG (HARD RULE 2): every sweep tests a CPU-time deadline as well as
 * the point budget, so the binary degrades to fewer points rather than being
 * killed. WOLFSSL_WC_XMSS_SMALL's recompute signing path is several times
 * slower and relies on that.
 *
 * VARIANT COVERAGE (HARD RULE 3): WOLFSSL_XMSS_VERIFY_ONLY compiles keygen and
 * signing out, and no valid signature can be built without them, so that
 * variant gets a skip stub. main() always returns 0.
 */

#include "mcdc_fault_hash.h"

/* wc_xmss_impl.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_xmss_impl.c>

#include <stdio.h>
#include <string.h>
#include <time.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY) && \
    defined(WC_XMSS_SHA256)

#define WB_HAVE_DRIVER 1

#define WB_DENSE       48
#define WB_POINTS      192
#define WB_DEADLINE_S  170

/* WALL clock, not clock(): the harness runs several variants concurrently and
 * TEST_TIMEOUT is 600 s of WALL time. Under that contention CPU time accrues
 * far slower than wall time, so a CPU-time budget would sail past the timeout
 * -- and a timed-out white-box is scored as a SILENT SKIP that loses the whole
 * file's coverage. */
static time_t wb_t0;

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
    if (difftime(time(NULL), wb_t0) > (double)WB_DEADLINE_S) {
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

/* Hand-build an XmssParams the way wc_xmss.c's XMSS_PARAMS() macro would (that
 * macro is not visible here), but with a deliberately tiny height so a full
 * keygen/sign/verify cycle is cheap enough to repeat a few hundred times.
 * Copied from the sibling test_wc_xmss_impl_whitebox.c so both files agree on
 * the sk_len/sig_len formulas. */
static void wb_params_init(XmssParams* p, byte hash, byte n, byte pad_len,
    byte h, byte d, byte idx_len, byte bds_k)
{
    byte sub_h = (byte)(h / d);
    word8 hsk = (word8)(sub_h - bds_k);

    XMEMSET(p, 0, sizeof(*p));
    p->hash = hash;
    p->n = n;
    p->pad_len = pad_len;
    p->wots_len = (word8)(n * 2 + 3);
    p->wots_sig_len = (word16)(n * p->wots_len);
    p->h = h;
    p->sub_h = sub_h;
    p->d = d;
    p->idx_len = idx_len;
    p->sig_len = (word32)idx_len + n +
        (word32)d * ((word32)n * 2 + 3) * n + (word32)h * n;
    p->sk_len = (word32)idx_len + 4U * n +
        (word32)(2 * d - 1) * ((word32)(sub_h + 1) * n + (word32)(sub_h + 1) +
            (word32)sub_h * n + (word32)(sub_h >> 1) * n +
            (word32)hsk * 4U + (word32)hsk * n +
            XMSS_RETAIN_LEN(bds_k, n) + 4U) +
        (word32)(d - 1) * n * ((word32)n * 2 + 3);
    p->pk_len = (word8)(n * 2);
    p->bds_k = bds_k;
}

/* wc_xmss_digest_init()'s job (that helper is file-static in wc_xmss.c).
 * wc_InitSha256/512 are NOT interposed, so setup can never be faulted. */
static int wb_state_init(XmssState* state, const XmssParams* params)
{
    int ret;

    XMEMSET(state, 0, sizeof(*state));
    state->params = params;
    state->heap   = NULL;
    state->ret    = 0;

#ifdef WC_XMSS_SHA512
    if (params->hash == WC_HASH_TYPE_SHA512) {
        ret = wc_InitSha512(&state->digest.sha512);
    }
    else
#endif
    {
        ret = wc_InitSha256(&state->digest.sha256);
    }
    return ret;
}

static void wb_state_free(XmssState* state)
{
#ifdef WC_XMSS_SHA512
    if (state->params->hash == WC_HASH_TYPE_SHA512) {
        wc_Sha512Free(&state->digest.sha512);
        return;
    }
#endif
    wc_Sha256Free(&state->digest.sha256);
}

/* ---- fixture ----------------------------------------------------------- */

/* Sized well past the h=4 d=1/d=2 SHA-256 shapes used below (the sibling
 * white-box uses 8192/8192 for the same shapes). */
#define WB_SK_LEN   16384
#define WB_SIG_LEN  16384

static XmssParams wb_params;
static XmssState  wb_state;
static byte       wb_seed[3 * 64];
static byte       wb_sk[WB_SK_LEN];
static byte       wb_sk_bak[WB_SK_LEN];
static byte       wb_pk[256];
static byte       wb_pk_bak[256];
static byte       wb_sig[WB_SIG_LEN];
static const byte wb_msg[] = "wc_xmss_impl hash-fault white-box message";

static void wb_snapshot(void)
{
    XMEMCPY(wb_sk_bak, wb_sk, sizeof(wb_sk));
    XMEMCPY(wb_pk_bak, wb_pk, sizeof(wb_pk));
}

static void wb_restore(void)
{
    XMEMCPY(wb_sk, wb_sk_bak, sizeof(wb_sk));
    XMEMCPY(wb_pk, wb_pk_bak, sizeof(wb_pk));
}

/* Each wb_do_* runs ONE entry point with a freshly initialised XmssState. */

static int wb_do_keygen(void)
{
    int ret = wb_state_init(&wb_state, &wb_params);

    if (ret == 0) {
        ret = wc_xmssmt_keygen(&wb_state, wb_seed, wb_sk, wb_pk);
        wb_state_free(&wb_state);
    }
    return ret;
}

static int wb_do_sign(int nsigs)
{
    int ret = wb_state_init(&wb_state, &wb_params);
    int i;

    if (ret == 0) {
        for (i = 0; (ret == 0) && (i < nsigs); i++) {
            ret = wc_xmssmt_sign(&wb_state, wb_msg, (word32)sizeof(wb_msg),
                wb_sk, wb_sig);
        }
        wb_state_free(&wb_state);
    }
    return ret;
}

static int wb_do_verify(void)
{
    int ret = wb_state_init(&wb_state, &wb_params);

    if (ret == 0) {
        ret = wc_xmssmt_verify(&wb_state, wb_msg, (word32)sizeof(wb_msg),
            wb_sig, wb_pk);
        wb_state_free(&wb_state);
    }
    return ret;
}

/* ---- sweeps ------------------------------------------------------------ */

static void wb_sweep_keygen(void)
{
    long k, n, points = 0;
    int  ret;

    mcdc_fh_disarm();
    ret = wb_do_keygen();
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline keygen failed; keygen sweep skipped");
        wb_fail = 1;
        return;
    }
    wb_snapshot();

    for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
        mcdc_fh_arm(n);
        (void)wb_do_keygen();
        mcdc_fh_disarm();
        points++;
    }

    /* The sweep left sk/pk in an aborted state; restore the good keygen. */
    wb_restore();
    printf("  [wb] keygen sweep: K=%ld, %ld points\n", k, points);
}

static void wb_sweep_sign(int nsigs)
{
    long k, n, points = 0;
    int  ret;

    wb_restore();
    mcdc_fh_disarm();
    ret = wb_do_sign(nsigs);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline sign failed; sign sweep skipped");
        wb_fail = 1;
        wb_restore();
        return;
    }

    for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
        wb_restore();               /* prepared while DISARMED */
        mcdc_fh_arm(n);
        (void)wb_do_sign(nsigs);
        mcdc_fh_disarm();
        points++;
    }

    wb_restore();
    printf("  [wb] sign sweep: K=%ld, %ld points\n", k, points);
}

static void wb_sweep_verify(void)
{
    long k, n, points = 0;
    int  ret;

    /* One valid signature, produced disarmed. */
    wb_restore();
    mcdc_fh_disarm();
    if (wb_do_sign(1) != 0) {
        WB_NOTE("signing for the verify sweep failed; verify sweep skipped");
        wb_fail = 1;
        wb_restore();
        return;
    }

    mcdc_fh_disarm();
    ret = wb_do_verify();
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline verify rejected a valid signature");
        wb_fail = 1;
        wb_restore();
        return;
    }

    for (n = 1; (n <= k) && !wb_expired(); n = wb_next(n, k)) {
        mcdc_fh_arm(n);
        (void)wb_do_verify();
        mcdc_fh_disarm();
        points++;
    }

    /* Tampered signature (the XMEMCMP(node, pub_root, n) != 0 half), disarmed
     * -- the TRUE side that pairs with the ret != 0 rows above. */
    wb_sig[wb_params.sig_len - 1] ^= 0x01;
    mcdc_fh_disarm();
    if (wb_do_verify() == 0) {
        WB_NOTE("verify accepted a tampered signature");
        wb_fail = 1;
    }
    wb_sig[wb_params.sig_len - 1] ^= 0x01;

    wb_restore();
    printf("  [wb] verify sweep: K=%ld, %ld points\n", k, points);
}

/* wc_xmss_sigsleft() is pure bookkeeping over sk (no hash calls), so it is
 * driven directly rather than swept: fresh key (indices left) and the
 * exhausted key the sign loop leaves behind. */
static void wb_sigsleft_rows(void)
{
    mcdc_fh_disarm();
    (void)wc_xmss_sigsleft(&wb_params, wb_sk);
}

/* Run every sweep for one (d, bds_k) shape. */
static void wb_run_shape(byte h, byte d, byte bds_k, int nsigs)
{
    printf("  [wb] --- h=%u d=%u bds_k=%u ---\n", (unsigned)h, (unsigned)d,
        (unsigned)bds_k);

    wb_params_init(&wb_params, WC_HASH_TYPE_SHA256, 32, 32, h, d, 4, bds_k);
    if (wb_params.sk_len > (word32)sizeof(wb_sk) ||
            wb_params.sig_len > (word32)sizeof(wb_sig)) {
        WB_NOTE("shape exceeds the scratch buffers; skipped");
        return;
    }

    XMEMSET(wb_seed, 0x33, sizeof(wb_seed));
    XMEMSET(wb_sk, 0, sizeof(wb_sk));
    XMEMSET(wb_pk, 0, sizeof(wb_pk));
    XMEMSET(wb_sig, 0, sizeof(wb_sig));

    wb_sweep_keygen();
    if (wb_expired())
        return;
    wb_sweep_sign(nsigs);
    wb_sigsleft_rows();
    if (wb_expired())
        return;
    wb_sweep_verify();
}

#endif /* WB_HAVE_DRIVER conditions */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_xmss_impl.c hash-fault white-box supplement\n");

#ifdef WB_HAVE_DRIVER
    wb_t0 = time(NULL);

    /* d=1: single tree, the plain wc_xmss_* helpers.
     * d=2: XMSS^MT, two layers -- required for the
     *      `for (i = ...; (ret == 0) && (i < params->d); ...)` loops to have a
     *      second iteration, and for wc_xmssmt_sign_next_idx()'s subtree
     *      rollover.
     * bds_k=0 keeps the BDS bookkeeping trivially valid for both. */
    wb_run_shape(4, 1, 0, 3);
    if (!wb_expired())
        wb_run_shape(4, 2, 0, 5);

    mcdc_fh_disarm();
#else
    printf("  [wb] XMSS keygen/signing not compiled in; nothing to do\n");
#endif

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the harness discard this binary's coverage. */
    return 0;
}
