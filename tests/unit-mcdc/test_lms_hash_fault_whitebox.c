/* test_lms_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/wc_lms_impl.c.
 *
 * WHAT IS LEFT AFTER THE OTHER TWO LMS WHITE-BOXES
 * ------------------------------------------------
 * campaign/reports/lms/GAPS.md is dominated by ONE shape inside
 * wc_lms_impl.c's WOTS / Merkle / HSS engine:
 *
 *     for (i = 0;    (ret == 0) && (i < params->p); i++) ...
 *     for (j = a[i]; (ret == 0) && (j < max);       j++) ...
 *     while (         (ret == 0) && ((j & 0x1) == 1))    ...
 *     if (            (ret == 0) && (auth_path != NULL) && ...) ...
 *
 * The (ret == 0) operand only ever goes FALSE when an earlier step failed
 * *inside the same operation*. wc_lms_impl.c performs ZERO allocations
 * (grep XMALLOC: none), so mcdc_fault_alloc.h -- the campaign's usual lever --
 * has nothing to fault here: `ret` in this file comes exclusively from
 * wc_Sha256HashBlock / wc_Sha256Update / wc_Sha256Final (and the SHAKE
 * equivalents). test_wc_lms_impl_whitebox_gap.c already closed everything that
 * a bad *argument* can reach (it uses an invalid Winternitz width to make the
 * very first step fail); what remains needs the chain broken at an arbitrary
 * DEPTH -- mid-loop, mid-tree, mid-subtree -- which only a failing hash
 * primitive can do.
 *
 * TECHNIQUE
 * ---------
 * mcdc_fault_hash.h interposes the SHA-256/SHAKE primitives by macro, for this
 * translation unit only, before wc_lms_impl.c is #included (the generalised
 * form of test_tsp_fault_whitebox.c's XGMTIME mock). mcdc_fh_arm(n) makes the
 * n-th primitive call -- and every later one -- return BAD_FUNC_ARG, exactly
 * mirroring mcdc_fa_arm()'s semantics.
 *
 * Each of the four engine entry points (make_key / sign / verify / reload) is
 * swept SEPARATELY, with its inputs always prepared while DISARMED:
 *
 *   1. run it once disarmed          -> the all-true baseline row for every
 *                                       guard, in THIS binary (HARD RULE 1),
 *                                       and mcdc_fh_seen() gives the sweep
 *                                       length K for that entry point;
 *   2. sweep n over [1..K]           -> for each n exactly one interior step
 *                                       fails, so the (ret == 0) operand is
 *                                       driven false at every decision the
 *                                       operation would have reached after
 *                                       that point.
 *
 * K is tens of thousands of hash calls for a real keygen, so the sweep is
 * dense over the first WB_DENSE indices (the entry-guard chains) and then
 * strided to a fixed budget of WB_POINTS points (the deep loops). Restoring
 * the private-key state for the sign sweep is a memcpy of the priv_raw /
 * priv_data / HssPrivKey snapshot rather than a fresh keygen -- HssPrivKey's
 * internal pointers all point into the SAME priv_data buffer, whose address
 * never changes, so the snapshot restores exactly. The public key is part of
 * the snapshot too: a faulted make_key leaves wb_pub half-written, and the
 * verify sweep needs the good one back.
 *
 * NEVER HANG (HARD RULE 2): every sweep is bounded by both a point budget and
 * a CPU-time deadline (WB_DEADLINE_S). The parameter set is the smallest that
 * still exercises the HSS multi-level machinery: levels=2, height=2 (16
 * signatures total, subtree rollover after 4), Winternitz w=8, SHA-256/32.
 * WOLFSSL_LMS_MAX_LEVELS is pinned to 2 by this module's campaign config, so
 * levels=2 is the maximum available.
 *
 * VARIANT COVERAGE (HARD RULE 3): WOLFSSL_LMS_VERIFY_ONLY compiles keygen and
 * signing out entirely, and no valid signature can be produced without them,
 * so that whole variant is a skip stub. WOLFSSL_WC_LMS_SMALL keeps every entry
 * point but drops LmsParams::rootLevels/cacheBits, which are assigned under an
 * #ifndef. main() always returns 0.
 */

#include "mcdc_fault_hash.h"

/* wc_lms_impl.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_lms_impl.c>

#include <stdio.h>
#include <string.h>
#include <time.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY) && \
    !defined(WOLFSSL_NO_LMS_SHA256_256)

#define WB_HAVE_DRIVER 1

/* Winternitz w=8, wb=3 for every family: LMS_V = 2, so ls = 0 and
 * p = 8*hash_len/8 + 2 = hash_len + 2 (LMS_U/LMS_V/LMS_P live in wc_lms.c,
 * which this TU does not include, so they are hand-expanded here). */
#define WB_WIDTH    8U
#define WB_LS       0U
#define WB_P_OF(hLen)   ((word16)((hLen) + 2U))

/* Largest hash length / p over all compiled families: sizes every fixed
 * buffer below. */
#define WB_HLEN_MAX WC_SHA256_DIGEST_SIZE   /* 32 */
#define WB_P_MAX    34U

/* Tree shapes. Kept tiny: keygen is 2^height WOTS keys per subtree per level
 * and each WOTS key is p * 255 hash calls, so height is the whole runtime
 * budget. Shape A is the smallest with more than one HSS level and a subtree
 * rollover; shape B raises rootLevels above 1 so wc_lms_treehash_init/update's
 * `h > height - rootLevels` guards can be true. */
#define WB_HEIGHT_MAX 3U
#define WB_LEVELS_MAX 2U

typedef struct WbShape {
    word8 levels;
    word8 height;
    word8 rootLevels;
    word8 cacheBits;
    int   nsigs;        /* one past the first subtree rollover (2^height) */
} WbShape;

static const WbShape wb_shapes[] = {
    { 2, 2, 1, 1,  6 },
    { 2, 3, 2, 2, 10 },
};

/* Hash families compiled into this variant. wc_lms_impl.c dispatches on
 * LMS_IS_SHAKE(lmOtsType) and on (lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192,
 * and each arm has its OWN copy of the WOTS/Merkle error chains -- so every
 * compiled family has to be swept or its arm's residuals stay open. */
typedef struct WbFamily {
    const char* name;
    word16      lmsType;
    word16      lmOtsType;
    word16      hash_len;
} WbFamily;

static const WbFamily wb_families[] = {
    { "sha256_256", LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8,
      WC_SHA256_DIGEST_SIZE },
#ifdef WOLFSSL_LMS_SHA256_192
    { "sha256_192", LMS_SHA256_M24_H5, LMOTS_SHA256_N24_W8, 24 },
#endif
#ifdef WOLFSSL_LMS_SHAKE256
    { "shake256_256", LMS_SHAKE_M32_H5, LMOTS_SHAKE_N32_W8,
      WC_SHA256_DIGEST_SIZE },
#endif
};
#define WB_NFAMILIES (sizeof(wb_families) / sizeof(wb_families[0]))
#define WB_NSHAPES   (sizeof(wb_shapes) / sizeof(wb_shapes[0]))

/* Sweep budget. WB_DENSE leading indices are visited one by one (the
 * entry-guard chains live there); the rest of [1..K] is covered by a stride
 * chosen so the total never exceeds WB_POINTS. */
#define WB_DENSE    48
#define WB_POINTS   192
/* Hard CPU-time ceiling for the whole program, well under the campaign's
 * 600 s TEST_TIMEOUT even with variants running concurrently and even in the
 * (much slower) WOLFSSL_WC_LMS_SMALL recompute build. Every sweep tests it, so
 * the program degrades to fewer points rather than being killed -- a killed
 * white-box is scored as a SILENT SKIP and loses the whole file. */
#define WB_DEADLINE_S  170

/* WALL clock, not clock(): the campaign runs several variants concurrently and
 * TEST_TIMEOUT is 600 s of WALL time. Under that contention CPU time accrues
 * far slower than wall time, so a CPU-time budget would sail past the timeout
 * -- and a timed-out white-box is scored as a SILENT SKIP that loses the whole
 * file's coverage. */
static time_t wb_t0;

static int wb_expired(void)
{
    return difftime(time(NULL), wb_t0) > (double)WB_DEADLINE_S;
}

/* Build a self-consistent LmsParams by hand (this file never goes through
 * wc_lms.c, so the values need only be internally consistent). */
static void wb_make_params(LmsParams* params, const WbFamily* fam,
    const WbShape* shape)
{
    XMEMSET(params, 0, sizeof(*params));
    params->levels    = shape->levels;
    params->height    = shape->height;
    params->width     = (word8)WB_WIDTH;
    params->ls        = (word8)WB_LS;
    params->p         = WB_P_OF(fam->hash_len);
    params->lmsType   = fam->lmsType;
    params->lmOtsType = fam->lmOtsType;
    params->hash_len  = fam->hash_len;
    params->sig_len   = 4U +
        (word32)shape->levels *
            LMS_SIG_LEN(shape->height, params->p, params->hash_len) +
        (word32)(shape->levels - 1U) * LMS_PUBKEY_LEN(params->hash_len);
#ifndef WOLFSSL_WC_LMS_SMALL
    params->rootLevels = shape->rootLevels;
    params->cacheBits  = shape->cacheBits;
#endif
}

/* Mirrors wc_lmskey_state_init() / _free() in wc_lms.c (static in another TU;
 * this file never includes wc_lms.c). wc_InitShake256 / wc_InitSha256 are NOT
 * interposed by mcdc_fault_hash.h, so test setup can never be faulted. */
static int wb_state_init(LmsState* state, const LmsParams* params)
{
    int ret;

    XMEMSET(state, 0, sizeof(*state));
    state->params = params;

#ifdef WOLFSSL_LMS_SHAKE256
    if (LMS_IS_SHAKE(params->lmOtsType)) {
        ret = wc_InitShake256(LMS_STATE_SHAKE(state), NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_InitShake256(LMS_STATE_SHAKE_K(state), NULL,
                INVALID_DEVID);
            if (ret != 0) {
                wc_Shake256_Free(LMS_STATE_SHAKE(state));
            }
        }
        return ret;
    }
#endif

    ret = wc_InitSha256(LMS_STATE_HASH(state));
    if (ret == 0) {
        ret = wc_InitSha256(LMS_STATE_HASH_K(state));
        if (ret != 0) {
            wc_Sha256Free(LMS_STATE_HASH(state));
        }
    }
    return ret;
}

static void wb_state_free(LmsState* state)
{
#ifdef WOLFSSL_LMS_SHAKE256
    if (LMS_IS_SHAKE(state->params->lmOtsType)) {
        wc_Shake256_Free(LMS_STATE_SHAKE_K(state));
        wc_Shake256_Free(LMS_STATE_SHAKE(state));
        return;
    }
#endif
    wc_Sha256Free(LMS_STATE_HASH_K(state));
    wc_Sha256Free(LMS_STATE_HASH(state));
}

/* ---- shared fixture ---------------------------------------------------- */

static LmsParams  wb_params;
static WC_RNG     wb_rng;
static HssPrivKey wb_pk;
static HssPrivKey wb_pk_bak;
static byte       wb_priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN_MAX)];
static byte       wb_priv_raw_bak[HSS_PRIVATE_KEY_LEN(WB_HLEN_MAX)];
static byte       wb_pub[HSS_PUBLIC_KEY_LEN(WB_HLEN_MAX)];
static byte       wb_pub_bak[HSS_PUBLIC_KEY_LEN(WB_HLEN_MAX)];
static byte       wb_sig[4U + WB_LEVELS_MAX *
                             LMS_SIG_LEN(WB_HEIGHT_MAX, WB_P_MAX, WB_HLEN_MAX)
                        + (WB_LEVELS_MAX - 1U) * LMS_PUBKEY_LEN(WB_HLEN_MAX)];
static int        wb_nsigs = 1;
static byte*      wb_priv_data     = NULL;
static byte*      wb_priv_data_bak = NULL;
static word32     wb_priv_data_len = 0;
static word32     wb_priv_data_cap = 0;
static const byte wb_msg[] = "wc_lms_impl hash-fault white-box message";

/* Snapshot / restore the whole signing state. HssPrivKey's internal pointers
 * address wb_priv_data, whose location never changes, so a byte-wise restore
 * is exact. */
static void wb_snapshot(void)
{
    XMEMCPY(wb_priv_raw_bak, wb_priv_raw, sizeof(wb_priv_raw));
    XMEMCPY(wb_pub_bak, wb_pub, sizeof(wb_pub));
    XMEMCPY(&wb_pk_bak, &wb_pk, sizeof(wb_pk));
    if (wb_priv_data_bak != NULL)
        XMEMCPY(wb_priv_data_bak, wb_priv_data, wb_priv_data_len);
}

static void wb_restore(void)
{
    XMEMCPY(wb_priv_raw, wb_priv_raw_bak, sizeof(wb_priv_raw));
    XMEMCPY(wb_pub, wb_pub_bak, sizeof(wb_pub));
    XMEMCPY(&wb_pk, &wb_pk_bak, sizeof(wb_pk));
    if (wb_priv_data_bak != NULL)
        XMEMCPY(wb_priv_data, wb_priv_data_bak, wb_priv_data_len);
}

/* Next sweep index after n, for a sweep of length k. */
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

/* ---- the four swept operations ----------------------------------------- */

/* Each wb_do_* runs ONE engine entry point with a freshly initialised
 * LmsState and returns its result. The caller arms/disarms around it. */

static int wb_do_make_key(void)
{
    LmsState state;
    int ret = wb_state_init(&state, &wb_params);

    if (ret == 0) {
        ret = wc_hss_make_key(&state, &wb_rng, wb_priv_raw, &wb_pk,
            wb_priv_data, wb_pub);
        wb_state_free(&state);
    }
    return ret;
}

static int wb_do_sign(int nsigs)
{
    LmsState state;
    int ret = wb_state_init(&state, &wb_params);
    int i;

    if (ret == 0) {
        for (i = 0; (ret == 0) && (i < nsigs); i++) {
            ret = wc_hss_sign(&state, wb_priv_raw, &wb_pk, wb_priv_data,
                wb_msg, (word32)sizeof(wb_msg), wb_sig);
        }
        wb_state_free(&state);
    }
    return ret;
}

static int wb_do_verify(void)
{
    LmsState state;
    int ret = wb_state_init(&state, &wb_params);

    if (ret == 0) {
        ret = wc_hss_verify(&state, wb_pub, wb_msg, (word32)sizeof(wb_msg),
            wb_sig, wb_params.sig_len);
        wb_state_free(&state);
    }
    return ret;
}

static int wb_do_reload(void)
{
    LmsState state;
    int ret = wb_state_init(&state, &wb_params);

    if (ret == 0) {
        ret = wc_hss_reload_key(&state, wb_priv_raw, &wb_pk, wb_priv_data,
            wb_pub + LMS_L_LEN + LMS_TYPE_LEN + LMS_TYPE_LEN + LMS_I_LEN);
        wb_state_free(&state);
    }
    return ret;
}

/* ---- sweeps ------------------------------------------------------------ */

static void wb_sweep_make_key(void)
{
    long k, n;
    int  ret;
    long points = 0;

    /* Baseline (disarmed): the TRUE half of every guard, plus the length. */
    mcdc_fh_disarm();
    ret = wb_do_make_key();
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline wc_hss_make_key failed; make_key sweep skipped");
        wb_fail = 1;
        return;
    }
    wb_snapshot();

    for (n = 1; n <= k; n = wb_next(n, k)) {
        mcdc_fh_arm(n);
        (void)wb_do_make_key();
        mcdc_fh_disarm();
        points++;
        if (wb_expired())
            break;
    }

    /* The sweep left priv_raw/priv_key/pub in an aborted state; put the
     * known-good keygen output back for the sign/verify sweeps. */
    wb_restore();
    printf("  [wb] make_key sweep: K=%ld, %ld points\n", k, points);
}

static void wb_sweep_sign(void)
{
    long k, n;
    int  ret;
    long points = 0;

    /* Baseline: WB_NSIGS signatures from the snapshot state. */
    wb_restore();
    mcdc_fh_disarm();
    ret = wb_do_sign(wb_nsigs);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline wc_hss_sign failed; sign sweep skipped");
        wb_fail = 1;
        wb_restore();
        return;
    }

    for (n = 1; n <= k; n = wb_next(n, k)) {
        wb_restore();           /* prepared while DISARMED */
        mcdc_fh_arm(n);
        (void)wb_do_sign(wb_nsigs);
        mcdc_fh_disarm();
        points++;
        if (wb_expired())
            break;
    }

    wb_restore();
    printf("  [wb] sign sweep: K=%ld, %ld points\n", k, points);
}

static void wb_sweep_verify(void)
{
    long k, n;
    int  ret;
    long points = 0;

    /* One valid signature, produced disarmed. */
    wb_restore();
    mcdc_fh_disarm();
    ret = wb_do_sign(1);
    if (ret != 0) {
        WB_NOTE("signing for the verify sweep failed; verify sweep skipped");
        wb_fail = 1;
        wb_restore();
        return;
    }

    mcdc_fh_disarm();
    ret = wb_do_verify();
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline wc_hss_verify rejected a valid signature");
        wb_fail = 1;
        wb_restore();
        return;
    }

    for (n = 1; n <= k; n = wb_next(n, k)) {
        mcdc_fh_arm(n);
        (void)wb_do_verify();
        mcdc_fh_disarm();
        points++;
        if (wb_expired())
            break;
    }

    /* Corrupted-signature verify (the XMEMCMP != 0 half), disarmed. */
    wb_sig[wb_params.sig_len - 1] ^= 0xFF;
    mcdc_fh_disarm();
    ret = wb_do_verify();
    if (ret == 0) {
        WB_NOTE("wc_hss_verify accepted a corrupted signature");
        wb_fail = 1;
    }
    wb_sig[wb_params.sig_len - 1] ^= 0xFF;

    wb_restore();
    printf("  [wb] verify sweep: K=%ld, %ld points\n", k, points);
}

static void wb_sweep_reload(void)
{
    long k, n;
    int  ret;
    long points = 0;

    wb_restore();
    mcdc_fh_disarm();
    ret = wb_do_reload();
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline wc_hss_reload_key failed; reload sweep skipped");
        wb_fail = 1;
        wb_restore();
        return;
    }

    for (n = 1; n <= k; n = wb_next(n, k)) {
        wb_restore();
        mcdc_fh_arm(n);
        (void)wb_do_reload();
        mcdc_fh_disarm();
        points++;
        if (wb_expired())
            break;
    }

    wb_restore();
    printf("  [wb] reload sweep: K=%ld, %ld points\n", k, points);
}

/* Run all four sweeps for one (family, shape) pair. */
static void wb_run_combo(const WbFamily* fam, const WbShape* shape)
{
    printf("  [wb] --- family %s, l=%u h=%u rl=%u cb=%u ---\n", fam->name,
        (unsigned)shape->levels, (unsigned)shape->height,
        (unsigned)shape->rootLevels, (unsigned)shape->cacheBits);

    wb_make_params(&wb_params, fam, shape);
    wb_nsigs = shape->nsigs;

    /* priv_data is sized once for the largest combo; only the prefix this
     * combo needs is used, and both the live and backup buffers keep the same
     * address, so the HssPrivKey snapshot stays valid. */
    wb_priv_data_len = LMS_PRIV_DATA_LEN(wb_params.levels, wb_params.height,
        wb_params.p, shape->rootLevels, shape->cacheBits, wb_params.hash_len);
    if (wb_priv_data_len > wb_priv_data_cap)
        wb_priv_data_len = wb_priv_data_cap;

    XMEMSET(wb_priv_raw, 0, sizeof(wb_priv_raw));
    XMEMSET(wb_pub, 0, sizeof(wb_pub));
    XMEMSET(wb_sig, 0, sizeof(wb_sig));
    XMEMSET(&wb_pk, 0, sizeof(wb_pk));
    XMEMSET(wb_priv_data, 0, wb_priv_data_cap);

    wb_sweep_make_key();
    if (wb_expired())
        return;
    wb_sweep_sign();
    if (wb_expired())
        return;
    wb_sweep_verify();
    if (wb_expired())
        return;
    wb_sweep_reload();
}

#endif /* WB_HAVE_DRIVER conditions */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_lms_impl.c hash-fault white-box supplement\n");

#ifdef WB_HAVE_DRIVER
    wb_t0 = time(NULL);

    /* Worst case over every (family, shape): largest hash_len, p, levels,
     * height, rootLevels and cacheBits used by the tables above. */
    wb_priv_data_cap = LMS_PRIV_DATA_LEN(WB_LEVELS_MAX, WB_HEIGHT_MAX,
        WB_P_MAX, WB_HEIGHT_MAX, WB_HEIGHT_MAX, WB_HLEN_MAX);
    wb_priv_data     = (byte*)XMALLOC(wb_priv_data_cap, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    wb_priv_data_bak = (byte*)XMALLOC(wb_priv_data_cap, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);

    if ((wb_priv_data == NULL) || (wb_priv_data_bak == NULL)) {
        WB_NOTE("XMALLOC of priv_data failed; nothing driven");
    }
    else if (wc_InitRng(&wb_rng) != 0) {
        WB_NOTE("wc_InitRng failed; nothing driven");
    }
    else {
        size_t f, sh;

        /* Every compiled hash family gets its own sweep: wc_lms_impl.c keeps a
         * SEPARATE copy of the WOTS/Merkle error chains per family arm. Shape
         * 0 is run for every family; the taller shape 1 (rootLevels > 1) only
         * for the first, to stay inside the time budget -- its extra decisions
         * are family-independent. */
        for (f = 0; f < WB_NFAMILIES; f++) {
            for (sh = 0; sh < WB_NSHAPES; sh++) {
                if ((sh > 0) && (f > 0))
                    continue;
                if (wb_expired()) {
                    WB_NOTE("time budget reached; remaining combos skipped");
                    break;
                }
                wb_run_combo(&wb_families[f], &wb_shapes[sh]);
            }
        }

        mcdc_fh_disarm();
        wc_FreeRng(&wb_rng);
    }

    XFREE(wb_priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(wb_priv_data_bak, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    printf("  [wb] LMS keygen/signing not compiled in; nothing to do\n");
#endif

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Setup/skip conditions are notes, not process failures: a non-zero exit
     * makes the campaign discard this binary's whole coverage. */
    return 0;
}
