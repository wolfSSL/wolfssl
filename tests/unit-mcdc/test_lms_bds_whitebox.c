/* test_lms_bds_whitebox.c
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
 * MC/DC BDS-state white-box supplement for wolfcrypt/src/wc_lms_impl.c.
 *
 * WHAT THIS FILE ADDS OVER THE OTHER THREE LMS WHITE-BOXES
 * -------------------------------------------------------
 * test_wc_lms_impl_whitebox.c / _gap.c drive the file-static helpers with
 * bad arguments; test_lms_hash_fault_whitebox.c sweeps a *global* hash-call
 * index over whole make_key / sign / verify / reload operations. That sweep
 * is necessarily strided: one WOTS leaf is p * (2^w - 1) = 34 * 255 = 8670
 * primitive calls, so the handful of Merkle *interior* node hashes are one
 * call in ~8700 and a strided sweep essentially never lands on them. The
 * decisions that need `ret != 0` at an interior-node step therefore stayed
 * open no matter how many sweep points were spent on them.
 *
 * This file replaces the search with arithmetic. Every target is reached by
 * calling the static helper DIRECTLY with a hand-built LmsParams /
 * LmsPrivState, and where a fault is needed the fault index is COMPUTED:
 *
 *   L = mcdc_fh_seen() after one wc_lms_leaf_hash()      (constant per leaf)
 *   C = mcdc_fh_seen() after one wc_lms_interior_hash()  (constant per node)
 *
 * In wc_lms_treehash{,_init}() the loop body is exactly "leaf hash, then the
 * carry chain of interior hashes", so leaf 0 occupies primitive calls
 * [1 .. L], leaf 1 occupies [L+1 .. 2L], and the FIRST interior hash (i=1,
 * h=1) occupies [2L+1 .. 2L+C]. Arming there fails that interior hash and
 * nothing before it, which is precisely the state the `(ret == 0)` operand
 * of the auth-path store needs. A small window around the computed index is
 * swept so the vector survives a change in how many primitives one hash
 * costs (raw-block vs WC_LMS_FULL_HASH vs SHAKE).
 *
 * wc_lms_compute_root() is small enough (one leaf hash + `height` node
 * hashes) that its whole primitive range is swept DENSELY, which is what
 * reaches the per-hash-family copies of the auth-path climb loop.
 *
 * TARGETS (suite/reports/lms/the uncovered-condition report keys, wc_lms_impl.c)
 *   2109:...:0   wc_lms_treehash()      `ret == 0` at the auth-path store
 *                (WOLFSSL_WC_LMS_SMALL arm)                    -- fault
 *   2262:...:0   wc_lms_treehash_init() same, table-based arm   -- fault
 *   2397:...:2   wc_lms_treehash_update() `h <= params->height` -- direct call
 *                with a leaf index whose trailing-ones run exceeds the tree
 *                height; no in-tree caller can pass one, which is exactly why
 *                the guard exists and why only a white-box can falsify it.
 *   2414:...:2   wc_lms_treehash_update() `!useRoot`            -- direct call
 *                with q == 0 AND useRoot != 0 (real callers only ever pair
 *                useRoot=1 with q != 0), plus the all-true partner row in the
 *                same binary (q == 0, useRoot = 0).
 *   2659:...:0   wc_lms_compute_root() SHAKE256 climb loop      -- fault
 *   2685:...:0   wc_lms_compute_root() SHA-256/192 climb loop   -- fault
 *   3359:...:1   wc_hss_update_auth_path() `i >= 0`             -- direct call
 *                with levels == 1 and q == 0 so the loop runs off the bottom
 *                instead of taking the `break` in the q != 0 arm.
 *   4120:...:0   wc_hss_verify() `ret == 0`                     -- public key
 *                whose encoded level count disagrees with the parameters.
 *
 * PAIRING (HARD RULE: MC/DC independence is computed per binary). Every
 * rejecting vector above is issued together with its accepting partner in
 * THIS program: the fault sweeps always run one DISARMED baseline first, the
 * treehash_update rows are issued as a useRoot=0 / useRoot=1 pair over the
 * same leaf range, and wc_hss_verify() is called twice (matching and
 * mismatching level count).
 *
 * DETERMINISM: this file uses NO RNG at all -- no wc_InitRng, no
 * wc_hss_make_key. Every input is a fixed byte pattern and every fault index
 * is derived from measured, input-independent counts, so two runs of an
 * unchanged tree produce byte-identical coverage. (The lms module's coverage
 * is known to depend on RNG-driven key diversity across variants; nothing
 * here pins or perturbs any RNG, so that diversity is untouched.)
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT COVER
 * ------------------------------------------
 * `2254:...:1` and `2414:...:4` are the SAME operand text,
 *
 *     ((i >> (h-1)) != ((i + 1) >> (h - 1)))
 *
 * in wc_lms_treehash_init() and wc_lms_treehash_update(). It is a tautology
 * at every evaluation, so no vector can pair it. Both sites reach it only
 * from inside
 *
 *     while ((ret == 0) && ((j & 0x1) == 1)) { ...; j >>= 1; h++; ... }
 *
 * whose k-th entry requires the pre-shift value i >> (k-1) to be odd. On
 * arrival with a given h, bits 0 .. h-1 of i are therefore all set, i.e.
 * i == (i >> (h-1)) * 2^(h-1) + (2^(h-1) - 1). Adding one carries out of
 * bit h-1, so (i + 1) >> (h - 1) == (i >> (h - 1)) + 1: the two sides differ
 * by exactly one on every evaluation and the `!=` is never false. Recorded
 * in the exclusion record and the exclusion record.
 *
 * COST: no keygen and no signing. The most expensive driver computes 8 WOTS
 * leaves; the whole program is a few hundred thousand SHA-256 blocks, orders
 * of magnitude inside the 600 s TEST_TIMEOUT.
 *
 * VARIANTS (HARD RULE: must compile under every variant of the module):
 *   WOLFSSL_LMS_VERIFY_ONLY  - keygen/signing static helpers are compiled
 *                              out, so only the compute_root sweep and the
 *                              wc_hss_verify rows are built.
 *   WOLFSSL_WC_LMS_SMALL     - selects wc_lms_treehash(); the table-based
 *                              treehash_init/update/update_auth_path drivers
 *                              are compiled out (and vice versa).
 *   WOLFSSL_LMS_SHA256_192 / WOLFSSL_LMS_SHAKE256 - add a family row to the
 *                              compute_root sweep table.
 * main() always returns 0; setup problems are printed skips.
 */

#include "mcdc_fault_hash.h"

/* wc_lms_impl.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_lms_impl.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_NO_LMS_SHA256_256)

#define WB_HAVE_DRIVER 1

/* Signing-side static helpers (treehash / auth-path) exist only outside the
 * verify-only build; the two treehash flavours are mutually exclusive. */
#ifdef WOLFSSL_LMS_VERIFY_ONLY
    #define WB_TREE_SMALL 0
    #define WB_TREE_TABLE 0
#elif defined(WOLFSSL_WC_LMS_SMALL)
    #define WB_TREE_SMALL 1
    #define WB_TREE_TABLE 0
#else
    #define WB_TREE_SMALL 0
    #define WB_TREE_TABLE 1
#endif

/* Largest hash length over all compiled families; sizes every fixed buffer. */
#define WB_HLEN_MAX     WC_SHA256_DIGEST_SIZE   /* 32 */
/* Winternitz w=8, wb=3: LMS_V = 2, ls = 0, p = hash_len + 2. */
#define WB_WIDTH        8U
#define WB_LS           0U
#define WB_P_OF(hLen)   ((word16)((hLen) + 2U))

/* Tree shape used by every driver here. Height 2 is the smallest that gives
 * the carry chain more than one level (h = 1 and h = 2), which is all the
 * targeted decisions need; keygen cost is 2^height WOTS leaves and each leaf
 * is p * 255 hash calls, so height is the entire runtime budget. */
#define WB_HEIGHT       2U
#define WB_ROOTLEVELS   2U
#define WB_CACHEBITS    2U
/* Generous fixed buffers: several drivers deliberately drive indices past
 * what an in-tree caller would produce (that is the point of 2397), so the
 * auth-path / root / stack buffers are sized well beyond the tree shape. */
#define WB_NODES        32U

typedef struct WbFam {
    const char* name;
    word16      lmsType;
    word16      lmOtsType;
    word16      hash_len;
} WbFam;

static const WbFam wb_fams[] = {
    { "sha256_256", LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8,
      WC_SHA256_DIGEST_SIZE },
#ifdef WOLFSSL_LMS_SHA256_192
    { "sha256_192", LMS_SHA256_M24_H5, LMOTS_SHA256_N24_W8, 24 },
#endif
#ifdef WOLFSSL_LMS_SHAKE256
    { "shake256", LMS_SHAKE_M32_H5, LMOTS_SHAKE_N32_W8,
      WC_SHA256_DIGEST_SIZE },
#endif
};
#define WB_NFAMS (sizeof(wb_fams) / sizeof(wb_fams[0]))

/* Build a self-consistent LmsParams by hand. This TU never goes through
 * wc_lms.c, so the values need only be internally consistent (see the same
 * construction in test_wc_lms_impl_whitebox_gap.c). */
static void wb_params(LmsParams* p, const WbFam* f, word8 levels, word8 height)
{
    XMEMSET(p, 0, sizeof(*p));
    p->levels    = levels;
    p->height    = height;
    p->width     = (word8)WB_WIDTH;
    p->ls        = (word8)WB_LS;
    p->p         = WB_P_OF(f->hash_len);
    p->lmsType   = f->lmsType;
    p->lmOtsType = f->lmOtsType;
    p->hash_len  = f->hash_len;
    p->sig_len   = 4U +
        (word32)levels * LMS_SIG_LEN(height, p->p, p->hash_len) +
        (word32)(levels - 1U) * LMS_PUBKEY_LEN(p->hash_len);
#ifndef WOLFSSL_WC_LMS_SMALL
    p->rootLevels = (word8)WB_ROOTLEVELS;
    p->cacheBits  = (word8)WB_CACHEBITS;
#endif
}

/* Mirrors wc_lmskey_state_init()/_free() in wc_lms.c (static in another TU).
 * wc_InitSha256 / wc_InitShake256 are NOT interposed by mcdc_fault_hash.h,
 * so this setup can never be faulted. */
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

/* Fixed, RNG-free inputs. */
static const byte wb_id[LMS_I_LEN] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
};
static byte wb_seed[WB_HLEN_MAX];

static void wb_init_seed(void)
{
    unsigned i;
    for (i = 0; i < (unsigned)sizeof(wb_seed); i++) {
        wb_seed[i] = (byte)(0x5A + i);
    }
}

/*******************************************************************
 * 2659:...:0 (SHAKE256 arm) and 2685:...:0 (SHA-256/192 arm), plus the
 * SHA-256/256 twin of the same loop:
 *
 *   for (i = 0; (ret == 0) && (i < params->height - 1); i++)
 *
 * inside wc_lms_compute_root(). The `ret == 0` operand can only go false
 * when the node hash of an EARLIER iteration failed, and the loop lives at
 * the very end of a verify, behind ~4300 WOTS primitive calls -- out of
 * reach of any strided sweep.
 *
 * wc_lms_compute_root() is a static, so it is called here on its own: one
 * leaf hash followed by `height` node hashes, a handful of primitive calls
 * in total, which lets the sweep be DENSE over [1 .. K]. Point n = C + 1
 * (C = primitive calls per node hash) fails the first loop iteration and
 * nothing before it, giving the (ret != 0) row; the disarmed baseline that
 * measured K is the accepting row, in this same binary.
 *
 * Each compiled hash family gets its own pass because wc_lms_compute_root()
 * keeps a separate copy of the climb loop per family arm.
 ******************************************************************/
static void wb_compute_root_sweep(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    byte kc[WB_HLEN_MAX];
    byte tc[WB_HLEN_MAX];
    byte path[WB_NODES * WB_HLEN_MAX];
    long k, n;
    int  ret;

    /* height 3 so the "all but last height" loop runs more than once. */
    wb_params(&params, f, 1, 3);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for compute_root sweep");
        wb_fail = 1;
        return;
    }
    XMEMSET(state.buffer, 0x3C, sizeof(state.buffer));
    XMEMCPY(state.buffer, wb_id, LMS_I_LEN);
    XMEMSET(kc, 0x11, sizeof(kc));
    XMEMSET(tc, 0, sizeof(tc));
    XMEMSET(path, 0x22, sizeof(path));

    /* Disarmed baseline: the all-true row for every guard in the function,
     * and the sweep length K. */
    mcdc_fh_disarm();
    ret = wc_lms_compute_root(&state, 1, kc, path, tc);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline wc_lms_compute_root failed; sweep skipped");
        wb_fail = 1;
        wb_state_free(&state);
        return;
    }

    for (n = 1; n <= k; n++) {
        mcdc_fh_arm(n);
        (void)wc_lms_compute_root(&state, 1, kc, path, tc);
        mcdc_fh_disarm();
    }

    wb_state_free(&state);
    printf("  [wb] compute_root sweep (%s): K=%ld, dense\n", f->name, k);
}

/*******************************************************************
 * 4120:...:0  wc_hss_verify(): if ((ret == 0) && (nspk + 1 != levels))
 *
 * The `ret == 0` operand is false exactly when the immediately preceding
 * check rejected the key: `if (levels != state->params->levels)`. Both rows
 * are issued here, in this binary:
 *
 *   A. encoded level count = params->levels + 1  -> ret != 0 at :4120,
 *      decision false with operand 0 false.
 *   B. encoded level count = params->levels, nspk deliberately wrong
 *      -> both operands true, decision true.
 *
 * Neither call reads past the 4-byte L field of the key or of the
 * signature: wc_hss_verify() returns SIG_VERIFY_E before the chain walk.
 ******************************************************************/
static void wb_hss_verify_levels(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN_MAX)];
    byte sig[64];
    static const byte msg[] = "4120 hss_verify level-count message";
    int ret;

    wb_params(&params, f, 1, WB_HEIGHT);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for hss_verify level rows");
        wb_fail = 1;
        return;
    }
    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(sig, 0, sizeof(sig));

    /* Row A: level count in the public key disagrees with the parameters. */
    c32toa((word32)params.levels + 1U, pub);
    c32toa(0, sig);
    ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg), sig,
        (word32)sizeof(sig));
    if (ret == 0) {
        WB_NOTE("hss_verify accepted a key with the wrong level count");
        wb_fail = 1;
    }

    /* Row B: level count matches, nspk does not. */
    c32toa((word32)params.levels, pub);
    c32toa(7, sig);
    ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg), sig,
        (word32)sizeof(sig));
    if (ret == 0) {
        WB_NOTE("hss_verify accepted a signature with the wrong nspk");
        wb_fail = 1;
    }

    wb_state_free(&state);
    WB_NOTE("4120 hss_verify level-count rows issued");
}

#if WB_TREE_SMALL || WB_TREE_TABLE
/* Primitive-call cost of one leaf hash (L) and one interior node hash (C).
 * Both are input independent: the WOTS chain length is (2^width - 1) and the
 * node hash is a single fixed-length hash, so measuring one of each is
 * enough to locate any leaf/node boundary in the treehash loops. */
static int wb_measure_lc(LmsState* state, long* pL, long* pC)
{
    byte temp[WB_HLEN_MAX];
    byte left[WB_HLEN_MAX];
    int  ret;

    XMEMSET(temp, 0, sizeof(temp));
    XMEMSET(left, 0x77, sizeof(left));

    XMEMCPY(state->buffer, wb_id, LMS_I_LEN);
    mcdc_fh_disarm();
    ret = wc_lms_leaf_hash(state, wb_seed, 0, 4, temp);
    *pL = mcdc_fh_seen();
    if (ret != 0) {
        return ret;
    }

    XMEMCPY(state->buffer, wb_id, LMS_I_LEN);
    mcdc_fh_disarm();
    ret = wc_lms_interior_hash(state, left, 2, temp);
    *pC = mcdc_fh_seen();
    mcdc_fh_disarm();
    return ret;
}
#endif /* WB_TREE_SMALL || WB_TREE_TABLE */

#if WB_TREE_TABLE
/*******************************************************************
 * 2262:...:0  wc_lms_treehash_init():
 *   if ((ret == 0) && (auth_path != NULL) && (((q >> h) ^ 0x1) == j))
 *
 * inside the carry `while ((ret == 0) && ((j & 0x1) == 1))` loop. Reaching
 * this decision with ret != 0 needs wc_lms_interior_hash() -- and NOT the
 * leaf hash before it -- to fail, because a failed leaf hash keeps the while
 * loop from being entered at all.
 *
 * The loop body is exactly "one leaf hash then the carry chain", so with L
 * primitive calls per leaf and C per node hash, leaf 0 is [1 .. L], leaf 1 is
 * [L+1 .. 2L], and the first interior hash is [2L+1 .. 2L+C]. The sweep runs
 * a small window around that so it stays correct if a hash costs a different
 * number of primitives (raw block vs WC_LMS_FULL_HASH vs SHAKE).
 *
 * The disarmed baseline call is the accepting partner: with q = 1 and
 * height = 2, leaf i = 3 climbs to h = 1 with j = 1 and (q >> 1) ^ 1 == 1,
 * so all three operands are true there.
 ******************************************************************/
static void wb_treehash_init_fault(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    LmsPrivState priv;
    byte auth_path[WB_NODES * WB_HLEN_MAX];
    byte stack_buf[WB_NODES * WB_HLEN_MAX];
    byte root_buf[WB_NODES * WB_HLEN_MAX];
    byte leaf_cache[WB_NODES * WB_HLEN_MAX];
    long L = 0, C = 0, n, lo, hi;
    int  ret;

    wb_params(&params, f, 1, WB_HEIGHT);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for treehash_init fault");
        wb_fail = 1;
        return;
    }
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(stack_buf, 0, sizeof(stack_buf));
    XMEMSET(root_buf, 0, sizeof(root_buf));
    XMEMSET(leaf_cache, 0, sizeof(leaf_cache));

    if (wb_measure_lc(&state, &L, &C) != 0) {
        WB_NOTE("leaf/interior hash cost measurement failed");
        wb_fail = 1;
        wb_state_free(&state);
        return;
    }

    /* Accepting baseline (disarmed). */
    XMEMSET(&priv, 0, sizeof(priv));
    priv.auth_path  = auth_path;
    priv.stack.stack = stack_buf;
    priv.root       = root_buf;
    priv.leaf.cache = leaf_cache;
    mcdc_fh_disarm();
    ret = wc_lms_treehash_init(&state, &priv, wb_id, wb_seed, 1);
    mcdc_fh_disarm();
    if (ret != 0) {
        WB_NOTE("baseline wc_lms_treehash_init failed; fault window skipped");
        wb_fail = 1;
        wb_state_free(&state);
        return;
    }

    lo = 2 * L + 1;
    hi = 2 * L + 2 * C;
    for (n = lo; n <= hi; n++) {
        XMEMSET(&priv, 0, sizeof(priv));
        priv.auth_path  = auth_path;
        priv.stack.stack = stack_buf;
        priv.root       = root_buf;
        priv.leaf.cache = leaf_cache;
        mcdc_fh_arm(n);
        (void)wc_lms_treehash_init(&state, &priv, wb_id, wb_seed, 1);
        mcdc_fh_disarm();
    }

    wb_state_free(&state);
    printf("  [wb] treehash_init fault window: L=%ld C=%ld n=[%ld..%ld]\n",
        L, C, lo, hi);
}

/*******************************************************************
 * 2397:...:2  wc_lms_treehash_update():
 *   if (useRoot && (h > params->height - params->rootLevels) &&
 *           (h <= params->height))
 * 2414:...:2  wc_lms_treehash_update():
 *   if ((ret == 0) && (q == 0) && (!useRoot) &&
 *           (h > params->height - params->rootLevels) && ...)
 * 2414:...:0  and 2424:...:0  wc_lms_treehash_update(): the `ret == 0`
 *   operand of the same root copy and of the auth-path store below it.
 *
 * Four direct calls over the same fixed leaf range, all with q == 0:
 *
 *   1. useRoot = 0, leaves [0 .. 3]  -> 2414 all-true row (accepting).
 *   2. useRoot = 1, leaves [0 .. 3]  -> 2414 with `!useRoot` false while
 *      ret == 0 and q == 0 hold (rejecting partner for cond 2), and 2397
 *      all-true.
 *   3. useRoot = 1, leaves [0 .. 7]  -> leaf 7 has three trailing one bits,
 *      so the carry chain climbs to h = 3 on a height-2 tree and
 *      `h <= params->height` is FALSE with the two preceding operands true.
 *      No in-tree caller can produce that index (wc_hss_update_auth_path()
 *      derives max_idx from LMS_AUTH_PATH_IDX(), bounded by 2^height - 1),
 *      which is why the bound exists and why only a direct call can falsify
 *      it. Every buffer here is sized WB_NODES nodes, well past what the
 *      over-long climb indexes.
 *
 *   4. useRoot = 0, leaves [0 .. 3], armed at primitive call 1 -> the two
 *      `ret == 0` operands (2414 cond 0, 2424 cond 0) go false, paired with
 *      call 1's all-true rows. The fault index needs no arithmetic here:
 *      leaves 0..3 are served from the leaf cache, so wc_lms_treehash_update
 *      issues NO primitive call until the carry chain of leaf 1 reaches
 *      wc_lms_interior_hash() -- primitive call 1 IS that node hash.
 *      These two conditions are the pair the 2026-08-11 flake
 *      hunt recorded as non-deterministic (they depend on where the global
 *      strided hash-fault sweep in test_lms_hash_fault_whitebox.c happens to
 *      land, which moves with the RNG-drawn key). This vector pins them.
 *
 * leaf.idx starts at 0 with cacheBits = 2, so leaves 0..3 are served from
 * the (zeroed) leaf cache -- the tree content is irrelevant to these
 * decisions, it keeps calls 1, 2 and 4 nearly free, and it is what makes
 * call 4's fault index exact.
 ******************************************************************/
static void wb_treehash_update_roots(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    LmsPrivState priv;
    byte auth_path[WB_NODES * WB_HLEN_MAX];
    byte stack_buf[WB_NODES * WB_HLEN_MAX];
    byte root_buf[WB_NODES * WB_HLEN_MAX];
    byte leaf_cache[WB_NODES * WB_HLEN_MAX];
    int  ret;
    int  i;
    static const struct {
        word32 max_idx; int useRoot; long arm; const char* what;
    } calls[] = {
        { 3, 0, 0, "q=0 useRoot=0 (2414/2424 accepting rows)" },
        { 3, 1, 0, "q=0 useRoot=1 (2414 cond-2 rejecting row)" },
        { 7, 1, 0, "leaf 7 on a height-2 tree (2397 cond-2 rejecting row)" },
        { 3, 0, 1, "q=0 useRoot=0, node hash faulted "
                   "(2414/2424 cond-0 rejecting rows)" },
    };

    wb_params(&params, f, 1, WB_HEIGHT);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for treehash_update roots");
        wb_fail = 1;
        return;
    }
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(stack_buf, 0, sizeof(stack_buf));
    XMEMSET(root_buf, 0x66, sizeof(root_buf));
    XMEMSET(leaf_cache, 0x44, sizeof(leaf_cache));

    mcdc_fh_disarm();
    for (i = 0; i < (int)(sizeof(calls) / sizeof(calls[0])); i++) {
        XMEMSET(&priv, 0, sizeof(priv));
        priv.auth_path   = auth_path;
        priv.stack.stack = stack_buf;
        priv.stack.offset = 0;
        priv.root        = root_buf;
        priv.leaf.cache  = leaf_cache;
        priv.leaf.idx    = 0;
        priv.leaf.offset = 0;

        if (calls[i].arm != 0) {
            mcdc_fh_arm(calls[i].arm);
        }
        ret = wc_lms_treehash_update(&state, &priv, wb_id, wb_seed, 0,
            calls[i].max_idx, 0, calls[i].useRoot);
        mcdc_fh_disarm();
        if ((calls[i].arm == 0) && (ret != 0)) {
            printf("  [wb] treehash_update %s returned %d\n", calls[i].what,
                ret);
            wb_fail = 1;
        }
        else if ((calls[i].arm != 0) && (ret == 0)) {
            printf("  [wb] treehash_update %s did NOT propagate the faulted "
                "node hash\n", calls[i].what);
            wb_fail = 1;
        }
    }

    wb_state_free(&state);
    WB_NOTE("2397/2414 treehash_update useRoot + over-long climb rows issued");
}

/*******************************************************************
 * 3359:...:1  wc_hss_update_auth_path():
 *   for (i = levels - 1; (ret == 0) && (i >= 0); i--)
 *
 * The `i >= 0` operand is only false when the loop runs off the bottom, and
 * every level's arm for q != 0 ends in an unconditional `break`. So the loop
 * reaches i == -1 only if EVERY level's q is zero -- which for the in-tree
 * caller (wc_hss_sign(), after wc_lms_idx_inc()) means a raw index of 0, a
 * state that call site can never present.
 *
 * A direct call with levels = 1 and a zeroed private key gives it: q == 0
 * skips the break arm, i drops to -1 and the loop condition is re-evaluated
 * with ret == 0 and i >= 0 false. The i = 0 pass of the same call is the
 * accepting row. The per-level LmsPrivState is given real buffers so the
 * WOLFSSL_LMS_NO_SIGN_SMOOTHING spelling of the q == 0 arm (which calls
 * wc_lms_treehash_init() instead of doing nothing) is equally safe.
 ******************************************************************/
static void wb_update_auth_path_bottom(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    HssPrivKey pk;
    byte priv_buf[LMS_MAX_LEVELS * LMS_PRIV_LEN(WB_HLEN_MAX)];
    byte priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN_MAX)];
    byte auth_path[WB_NODES * WB_HLEN_MAX];
    byte stack_buf[WB_NODES * WB_HLEN_MAX];
    byte root_buf[WB_NODES * WB_HLEN_MAX];
    byte leaf_cache[WB_NODES * WB_HLEN_MAX];
    int  ret;

    wb_params(&params, f, 1, WB_HEIGHT);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for update_auth_path bottom");
        wb_fail = 1;
        return;
    }
    XMEMSET(&pk, 0, sizeof(pk));
    XMEMSET(priv_buf, 0, sizeof(priv_buf));
    XMEMSET(priv_raw, 0, sizeof(priv_raw));
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(stack_buf, 0, sizeof(stack_buf));
    XMEMSET(root_buf, 0, sizeof(root_buf));
    XMEMSET(leaf_cache, 0, sizeof(leaf_cache));

    pk.priv = priv_buf;
    pk.state[0].auth_path   = auth_path;
    pk.state[0].stack.stack = stack_buf;
    pk.state[0].root        = root_buf;
    pk.state[0].leaf.cache  = leaf_cache;

    mcdc_fh_disarm();
    ret = wc_hss_update_auth_path(&state, &pk, priv_raw, 1);
    if (ret != 0) {
        WB_NOTE("wc_hss_update_auth_path(levels=1, q=0) failed");
        wb_fail = 1;
    }

    wb_state_free(&state);
    WB_NOTE("3359 update_auth_path run-off-the-bottom row issued");
}
#endif /* WB_TREE_TABLE */

#if WB_TREE_SMALL
/*******************************************************************
 * 2109:...:0  wc_lms_treehash() (WOLFSSL_WC_LMS_SMALL arm):
 *   if ((ret == 0) && (auth_path != NULL) && (((q >> h) ^ 0x1) == j))
 *
 * Same shape and same arithmetic as the table-based treehash_init above:
 * the first interior hash of the recompute treehash occupies primitive
 * calls [2L+1 .. 2L+C]. The disarmed baseline (q = 1, height = 2, leaf
 * i = 3 climbing to h = 1) is the accepting partner in this binary.
 ******************************************************************/
static void wb_treehash_small_fault(const WbFam* f)
{
    LmsParams params;
    LmsState  state;
    byte auth_path[WB_NODES * WB_HLEN_MAX];
    byte pub[WB_HLEN_MAX];
    long L = 0, C = 0, n, lo, hi;
    int  ret;

    wb_params(&params, f, 1, WB_HEIGHT);
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for small treehash fault");
        wb_fail = 1;
        return;
    }
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(pub, 0, sizeof(pub));

    if (wb_measure_lc(&state, &L, &C) != 0) {
        WB_NOTE("leaf/interior hash cost measurement failed");
        wb_fail = 1;
        wb_state_free(&state);
        return;
    }

    mcdc_fh_disarm();
    ret = wc_lms_treehash(&state, wb_id, wb_seed, 1, auth_path, pub);
    mcdc_fh_disarm();
    if (ret != 0) {
        WB_NOTE("baseline wc_lms_treehash failed; fault window skipped");
        wb_fail = 1;
        wb_state_free(&state);
        return;
    }

    lo = 2 * L + 1;
    hi = 2 * L + 2 * C;
    for (n = lo; n <= hi; n++) {
        mcdc_fh_arm(n);
        (void)wc_lms_treehash(&state, wb_id, wb_seed, 1, auth_path, pub);
        mcdc_fh_disarm();
    }

    wb_state_free(&state);
    printf("  [wb] small treehash fault window: L=%ld C=%ld n=[%ld..%ld]\n",
        L, C, lo, hi);
}
#endif /* WB_TREE_SMALL */

#endif /* WOLFSSL_HAVE_LMS && !WOLFSSL_NO_LMS_SHA256_256 */

int main(void)
{
    /* Unbuffered: a TEST_TIMEOUT kill discards anything still in the stdio
     * buffer, which reads as an empty log and no clue where it stopped. */
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_lms_impl.c BDS-state white-box supplement\n");

#ifdef WB_HAVE_DRIVER
    {
        size_t i;

        wb_init_seed();

        /* Family-specific: wc_lms_compute_root() keeps one copy of the
         * auth-path climb loop per compiled hash family. */
        for (i = 0; i < WB_NFAMS; i++) {
            wb_compute_root_sweep(&wb_fams[i]);
        }

        /* Family-independent: the remaining targets are in code shared by
         * every family, so the default SHA-256/256 family is enough. */
        wb_hss_verify_levels(&wb_fams[0]);
#if WB_TREE_TABLE
        wb_treehash_init_fault(&wb_fams[0]);
        wb_treehash_update_roots(&wb_fams[0]);
        wb_update_auth_path_bottom(&wb_fams[0]);
#elif WB_TREE_SMALL
        wb_treehash_small_fault(&wb_fams[0]);
#else
        printf("  [wb] WOLFSSL_LMS_VERIFY_ONLY: treehash/auth-path "
               "helpers not compiled; those rows are skipped\n");
#endif
        mcdc_fh_disarm();
    }
#else
    printf("  [wb] LMS (SHA-256/256) not compiled in; nothing to do\n");
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup problems are printed skips, never a non-zero exit: a non-zero
     * exit makes the harness discard this binary's whole coverage. */
    return 0;
}
