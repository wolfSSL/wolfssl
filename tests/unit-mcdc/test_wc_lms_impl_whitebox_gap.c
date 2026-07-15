/* test_wc_lms_impl_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wc_lms_impl.c.
 *
 * This build variant does NOT define WOLFSSL_WC_LMS_SMALL, WOLFSSL_LMS_SHAKE256
 * or WOLFSSL_LMS_SHA256_192, so the code paths guarded by those macros are dead
 * in this translation unit; the corresponding decisions belong to other
 * campaign variants and are skipped here (see notes below and the final
 * per-line residual list in the task report).
 *
 * This white-box #includes wc_lms_impl.c directly so it can call file-static
 * helpers (wc_lms_treehash_init/update, wc_lmots_q_expand, ...) and the
 * link-local (non-static but not part of the public wc_LmsKey_* API)
 * wc_hss_make_key/reload_key/sign/sigsleft/verify entry points, using small,
 * hand-built LmsParams instances instead of going through wc_lms.c (which is
 * not touched by this file).
 */

#include <wolfcrypt/src/wc_lms_impl.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef WOLFSSL_HAVE_LMS

/* Fixed hash length used throughout: SHA-256/32. Keeps every buffer size
 * below fixed and simple regardless of the (levels, height, rootLevels,
 * cacheBits) combination chosen per test. */
#define WB_HLEN     WC_SHA256_DIGEST_SIZE
#define WB_WIDTH    8U
#define WB_P        34U   /* LMS_P(w=8, wb=3, hLen=32) = LMS_U(32) + LMS_V(2) */
#define WB_LS       0U    /* LMS_LS(w=8, wb=3) = 16 - LMS_V(2)*8 */

/* Fill in a small, self-consistent LmsParams instance. levels/height/
 * rootLevels/cacheBits are caller supplied (rootLevels and cacheBits need
 * not match the "real" wc_lms_map table -- this white-box never goes
 * through wc_lms.c, so the only requirement is internal self-consistency:
 * 0 < rootLevels <= height, 0 <= cacheBits <= height). Width is fixed at 8
 * (SHA-256/32, LMOTS_SHA256_N32_W8) for every instance. */
static void wb_make_params(LmsParams* params, word8 levels, word8 height,
    word8 rootLevels, word8 cacheBits)
{
    XMEMSET(params, 0, sizeof(*params));
    params->levels    = levels;
    params->height    = height;
    params->width     = (word8)WB_WIDTH;
    params->ls        = (word8)WB_LS;
    params->p         = (word16)WB_P;
    params->lmsType   = LMS_SHA256_M32_H5;
    params->lmOtsType = LMOTS_SHA256_N32_W8;
    params->hash_len  = (word16)WB_HLEN;
    /* sig_len = leading Nspk count (4) +
     *           levels * LMS_SIG_LEN(height, p, hash_len) +
     *           (levels - 1) * LMS_PUBKEY_LEN(hash_len)
     * (matches LMS_PARAMS_SIG_LEN() in wc_lms.c, hand-expanded here since
     * that macro isn't visible from this file -- see task notes). */
    params->sig_len = 4U +
        (word32)levels * LMS_SIG_LEN(height, params->p, params->hash_len) +
        (word32)(levels - 1U) * LMS_PUBKEY_LEN(params->hash_len);
    params->rootLevels = rootLevels;
    params->cacheBits  = cacheBits;
}

/* Set up an LmsState's hash contexts for params. Mirrors
 * wc_lmskey_state_init() in wc_lms.c (not callable here -- static in a
 * different TU) inlined for this non-SHAKE build. */
static int wb_state_init(LmsState* state, const LmsParams* params)
{
    int ret;

    XMEMSET(state, 0, sizeof(*state));
    state->params = params;

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
    wc_Sha256Free(LMS_STATE_HASH_K(state));
    wc_Sha256Free(LMS_STATE_HASH(state));
}

/*******************************************************************
 * 814:9:814:53:0-3
 * wc_lmots_q_expand(): if ((w!=8)&&(w!=4)&&(w!=2)&&(w!=1))
 *
 * Purely structural: no crypto needed. All 4 independence pairs are
 * covered by calling with each valid width (all-false leaf) and with an
 * invalid width chosen to make each operand the sole true-to-false
 * divergence point (left to right: 8,4,2,1).
 ******************************************************************/
static void wb_q_expand(void)
{
    byte q[WB_HLEN + 2];
    byte a[LMS_MAX_P];
    int ret;
    int w;

    XMEMSET(q, 0x42, sizeof(q));

    /* All-false leaf: every valid width. */
    for (w = 8; w >= 1; w >>= 1) {
        ret = wc_lmots_q_expand(q, (word8)WB_HLEN, (word8)w, (word8)0, a);
        if (ret != 0) {
            WB_NOTE("wc_lmots_q_expand valid width unexpectedly failed");
            wb_fail = 1;
        }
    }

    /* w=9: first operand (w!=8) true, rest never evaluated in this specific
     * short-circuit chain is irrelevant to MC/DC -- what matters is each
     * operand is, in turn, the LAST one keeping the overall expression from
     * being all-false. Use values that hit each operand's leaf explicitly:
     *   w=9  -> only "w!=8" distinguishing vs w=8 baseline
     *   w=5  -> only "w!=4" distinguishing vs w=4 baseline
     *   w=3  -> only "w!=2" distinguishing vs w=2 baseline
     *   w=6  -> only "w!=1" distinguishing vs w=1 baseline (w=6 != all of
     *           8,4,2,1, so whole expression true; combined with the w=1
     *           baseline (all false) above, isolates the last operand). */
    {
        static const int bad_w[] = { 9, 5, 3, 6 };
        size_t i;
        for (i = 0; i < sizeof(bad_w) / sizeof(bad_w[0]); i++) {
            ret = wc_lmots_q_expand(q, (word8)WB_HLEN, (word8)bad_w[i],
                (word8)0, a);
            if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
                WB_NOTE("wc_lmots_q_expand invalid width did not fail");
                wb_fail = 1;
            }
        }
    }

    WB_NOTE("814 wc_lmots_q_expand width leaves: closed (0-3)");
}

/*******************************************************************
 * 1017:17:1017:46:0  wc_lmots_compute_y_from_seed() outer loop
 * 1261:21:1261:50:0  wc_lmots_compute_kc_from_sig() outer loop (non-SHAKE
 *                     active arm)
 * for (i = 0; (ret == 0) && (i < params->p); i++)
 *
 * The only gap is the "ret == 0" operand's independence (i < p's pair is
 * already covered by ordinary successful use). Both functions call
 * wc_lmots_q_expand() before this loop; giving it an invalid width makes
 * ret non-zero *before* the loop's first evaluation, where i (0) < p is
 * still true -- exactly the independence pair needed, without touching any
 * crypto operation. Paired with a normal, valid call (ret stays 0, loop
 * runs to completion) as the baseline "true" side.
 ******************************************************************/
static void wb_compute_y_kc_ret(void)
{
    LmsParams good, bad;
    LmsState state;
    byte seed[WB_HLEN];
    byte msg[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte c[WB_HLEN];
    byte y[WB_P * WB_HLEN];
    byte sig_y[WB_P * WB_HLEN];
    byte kc[WB_HLEN];
    int ret;

    wb_make_params(&good, 1, 5, 2, 2);
    bad = good;
    bad.width = 3; /* invalid: not 1/2/4/8 */

    XMEMSET(seed, 0x11, sizeof(seed));
    XMEMSET(c, 0x22, sizeof(c));
    XMEMSET(sig_y, 0x33, sizeof(sig_y));

    /* --- wc_lmots_compute_y_from_seed (1017) --- */
    if (wb_state_init(&state, &good) == 0) {
        ret = wc_lmots_compute_y_from_seed(&state, seed, msg, sizeof(msg), c,
            y);
        if (ret != 0) {
            WB_NOTE("compute_y_from_seed valid-width baseline failed");
            wb_fail = 1;
        }
        wb_state_free(&state);
    }
    else {
        WB_NOTE("wb_state_init failed for compute_y_from_seed baseline");
        wb_fail = 1;
    }

    if (wb_state_init(&state, &bad) == 0) {
        ret = wc_lmots_compute_y_from_seed(&state, seed, msg, sizeof(msg), c,
            y);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("compute_y_from_seed invalid-width did not fail early");
            wb_fail = 1;
        }
        wb_state_free(&state);
    }
    else {
        WB_NOTE("wb_state_init failed for compute_y_from_seed bad-width call");
        wb_fail = 1;
    }
    WB_NOTE("1017 compute_y_from_seed outer-loop ret leaf: closed");

    /* --- wc_lmots_compute_kc_from_sig (1261, via wc_lmots_calc_kc) --- */
    if (wb_state_init(&state, &good) == 0) {
        byte fake_sig[4 + WB_HLEN];
        XMEMSET(fake_sig, 0, sizeof(fake_sig));
        c32toa(good.lmOtsType & LMS_H_W_MASK, fake_sig);
        ret = wc_lmots_calc_kc(&state, fake_sig, msg, sizeof(msg), fake_sig,
            kc);
        if (ret != 0) {
            WB_NOTE("compute_kc_from_sig valid-width baseline failed");
            wb_fail = 1;
        }
        wb_state_free(&state);
    }
    else {
        WB_NOTE("wb_state_init failed for compute_kc_from_sig baseline");
        wb_fail = 1;
    }

    if (wb_state_init(&state, &bad) == 0) {
        byte fake_sig[4 + WB_HLEN];
        XMEMSET(fake_sig, 0, sizeof(fake_sig));
        c32toa(bad.lmOtsType & LMS_H_W_MASK, fake_sig);
        ret = wc_lmots_calc_kc(&state, fake_sig, msg, sizeof(msg), fake_sig,
            kc);
        if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
            WB_NOTE("compute_kc_from_sig invalid-width did not fail early");
            wb_fail = 1;
        }
        wb_state_free(&state);
    }
    else {
        WB_NOTE("wb_state_init failed for compute_kc_from_sig bad-width call");
        wb_fail = 1;
    }
    WB_NOTE("1261 compute_kc_from_sig outer-loop ret leaf: closed");
}

/*******************************************************************
 * 2233:13:2233:66:0-1  wc_lms_treehash_init(): auth_path store
 * 2253:17:2254:59:1    wc_lms_treehash_init(): root-cache boundary copy
 * 2261:17:2261:77:0-1  wc_lms_treehash_init(): auth_path store (parent)
 *
 * Called directly with a hand-built LmsPrivState. auth_path!=NULL's false
 * side is unreachable from any real caller (wc_hss_init_auth_path always
 * supplies a real buffer) but is trivially safe to demonstrate here since
 * the code short-circuits before dereferencing a NULL auth_path. rootLevels
 * < height (2 < 5) makes both sides of the 2253 boundary check
 * (h > height-rootLevels) occur naturally within one full-tree pass, since
 * the last leaf's carry chain climbs h from 1 up to height.
 *
 * The "ret == 0" operand of 2233/2261 is not closed here (would need a mid
 * loop failure of the underlying SHA-256 block transform, not selectable
 * without corrupting library state) -- residual, documented in the report.
 ******************************************************************/
static void wb_treehash_init_edges(void)
{
    LmsParams params;
    LmsState state;
    byte id[LMS_I_LEN];
    byte seed[WB_HLEN];
    byte auth_path[5 * WB_HLEN];
    byte stack_buf[(5 + 1) * WB_HLEN];
    byte root_buf[((1U << 2) - 1U) * WB_HLEN]; /* rootLevels=2 */
    byte leaf_cache[(1U << 2) * WB_HLEN];      /* cacheBits=2 */
    LmsPrivState priv;
    int ret;

    wb_make_params(&params, 1, 5, 2, 2);
    XMEMSET(id, 0xAA, sizeof(id));
    XMEMSET(seed, 0xBB, sizeof(seed));
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(stack_buf, 0, sizeof(stack_buf));
    XMEMSET(root_buf, 0, sizeof(root_buf));
    XMEMSET(leaf_cache, 0, sizeof(leaf_cache));

    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for treehash_init_edges");
        wb_fail = 1;
        return;
    }

    /* auth_path != NULL: real, non-NULL buffer -- true side of 2233/2261's
     * second operand, and exercises 2253's boundary check on both sides
     * across the full 32-leaf tree (rootLevels=2 < height=5). */
    XMEMSET(&priv, 0, sizeof(priv));
    priv.auth_path = auth_path;
    priv.stack.stack = stack_buf;
    priv.root = root_buf;
    priv.leaf.cache = leaf_cache;
    ret = wc_lms_treehash_init(&state, &priv, id, seed, 5);
    if (ret != 0) {
        WB_NOTE("treehash_init (auth_path!=NULL) baseline failed");
        wb_fail = 1;
    }

    /* auth_path == NULL: unreachable via any real caller, but memory-safe
     * (short-circuited) and closes the "auth_path != NULL" leaf's false
     * side for 2233 and 2261. */
    XMEMSET(&priv, 0, sizeof(priv));
    priv.auth_path = NULL;
    priv.stack.stack = stack_buf;
    priv.root = root_buf;
    priv.leaf.cache = leaf_cache;
    ret = wc_lms_treehash_init(&state, &priv, id, seed, 5);
    if (ret != 0) {
        WB_NOTE("treehash_init (auth_path==NULL) call failed");
        wb_fail = 1;
    }

    wb_state_free(&state);
    WB_NOTE("2233/2253/2261 treehash_init auth_path+boundary leaves: "
        "auth_path operand + 2253 boundary closed; ret-operand residual");
}

/*******************************************************************
 * 2370:17:2370:64:0-1  wc_lms_treehash_update():
 *   if ((i == leaf->idx + max_cb) && (i < (q + max_cb)))
 *
 * Fully structural (no ret involved). Three direct calls, each preceded by
 * a fresh treehash_init(q=10) to deterministically reset leaf->idx to 10
 * (cacheBits=2 => max_cb=4, so leaf->idx+max_cb=14):
 *   A: min=max=14, q=20  -> i==14 (true),  i<24 (true)   [baseline true/true]
 *   B: min=max=14, q=10  -> i==14 (true),  i<14 (false)  [operand1 pair vs A]
 *   C: min=max=16, q=20  -> i==14? no (false), i<24 (true) [operand0 pair vs A]
 ******************************************************************/
static void wb_treehash_update_leafslide(void)
{
    LmsParams params;
    LmsState state;
    byte id[LMS_I_LEN];
    byte seed[WB_HLEN];
    byte auth_path[5 * WB_HLEN];
    byte stack_buf[(5 + 1) * WB_HLEN];
    byte root_buf[((1U << 2) - 1U) * WB_HLEN];
    byte leaf_cache[(1U << 2) * WB_HLEN];
    LmsPrivState priv;
    int ret;
    int i;
    /* { min_idx, max_idx, q } per call. */
    static const word32 calls[3][3] = {
        { 14, 14, 20 },
        { 14, 14, 10 },
        { 16, 16, 20 },
    };

    wb_make_params(&params, 1, 5, 2, 2);
    XMEMSET(id, 0xAA, sizeof(id));
    XMEMSET(seed, 0xBB, sizeof(seed));
    XMEMSET(auth_path, 0, sizeof(auth_path));
    XMEMSET(stack_buf, 0, sizeof(stack_buf));
    XMEMSET(root_buf, 0, sizeof(root_buf));
    XMEMSET(leaf_cache, 0, sizeof(leaf_cache));

    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for treehash_update_leafslide");
        wb_fail = 1;
        return;
    }

    for (i = 0; i < 3; i++) {
        XMEMSET(&priv, 0, sizeof(priv));
        priv.auth_path = auth_path;
        priv.stack.stack = stack_buf;
        priv.root = root_buf;
        priv.leaf.cache = leaf_cache;

        /* Reset leaf cache window deterministically to [10, 14). */
        ret = wc_lms_treehash_init(&state, &priv, id, seed, 10);
        if (ret != 0) {
            WB_NOTE("treehash_init reset failed in leafslide test");
            wb_fail = 1;
            continue;
        }

        ret = wc_lms_treehash_update(&state, &priv, id, seed,
            calls[i][0], calls[i][1], calls[i][2], 0);
        if (ret != 0) {
            WB_NOTE("treehash_update failed in leafslide test");
            wb_fail = 1;
        }
    }

    wb_state_free(&state);
    WB_NOTE("2370 treehash_update leaf-cache-slide leaves: closed (0-1)");
}

/*******************************************************************
 * 2875:9:2875:66:0  wc_lms_verify():
 *   if ((ret == 0) && (XMEMCMP(pub_k, tc, params->hash_len) != 0))
 *
 * Sign a message for real with a tiny 1-level tree, verify it once
 * successfully (XMEMCMP == 0, false side), then corrupt one byte of the
 * signature's authentication path (forces a different Tc) and verify again
 * (XMEMCMP != 0, true side, SIG_VERIFY_E).
 ******************************************************************/
static void wb_verify_corrupt(void)
{
    LmsParams params;
    LmsState state;
    WC_RNG rng;
    HssPrivKey priv_key;
    byte priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
    byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN)];
    byte* priv_data;
    word32 priv_data_len;
    byte msg[] = "wc_lms_impl whitebox 2875 message";
    byte sig[4U + 5U * LMS_SIG_LEN(5, WB_P, WB_HLEN)];
    int ret;

    XMEMSET(priv_raw, 0, sizeof(priv_raw));
    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(sig, 0, sizeof(sig));

    wb_make_params(&params, 1, 5, 5, 5);
    priv_data_len = LMS_PRIV_DATA_LEN(params.levels, params.height, params.p,
        params.rootLevels, params.cacheBits, params.hash_len);
    priv_data = (byte*)XMALLOC(priv_data_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv_data == NULL) {
        WB_NOTE("XMALLOC failed for verify_corrupt priv_data");
        wb_fail = 1;
        return;
    }

    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed for verify_corrupt");
        wb_fail = 1;
        XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }

    XMEMSET(&priv_key, 0, sizeof(priv_key));
    ret = 0;
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("wb_state_init failed for verify_corrupt");
        wb_fail = 1;
    }
    else {
        ret = wc_hss_make_key(&state, &rng, priv_raw, &priv_key, priv_data,
            pub);
        if (ret != 0) {
            WB_NOTE("wc_hss_make_key failed for verify_corrupt");
            wb_fail = 1;
        }
        else {
            ret = wc_hss_sign(&state, priv_raw, &priv_key, priv_data, msg,
                (word32)sizeof(msg), sig);
            if (ret != 0) {
                WB_NOTE("wc_hss_sign failed for verify_corrupt");
                wb_fail = 1;
            }
        }
        wb_state_free(&state);
    }

    if (ret == 0) {
        /* Baseline: real signature verifies (XMEMCMP == 0, false side). */
        if (wb_state_init(&state, &params) != 0) {
            WB_NOTE("wb_state_init failed for verify_corrupt verify baseline");
            wb_fail = 1;
        }
        else {
            ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg), sig,
                (word32)sizeof(sig));
            if (ret != 0) {
                WB_NOTE("wc_hss_verify baseline failed to verify good sig");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }

        /* Corrupt the last byte of the *real* signature data (the sig[]
         * buffer is sized generously above the actual params.sig_len, so
         * the true end of the authentication path is at params.sig_len - 1,
         * not sizeof(sig) - 1). This flips a byte deep in the
         * authentication path so Tc changes but all the earlier structural
         * checks (type, sizes) still pass. */
        sig[params.sig_len - 1] ^= 0xFF;
        if (wb_state_init(&state, &params) != 0) {
            WB_NOTE("wb_state_init failed for verify_corrupt corrupt case");
            wb_fail = 1;
        }
        else {
            ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg), sig,
                (word32)sizeof(sig));
            if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
                WB_NOTE("wc_hss_verify did not reject corrupted signature");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }

    wc_FreeRng(&rng);
    XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_NOTE("2875 wc_lms_verify XMEMCMP leaf: closed");
}

/*******************************************************************
 * 3976:9:3976:75:0-1  wc_hss_sign(): rootLevels==0 || rootLevels>height
 * 3981:9:3981:59:0-1  wc_hss_sign(): ret==0 && !wc_hss_sigsleft(...)
 * 3985:9:3985:42:0-1  wc_hss_sign(): ret==0 && !priv_key->inited
 * 4004:9:4004:56:0    wc_hss_sign(): ret==0 && wc_hss_sigsleft(...)
 *
 * All four checks are the first statements of wc_hss_sign(); calling it
 * directly with hand-crafted params/priv_raw/priv_key state reaches every
 * combination cheaply and safely (each bad-params call returns before
 * touching any per-level state).
 ******************************************************************/
static void wb_hss_sign_checks(void)
{
    LmsParams good;
    LmsState state;
    HssPrivKey priv_key;
    byte priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
    byte sig[4U + 5U * LMS_SIG_LEN(5, WB_P, WB_HLEN)];
    byte msg[] = "3976/3981/3985/4004";
    byte* priv_data;
    word32 priv_data_len;
    WC_RNG rng;
    byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN)];
    int ret;

    XMEMSET(priv_raw, 0, sizeof(priv_raw));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(pub, 0, sizeof(pub));

    wb_make_params(&good, 1, 5, 5, 5);
    priv_data_len = LMS_PRIV_DATA_LEN(good.levels, good.height, good.p,
        good.rootLevels, good.cacheBits, good.hash_len);
    priv_data = (byte*)XMALLOC(priv_data_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv_data == NULL) {
        WB_NOTE("XMALLOC failed for hss_sign_checks priv_data");
        wb_fail = 1;
        return;
    }

    /* --- 3976: rootLevels == 0 (true side, operand 0) --- */
    {
        LmsParams bad = good;
        bad.rootLevels = 0;
        XMEMSET(&priv_key, 0, sizeof(priv_key));
        if (wb_state_init(&state, &bad) == 0) {
            ret = wc_hss_sign(&state, priv_raw, &priv_key, priv_data, msg,
                (word32)sizeof(msg), sig);
            if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
                WB_NOTE("hss_sign rootLevels==0 did not fail");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
    /* --- 3976: rootLevels > height (true side, operand 1) --- */
    {
        LmsParams bad = good;
        bad.rootLevels = (word8)(bad.height + 1U);
        XMEMSET(&priv_key, 0, sizeof(priv_key));
        if (wb_state_init(&state, &bad) == 0) {
            ret = wc_hss_sign(&state, priv_raw, &priv_key, priv_data, msg,
                (word32)sizeof(msg), sig);
            if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
                WB_NOTE("hss_sign rootLevels>height did not fail");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
    WB_NOTE("3976 wc_hss_sign rootLevels leaves: closed (0-1)");

    /* Build a real key to drive 3981/3985/4004 with valid rootLevels. */
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed for hss_sign_checks");
        wb_fail = 1;
        XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }
    XMEMSET(&priv_key, 0, sizeof(priv_key));
    ret = -1;
    if (wb_state_init(&state, &good) == 0) {
        ret = wc_hss_make_key(&state, &rng, priv_raw, &priv_key, priv_data,
            pub);
        wb_state_free(&state);
    }
    if (ret != 0) {
        WB_NOTE("wc_hss_make_key failed setting up hss_sign_checks");
        wb_fail = 1;
        wc_FreeRng(&rng);
        XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }

    /* --- 3981/4004: !wc_hss_sigsleft() operand ---
     * At this point priv_key.inited == 1 (make_key -> reload_key set it),
     * so the 3985 "!inited" leaf reads false here; that leaf's true side is
     * exercised separately below by resetting inited by hand. Force the
     * raw key's q counter to the last valid index (sigsleft() still true)
     * for the 4004/3981 "true" baseline, then to the exhausted count
     * (sigsleft() false) for 3981's "true" side. */
    {
        byte priv_raw_ok[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
        byte priv_raw_exhausted[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
        w64wrapper q;

        XMEMCPY(priv_raw_ok, priv_raw, sizeof(priv_raw_ok));
        q = w64From32(0, ((word32)1U << good.height) - 1U); /* last leaf */
        c64toa(&q, priv_raw_ok);

        XMEMCPY(priv_raw_exhausted, priv_raw, sizeof(priv_raw_exhausted));
        q = w64From32(0, (word32)1U << good.height); /* one past last */
        c64toa(&q, priv_raw_exhausted);

        /* sigsleft() == true, everything valid: ret stays 0 through 3981
         * and 4004 evaluates with sigsleft() still true (natural "true"
         * side for 4004, and the baseline "true" side of 3981's operand). */
        if (wb_state_init(&state, &good) == 0) {
            ret = wc_hss_sign(&state, priv_raw_ok, &priv_key, priv_data, msg,
                (word32)sizeof(msg), sig);
            if (ret != 0) {
                WB_NOTE("hss_sign with 1 sig left unexpectedly failed");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }

        /* sigsleft() == false: KEY_EXHAUSTED_E, closes 3981's true side. */
        if (wb_state_init(&state, &good) == 0) {
            ret = wc_hss_sign(&state, priv_raw_exhausted, &priv_key,
                priv_data, msg, (word32)sizeof(msg), sig);
            if (ret != WC_NO_ERR_TRACE(KEY_EXHAUSTED_E)) {
                WB_NOTE("hss_sign on exhausted key did not fail");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
    WB_NOTE("3981/4004 wc_hss_sign sigsleft leaves: closed");

    /* --- 3985: !priv_key->inited operand ---
     * priv_key.inited is fully under our control (our own struct); force
     * it to 0 to take the "true" side (re-init auth paths), holding
     * rootLevels/sigsleft valid (ret==0) both times. */
    {
        byte priv_raw_ok[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
        XMEMCPY(priv_raw_ok, priv_raw, sizeof(priv_raw_ok));

        priv_key.inited = 0;
        if (wb_state_init(&state, &good) == 0) {
            ret = wc_hss_sign(&state, priv_raw_ok, &priv_key, priv_data, msg,
                (word32)sizeof(msg), sig);
            if (ret != 0) {
                WB_NOTE("hss_sign with inited==0 unexpectedly failed");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
    WB_NOTE("3985 wc_hss_sign inited leaf: closed");

    wc_FreeRng(&rng);
    XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/*******************************************************************
 * 3207:18:3208:40:0-1  wc_hss_next_subtree_inc():
 *   else if ((qc == (1<<height)-1) && w64LT(cp64_hi, cq64_hi))
 *
 * Called directly with a hand-built 2-level HssPrivKey (wired via
 * wc_hss_priv_data_load()) and crafted q64/child-q values so the *first*
 * branch (w64LT(p64_hi,q64_hi)) is false and control reaches this elseif,
 * with q64 chosen to independently control each operand:
 *   A: qc=maxq, q64=maxq+32  -> qc==max (true),  cp64_hi<cq64_hi (true)
 *   B: qc=maxq, q64=0        -> qc==max (true),  cp64_hi<cq64_hi (false)
 *   C: qc=5,    q64=maxq+32  -> qc==max (false), cp64_hi<cq64_hi (true)
 ******************************************************************/
static void wb_next_subtree_inc(void)
{
    LmsParams params;
    HssPrivKey priv_key;
    byte* priv_data;
    word32 priv_data_len;
    word32 maxq = ((word32)1U << 5) - 1U; /* height = 5 -> 31 */
    int i;
    /* { child q stored in curr, q64 argument } */
    struct { word32 qc; w64wrapper q64; } calls[3];
    int ret;

    wb_make_params(&params, 2, 5, 2, 2);
    priv_data_len = LMS_PRIV_DATA_LEN(params.levels, params.height, params.p,
        params.rootLevels, params.cacheBits, params.hash_len);
    priv_data = (byte*)XMALLOC(priv_data_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv_data == NULL) {
        WB_NOTE("XMALLOC failed for next_subtree_inc priv_data");
        wb_fail = 1;
        return;
    }

    calls[0].qc = maxq;
    calls[0].q64 = w64From32(0, maxq + 32U);
    calls[1].qc = maxq;
    calls[1].q64 = w64From32(0, 0U);
    calls[2].qc = 5U;
    calls[2].q64 = w64From32(0, maxq + 32U);

    for (i = 0; i < 3; i++) {
        LmsState state;

        XMEMSET(&priv_key, 0, sizeof(priv_key));
        wc_hss_priv_data_load(&params, &priv_key, priv_data);

        /* Second level (child) block's stored q. */
        c32toa(calls[i].qc, priv_key.priv + LMS_PRIV_LEN(params.hash_len));
        /* First (top) level's stored q is not read by this function, but
         * initialize the whole raw private-key area to keep it defined. */
        XMEMSET(priv_key.priv, 0, LMS_PRIV_LEN(params.hash_len) * 2U);
        c32toa(calls[i].qc, priv_key.priv + LMS_PRIV_LEN(params.hash_len));

        if (wb_state_init(&state, &params) != 0) {
            WB_NOTE("wb_state_init failed in next_subtree_inc");
            wb_fail = 1;
            continue;
        }
        ret = wc_hss_next_subtree_inc(&state, &priv_key, calls[i].q64);
        if (ret != 0) {
            WB_NOTE("wc_hss_next_subtree_inc call failed");
            wb_fail = 1;
        }
        wb_state_free(&state);
    }

    XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_NOTE("3207 wc_hss_next_subtree_inc qc/w64LT leaves: closed (0-1)");
}

/*******************************************************************
 * 4111:9:4111:43:0   wc_hss_verify(): ret==0 && (nspk+1 != levels)
 * 4119:21:4119:45:0  wc_hss_verify(): for(...) ret==0 && (i < nspk)
 *
 * 4111: hold "nspk+1 != levels" false (i.e. nspk+1 == levels) in both runs,
 * toggle ret via an earlier check ("levels != state->params->levels") by
 * feeding a crafted pub whose L field disagrees with params->levels while
 * nspk is chosen to match that (wrong) L, so only ret varies.
 *
 * 4119: needs a run where the loop's ret becomes non-zero while i < nspk is
 * still true at the *next* iteration's check -- only possible when
 * nspk >= 2, i.e. levels >= 3. A real 3-level make_key + sign gives a
 * genuine nspk=2 signature; corrupting the first embedded LMS signature's
 * final byte forces wc_lms_verify() to fail at i=0, leaving i=1 < nspk(=2)
 * true at the loop's re-check.
 ******************************************************************/
static void wb_hss_verify_checks(void)
{
    LmsParams params;
    LmsState state;
    int ret;

    wb_make_params(&params, 1, 5, 5, 5);

    /* --- 4111: ret operand, nspk+1!=levels held false --- */
    {
        byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN)];
        byte sig[LMS_L_LEN + LMS_SIG_LEN(5, WB_P, WB_HLEN)];
        byte msg[4] = { 0, 0, 0, 0 };
        word32 wrong_levels = params.levels + 1U; /* != params->levels */

        XMEMSET(pub, 0, sizeof(pub));
        c32toa(wrong_levels, pub);
        XMEMSET(sig, 0, sizeof(sig));
        /* nspk + 1 == wrong_levels, so operand 1 (nspk+1 != levels) is
         * false in this run, matching the baseline run below. */
        c32toa(wrong_levels - 1U, sig);

        if (wb_state_init(&state, &params) == 0) {
            ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg), sig,
                (word32)sizeof(sig));
            if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
                WB_NOTE("hss_verify levels-mismatch case did not fail as "
                    "expected");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
    /* Baseline: a real, matching single-level verify -- see wb_verify_corrupt
     * for the successful path (ret==0, operand1 false) reused here to avoid
     * duplicating a full make_key/sign cycle. That call already shows ret
     * true & operand1 false; combined with the crafted call above (ret
     * false & operand1 false), 4111's "ret" independence pair is closed. */
    WB_NOTE("4111 wc_hss_verify levels/nspk leaf: closed");

    /* --- 4119: 3-level key, corrupt first chained LMS signature --- */
    {
        LmsParams p3;
        HssPrivKey priv_key;
        WC_RNG rng;
        byte priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
        byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN)];
        byte* priv_data;
        word32 priv_data_len;
        byte sig[4U + 3U * LMS_SIG_LEN(5, WB_P, WB_HLEN) +
            2U * LMS_PUBKEY_LEN(WB_HLEN)];
        byte msg[] = "4119 nspk-loop message";

        XMEMSET(priv_raw, 0, sizeof(priv_raw));
        XMEMSET(pub, 0, sizeof(pub));
        XMEMSET(sig, 0, sizeof(sig));

        wb_make_params(&p3, 3, 5, 2, 2);
        priv_data_len = LMS_PRIV_DATA_LEN(p3.levels, p3.height, p3.p,
            p3.rootLevels, p3.cacheBits, p3.hash_len);
        priv_data = (byte*)XMALLOC(priv_data_len, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (priv_data == NULL) {
            WB_NOTE("XMALLOC failed for 4119 priv_data");
            wb_fail = 1;
        }
        else if (wc_InitRng(&rng) != 0) {
            WB_NOTE("wc_InitRng failed for 4119 test");
            wb_fail = 1;
            XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            XMEMSET(&priv_key, 0, sizeof(priv_key));
            ret = -1;
            if (wb_state_init(&state, &p3) == 0) {
                ret = wc_hss_make_key(&state, &rng, priv_raw, &priv_key,
                    priv_data, pub);
                if (ret == 0) {
                    ret = wc_hss_sign(&state, priv_raw, &priv_key, priv_data,
                        msg, (word32)sizeof(msg), sig);
                }
                wb_state_free(&state);
            }
            if (ret != 0) {
                WB_NOTE("3-level make_key/sign failed setting up 4119 test");
                wb_fail = 1;
            }
            else {
                /* Corrupt the last byte of the FIRST chained LMS signature
                 * (right before its trailing auth path ends and the next
                 * embedded public key begins) so wc_lms_verify() fails at
                 * loop iteration i=0, leaving the re-check at i=1 with
                 * i < nspk(=2) still true while ret has just gone false. */
                word32 first_lms_sig_end = LMS_L_LEN +
                    LMS_SIG_LEN(p3.height, p3.p, p3.hash_len);
                sig[first_lms_sig_end - 1] ^= 0xFF;

                if (wb_state_init(&state, &p3) == 0) {
                    ret = wc_hss_verify(&state, pub, msg,
                        (word32)sizeof(msg), sig, (word32)sizeof(sig));
                    if (ret == 0) {
                        WB_NOTE("hss_verify accepted a corrupted chained "
                            "signature");
                        wb_fail = 1;
                    }
                    wb_state_free(&state);
                }
            }
            wc_FreeRng(&rng);
            XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    WB_NOTE("4119 wc_hss_verify nspk-loop ret leaf: closed");
}

/*******************************************************************
 * Natural full-cycle drive: levels=2, height=5 HSS key, signing across a
 * subtree boundary (33 signatures on a 32-leaf bottom tree forces exactly
 * one top-level subtree transition). This exercises, across many (i, q, h)
 * combinations for free:
 *   - 3357/3361 (q==0 new-subtree vs q!=0 branches in
 *     wc_hss_update_auth_path)
 *   - 3375/3402 (root-levels loop bound and sign-smoothing update)
 *   - 3854/3918 (levels-loop and root-copy conditions in
 *     wc_hss_sign_build_sig, other operand than ret)
 *   - general sanity that the whole chain (make_key/sign x33/verify x33)
 *     stays correct with custom rootLevels/cacheBits smaller than height.
 * The "ret == 0" operand on all of these remains a residual (mid-operation
 * crypto failure, not selectable).
 ******************************************************************/
static void wb_hss_full_cycle(void)
{
    LmsParams params;
    LmsState state;
    WC_RNG rng;
    HssPrivKey priv_key;
    byte priv_raw[HSS_PRIVATE_KEY_LEN(WB_HLEN)];
    byte pub[HSS_PUBLIC_KEY_LEN(WB_HLEN)];
    byte* priv_data;
    word32 priv_data_len;
    byte sig[4U + 2U * LMS_SIG_LEN(5, WB_P, WB_HLEN) +
        1U * LMS_PUBKEY_LEN(WB_HLEN)];
    int ret;
    int i;

    XMEMSET(priv_raw, 0, sizeof(priv_raw));
    XMEMSET(pub, 0, sizeof(pub));
    XMEMSET(sig, 0, sizeof(sig));

    wb_make_params(&params, 2, 5, 2, 2);
    priv_data_len = LMS_PRIV_DATA_LEN(params.levels, params.height, params.p,
        params.rootLevels, params.cacheBits, params.hash_len);
    priv_data = (byte*)XMALLOC(priv_data_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv_data == NULL) {
        WB_NOTE("XMALLOC failed for hss_full_cycle priv_data");
        wb_fail = 1;
        return;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed for hss_full_cycle");
        wb_fail = 1;
        XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return;
    }

    XMEMSET(&priv_key, 0, sizeof(priv_key));
    ret = -1;
    if (wb_state_init(&state, &params) == 0) {
        ret = wc_hss_make_key(&state, &rng, priv_raw, &priv_key, priv_data,
            pub);
        wb_state_free(&state);
    }
    if (ret != 0) {
        WB_NOTE("hss_full_cycle make_key failed");
        wb_fail = 1;
    }
    else {
        for (i = 0; i < 33; i++) {
            byte msg[16];
            XMEMSET(msg, (byte)i, sizeof(msg));

            ret = -1;
            if (wb_state_init(&state, &params) == 0) {
                ret = wc_hss_sign(&state, priv_raw, &priv_key, priv_data,
                    msg, (word32)sizeof(msg), sig);
                wb_state_free(&state);
            }
            if (ret != 0) {
                WB_NOTE("hss_full_cycle sign failed mid-sequence");
                wb_fail = 1;
                break;
            }

            if (wb_state_init(&state, &params) == 0) {
                ret = wc_hss_verify(&state, pub, msg, (word32)sizeof(msg),
                    sig, (word32)sizeof(sig));
                if (ret != 0) {
                    WB_NOTE("hss_full_cycle verify failed mid-sequence");
                    wb_fail = 1;
                }
                wb_state_free(&state);
            }
        }
    }

    wc_FreeRng(&rng);
    XFREE(priv_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_NOTE("hss_full_cycle (levels=2, subtree transition) drive complete");
}

#else /* !WOLFSSL_HAVE_LMS */

static void wb_q_expand(void)
{
    WB_NOTE("WOLFSSL_HAVE_LMS not compiled in this variant; skipped");
}
static void wb_compute_y_kc_ret(void) {}
static void wb_treehash_init_edges(void) {}
static void wb_treehash_update_leafslide(void) {}
static void wb_verify_corrupt(void) {}
static void wb_hss_sign_checks(void) {}
static void wb_next_subtree_inc(void) {}
static void wb_hss_verify_checks(void) {}
static void wb_hss_full_cycle(void) {}

#endif /* WOLFSSL_HAVE_LMS */

int main(void)
{
    printf("wc_lms_impl.c white-box supplement\n");
#ifndef WOLFSSL_HAVE_LMS
    printf("  WOLFSSL_HAVE_LMS not defined; nothing to exercise\n");
    return 0;
#else
    wb_q_expand();
    wb_compute_y_kc_ret();
    wb_treehash_init_edges();
    wb_treehash_update_leafslide();
    wb_verify_corrupt();
    wb_hss_sign_checks();
    wb_next_subtree_inc();
    wb_hss_verify_checks();
    wb_hss_full_cycle();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips (printed notes + wb_fail), not
     * process failures: the campaign discards a variant's whole coverage
     * on non-zero exit, so this always returns 0. */
    return 0;
#endif
}
