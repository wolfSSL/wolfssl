/* test_wc_xmss_impl_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wc_xmss_impl.c (the native XMSS /
 * XMSS^MT implementation - 51 file-static WOTS+ / L-tree / BDS helpers). This
 * TU #includes wc_xmss_impl.c verbatim so the static helpers are directly reachable,
 * and links against libwolfssl.a with wc_xmss_impl.o trimmed (wc_xmss.o kept).
 * The static helpers are exercised by driving a full public wc_XmssKey_* keygen /
 * multi-sign / verify roundtrip (which flows through this file's WOTS+ chain,
 * L-tree, tree-hash and BDS state helpers), once per compiled-in hash family,
 * for a single tree, a 2-layer XMSS^MT tree, and a tall (height-40, 8-layer)
 * XMSS^MT tree whose actual height > 32 drives the 64-bit tree-index runtime
 * path. Negative verifies flip the mismatch decision false-sides.
 *
 * MC/DC is per-binary, so both sides of each targeted decision are driven in
 * this one instrumented binary. Crash-safety: every key is XMEMSET to zero
 * before use and freed after; the in-memory secret-key scratch buffer is
 * sized for the tall parameter set and roundtrips that would exceed it are
 * skipped cleanly.
 *
 * What this file deliberately does NOT cover - both are in the
 * exclusion ledger (the exclusion record,
 * the exclusion record#condition-level-exclusions):
 *
 *   2465:2 and 4131:2 - the "c <= 4" operand of WC_IDX_INVALID's mixed
 *   32/64-bit arm, i.e. "((c > 4) && IDX64_INVALID(..)) || ((c <= 4) &&
 *   IDX32_INVALID(..))" with c = params->idx_len. It is the exact logical
 *   negation of the "c > 4" operand, which is evaluated on every arrival that
 *   gets past "ret == 0", so every vector that flips it flips "c > 4" too and
 *   no independence pair exists. It is not dead: it IS evaluated, and false,
 *   whenever c > 4 is true and IDX64_INVALID is false (a live height-40 key).
 *   The other four operands of both decisions ARE driven here - "ret == 0"
 *   false from a forged idx_len of 2, "c > 4"/IDX64_INVALID from live and
 *   retired XMSSMT-SHA2_40/8_256 keys, IDX32_INVALID from live and retired
 *   XMSSMT-SHA2_20/2_256 keys. Beware the index: these five conditions all
 *   share one macro-expansion location, and llvm-cov's export order is NOT
 *   source order there - index 2 is "c <= 4" and index 3 is IDX64_INVALID.
 */

#include <wolfcrypt/src/wc_xmss_impl.c>

/* wc_xmssmt_sign()'s
 *
 *     if ((ret == 0) && xmss_idx_invalid(idx, h))
 *
 * needs a vector with ret != 0 to pair against the retired-index TRUE row
 * below. The only assignment to ret before that guard is
 * wc_xmss_bds_state_alloc() / wc_xmss_bds_state_load(), and the alloc is this
 * file's ONE heap call -- so the generic allocator injector is the lever, and
 * it has to live in the SAME binary as the retired-index row because llvm-cov
 * derives independence pairs per binary. Armed only around that one Sign call.
 */
#include "mcdc_fault_alloc.h"

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)

/* In-memory secret-key persistence for the whitebox roundtrip. Sized for the
 * tall XMSS^MT parameter set. */
static byte   wb_priv[262144];
static word32 wb_privSz = 0;

static enum wc_XmssRc wb_write_key(const byte* priv, word32 privSz,
    void* context)
{
    (void)context;
    if (privSz > (word32)sizeof(wb_priv))
        return WC_XMSS_RC_WRITE_FAIL;
    XMEMCPY(wb_priv, priv, privSz);
    wb_privSz = privSz;
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}

static enum wc_XmssRc wb_read_key(byte* priv, word32 privSz, void* context)
{
    (void)context;
    if (privSz != wb_privSz)
        return WC_XMSS_RC_READ_FAIL;
    XMEMCPY(priv, wb_priv, privSz);
    return WC_XMSS_RC_READ_TO_MEMORY;
}

/* Full keygen + multi-sign + verify (+ negative verify) for one parameter set,
 * flowing through the WOTS+/L-tree/BDS static helpers in this file. */
static void wb_param_roundtrip(WC_RNG* rng, const char* paramStr)
{
    XmssKey key;
    byte    msg[] = "wc_xmss_impl whitebox message";
    byte*   sig = NULL;
    word32  sigSz;
    word32  sigLen = 0;
    word32  privLen = 0;
    int     i;
    int     ret;

    XMEMSET(&key, 0, sizeof(key));
    wb_privSz = 0;

    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_XmssKey_SetParamStr(&key, paramStr);
    if (ret != 0) {
        WB_NOTE(paramStr);
        WB_NOTE("  parameter set unavailable; skipped");
        wc_XmssKey_Free(&key);
        return;
    }
    (void)wc_XmssKey_SetWriteCb(&key, wb_write_key);
    (void)wc_XmssKey_SetReadCb(&key, wb_read_key);
    (void)wc_XmssKey_SetContext(&key, (void*)wb_priv);

    if (wc_XmssKey_GetPrivLen(&key, &privLen) != 0 ||
            privLen > (word32)sizeof(wb_priv)) {
        WB_NOTE(paramStr);
        WB_NOTE("  secret key exceeds scratch; skipped");
        wc_XmssKey_Free(&key);
        return;
    }

    if (wc_XmssKey_MakeKey(&key, rng) != 0) {
        WB_NOTE(paramStr);
        WB_NOTE("  MakeKey failed");
        wb_fail = 1;
        wc_XmssKey_Free(&key);
        return;
    }

    if (wc_XmssKey_GetSigLen(&key, &sigLen) != 0 || sigLen == 0) {
        WB_NOTE("GetSigLen failed");
        wb_fail = 1;
        wc_XmssKey_Free(&key);
        return;
    }
    sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL) {
        WB_NOTE("sig alloc failed; skipped");
        wc_XmssKey_Free(&key);
        return;
    }

    for (i = 0; i < 2; i++) {
        sigSz = sigLen;
        if (wc_XmssKey_Sign(&key, sig, &sigSz, msg, (int)sizeof(msg)) != 0) {
            WB_NOTE("Sign failed");
            wb_fail = 1;
            break;
        }
        if (wc_XmssKey_Verify(&key, sig, sigSz, msg, (int)sizeof(msg)) != 0) {
            WB_NOTE("Verify(valid) failed");
            wb_fail = 1;
            break;
        }
        /* Negative verify: flip a byte -> drives the WOTS+ chain / root
         * comparison mismatch false-sides. */
        sig[sigSz - 1] ^= 0x01;
        if (wc_XmssKey_Verify(&key, sig, sigSz, msg, (int)sizeof(msg)) == 0) {
            WB_NOTE("Verify(tampered) unexpectedly succeeded");
            wb_fail = 1;
            break;
        }
        sig[sigSz - 1] ^= 0x01;
    }

    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_XmssKey_Free(&key);
}

/* ------------------------------------------------------------------------- *
 * Exhausted-index rows.
 *
 * wc_xmssmt_sign() and wc_xmss_sigsleft() both guard on
 *
 *     if ((ret == 0) && (WC_IDX_INVALID(idx, params->idx_len, params->h)))
 *
 * whose macro expands, in the mixed 32/64-bit build, to
 *
 *     ((idx_len >  4) && IDX64_INVALID(idx.u64, idx_len, h)) ||
 *     ((idx_len <= 4) && IDX32_INVALID(idx.u32, idx_len, h))
 *
 * A key is "exhausted" only after 2^h - 1 signatures, so no test can reach the
 * TRUE side by signing: for h == 10 that is a thousand signatures and for
 * h == 40 it is a trillion. Without a TRUE row NONE of the operands pairs --
 * the decision is false in every vector, so flipping any single operand cannot
 * change the outcome.
 *
 * The index lives in the first idx_len bytes of the persisted secret key, and
 * this file already owns that storage (wb_priv, via the write/read callbacks).
 * Writing it to all-ones is exactly what the library itself writes when it
 * retires a key, so the forged state is one the library produces in the field
 * -- it is simply not one a test can reach by counting. Both the 64-bit
 * (idx_len == 5, XMSS^MT h=40) and 32-bit (idx_len == 4) arms are driven, so
 * IDX64_INVALID and IDX32_INVALID each get their TRUE row against the ordinary
 * FALSE row from wb_param_roundtrip().
 *
 * `(idx_len > 4)` and `(idx_len <= 4)` are exact logical complements of one
 * parameter, so the second of them has no independence pair by construction;
 * that residual is recorded in the exclusion record.
 */
static void wb_exhausted_index(WC_RNG* rng, const char* paramStr, int doSign)
{
    XmssKey key;
    byte    msg[] = "wc_xmss_impl exhausted-index message";
    byte*   sig = NULL;
    word32  sigLen = 0;
    word32  sigSz;
    word32  privLen = 0;
    byte    idxLen;

    XMEMSET(&key, 0, sizeof(key));
    wb_privSz = 0;

    if (wc_XmssKey_Init(&key, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_XmssKey_SetParamStr(&key, paramStr) != 0) {
        WB_NOTE(paramStr);
        WB_NOTE("  parameter set unavailable; exhausted-index rows skipped");
        wc_XmssKey_Free(&key);
        return;
    }
    (void)wc_XmssKey_SetWriteCb(&key, wb_write_key);
    (void)wc_XmssKey_SetReadCb(&key, wb_read_key);
    (void)wc_XmssKey_SetContext(&key, (void*)wb_priv);

    if (wc_XmssKey_GetPrivLen(&key, &privLen) != 0 ||
            privLen > (word32)sizeof(wb_priv)) {
        WB_NOTE(paramStr);
        WB_NOTE("  secret key exceeds scratch; skipped");
        wc_XmssKey_Free(&key);
        return;
    }
    if (wc_XmssKey_MakeKey(&key, rng) != 0) {
        WB_NOTE(paramStr);
        WB_NOTE("  MakeKey failed; exhausted-index rows skipped");
        wb_fail = 1;
        wc_XmssKey_Free(&key);
        return;
    }
    if (wc_XmssKey_GetSigLen(&key, &sigLen) != 0 || sigLen == 0) {
        wc_XmssKey_Free(&key);
        return;
    }
    sig = (byte*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL) {
        wc_XmssKey_Free(&key);
        return;
    }

    idxLen = key.params->idx_len;

    /* The FALSE row for this parameter set: one ordinary signature, so the
     * decision is evaluated with a valid index and the same idx_len. Under
     * WOLFSSL_WC_XMSS_SMALL a height-40 signature recomputes every subtree, so
     * it is a single signature per key here and the four-vector allocator
     * sweep below (which has nothing to fail in the small build) is compiled
     * out; the measured white-box runtime is in the run log. This row is what
     * pairs IDX64_INVALID inside the small build's own wc_xmssmt_sign()
     * (2455): its retired-index partner alone shows only the true side.
     * wc_XmssKey_SigsLeft() is cheap in every build and still supplies the
     * live-index row for wc_xmss_sigsleft()'s copy of the same macro. */
    if (doSign) {
        sigSz = sigLen;
        if (wc_XmssKey_Sign(&key, sig, &sigSz, msg, (int)sizeof(msg)) != 0) {
            WB_NOTE(paramStr);
            WB_NOTE("  baseline Sign failed; exhausted-index rows skipped");
            wb_fail = 1;
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wc_XmssKey_Free(&key);
            return;
        }
    }
    /* SigsLeft on a live key: the FALSE row of the same macro in
     * wc_xmss_sigsleft(). */
    if (wc_XmssKey_SigsLeft(&key) == 0) {
        WB_NOTE("SigsLeft reported an exhausted key after one signature");
        wb_fail = 1;
    }

    /* The `ret != 0` row for the same guard, taken BEFORE the index is
     * retired so the key is still live: a failing BDS-state allocation makes
     * wc_xmssmt_sign() reach the guard with ret != 0. A short dense sweep --
     * a vector count, not a clock -- covers the handful of allocations the
     * sign path makes. */
#ifndef WOLFSSL_WC_XMSS_SMALL
    if (doSign) {
        int n;

        mcdc_fa_install();
        for (n = 1; n <= 4; n++) {
            sigSz = sigLen;
            mcdc_fa_arm(n);
            (void)wc_XmssKey_Sign(&key, sig, &sigSz, msg, (int)sizeof(msg));
            mcdc_fa_disarm();
        }
        mcdc_fa_restore();
        /* The first injected failure moves the XmssKey to WC_XMSS_STATE_BAD
         * and wc_XmssKey_Sign()/_SigsLeft() then short-circuit in wc_xmss.c
         * WITHOUT calling into this file - which silently dropped every
         * retired-index row below (measured: the 64-bit arm of the macro at
         * 2455/4117 was left unpaired in each non-small variant). The
         * injected failures happen before any secret-key mutation, so the
         * persisted key is still consistent; put the handle back in a good
         * state so the rows that follow actually reach wc_xmss_impl.c. */
        key.state = WC_XMSS_STATE_OK;
    }
#else
    /* wc_xmss_impl.c's only XMALLOC is the BDS-state allocation, which lives
     * in the non-small block, so the injector has nothing to fail here: the
     * sweep would only burn four height-40 recompute signatures. */
    (void)0;
#endif

    /* The TRUE row: retire the persisted index. Both entry points reload the
     * secret key through the read callback, so this is all that is needed. */
    XMEMSET(wb_priv, 0xFF, idxLen);

    if (wc_XmssKey_SigsLeft(&key) != 0) {
        WB_NOTE("SigsLeft accepted a retired index");
        wb_fail = 1;
    }
    sigSz = sigLen;
    if (wc_XmssKey_Sign(&key, sig, &sigSz, msg, (int)sizeof(msg)) == 0) {
        WB_NOTE("Sign accepted a retired index");
        wb_fail = 1;
    }

    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_XmssKey_Free(&key);
    WB_NOTE(paramStr);
    WB_NOTE("  exhausted-index rows exercised");
}

static void wb_run(void)
{
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(rng));
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; skipping roundtrips");
        return;
    }

    /* Single tree, one per compiled-in hash family. */
#ifdef WC_XMSS_SHA256
    wb_param_roundtrip(&rng, "XMSS-SHA2_10_256");
#endif
#ifdef WC_XMSS_SHA512
    wb_param_roundtrip(&rng, "XMSS-SHA2_10_512");
#endif
#ifdef WC_XMSS_SHAKE128
    wb_param_roundtrip(&rng, "XMSS-SHAKE_10_256");
#endif
#ifdef WC_XMSS_SHAKE256
    wb_param_roundtrip(&rng, "XMSS-SHAKE256_10_256");
#endif

    /* 2-layer XMSS^MT: drives the XMSS^MT subtree / BDS helpers. */
#if defined(WC_XMSS_SHA256) && (WOLFSSL_XMSS_MAX_HEIGHT >= 20) && \
    (!defined(WOLFSSL_XMSS_MIN_HEIGHT) || (WOLFSSL_XMSS_MIN_HEIGHT <= 20))
    wb_param_roundtrip(&rng, "XMSSMT-SHA2_20/2_256");
#endif

    /* Tall XMSS^MT (height 40 > 32): 64-bit tree-index runtime path. Skipped
     * under WOLFSSL_WC_XMSS_SMALL (recompute signing is slow at this height;
     * the 64-bit path is unioned from the fast variant). */
#if defined(WC_XMSS_SHA256) && !defined(WOLFSSL_WC_XMSS_SMALL) && \
    (WOLFSSL_XMSS_MAX_HEIGHT >= 40) && \
    (!defined(WOLFSSL_XMSS_MIN_HEIGHT) || (WOLFSSL_XMSS_MIN_HEIGHT <= 40))
    wb_param_roundtrip(&rng, "XMSSMT-SHA2_40/8_256");
#endif

    /* Retired-index rows. The 32-bit arm (idx_len == 4) comes from the single
     * tree; the 64-bit arm (idx_len == 5) needs the tall XMSS^MT set, and is
     * driven under WOLFSSL_WC_XMSS_SMALL too -- unlike the roundtrip above,
     * this one produces exactly one signature per key. */
#ifdef WC_XMSS_SHA256
    wb_exhausted_index(&rng, "XMSS-SHA2_10_256", 1);
#endif
    /* An XMSS^MT set with idx_len <= 4, so the 32-bit arm of the macro is
     * driven inside wc_xmssmt_sign() as well -- the single-tree set above
     * reaches wc_xmss_sign()'s own copy of the check, not this one. */
#if defined(WC_XMSS_SHA256) && (WOLFSSL_XMSS_MAX_HEIGHT >= 20) && \
    (!defined(WOLFSSL_XMSS_MIN_HEIGHT) || (WOLFSSL_XMSS_MIN_HEIGHT <= 20))
    wb_exhausted_index(&rng, "XMSSMT-SHA2_20/2_256", 1);
#endif
#if defined(WC_XMSS_SHA256) && (WOLFSSL_XMSS_MAX_HEIGHT >= 40) && \
    (!defined(WOLFSSL_XMSS_MIN_HEIGHT) || (WOLFSSL_XMSS_MIN_HEIGHT <= 40))
    wb_exhausted_index(&rng, "XMSSMT-SHA2_40/8_256", 1);
#endif

    wc_FreeRng(&rng);
}

#else /* !WOLFSSL_HAVE_XMSS || WOLFSSL_XMSS_VERIFY_ONLY */

static void wb_run(void)
{
    WB_NOTE("XMSS signing not compiled in this variant; nothing to exercise");
}

#endif

#ifdef WOLFSSL_HAVE_XMSS

/********************************************
 * Shared small-parameter / state helpers
 ********************************************/

/* Hand-build an XmssParams the same way wc_xmss.c's XMSS_PARAMS() macro
 * would (that macro itself is not visible here - it lives in wc_xmss.c),
 * but with a caller-chosen (deliberately tiny) height/depth so full
 * keygen/sign/verify cycles are cheap enough to run repeatedly. bds_k must
 * keep (sub_h - bds_k) even/sane for the BDS bookkeeping; 0 is always safe.
 */
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
    /* sk_len: replicate XMSS_SK_LEN(n,h,d,sub_h,idx_len,bds_k)'s formula
     * from wc_xmss.c (not visible to this TU). Callers additionally
     * over-allocate their sk buffers well beyond this. */
    p->sk_len = (word32)idx_len + 4U * n +
        (word32)(2 * d - 1) * ((word32)(sub_h + 1) * n + (word32)(sub_h + 1) +
            (word32)sub_h * n + (word32)(sub_h >> 1) * n +
            (word32)hsk * 4U + (word32)hsk * n +
            XMSS_RETAIN_LEN(bds_k, n) + 4U) +
        (word32)(d - 1) * n * ((word32)n * 2 + 3);
    p->pk_len = (word8)(n * 2);
    p->bds_k = bds_k;
}

/* Initialize an XmssState's digest for the hash family named in params.
 * Returns 0 on success, matching wc_xmss_digest_init()'s own contract
 * (which is file-static in wc_xmss.c and not reachable from here). */
static int wb_state_init(XmssState* state, const XmssParams* params)
{
    int ret;

    XMEMSET(state, 0, sizeof(*state));
    state->params = params;
    state->heap = NULL;
    state->ret = 0;

#ifdef WC_XMSS_SHA256
    if (params->hash == WC_HASH_TYPE_SHA256) {
        ret = wc_InitSha256(&state->digest.sha256);
    }
    else
#endif
#ifdef WC_XMSS_SHA512
    if (params->hash == WC_HASH_TYPE_SHA512) {
        ret = wc_InitSha512(&state->digest.sha512);
    }
    else
#endif
    {
        ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    }

    return ret;
}

static void wb_state_free(XmssState* state)
{
#ifdef WC_XMSS_SHA256
    if (state->params->hash == WC_HASH_TYPE_SHA256) {
        wc_Sha256Free(&state->digest.sha256);
        return;
    }
#endif
#ifdef WC_XMSS_SHA512
    if (state->params->hash == WC_HASH_TYPE_SHA512) {
        wc_Sha512Free(&state->digest.sha512);
        return;
    }
#endif
    (void)state;
}

/********************************************
 * 614/615, 1033-1035, 1218-1220, 1813-1815, 1884-1886, 1952-1954,
 * 2022-2024, 2053-2055:
 *   "params->n == <32-bit-digest-size>" (held alongside pad_len==32 and/or
 *   hash==SHA256, whichever the decision requires) selects the SHA-256/
 *   32-byte fast path vs. the fully generic path. Driving the SAME helper
 *   with n=32 (fast path taken) and n=24 (still SHA-256, still within the
 *   192..256-bit partial-digest range, but NOT 32 bytes, so the fast path's
 *   condition is false and the generic/partial path runs) isolates the "n"
 *   operand while hash==SHA256 (and pad_len==32, where applicable) stay
 *   true in both calls.
 ********************************************/
static void wb_hash_family_pairs(void)
{
    XmssParams paramsFull;
    XmssParams paramsPartial;
    XmssState state;
    HashAddress addr;
    byte sk_seed[32];
    byte pk_seed[32];
    byte data[64];
    byte hashOut[64];
    byte pkBuf[WC_XMSS_MAX_WOTS_SIG_LEN];
    byte sigBuf[WC_XMSS_MAX_WOTS_SIG_LEN];
    int i;

    wb_params_init(&paramsFull, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 0);
    wb_params_init(&paramsPartial, WC_HASH_TYPE_SHA256, 24, 32, 4, 1, 4, 0);

    if (wb_state_init(&state, &paramsFull) != 0) {
        WB_NOTE("hash family pairs: SHA-256 state init failed; skipped");
        return;
    }

    for (i = 0; i < 64; i++) {
        data[i] = (byte)(i ^ 0x5a);
    }
    XMEMSET(sk_seed, 0x77, sizeof(sk_seed));
    XMEMSET(pk_seed, 0x88, sizeof(pk_seed));
    XMEMSET(hashOut, 0, sizeof(hashOut));

    /* Line 614/615: wc_xmss_hash()'s "params->n == WC_SHA256_DIGEST_SIZE"
     * operand. */
    state.ret = 0;
    wc_xmss_hash(&state, data, 16, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_hash n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    wc_xmss_hash(&state, data, 16, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_hash n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;

    /* wc_xmss_rand_hash() and wc_xmss_rand_hash_lr()'s
     * "params->n == XMSS_SHA256_32_N" operand, both arms of each. */
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_rand_hash(&state, data, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_rand_hash n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_rand_hash(&state, data, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_rand_hash n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;

/* wc_xmss_rand_hash_lr() is compiled under this condition only
 * (wc_xmss_impl.c). */
#if !defined(WOLFSSL_WC_XMSS_SMALL) || defined(WOLFSSL_XMSS_VERIFY_ONLY)
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_rand_hash_lr(&state, data, data + 32, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_rand_hash_lr n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_rand_hash_lr(&state, data, data + 24, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_rand_hash_lr n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;
#endif

#ifndef WOLFSSL_XMSS_VERIFY_ONLY
    /* Lines 1813-1815: wc_xmss_wots_gen_pk(). */
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(pkBuf, 0, sizeof(pkBuf));
    wc_xmss_wots_gen_pk(&state, sk_seed, pk_seed, addr, pkBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_gen_pk n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(pkBuf, 0, sizeof(pkBuf));
    wc_xmss_wots_gen_pk(&state, sk_seed, pk_seed, addr, pkBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_gen_pk n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;

    /* Lines 1884-1886: wc_xmss_wots_sign(). */
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(sigBuf, 0, sizeof(sigBuf));
    wc_xmss_wots_sign(&state, data, sk_seed, pk_seed, addr, sigBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_sign n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(sigBuf, 0, sizeof(sigBuf));
    wc_xmss_wots_sign(&state, data, sk_seed, pk_seed, addr, sigBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_sign n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;
#else
    WB_NOTE("WOLFSSL_XMSS_VERIFY_ONLY: wots_gen_pk/wots_sign (1813, 1884) "
        "not compiled in; skipped");
    XMEMSET(sigBuf, 0, sizeof(sigBuf));
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

    /* Lines 1952-1954: wc_xmss_wots_pk_from_sig(). sigBuf holds whatever
     * the wots_sign call above produced (or zeros, in VERIFY_ONLY builds);
     * this decision's independence only needs the call to complete without
     * a digest failure, not a cryptographically valid pk. */
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(pkBuf, 0, sizeof(pkBuf));
    wc_xmss_wots_pk_from_sig(&state, sigBuf, data, pk_seed, addr, pkBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_pk_from_sig n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    XMEMSET(pkBuf, 0, sizeof(pkBuf));
    wc_xmss_wots_pk_from_sig(&state, sigBuf, data, pk_seed, addr, pkBuf);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_wots_pk_from_sig n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;

    /* Lines 2022-2024 / 2053-2055: wc_xmss_ltree() - the same decision
     * appears twice (once to prime the cached hash state, once inside the
     * len-reduction loop); one call exercises both occurrences. pkBuf is
     * used purely as WOTS+-shaped scratch input. */
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_ltree(&state, pkBuf, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_ltree n=32 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsPartial;
    state.ret = 0;
    XMEMSET(&addr, 0, sizeof(addr));
    wc_xmss_ltree(&state, pkBuf, pk_seed, addr, hashOut);
    if (state.ret != 0) {
        WB_NOTE("wc_xmss_ltree n=24 arm failed");
        wb_fail = 1;
    }
    state.params = &paramsFull;

    wb_state_free(&state);
    WB_NOTE("hash-family n-operand independence pairs exercised");
}

/********************************************
 * 1623, 1697: WOTS+ chain functions'
 *   "for (i = start+1; i < (start+steps) && i < XMSS_WOTS_W; i++)"
 * condIndex 1 ("i < XMSS_WOTS_W"). Calling with start=0, steps well beyond
 * XMSS_WOTS_W (16) keeps "i < start+steps" true for the whole loop, so it
 * is "i < XMSS_WOTS_W" alone that is true for i=1..15 and false at i=16 -
 * both sides of that one operand, shown within this single call.
 ********************************************/
/* wc_xmss_chain_sha256_32() is built only in the non-small SHA-256 path
 * (wc_xmss_impl.c). */
#if !defined(WOLFSSL_WC_XMSS_SMALL) && defined(WC_XMSS_SHA256)
static void wb_wots_chain_loop(void)
{
    /* wc_xmss_chain_sha256_32() - fixed SHA-256/32-byte path. */
    {
        XmssParams params;
        XmssState state;
        ALIGN16 byte addrBuf[WC_XMSS_ADDR_LEN + 8];
        byte data[32];
        byte pkseed[32];
        byte hashOut[32];
        int i;

        wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 0);
        if (wb_state_init(&state, &params) != 0) {
            WB_NOTE("wots chain loop: SHA-256 state init failed; skipped");
        }
        else {
            for (i = 0; i < 32; i++) {
                data[i] = (byte)i;
                pkseed[i] = (byte)(0x50 + i);
            }
            XMEMSET(addrBuf, 0, sizeof(addrBuf));
            state.ret = 0;
            wc_xmss_chain_sha256_32(&state, data, 0, 40, pkseed, addrBuf,
                hashOut);
            if (state.ret != 0) {
                WB_NOTE("wc_xmss_chain_sha256_32 start/steps run failed");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }

    /* Line 1697: wc_xmss_chain() - generic path. Using SHA-512 (n=64)
     * guarantees this is NOT the sha256_32-specific fast path, so the
     * generic wc_xmss_chain() implementation is what actually runs. */
#ifdef WC_XMSS_SHA512
    {
        XmssParams params;
        XmssState state;
        ALIGN16 byte addrBuf[WC_XMSS_ADDR_LEN + 8];
        byte data[64];
        byte pkseed[64];
        byte hashOut[64];
        int i;

        wb_params_init(&params, WC_HASH_TYPE_SHA512, 64, 64, 4, 1, 4, 0);
        if (wb_state_init(&state, &params) != 0) {
            WB_NOTE("wots chain loop: SHA-512 state init failed; skipped");
        }
        else {
            for (i = 0; i < 64; i++) {
                data[i] = (byte)i;
                pkseed[i] = (byte)(0x60 + i);
            }
            XMEMSET(addrBuf, 0, sizeof(addrBuf));
            state.ret = 0;
            wc_xmss_chain(&state, data, 0, 40, pkseed, addrBuf, hashOut);
            if (state.ret != 0) {
                WB_NOTE("wc_xmss_chain start/steps run failed");
                wb_fail = 1;
            }
            wb_state_free(&state);
        }
    }
#else
    WB_NOTE("WC_XMSS_SHA512 not compiled in; generic wc_xmss_chain arm "
        "skipped");
#endif
}
#else
static void wb_wots_chain_loop(void)
{
    WB_NOTE("WOLFSSL_WC_XMSS_SMALL: wc_xmss_chain_sha256_32 not built; "
        "chain-loop section skipped");
}
#endif /* !WOLFSSL_WC_XMSS_SMALL && WC_XMSS_SHA256 */

/* BdsState and the BDS helpers exist only in the non-small signing path
 * (wc_xmss_impl.c). */
#if !defined(WOLFSSL_XMSS_VERIFY_ONLY) && !defined(WOLFSSL_WC_XMSS_SMALL)
/********************************************
 * 2846: wc_xmss_bds_next_idx()'s "if ((hsk > 0) && (i == 3))".
 * hsk = sub_h - bds_k. Direct calls with offset=0 (so the function's
 * internal "while (o >= 1...)" loop never runs) keep this test isolated to
 * just the targeted if.
 ********************************************/
static void wb_bds_next_idx(void)
{
    XmssParams paramsPos;   /* bds_k=0  -> hsk=sub_h=4 > 0 */
    XmssParams paramsZero;  /* bds_k=4  -> hsk=0 */
    XmssState state;
    BdsState bdsPos[1];
    BdsState bdsZero[1];
    byte skPos[2048];
    byte skZero[2048];
    byte sk_seed[32];
    byte pk_seed[32];
    HashAddress addr;
    word8 height[8];
    word8 offset;
    byte* sp;

    wb_params_init(&paramsPos, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 0);
    wb_params_init(&paramsZero, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 4);

    if (wb_state_init(&state, &paramsPos) != 0) {
        WB_NOTE("bds_next_idx: state init failed; skipped");
        return;
    }
    XMEMSET(sk_seed, 0x33, sizeof(sk_seed));
    XMEMSET(pk_seed, 0x44, sizeof(pk_seed));
    XMEMSET(skPos, 0, sizeof(skPos));
    XMEMSET(skZero, 0, sizeof(skZero));

    /* hsk > 0, i == 3: both operands true -> the guarded copy runs. */
    if (wc_xmss_bds_state_load(&state, skPos, bdsPos, NULL) == 0) {
        XMEMSET(&addr, 0, sizeof(addr));
        XMEMSET(height, 0, sizeof(height));
        offset = 0;
        sp = state.stack;
        state.ret = 0;
        wc_xmss_bds_next_idx(&state, &bdsPos[0], sk_seed, pk_seed, addr, 3,
            height, &offset, &sp);
        if (state.ret != 0) {
            WB_NOTE("bds_next_idx hsk>0,i==3 call failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("bds_next_idx: bds_state_load (hsk>0) failed; skipped");
    }

    /* hsk > 0, i != 3: condIndex1 false, condIndex0 held true. */
    if (wc_xmss_bds_state_load(&state, skPos, bdsPos, NULL) == 0) {
        XMEMSET(&addr, 0, sizeof(addr));
        XMEMSET(height, 0, sizeof(height));
        offset = 0;
        sp = state.stack;
        state.ret = 0;
        wc_xmss_bds_next_idx(&state, &bdsPos[0], sk_seed, pk_seed, addr, 5,
            height, &offset, &sp);
        if (state.ret != 0) {
            WB_NOTE("bds_next_idx hsk>0,i!=3 call failed");
            wb_fail = 1;
        }
    }

    /* hsk == 0: condIndex0 false (masks the AND) with i == 3 held true. */
    state.params = &paramsZero;
    if (wc_xmss_bds_state_load(&state, skZero, bdsZero, NULL) == 0) {
        XMEMSET(&addr, 0, sizeof(addr));
        XMEMSET(height, 0, sizeof(height));
        offset = 0;
        sp = state.stack;
        state.ret = 0;
        wc_xmss_bds_next_idx(&state, &bdsZero[0], sk_seed, pk_seed, addr, 3,
            height, &offset, &sp);
        if (state.ret != 0) {
            WB_NOTE("bds_next_idx hsk==0,i==3 call failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("bds_next_idx: bds_state_load (hsk==0) failed; skipped");
    }
    state.params = &paramsPos;

    wb_state_free(&state);
}

/********************************************
 * 3212: wc_xmss_bds_auth_path()'s
 *   "if ((bds->keep == NULL) || (bds->authPath == NULL))"
 * 3251: same function's "if ((tau < hs - 1) && (parent == 0))", where tau
 * and parent come from wc_xmss_lowest_zero_bit_index(leafIdx, hs, &parent).
 * For hs=4: leafIdx=1 -> tau=1,parent=0 (both true); leafIdx=5 -> tau=1,
 * parent=1 (condIndex1 false, condIndex0 held true); leafIdx=7 -> tau=3,
 * parent=0 (condIndex0 false, masking condIndex1). bds_k=0 keeps hsk=4
 * (>= all tau values used here), so the "i < hsk" arm of the trailing
 * per-height loop is always taken and bds->retain is never dereferenced.
 ********************************************/
static void wb_bds_auth_path(void)
{
    XmssParams params;
    XmssState state;
    BdsState bds[1];
    byte skBuf[2048];
    byte sk_seed[32];
    byte pk_seed[32];
    HashAddress addr;

    wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 0);

    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("bds_auth_path: state init failed; skipped");
        return;
    }
    XMEMSET(sk_seed, 0x55, sizeof(sk_seed));
    XMEMSET(pk_seed, 0x66, sizeof(pk_seed));

    /* Line 3212, "keep == NULL" true side (authPath left valid). */
    XMEMSET(skBuf, 0, sizeof(skBuf));
    if (wc_xmss_bds_state_load(&state, skBuf, bds, NULL) == 0) {
        byte* savedKeep = bds[0].keep;

        bds[0].keep = NULL;
        state.ret = 0;
        XMEMSET(&addr, 0, sizeof(addr));
        wc_xmss_bds_auth_path(&state, &bds[0], 1, sk_seed, pk_seed, addr);
        if (state.ret != WC_NO_ERR_TRACE(WC_FAILURE)) {
            WB_NOTE("bds_auth_path keep==NULL did not report WC_FAILURE");
            wb_fail = 1;
        }
        bds[0].keep = savedKeep;
    }
    else {
        WB_NOTE("bds_auth_path: bds_state_load failed; skipped");
    }

    /* Line 3212, "authPath == NULL" true side (keep left valid). */
    XMEMSET(skBuf, 0, sizeof(skBuf));
    if (wc_xmss_bds_state_load(&state, skBuf, bds, NULL) == 0) {
        byte* savedAuth = bds[0].authPath;

        bds[0].authPath = NULL;
        state.ret = 0;
        XMEMSET(&addr, 0, sizeof(addr));
        wc_xmss_bds_auth_path(&state, &bds[0], 1, sk_seed, pk_seed, addr);
        if (state.ret != WC_NO_ERR_TRACE(WC_FAILURE)) {
            WB_NOTE("bds_auth_path authPath==NULL did not report "
                "WC_FAILURE");
            wb_fail = 1;
        }
        bds[0].authPath = savedAuth;
    }

    /* Baseline + line 3251: leafIdx=1 -> tau=1,parent=0 -> both operands
     * true (also exercises line 3212's false side with both pointers
     * valid). */
    XMEMSET(skBuf, 0, sizeof(skBuf));
    if (wc_xmss_bds_state_load(&state, skBuf, bds, NULL) == 0) {
        state.ret = 0;
        XMEMSET(&addr, 0, sizeof(addr));
        wc_xmss_bds_auth_path(&state, &bds[0], 1, sk_seed, pk_seed, addr);
        if (state.ret != 0) {
            WB_NOTE("bds_auth_path leafIdx=1 call failed");
            wb_fail = 1;
        }
    }

    /* Line 3251: leafIdx=5 -> tau=1,parent=1 -> condIndex1 false,
     * condIndex0 held true. */
    XMEMSET(skBuf, 0, sizeof(skBuf));
    if (wc_xmss_bds_state_load(&state, skBuf, bds, NULL) == 0) {
        state.ret = 0;
        XMEMSET(&addr, 0, sizeof(addr));
        wc_xmss_bds_auth_path(&state, &bds[0], 5, sk_seed, pk_seed, addr);
        if (state.ret != 0) {
            WB_NOTE("bds_auth_path leafIdx=5 call failed");
            wb_fail = 1;
        }
    }

    /* Line 3251: leafIdx=7 -> tau=3,parent=0 -> condIndex0 false (masks
     * condIndex1). */
    XMEMSET(skBuf, 0, sizeof(skBuf));
    if (wc_xmss_bds_state_load(&state, skBuf, bds, NULL) == 0) {
        state.ret = 0;
        XMEMSET(&addr, 0, sizeof(addr));
        wc_xmss_bds_auth_path(&state, &bds[0], 7, sk_seed, pk_seed, addr);
        if (state.ret != 0) {
            WB_NOTE("bds_auth_path leafIdx=7 call failed");
            wb_fail = 1;
        }
    }

    wb_state_free(&state);
}

/********************************************
 * 3651: wc_xmssmt_keygen()'s (non-SMALL, active variant)
 *   "for (i = 0; (ret == 0) && (i < params->d - 1); i++)"
 * A real d=2 keygen naturally exercises "i < d - 1" true (i=0) then false
 * (i=1) with ret==0 throughout a successful call.
 *
 * 3956, 3985-3987: wc_xmssmt_sign_next_idx() (static, only reachable
 * through wc_xmssmt_sign()) - repeatedly signing every valid index of a
 * small d=2 tree drives its internal per-subtree bookkeeping (including the
 * subtree-boundary crossings every 2^sub_h signs) through many operand
 * combinations, with ret==0 throughout a successful run.
 *
 * 4379: wc_xmssmt_verify()'s "for (i = 1; (ret==0) && (i < params->d);
 * i++)" - a d=2 verify naturally exercises "i < d" true (i=1) then false
 * (i=2).
 ********************************************/
static void wb_full_cycle_d2(void)
{
    XmssParams params;
    XmssState state;
    byte seed[3 * 32];
    byte sk[8192];
    byte pk[160];
    byte sig[8192];
    static const byte msg[] = "xmss whitebox d2 message";
    int ret;
    int i;

    wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 4, 2, 4, 0);

    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("d2 cycle: state init failed; skipped");
        return;
    }

    XMEMSET(seed, 0x22, sizeof(seed));
    XMEMSET(sk, 0, sizeof(sk));
    XMEMSET(pk, 0, sizeof(pk));

    ret = wc_xmssmt_keygen(&state, seed, sk, pk);
    if (ret != 0) {
        WB_NOTE("d2 cycle: keygen failed; skipped");
        wb_state_free(&state);
        return;
    }

    /* Sign through every valid index (0..2^h-2 == 14): exercises
     * wc_xmssmt_sign_next_idx()'s internals across both subtrees. */
    for (i = 0; i < 15; i++) {
        XMEMSET(sig, 0, sizeof(sig));
        ret = wc_xmssmt_sign(&state, msg, (word32)sizeof(msg), sk, sig);
        if (ret != 0) {
            WB_NOTE("d2 cycle: sign failed before exhaustion");
            wb_fail = 1;
            break;
        }

        if (i == 14) {
            /* Last valid index: verify exercises the full d=2 loop at
             * line 4379 (i=1<2 true, then i=2<2 false), ret==0
             * throughout. */
            ret = wc_xmssmt_verify(&state, msg, (word32)sizeof(msg), sig,
                pk);
            if (ret != 0) {
                WB_NOTE("d2 cycle: verify of a good signature failed");
                wb_fail = 1;
            }
        }
    }

    wb_state_free(&state);
}

/********************************************
 * 4070: wc_xmssmt_sign()'s "if ((ret == 0) && xmss_idx_invalid(idx, h))".
 * 4087: same function's
 *   "if ((ret == 0) && (idx < (((XmssIdx)1 << h) - 1)))" - given the
 *   upstream invalid-index check at 4070 already rejects any idx that
 *   would make this false (the largest idx that can reach here is
 *   2^h - 2, and 2^h - 2 < 2^h - 1 always), condIndex1's false side is
 *   provably unreachable while ret==0; only condIndex0 is closed here
 *   (see SKIP note in the final report).
 * 4121: wc_xmss_sigsleft()'s
 *   "if ((ret == 0) && (WC_IDX_INVALID(idx, params->idx_len, params->h)))".
 * 4391: wc_xmssmt_verify()'s "if ((ret == 0) && (XMEMCMP(node, pub_root, n)
 *   != 0))" - forced both ways directly (valid vs. corrupted public key).
 *
 * A small d=1 tree is signed through every valid index until natural
 * exhaustion (idx reaches 2^h - 1), which is exactly when line 4070's
 * "xmss_idx_invalid" operand flips true (having been false on every prior,
 * successful sign) - masking line 4087's "ret == 0" operand to false on
 * that same call. A separate, cheap direct call to wc_xmss_sigsleft() with
 * an idx_len wc_xmss's dual-width WC_IDX_DECODE doesn't recognize (2, vs.
 * the valid 3/4/5/8) forces "ret == 0" false at line 4121 without ever
 * evaluating WC_IDX_INVALID - the complementary independence pair to the
 * exhausted-key call (which shows WC_IDX_INVALID's true side with ret==0
 * true) and the fresh-key call (WC_IDX_INVALID's false side, ret==0 true).
 ********************************************/
static void wb_full_cycle_d1(void)
{
    XmssParams params;
    XmssState state;
    byte seed[3 * 32];
    byte sk[2048];
    byte pk[160];
    byte sig[4096];
    static const byte msg[] = "xmss whitebox d1 message";
    int ret;
    int i;
    int exhausted = 0;

    wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 4, 0);

    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("d1 cycle: state init failed; skipped");
        return;
    }

    XMEMSET(seed, 0x11, sizeof(seed));
    XMEMSET(sk, 0, sizeof(sk));
    XMEMSET(pk, 0, sizeof(pk));

    ret = wc_xmssmt_keygen(&state, seed, sk, pk);
    if (ret != 0) {
        WB_NOTE("d1 cycle: keygen failed; skipped");
        wb_state_free(&state);
        return;
    }

    /* wc_xmss_sigsleft() on a fresh, unexhausted key: line 4121's
     * WC_IDX_INVALID false side, ret == 0 true. */
    ret = wc_xmss_sigsleft(&params, sk);
    if (ret != 1) {
        WB_NOTE("d1 cycle: sigsleft on a fresh key did not report sigs "
            "left");
        wb_fail = 1;
    }

    /* Sign through every valid index (0..2^h-2 == 14). */
    for (i = 0; i < 15; i++) {
        XMEMSET(sig, 0, sizeof(sig));
        ret = wc_xmssmt_sign(&state, msg, (word32)sizeof(msg), sk, sig);
        if (ret != 0) {
            WB_NOTE("d1 cycle: sign failed before exhaustion");
            wb_fail = 1;
            break;
        }

        if (i == 0) {
            /* Genuine verify: line 4391's XMEMCMP==0 (false) side, and
             * the successful d=1 loop path at line 4379. */
            ret = wc_xmssmt_verify(&state, msg, (word32)sizeof(msg), sig,
                pk);
            if (ret != 0) {
                WB_NOTE("d1 cycle: verify of a good signature failed");
                wb_fail = 1;
            }

            /* Corrupt the public root and re-verify: line 4391's
             * XMEMCMP!=0 (true) side, ret==0 up to that point. */
            {
                byte badPk[160];

                XMEMCPY(badPk, pk, sizeof(pk));
                badPk[0] ^= 0xFFU;
                ret = wc_xmssmt_verify(&state, msg, (word32)sizeof(msg),
                    sig, badPk);
                if (ret != WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
                    WB_NOTE("d1 cycle: corrupted-pk verify did not fail "
                        "as expected");
                    wb_fail = 1;
                }
            }
        }
    }

    /* sk's index is now 2^h - 1 == 15. This sign attempt hits line 4070's
     * "xmss_idx_invalid(idx,h)" true side (ret==0 up to that point),
     * forcing ret = KEY_EXHAUSTED_E, which (masking) drives line 4087's
     * "ret == 0" operand to false. */
    ret = wc_xmssmt_sign(&state, msg, (word32)sizeof(msg), sk, sig);
    if (ret == WC_NO_ERR_TRACE(KEY_EXHAUSTED_E)) {
        exhausted = 1;
    }
    else {
        WB_NOTE("d1 cycle: key was not reported exhausted as expected");
        wb_fail = 1;
    }

    /* wc_xmss_sigsleft(): line 4121's WC_IDX_INVALID true side, ret == 0
     * true. Craft an sk whose encoded idx is exactly 2^h - 1 == 15 (the
     * smallest value for which (idx+1)>>h != 0) directly, rather than
     * reusing the just-exhausted sk above, whose index field wc_xmssmt_sign()
     * has XMEMSET to all-0xFF: 2^h - 1 is the smallest value the check must
     * reject and is the one this test is after. (The all-0xFF marker used to
     * read back as "valid" because IDX32_INVALID's "(idx+1)>>h" overflowed to
     * 0 - a real defect, fixed in "wolfcrypt: xmss exhausted-key index marker
     * wrapped and re-enabled signing".) */
    if (exhausted) {
        byte idxSk[2048];

        XMEMCPY(idxSk, sk, sizeof(idxSk));
        idxSk[0] = 0x00;
        idxSk[1] = 0x00;
        idxSk[2] = 0x00;
        idxSk[3] = 0x0F; /* idx = 15 = 2^h - 1, h = 4 */
        ret = wc_xmss_sigsleft(&params, idxSk);
        if (ret != 0) {
            WB_NOTE("d1 cycle: sigsleft with idx==2^h-1 unexpectedly "
                "reported sigs left");
            wb_fail = 1;
        }
    }

    wb_state_free(&state);

    /* Line 4121, "ret == 0" false side: idx_len=2 matches neither
     * WC_IDX_DECODE's 32-bit arm (3 or 4 bytes) nor its 64-bit arm (5 or
     * 8 bytes), so decode sets ret = NOT_COMPILED_IN and WC_IDX_INVALID is
     * never evaluated - independent of any sk content. */
    {
        XmssParams badLenParams;
        byte dummySk[8];

        wb_params_init(&badLenParams, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 2,
            0);
        XMEMSET(dummySk, 0, sizeof(dummySk));
        ret = wc_xmss_sigsleft(&badLenParams, dummySk);
        if (ret != 0) {
            WB_NOTE("d1 cycle: sigsleft with an unsupported idx_len "
                "unexpectedly reported sigs left");
            wb_fail = 1;
        }
    }
}
#else /* verify-only, or the small signing path */
static void wb_bds_next_idx(void)
{
    WB_NOTE("BDS helpers not compiled in; wb_bds_next_idx skipped");
}
static void wb_bds_auth_path(void)
{
    WB_NOTE("BDS helpers not compiled in; wb_bds_auth_path skipped");
}
static void wb_full_cycle_d2(void)
{
    WB_NOTE("keygen/sign not compiled in; wb_full_cycle_d2 skipped");
}
static void wb_full_cycle_d1(void)
{
    WB_NOTE("keygen/sign not compiled in; wb_full_cycle_d1 skipped");
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY && !WOLFSSL_WC_XMSS_SMALL */

/********************************************
 * 3995-3997 (3981-3983 before the exhausted-marker fix moved the file):
 * wc_xmssmt_sign_next_idx()'s
 *   "if ((ret == 0) && (i > 0) && (updates > 0) &&
 *        (idx_tree < ((XmssIdx)1 << (h - (hs * (i + 1))))) &&
 *        (bds[alt_i].next < ((XmssIdx)1 << h)))"
 *
 * condIndex 0 ("ret == 0") and condIndex 4 ("bds[alt_i].next < (1 << h)")
 * have no independence pair from ordinary signing:
 *
 *  - condIndex 4: BdsState.next is a *sub*tree leaf counter. It is reset to 0
 *    at a subtree boundary and wc_xmss_bds_update() itself stops incrementing
 *    it at (1 << sub_h), while the bound tested here is (1 << h) with h the
 *    FULL tree height. On every reachable signing vector next <= 2^sub_h <=
 *    2^h, so the operand is true. It is only false when the value loaded out
 *    of the persisted secret key (a 24-bit big-endian field, wc_xmss_bds_
 *    state_load() at 2743) is already >= 2^h - i.e. a corrupted/forged
 *    private key, which is exactly the case this defensive guard exists for.
 *    Here that state is forged directly: the BDS array is loaded from a COPY
 *    of a good secret key and every state's "next" is set to 1 << h before
 *    wc_xmssmt_sign_next_idx() is called. Memory-safe: "next" is read in
 *    exactly two places - this guard, and wc_xmss_bds_update()'s own
 *    "next < (1 << sub_h)" entry test, which the forged value turns into a
 *    no-op. It indexes nothing.
 *
 *  - condIndex 0: reaching this guard with ret != 0 needs the *same* loop
 *    iteration's wc_xmss_bds_auth_path() (or wc_xmss_bds_treehash_updates())
 *    to have failed; a failure in any earlier iteration leaves through the
 *    for-header instead. Both only fail on a NULL BDS sub-buffer or a digest
 *    failure. Forged the same way: bds[BDS_IDX(...)].keep is NULLed, so
 *    wc_xmss_bds_auth_path() takes its "(bds->keep == NULL) ||
 *    (bds->authPath == NULL)" bail-out, sets state->ret = WC_FAILURE and
 *    returns before touching anything.
 *
 * Both forged rows are driven against the ORDINARY, all-operands-true row
 * from a real wc_xmssmt_sign() at the same index, in this same binary, so
 * the independence pairs are complete here and do not lean on any other
 * build. Parameters are hand-built with the same per-layer geometry as
 * XMSSMT-SHA2_40/8_256 (sub_h = 5, bds_k = 0, so updates = 2) but only
 * h = 20 / d = 4, which keeps keygen and eight signatures cheap.
 ********************************************/
#if !defined(WOLFSSL_XMSS_VERIFY_ONLY) && !defined(WOLFSSL_WC_XMSS_SMALL) && \
    defined(WC_XMSS_SHA256)
static byte wb_ni_sk[16384];
static byte wb_ni_skCopy[16384];
static byte wb_ni_sig[16384];

static void wb_sign_next_idx_rows(void)
{
    XmssParams  params;
    XmssState   state;
    byte        seed[3 * 32];
    byte        pk[160];
    static const byte msg[] = "xmss whitebox next-idx message";
    int         ret;
    int         k;

    wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 20, 4, 4, 0);
    if ((params.sk_len > (word32)sizeof(wb_ni_sk)) ||
            (params.sig_len > (word32)sizeof(wb_ni_sig))) {
        WB_NOTE("next-idx rows: scratch too small; skipped");
        return;
    }
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("next-idx rows: state init failed; skipped");
        return;
    }

    XMEMSET(seed, 0x33, sizeof(seed));
    XMEMSET(wb_ni_sk, 0, sizeof(wb_ni_sk));
    XMEMSET(pk, 0, sizeof(pk));

    ret = wc_xmssmt_keygen(&state, seed, wb_ni_sk, pk);
    if (ret != 0) {
        WB_NOTE("next-idx rows: keygen failed; skipped");
        wb_state_free(&state);
        return;
    }

    for (k = 0; k < 8; k++) {
        BdsState* bds;
        byte*     wots_sigs;
        int       j;

        /* Row A - forged BDS state: every state's next is already past the
         * full-tree bound, so condIndex 4 is false with condIndex 0..3 true. */
        XMEMCPY(wb_ni_skCopy, wb_ni_sk, sizeof(wb_ni_skCopy));
        bds = NULL;
        wots_sigs = NULL;
        if (wc_xmss_bds_state_alloc(&params, &bds, state.heap) == 0) {
            if (wc_xmss_bds_state_load(&state, wb_ni_skCopy, bds,
                    &wots_sigs) == 0) {
                for (j = 0; j < 2 * (int)params.d - 1; j++) {
                    bds[j].next = (word32)1U << params.h;
                }
                state.ret = 0;
                (void)wc_xmssmt_sign_next_idx(&state, bds, (XmssIdx)k,
                    wots_sigs, wb_ni_skCopy);
                state.ret = 0;
            }
            wc_xmss_bds_state_free(bds, state.heap);
        }

        /* Row B - forged BDS state: the working state's keep buffer is NULL,
         * so this iteration's wc_xmss_bds_auth_path() fails and the guard is
         * reached with ret != 0 (condIndex 0 false). */
        XMEMCPY(wb_ni_skCopy, wb_ni_sk, sizeof(wb_ni_skCopy));
        bds = NULL;
        wots_sigs = NULL;
        if (wc_xmss_bds_state_alloc(&params, &bds, state.heap) == 0) {
            if (wc_xmss_bds_state_load(&state, wb_ni_skCopy, bds,
                    &wots_sigs) == 0) {
                bds[BDS_IDX((XmssIdx)k, 0, params.sub_h, params.d)].keep =
                    NULL;
                state.ret = 0;
                (void)wc_xmssmt_sign_next_idx(&state, bds, (XmssIdx)k,
                    wots_sigs, wb_ni_skCopy);
                state.ret = 0;
            }
            wc_xmss_bds_state_free(bds, state.heap);
        }

        /* Row C - the ordinary all-true row: a real signature at the same
         * index, whose wc_xmssmt_sign() runs wc_xmssmt_sign_next_idx()
         * unforged. */
        XMEMSET(wb_ni_sig, 0, sizeof(wb_ni_sig));
        ret = wc_xmssmt_sign(&state, msg, (word32)sizeof(msg), wb_ni_sk,
            wb_ni_sig);
        if (ret != 0) {
            WB_NOTE("next-idx rows: ordinary sign failed");
            wb_fail = 1;
            break;
        }
    }

    wb_state_free(&state);
    WB_NOTE("next-idx forged-BDS rows exercised");
}
#else
static void wb_sign_next_idx_rows(void)
{
    WB_NOTE("BDS signing path not compiled in; wb_sign_next_idx_rows "
        "skipped");
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY && !WOLFSSL_WC_XMSS_SMALL &&
        * WC_XMSS_SHA256 */

/********************************************
 * 2465 (WOLFSSL_WC_XMSS_SMALL's wc_xmssmt_sign() only):
 *   "if ((ret == 0) && (WC_IDX_INVALID(idx, params->idx_len, params->h)))"
 * condIndex 0's false side. The only assignment to ret before the guard is
 * WC_IDX_DECODE's trailing "else { ret = NOT_COMPILED_IN; }", which fires
 * only when params->idx_len is none of 3, 4, 5 and 8 - and every set in
 * wc_xmss_alg[] uses one of those four, so no key can produce it. A
 * hand-built parameter set with idx_len == 2 does, exactly as
 * wb_full_cycle_d1() already does for wc_xmss_sigsleft()'s copy of the same
 * macro.
 *
 * Memory-safe: before the guard the function only zeroes state->addr and
 * copies idx_len (2) bytes sk->sig; sk_seed/pk_seed/sig_r are pointer
 * arithmetic that is never dereferenced on this path, and with ret != 0
 * every later block is gated by "if (ret == 0)" down to "return ret", so
 * nothing is allocated or hashed. The buffers are still sized past
 * params.sk_len so even the unused interior pointers stay in-object.
 *
 * Only built for WOLFSSL_WC_XMSS_SMALL: the non-small wc_xmssmt_sign()
 * (4055) allocates and loads the BDS state from sk *before* its own index
 * check and decodes with xmss_idx_decode(), which has no NOT_COMPILED_IN
 * arm - it would neither reach this decision nor be memory-safe with a
 * forged parameter set.
 ********************************************/
#if defined(WOLFSSL_WC_XMSS_SMALL) && !defined(WOLFSSL_XMSS_VERIFY_ONLY) && \
    defined(WC_XMSS_SHA256)
static void wb_smallmt_bad_idx_len(void)
{
    XmssParams  params;
    XmssState   state;
    byte        sk[1024];
    byte        sig[1024];
    static const byte msg[] = "xmss whitebox bad idx_len message";
    int         ret;

    wb_params_init(&params, WC_HASH_TYPE_SHA256, 32, 32, 4, 1, 2, 0);
    if (params.sk_len > (word32)sizeof(sk)) {
        WB_NOTE("bad idx_len row: scratch too small; skipped");
        return;
    }
    if (wb_state_init(&state, &params) != 0) {
        WB_NOTE("bad idx_len row: state init failed; skipped");
        return;
    }

    XMEMSET(sk, 0, sizeof(sk));
    XMEMSET(sig, 0, sizeof(sig));

    ret = wc_xmssmt_sign(&state, msg, (word32)sizeof(msg), sk, sig);
    if (ret != WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
        WB_NOTE("bad idx_len row: wc_xmssmt_sign did not reject an "
            "unsupported idx_len");
        wb_fail = 1;
    }

    wb_state_free(&state);
    WB_NOTE("small-path unsupported idx_len row exercised");
}
#else
static void wb_smallmt_bad_idx_len(void)
{
    WB_NOTE("small XMSS^MT signing path not compiled in; "
        "wb_smallmt_bad_idx_len skipped");
}
#endif /* WOLFSSL_WC_XMSS_SMALL && !WOLFSSL_XMSS_VERIFY_ONLY &&
        * WC_XMSS_SHA256 */

#else /* WOLFSSL_HAVE_XMSS */

static void wb_hash_family_pairs(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_wots_chain_loop(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_bds_next_idx(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_bds_auth_path(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_full_cycle_d2(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_full_cycle_d1(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_sign_next_idx_rows(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}
static void wb_smallmt_bad_idx_len(void)
{
    WB_NOTE("WOLFSSL_HAVE_XMSS not compiled in; skipped");
}

#endif /* WOLFSSL_HAVE_XMSS */

int main(void)
{
    printf("wc_xmss_impl.c white-box supplement\n");
    wb_run();
    wb_hash_family_pairs();
    wb_wots_chain_loop();
    wb_bds_next_idx();
    wb_bds_auth_path();
    wb_full_cycle_d2();
    wb_full_cycle_d1();
    wb_sign_next_idx_rows();
    wb_smallmt_bad_idx_len();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return 0;
}
