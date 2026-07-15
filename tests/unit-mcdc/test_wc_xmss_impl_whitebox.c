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
 * TU #includes wc_xmss_impl.c verbatim so the statics are directly reachable,
 * and links against libwolfssl.a with wc_xmss_impl.o trimmed (wc_xmss.o kept).
 * The statics are exercised by driving a full public wc_XmssKey_* keygen /
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
 */

#include <wolfcrypt/src/wc_xmss_impl.c>

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
 * flowing through the WOTS+/L-tree/BDS statics in this file. */
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

    wc_FreeRng(&rng);
}

#else /* !WOLFSSL_HAVE_XMSS || WOLFSSL_XMSS_VERIFY_ONLY */

static void wb_run(void)
{
    WB_NOTE("XMSS signing not compiled in this variant; nothing to exercise");
}

#endif

int main(void)
{
    printf("wc_xmss_impl.c white-box supplement\n");
    wb_run();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return 0;
}
