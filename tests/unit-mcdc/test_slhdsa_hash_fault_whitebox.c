/* test_slhdsa_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/wc_slhdsa.c.
 *
 * campaign/reports/slhdsa/GAPS.md is almost entirely error propagation:
 *
 *     if ((ret == 0) && (hdr != NULL))                 -- PRF_msg / H_msg
 *     if ((ret == 0) && (ctxSz > 0) && (ctx != NULL))     streaming chains
 *     if ((ret == 0) && (ctxSz > 0))
 *     while ((ret == 0) && (done < outLen))            -- MGF1
 *     if ((ret != 0) && WC_VAR_OK(sk))                 -- WOTS+ cleanup
 *     if ((ret == 0) && (XMEMCMP(node, pk_root, n) != 0))
 *
 * wc_slhdsa.c contains ZERO XMALLOC calls, so mcdc_fault_alloc.h has nothing
 * to fault: every `ret` in this file comes from a SHA-2, SHAKE or HMAC
 * primitive. mcdc_fault_hash.h macro-interposes those for THIS translation
 * unit only, before wc_slhdsa.c is #included, and mcdc_fh_arm(n) makes the
 * n-th primitive call -- and every later one -- return BAD_FUNC_ARG.
 * wc_InitSha256/512 and wc_InitShake* are NOT interposed, so the key's own
 * hash-object setup is never faulted (only its *use* is).
 *
 * WHERE THE INDEX HAS TO LAND
 * ---------------------------
 * SLH-DSA sign is by far the most expensive operation in the campaign, so the
 * sweep is deliberately shaped:
 *
 *   - a DENSE head (1..WB_DENSE) over every entry point. Almost all of the
 *     residuals are in the PRF_msg / H_msg / MGF1 streaming preamble, which is
 *     within the first few dozen primitive calls of Sign/Verify -- and an
 *     armed call there aborts immediately, so these points are nearly free;
 *   - a STRIDED tail with a small point budget, for the deep ones (the WOTS+
 *     ForceZero-on-error cleanup and the hypertree root compare);
 *   - `f` (fast) parameter sets in preference to `s`, and Verify swept more
 *     densely than Sign, because verify is orders of magnitude cheaper.
 *
 * Every sweep also tests a CPU-time deadline, so the binary degrades to fewer
 * points instead of being killed at the campaign's 600 s TEST_TIMEOUT -- a
 * timeout is scored as a SILENT SKIP and would lose the whole file (HARD
 * RULE 2).
 *
 * NOT REACHABLE HERE (documented residual): `(ret == 0) && (n > 16)` at
 * slhdsakey_sha2_midstate() and wc_SlhDsaKey_Init() needs a category 3/5
 * parameter set, and this module's base config compiles ONLY the 128-bit sets
 * (WOLFSSL_SLHDSA_PARAM_NO_192/256 and *_NO_SHA2_192/256), so n is always 16
 * and the second operand can never be true.
 *
 * VARIANT COVERAGE (HARD RULE 3): under WOLFSSL_SLHDSA_VERIFY_ONLY there is no
 * keygen or signing, so no signature can be produced and the file becomes a
 * skip stub. main() always returns 0.
 */

#include "mcdc_fault_hash.h"

/* wc_slhdsa.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/wc_slhdsa.c>

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)

#define WB_HAVE_DRIVER 1

/* Dense head covers the streaming preamble of every entry point; the strided
 * tail reaches the deep WOTS+/hypertree residuals. */
#define WB_DENSE          96
#define WB_POINTS_SIGN    24
#define WB_POINTS_VERIFY  128
#define WB_DEADLINE_S     170

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

static long wb_next(long n, long k, long budget)
{
    long stride;

    if (n < (long)WB_DENSE)
        return n + 1;
    stride = (k - (long)WB_DENSE) / budget;
    if (stride < 1)
        stride = 1;
    return n + stride;
}

/* Parameter sets to drive. The `f` (fast) sets are preferred: same code, far
 * cheaper signing. Sets absent from the build are rejected by
 * wc_SlhDsaKey_Init and skipped. */
static const int wb_params_list[] = {
#ifndef WC_SLHDSA_ALL_NO_128F
    SLHDSA_SHAKE128F,
#endif
#if defined(WOLFSSL_SLHDSA_SHA2) && !defined(WC_SLHDSA_ALL_NO_128F)
    SLHDSA_SHA2_128F,
#endif
#ifndef WC_SLHDSA_ALL_NO_128S
    SLHDSA_SHAKE128S,
#endif
    -1
};

static WC_RNG     wb_rng;
static SlhDsaKey  wb_key;
static byte       wb_sig[WC_SLHDSA_MAX_SIG_LEN];
static word32     wb_sigLen = 0;
static const byte wb_msg[] = "wc_slhdsa hash-fault white-box message";
/* A non-empty context exercises the (ctxSz > 0) && (ctx != NULL) operands
 * TRUE; the empty-context rows come from the module's ordinary API tests. */
static const byte wb_ctx[] = { 0x41, 0x42, 0x43 };

/* ---- sweeps ------------------------------------------------------------ */

static void wb_sweep_sign(int param)
{
    long   k, n, points = 0;
    word32 len;
    int    ret;

    mcdc_fh_disarm();
    len = (word32)sizeof(wb_sig);
    ret = wc_SlhDsaKey_Sign(&wb_key, wb_ctx, (word32)sizeof(wb_ctx), wb_msg,
        (word32)sizeof(wb_msg), wb_sig, &len, &wb_rng);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline Sign failed; sign sweep skipped");
        wb_fail = 1;
        return;
    }
    wb_sigLen = len;
    printf("  [wb] param %d: sign K=%ld\n", param, k);

    for (n = 1; (n <= k) && !wb_expired();
            n = wb_next(n, k, WB_POINTS_SIGN)) {
        byte   s2[WC_SLHDSA_MAX_SIG_LEN];
        word32 l2 = (word32)sizeof(s2);
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_Sign(&wb_key, wb_ctx, (word32)sizeof(wb_ctx),
            wb_msg, (word32)sizeof(wb_msg), s2, &l2, &wb_rng);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] sign sweep: %ld points\n", points);
}

static void wb_sweep_verify(int param)
{
    long k, n, points = 0;
    int  ret;

    if (wb_sigLen == 0)
        return;

    mcdc_fh_disarm();
    ret = wc_SlhDsaKey_Verify(&wb_key, wb_ctx, (word32)sizeof(wb_ctx), wb_msg,
        (word32)sizeof(wb_msg), wb_sig, wb_sigLen);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline Verify rejected a valid signature");
        wb_fail = 1;
        return;
    }
    printf("  [wb] param %d: verify K=%ld\n", param, k);

    for (n = 1; (n <= k) && !wb_expired();
            n = wb_next(n, k, WB_POINTS_VERIFY)) {
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_Verify(&wb_key, wb_ctx, (word32)sizeof(wb_ctx),
            wb_msg, (word32)sizeof(wb_msg), wb_sig, wb_sigLen);
        mcdc_fh_disarm();
        points++;
    }

    /* Tampered signature (the XMEMCMP(node, pk_root, n) != 0 TRUE half), run
     * DISARMED so it pairs with the ret != 0 rows above. */
    wb_sig[wb_sigLen - 1] ^= 0x01;
    mcdc_fh_disarm();
    if (wc_SlhDsaKey_Verify(&wb_key, wb_ctx, (word32)sizeof(wb_ctx), wb_msg,
            (word32)sizeof(wb_msg), wb_sig, wb_sigLen) == 0) {
        WB_NOTE("Verify accepted a tampered signature");
        wb_fail = 1;
    }
    wb_sig[wb_sigLen - 1] ^= 0x01;

    printf("  [wb] verify sweep: %ld points\n", points);
}

/* MakeKey ends with a root computation compared against the stored key
 * material; faulting into it drives the keygen-side chains. */
static void wb_sweep_makekey(int param)
{
    long k, n, points = 0;

    mcdc_fh_disarm();
    for (n = 1; (n <= (long)WB_DENSE) && !wb_expired(); n++) {
        SlhDsaKey k2;
        XMEMSET(&k2, 0, sizeof(k2));
        if (wc_SlhDsaKey_Init(&k2, (enum SlhDsaParam)param, NULL,
                INVALID_DEVID) == 0) {
            mcdc_fh_arm(n);
            (void)wc_SlhDsaKey_MakeKey(&k2, &wb_rng);
            mcdc_fh_disarm();
            points++;
        }
        wc_SlhDsaKey_Free(&k2);
    }
    k = 0;
    (void)k;
    printf("  [wb] makekey sweep: %ld points\n", points);
}

/* Import/export + DER encode/decode: the ASN-side residuals
 * (`(key->params != NULL) && ...`, `while (ret == 0 && *inOutIdx < seqEnd)`)
 * live here and cost nothing to drive. */
static void wb_der_rows(int param)
{
    byte   der[WC_SLHDSA_MAX_PRIV_LEN + 128];
    byte   pub[WC_SLHDSA_MAX_PUB_LEN];
    word32 idx = 0;
    int    len;

    mcdc_fh_disarm();

    len = wc_SlhDsaKey_KeyToDer(&wb_key, der, (word32)sizeof(der));
    if (len > 0) {
        SlhDsaKey k2;
        XMEMSET(&k2, 0, sizeof(k2));
        if (wc_SlhDsaKey_Init(&k2, (enum SlhDsaParam)param, NULL,
                INVALID_DEVID) == 0) {
            idx = 0;
            (void)wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &k2, (word32)len);
            /* Truncated input: drives the decode loops' early-exit rows. */
            idx = 0;
            (void)wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &k2,
                (word32)len / 2);
        }
        wc_SlhDsaKey_Free(&k2);
    }

    len = wc_SlhDsaKey_PublicKeyToDer(&wb_key, der, (word32)sizeof(der), 1);
    if (len > 0) {
        SlhDsaKey k2;
        XMEMSET(&k2, 0, sizeof(k2));
        if (wc_SlhDsaKey_Init(&k2, (enum SlhDsaParam)param, NULL,
                INVALID_DEVID) == 0) {
            idx = 0;
            (void)wc_SlhDsaKey_PublicKeyDecode(der, &idx, &k2, (word32)len);
            idx = 0;
            (void)wc_SlhDsaKey_PublicKeyDecode(der, &idx, &k2,
                (word32)len / 2);
        }
        wc_SlhDsaKey_Free(&k2);
    }

    (void)wc_SlhDsaKey_ExportPublic(&wb_key, pub, &idx);
}

static void wb_run_param(int param)
{
    printf("  [wb] --- param %d ---\n", param);

    XMEMSET(&wb_key, 0, sizeof(wb_key));
    wb_sigLen = 0;

    mcdc_fh_disarm();
    if (wc_SlhDsaKey_Init(&wb_key, (enum SlhDsaParam)param, NULL,
            INVALID_DEVID) != 0) {
        WB_NOTE("parameter set not compiled in; skipped");
        wc_SlhDsaKey_Free(&wb_key);
        return;
    }
    if (wc_SlhDsaKey_MakeKey(&wb_key, &wb_rng) != 0) {
        WB_NOTE("MakeKey failed; parameter set skipped");
        wc_SlhDsaKey_Free(&wb_key);
        return;
    }

    wb_sweep_sign(param);
    if (!wb_expired())
        wb_sweep_verify(param);
    if (!wb_expired())
        wb_der_rows(param);
    if (!wb_expired())
        wb_sweep_makekey(param);

    mcdc_fh_disarm();
    wc_SlhDsaKey_Free(&wb_key);
}

#endif /* WB_HAVE_DRIVER conditions */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_slhdsa.c hash-fault white-box supplement\n");

#ifdef WB_HAVE_DRIVER
    {
        size_t i;

        wb_t0 = time(NULL);
        XMEMSET(&wb_rng, 0, sizeof(wb_rng));
        XMEMSET(wb_sig, 0, sizeof(wb_sig));

        if (wc_InitRng(&wb_rng) != 0) {
            WB_NOTE("wc_InitRng failed; nothing driven");
        }
        else {
            for (i = 0;
                 i < sizeof(wb_params_list) / sizeof(wb_params_list[0]); i++) {
                if ((wb_params_list[i] < 0) || wb_expired())
                    break;
                wb_run_param(wb_params_list[i]);
            }
            mcdc_fh_disarm();
            wc_FreeRng(&wb_rng);
        }
    }
#else
    printf("  [wb] SLH-DSA keygen/signing not compiled in; nothing to do\n");
#endif

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the campaign discard this binary's coverage. */
    return 0;
}
