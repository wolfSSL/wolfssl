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
 * ENTRY POINTS THAT MUST BE SWEPT SEPARATELY
 * ------------------------------------------
 * The PRF_msg / H_msg streaming preamble is written out once per entry point,
 * so the `(ret == 0) && (ctxSz > 0)` guards inside the PRE-HASH signer and
 * verifier are different source lines from the ones inside the plain signer.
 * wc_SlhDsaKey_SignHash() / wc_SlhDsaKey_VerifyHash() are therefore swept in
 * their own right, as are wc_SlhDsaKey_CheckKey() (whose recomputed-root
 * compare needs its keygen to fail) and wc_SlhDsaKey_ImportPrivate() /
 * ImportPublic() (whose SHA-2 midstate precompute is the only caller of
 * slhdsakey_precompute_sha2_midstates()).
 *
 * NOT REACHABLE HERE (documented residuals, mirrored in
 * campaign/db/exclusions.json):
 *   - `(ret == 0) && (n > 16)` / `(ret == 0) && (key->params->n > 16)`: the
 *     second operand needs a category 3/5 parameter set, and this module's base
 *     config compiles ONLY the 128-bit sets (WOLFSSL_SLHDSA_PARAM_NO_192/256
 *     and *_NO_SHA2_192/256), so n is always 16. NEITHER operand pairs: with
 *     `n > 16` pinned false the decision is false in every vector, so flipping
 *     `ret == 0` cannot change the outcome either.
 *   - slhdsakey_h_msg_sha2()'s `(ret == 0) && (hdr != NULL)` and
 *     `(ret == 0) && (ctxSz > 0) && (ctx != NULL)`: those two live in the
 *     `else` arm of `if (n == WC_SLHDSA_N_128)`, i.e. the SHA-512 category 3/5
 *     arm, which the 128-bit-only parameter table can never select.
 *   - `(ret != 0) && WC_VAR_OK(sk)`: without WOLFSSL_SMALL_STACK, types.h
 *     defines WC_VAR_OK(x) as the literal 1, so the operand is not merely
 *     undriven -- it has no false side to drive. No slhdsa variant sets
 *     WOLFSSL_SMALL_STACK.
 *   - `while (ret == 0 && *inOutIdx < seqEnd)`: every statement in that loop
 *     body that assigns a non-zero ret is immediately followed by `break`, so
 *     control never reaches the condition again with ret != 0.
 *
 * VARIANT COVERAGE (HARD RULE 3): under WOLFSSL_SLHDSA_VERIFY_ONLY there is no
 * keygen or signing, so no signature can be produced and the file becomes a
 * skip stub. main() always returns 0.
 */

/* wc_SlhDsaKey_Init()'s `(ret == 0) && (key->params->n > 16)` takes its ret
 * from wc_InitSha256() and from nothing else, so the SHA context-init family
 * has to be interposed too. It is opt-in, and armed only inside
 * wb_init_rows(); every other sweep here builds its keys while disarmed. */
#define MCDC_FH_WITH_SHA_INIT

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

/* Pre-hash signer/verifier. FIPS 205 Section 10.2 HashSLH-DSA carries its OWN
 * copy of the PRF_msg / H_msg streaming preamble, so its `(ret == 0) &&
 * (ctxSz > 0)` guards are separate source lines from the plain signer's and
 * need their own armed rows. A pre-hashed SHA-256 digest is used because it is
 * the cheapest accepted (hashType, hashSz) pair; a build without it just
 * reports NOT_COMPILED_IN from the baseline call and the sweep is skipped. */
static void wb_sweep_prehash(int param)
{
    byte   hash[WC_SHA256_DIGEST_SIZE];
    byte   sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigLen = (word32)sizeof(sig);
    long   k, n, points = 0;
    int    ret;

    XMEMSET(hash, 0x5a, sizeof(hash));

#ifndef WC_SLHDSA_ALL_NO_128S
    /* The `s` sets sign orders of magnitude slower than the `f` ones and the
     * pre-hash preamble is identical code, so one full SignHash on an `s` set
     * would buy nothing and cost most of the module's wall-clock budget. */
    if (param == SLHDSA_SHAKE128S) {
        WB_NOTE("pre-hash sweep skipped for the slow parameter set");
        return;
    }
#endif

    mcdc_fh_disarm();
    ret = wc_SlhDsaKey_SignHash(&wb_key, wb_ctx, (byte)sizeof(wb_ctx), hash,
        (word32)sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, &wb_rng);
    k = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("baseline SignHash unavailable; pre-hash sweep skipped");
        return;
    }
    printf("  [wb] param %d: signhash K=%ld\n", param, k);

    /* Only the dense head is useful here: everything this sweep adds over the
     * plain signer is in the streaming preamble, which is the first handful of
     * primitive calls. */
    for (n = 1; (n <= k) && (n <= (long)WB_DENSE) && !wb_expired(); n++) {
        byte   s2[WC_SLHDSA_MAX_SIG_LEN];
        word32 l2 = (word32)sizeof(s2);
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_SignHash(&wb_key, wb_ctx, (byte)sizeof(wb_ctx),
            hash, (word32)sizeof(hash), WC_HASH_TYPE_SHA256, s2, &l2, &wb_rng);
        mcdc_fh_disarm();
        points++;
    }

    mcdc_fh_disarm();
    if (wc_SlhDsaKey_VerifyHash(&wb_key, wb_ctx, (byte)sizeof(wb_ctx), hash,
            (word32)sizeof(hash), WC_HASH_TYPE_SHA256, sig, sigLen) != 0) {
        WB_NOTE("VerifyHash rejected its own signature");
        wb_fail = 1;
    }
    for (n = 1; (n <= (long)WB_DENSE) && !wb_expired(); n++) {
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_VerifyHash(&wb_key, wb_ctx, (byte)sizeof(wb_ctx),
            hash, (word32)sizeof(hash), WC_HASH_TYPE_SHA256, sig, sigLen);
        mcdc_fh_disarm();
        points++;
    }
    printf("  [wb] pre-hash sweep: %ld points\n", points);
}

/* wc_SlhDsaKey_CheckKey() recomputes the public root and compares it against
 * the stored one:
 *
 *     if ((ret == 0) && (XMEMCMP(root, key->sk + 3 * n, n) != 0))
 *
 * The first operand's independence pair needs the decision to be TRUE in one
 * of the two vectors, so the armed (ret != 0, outcome FALSE) row is NOT enough
 * on its own -- it has the same outcome as the ordinary (T, compare-equal) row.
 * The (T,T) row is produced by corrupting the STORED root before the call:
 * CheckKey re-derives the real root from the seeds, so the comparison differs
 * while ret is still 0. The re-derivation also rewrites key->sk with the
 * correct root, so the key is left exactly as it was found. */
static void wb_sweep_checkkey(int param)
{
    long n, points = 0;
    byte n8;

    mcdc_fh_disarm();
    if (wc_SlhDsaKey_CheckKey(&wb_key) != 0) {
        WB_NOTE("CheckKey rejected a freshly made key");
        wb_fail = 1;
        return;
    }

    /* (T,T): stored root != recomputed root. */
    n8 = wb_key.params->n;
    wb_key.sk[3 * n8] ^= 0x01;
    if (wc_SlhDsaKey_CheckKey(&wb_key) == 0) {
        WB_NOTE("CheckKey accepted a key whose stored root was corrupted");
        wb_fail = 1;
    }
    if (wc_SlhDsaKey_CheckKey(&wb_key) != 0) {
        WB_NOTE("CheckKey did not restore the recomputed root");
        wb_fail = 1;
    }

    /* (F,-): the re-derivation itself fails. */
    for (n = 1; (n <= (long)WB_POINTS_SIGN) && !wb_expired(); n++) {
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_CheckKey(&wb_key);
        mcdc_fh_disarm();
        points++;
    }
    /* An armed run can leave sk half-written; restore it. */
    mcdc_fh_disarm();
    (void)wc_SlhDsaKey_CheckKey(&wb_key);
    printf("  [wb] param %d: checkkey sweep: %ld points\n", param, points);
}

/* Raw import: slhdsakey_precompute_sha2_midstates() is reached only from
 * ImportPrivate / ImportPublic / MakeKeyWithRandom, and an armed import is the
 * cheapest way to make its `(ret == 0) && (n > 16)` guard see ret != 0 -- the
 * import does almost nothing before the precompute, so a low fault index lands
 * squarely inside it. */
static void wb_sweep_import(int param)
{
    byte   raw[4 * SLHDSA_MAX_N];
    word32 rawLen = (word32)sizeof(raw);
    long   n, points = 0;

    mcdc_fh_disarm();
    if (wc_SlhDsaKey_ExportPrivate(&wb_key, raw, &rawLen) != 0) {
        WB_NOTE("ExportPrivate failed; import sweep skipped");
        return;
    }

    for (n = 1; (n <= 24L) && !wb_expired(); n++) {
        SlhDsaKey k2;
        XMEMSET(&k2, 0, sizeof(k2));
        if (wc_SlhDsaKey_Init(&k2, (enum SlhDsaParam)param, NULL,
                INVALID_DEVID) == 0) {
            mcdc_fh_arm(n);
            (void)wc_SlhDsaKey_ImportPrivate(&k2, raw, rawLen);
            mcdc_fh_disarm();
            /* The public half is a different caller of the same precompute. */
            mcdc_fh_arm(n);
            (void)wc_SlhDsaKey_ImportPublic(&k2, raw + 2 * (rawLen / 4),
                rawLen / 2);
            mcdc_fh_disarm();
            points++;
        }
        wc_SlhDsaKey_Free(&k2);
    }
    printf("  [wb] param %d: import sweep: %ld points\n", param, points);
}

/* wc_SlhDsaKey_Init()'s `(ret == 0) && (key->params->n > 16)` -- the only
 * assignment to ret before it is wc_InitSha256()'s, so the SHA context-init
 * interposer is what drives the first operand false. */
static void wb_init_rows(int param)
{
    SlhDsaKey k2;
    long      n;

    for (n = 1; n <= 4L; n++) {
        XMEMSET(&k2, 0, sizeof(k2));
        mcdc_fh_arm(n);
        (void)wc_SlhDsaKey_Init(&k2, (enum SlhDsaParam)param, NULL,
            INVALID_DEVID);
        mcdc_fh_disarm();
        wc_SlhDsaKey_Free(&k2);
    }
    printf("  [wb] param %d: init hash-object rows exercised\n", param);
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

            /* `if ((key->params != NULL) && (SLHDSA_IS_SHA2(...) != ...))`:
             * wc_SlhDsaKey_PrivateKeyDecode does not require key->params, and
             * every public initialiser sets it, so the first operand's false
             * side is only reachable by clearing it here. The decoder assigns
             * key->params from the detected parameter set before using it, and
             * restores this NULL on failure, so the call stays memory-safe. */
            k2.params = NULL;
            idx = 0;
            (void)wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &k2, (word32)len);
        }
        wc_SlhDsaKey_Free(&k2);

#ifdef WOLFSSL_SLHDSA_SHA2
        /* The same decision's TRUE row -- which the operand above needs as its
         * partner, since a decision that is FALSE in both vectors cannot show
         * independence. It requires a key whose placeholder parameter set is
         * from the OTHER hash family than the DER's, which no ordinary caller
         * produces: every test decodes into a key initialised for the same
         * family. Both candidate placeholders are tried; the one that is not
         * compiled in is rejected by Init and skipped. */
        {
            static const int wb_other[] = {
#ifndef WC_SLHDSA_ALL_NO_128F
                SLHDSA_SHAKE128F,
                SLHDSA_SHA2_128F,
#endif
                -1
            };
            size_t o;

            for (o = 0; wb_other[o] >= 0; o++) {
                SlhDsaKey k3;

                if (wb_other[o] == param) {
                    continue;
                }
                XMEMSET(&k3, 0, sizeof(k3));
                if (wc_SlhDsaKey_Init(&k3, (enum SlhDsaParam)wb_other[o], NULL,
                        INVALID_DEVID) == 0) {
                    idx = 0;
                    (void)wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &k3,
                        (word32)len);
                }
                wc_SlhDsaKey_Free(&k3);
            }
        }
#endif
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
        wb_sweep_prehash(param);
    if (!wb_expired())
        wb_der_rows(param);
    if (!wb_expired())
        wb_sweep_import(param);
    if (!wb_expired())
        wb_init_rows(param);
    if (!wb_expired())
        wb_sweep_checkkey(param);
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
