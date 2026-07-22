/* test_frodokem_fault_common.h
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
 * Shared body for the two FrodoKEM MC/DC fault-injection white-boxes.
 *
 * wolfcrypt/src/wc_frodokem.c and wolfcrypt/src/wc_frodokem_mat.c are compiled
 * as SEPARATE translation units in the library, so each involved file gets its
 * own white-box driver TU that #includes just that one .c (so llvm-cov
 * instruments its file-statics), then #includes THIS header for the common
 * main()/sweep. The harness links each driver against libwolfssl.a with only
 * the one instrumented object trimmed, so the other FrodoKEM object is still
 * provided by the archive -- make/encap/decap therefore run end to end in both
 * builds; only which file's decisions are exported differs.
 *
 * DOMINANT RESIDUAL CLASS -- AND AN IMPORTANT PLATFORM CAVEAT
 * ----------------------------------------------------------
 * Both files are dominated by success-chain guards shaped
 *
 *     if ((ret == 0) && !cbHandled) ...               (drive the ret != 0 half)
 *     if ((ret == 0) && (cnt1 > 0)) ...               (drive ret != 0)
 *     for (i = 0; (ret == 0) && (i < n); i++) ...     (drive ret != 0 mid-loop)
 *     if ((ret == 0) && (p->qMask != 0xffff)) ...     (drive ret != 0)
 *
 * In normal execution every allocation succeeds, ret stays 0, and the ret != 0
 * operand is never taken. The only way to force ret != 0 at these sites is to
 * make an earlier allocation return NULL so MEMORY_E propagates. This body
 * installs the generic heap-fault injector (mcdc_fault_alloc.h) and sweeps the
 * fail-index across each param set's make_key / encapsulate / decapsulate
 * allocation sequence.
 *
 * WHERE THE MOCK HELPS -- and where it CANNOT:
 *   * wc_frodokem.c: its per-operation scratch buffers (mat / rand / arena) are
 *     heap-allocated ONLY under WOLFSSL_SMALL_STACK. In that variant the sweep
 *     drives the ret != 0 (C1) independence pair of the
 *     `if ((ret == 0) && !cbHandled)` guards that no normal-path test can reach
 *     (a successful run keeps ret == 0). In the DEFAULT (large-stack) build
 *     those buffers live on the stack, make_key performs a single heap
 *     allocation, and the mock has essentially nothing to fault -- so a
 *     small_stack variant is REQUIRED for this supplement to add coverage.
 *   * wc_frodokem_mat.c: on x86/x86_64 its (ret == 0) && step residuals become
 *     ret != 0 ONLY when a SHAKE (wc_InitShake* / Absorb / Squeeze) or AES-ECB
 *     primitive returns an error. Those primitives DO NOT route through the
 *     heap allocator (sha3.c has zero XMALLOC; AES-ECB over the 16-byte-aligned
 *     FrodoKEM scratch takes the AESNI/C non-allocating path), so NO heap-fault
 *     index can make them fail. The mat file's 13 residuals are therefore NOT
 *     closable by this heap-alloc mock under any x86 variant -- they would need
 *     a primitive-return fault mock (stub wc_Shake*/wc_AesEcbEncrypt), a
 *     separate deferred technique. This driver still exercises the mat file
 *     end to end (its baseline true-chain rows) but closes none of the 13.
 *
 * Crash-safety: every armed call either fails an allocation whose MEMORY_E the
 * FrodoKEM cleanup absorbs (that cleanup is what is under test) or returns
 * before building anything. All keys/ciphertexts are prepared while DISARMED,
 * and the harness never dereferences a value a faulted call returned. Verified
 * clean (no errors, no leaks) under -fsanitize=address.
 *
 * Invocation:
 *   ./wb.test            default: baseline valid ops + the full fault sweep
 *   ./wb.test baseline   only the unarmed valid ops (measure sweep as a delta)
 *   ./wb.test probe      print per-entry-point allocation counts (sizes K)
 * The campaign's run_whitebox harness runs the binary with NO args, so the
 * default action is the full sweep.
 */

#ifndef TEST_FRODOKEM_FAULT_COMMON_H
#define TEST_FRODOKEM_FAULT_COMMON_H

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_frodokem.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifndef WOLFSSL_HAVE_FRODOKEM

int main(void)
{
    printf("frodokem fault white-box: !WOLFSSL_HAVE_FRODOKEM, nothing to do\n");
    return 0;
}

#else

/* Every compiled key type: base sets 640/976/1344 x {SHAKE,AES} x
 * {standard,ephemeral}. Each row exercises a different matrix-A generation and
 * noise path in wc_frodokem_mat.c. Types absent from the build are simply
 * rejected by wc_FrodoKemKey_Init and skipped. */
static const int fk_types[] = {
#ifdef WOLFSSL_FRODOKEM_SHAKE
    WC_FRODOKEM_640_SHAKE, WC_FRODOKEM_976_SHAKE, WC_FRODOKEM_1344_SHAKE,
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    WC_FRODOKEM_640_AES, WC_FRODOKEM_976_AES, WC_FRODOKEM_1344_AES,
#endif
#if defined(WOLFSSL_FRODOKEM_EPHEMERAL) && defined(WOLFSSL_FRODOKEM_SHAKE)
    WC_EFRODOKEM_640_SHAKE, WC_EFRODOKEM_976_SHAKE, WC_EFRODOKEM_1344_SHAKE,
#endif
#if defined(WOLFSSL_FRODOKEM_EPHEMERAL) && defined(WOLFSSL_FRODOKEM_AES)
    WC_EFRODOKEM_640_AES, WC_EFRODOKEM_976_AES, WC_EFRODOKEM_1344_AES,
#endif
};

/* Build a fully made key of a given type. Must be called DISARMED. */
static int fk_build(FrodoKemKey* key, int type, WC_RNG* rng)
{
    int ret = wc_FrodoKemKey_Init(key, type, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_FrodoKemKey_MakeKey(key, rng);
    return ret;
}

int main(int argc, char** argv)
{
    int      do_sweep   = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    int      do_probe   = (argc > 1 && strcmp(argv[1], "probe") == 0);
    WC_RNG   rng;
    byte     ct[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
    byte     ss[FRODOKEM_MAX_LENSEC];
    byte     ssDec[FRODOKEM_MAX_LENSEC];
    word32   ctLen, ssLen;
    unsigned t;
    int      n;
    int      ret;

    printf("frodokem fault white-box (%s)\n",
           do_probe ? "probe" : (do_sweep ? "sweep" : "baseline"));

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(ss, 0, sizeof(ss));
    XMEMSET(ssDec, 0, sizeof(ssDec));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    /* ---- baseline: one full make/encap/decap per compiled type. Covers the
     *      ret==0 TRUE chains, every matrix-A / noise / mul-add path, and the
     *      encode/decode helpers on the wc_frodokem.c side. ---- */
    for (t = 0; t < sizeof(fk_types) / sizeof(fk_types[0]); t++) {
        FrodoKemKey key;
        XMEMSET(&key, 0, sizeof(key));
        ret = fk_build(&key, fk_types[t], &rng);
        if (ret != 0) {
            wc_FrodoKemKey_Free(&key);
            continue;                    /* type not compiled in / unsupported */
        }
        ctLen = sizeof(ct); ssLen = sizeof(ss);
        (void)wc_FrodoKemKey_CipherTextSize(&key, &ctLen);
        (void)wc_FrodoKemKey_SharedSecretSize(&key, &ssLen);
        if (wc_FrodoKemKey_Encapsulate(&key, ct, ss, &rng) == 0)
            (void)wc_FrodoKemKey_Decapsulate(&key, ssDec, ct, ctLen);
        wc_FrodoKemKey_Free(&key);
    }

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Count allocations per entry point (arm huge so the counter advances
         * but never trips) to size each sweep's K. Uses the first compiled
         * type as representative; the larger param sets allocate more, so the
         * printed counts are lower bounds -- K is chosen well above them. */
        for (t = 0; t < sizeof(fk_types) / sizeof(fk_types[0]); t++) {
            FrodoKemKey key;
            XMEMSET(&key, 0, sizeof(key));
            if (wc_FrodoKemKey_Init(&key, fk_types[t], NULL, INVALID_DEVID) != 0)
                continue;
            mcdc_fa_arm(1000000);
            (void)wc_FrodoKemKey_MakeKey(&key, &rng);
            printf("  PROBE type=0x%02x make    allocs = %lu\n",
                   (unsigned)fk_types[t], mcdc_fa_count);
            mcdc_fa_disarm();
            ctLen = sizeof(ct); ssLen = sizeof(ss);
            (void)wc_FrodoKemKey_CipherTextSize(&key, &ctLen);
            mcdc_fa_arm(1000000);
            (void)wc_FrodoKemKey_Encapsulate(&key, ct, ss, &rng);
            printf("  PROBE type=0x%02x encap   allocs = %lu\n",
                   (unsigned)fk_types[t], mcdc_fa_count);
            mcdc_fa_disarm();
            mcdc_fa_arm(1000000);
            (void)wc_FrodoKemKey_Decapsulate(&key, ssDec, ct, ctLen);
            printf("  PROBE type=0x%02x decap   allocs = %lu\n",
                   (unsigned)fk_types[t], mcdc_fa_count);
            mcdc_fa_disarm();
            wc_FrodoKemKey_Free(&key);
        }
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
#endif

    if (do_sweep) {
        /* K over-sweeps the probed allocation counts (make/encap perform ~9
         * heap allocations under WOLFSSL_SMALL_STACK; decap ~1). Every index up
         * to K faults one allocation site; indices past the last site just run
         * the target to completion, so a small margin over the max count is all
         * that is needed -- a large K would waste thousands of full (expensive)
         * FrodoKEM operations for no new coverage. */
        const int K = 24;

        for (t = 0; t < sizeof(fk_types) / sizeof(fk_types[0]); t++) {
            int type = fk_types[t];

            /* Prepare ONE valid key + ciphertext for this type (disarmed) so
             * encapsulate/decapsulate have valid inputs to fault into. */
            FrodoKemKey good;
            int haveGood, haveCt = 0;
            XMEMSET(&good, 0, sizeof(good));
            haveGood = (fk_build(&good, type, &rng) == 0);
            if (haveGood) {
                ctLen = sizeof(ct); ssLen = sizeof(ss);
                (void)wc_FrodoKemKey_CipherTextSize(&good, &ctLen);
                (void)wc_FrodoKemKey_SharedSecretSize(&good, &ssLen);
                haveCt = (wc_FrodoKemKey_Encapsulate(&good, ct, ss, &rng) == 0);
            }
            if (!haveGood) {
                wc_FrodoKemKey_Free(&good);
                continue;                /* type not in this build */
            }

            /* --- make_key: allocates its own big scratch AND calls into the
             * matrix-A generation + mul_add_as_plus_e paths in
             * wc_frodokem_mat.c. A fresh key per index (make_key mutates the
             * key object). Low indices fault wc_frodokem.c's own scratch; the
             * deeper band faults allocations inside the mat routines, driving
             * their (ret==0)&&step failure halves. --- */
            for (n = 1; n <= K; n++) {
                FrodoKemKey key;
                XMEMSET(&key, 0, sizeof(key));
                if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) == 0) {
                    mcdc_fa_arm(n);
                    (void)wc_FrodoKemKey_MakeKey(&key, &rng);
                    mcdc_fa_disarm();
                }
                wc_FrodoKemKey_Free(&key);
            }

            /* --- encapsulate: reuses the good public key (encap does not
             * mutate it); reaches mul_add_sa_plus_e + a second matrix-A gen. */
            if (haveCt) {
                for (n = 1; n <= K; n++) {
                    byte c2[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
                    byte s2[FRODOKEM_MAX_LENSEC];
                    XMEMSET(c2, 0, sizeof(c2));
                    XMEMSET(s2, 0, sizeof(s2));
                    mcdc_fa_arm(n);
                    (void)wc_FrodoKemKey_Encapsulate(&good, c2, s2, &rng);
                    mcdc_fa_disarm();
                }

                /* --- decapsulate: reuses the good private key + valid ct;
                 * re-encapsulates internally so it hits the mat paths again
                 * plus the shared-secret compare. --- */
                for (n = 1; n <= K; n++) {
                    byte d2[FRODOKEM_MAX_LENSEC];
                    XMEMSET(d2, 0, sizeof(d2));
                    mcdc_fa_arm(n);
                    (void)wc_FrodoKemKey_Decapsulate(&good, d2, ct, ctLen);
                    mcdc_fa_disarm();
                }
            }

            wc_FrodoKemKey_Free(&good);
        }
        WB_NOTE("fault-index sweeps over make/encap/decap for all types done");
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* TEST_FRODOKEM_FAULT_COMMON_H */
