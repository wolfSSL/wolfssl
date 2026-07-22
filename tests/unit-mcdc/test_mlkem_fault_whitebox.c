/* test_mlkem_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/wc_mlkem.c.
 *
 * wc_mlkem.c's residual uncovered decisions are the FALSE half of allocation
 * success chains that only diverge when an EARLIER heap allocation fails,
 * leaving ret == MEMORY_E when the guard is reached:
 *
 *   wc_MlKemKey_Encapsulate (WOLFSSL_MLKEM_CACHE_A arm):
 *       if ((ret == 0) && ((key->flags & MLKEM_FLAG_A_SET) != 0)) { ... }
 *       -- the ret==0 FALSE half (wc_mlkem.c:1226) needs the up-front working
 *          buffer y (XMALLOC, wc_mlkem.c:1198) to fail so ret==MEMORY_E reaches
 *          the cached-matrix transpose guard.
 *
 *   wc_mlkemkey_check_h (called by Encapsulate/Decapsulate):
 *       if ((ret == 0) && ((key->flags & MLKEM_FLAG_H_SET) == 0)) ret=BAD_STATE_E;
 *       -- the ret==0 FALSE half (wc_mlkem.c:1373:...:0) needs the encoded-
 *          public-key buffer pubKey (XMALLOC, wc_mlkem.c:1357) to fail so the
 *          re-check sees ret==MEMORY_E. (The SECOND condition, MLKEM_FLAG_H_SET,
 *          is a defensive/impossible-state check -- reaching it True with ret==0
 *          means EncodePublicKey succeeded yet left the h flag unset, which the
 *          working encode never does -- so 1373:...:1 is NOT alloc-closable and
 *          is left justified.)
 *
 * In normal execution every XMALLOC succeeds, so these decisions never take the
 * failure branch. This white-box installs the generic heap-fault injector
 * (mcdc_fault_alloc.h) and sweeps the fail-index across each entry point's
 * allocation sites: for each index exactly one earlier XMALLOC returns NULL,
 * driving one guard's ret==0 FALSE half per call.
 *
 * SCOPE NOTE: wc_mlkem_poly.c's uncovered decisions are NOT addressed here.
 * Its only heap-allocation sites are all guarded by WOLFSSL_SMALL_STACK (which
 * no ML-KEM campaign variant defines), and its remaining `(ret==0) && ...` loop
 * guards go non-zero only via a mid-loop PRF/XOF failure, not via an allocation
 * -- neither is reachable through a pass-through allocation fault. The bulk of
 * wc_mlkem_poly.c's residuals are AVX2 cpuid-dispatch and rejection-sampling
 * data-path decisions (a separate, input-driven effort). See the campaign
 * report for the full accounting.
 *
 * It #includes wc_mlkem.c directly (like the other unit-mcdc white-boxes) to
 * reach the file-static wc_mlkemkey_check_h and the MLKEM_FLAG_* macros.
 *
 * Crash-safety: every armed call either returns MEMORY_E before building any
 * output, or fails a deeper allocation whose error the target's own cleanup
 * absorbs (that cleanup is exactly what is under test). The key inputs are
 * prepared while DISARMED, and the harness never dereferences a value a faulted
 * call returned. Runs clean under -fsanitize=address.
 *
 * Invocation:
 *   ./test_mlkem_fault_whitebox            full fault-index sweep (default)
 *   ./test_mlkem_fault_whitebox baseline   unarmed valid ops only (delta base)
 *   ./test_mlkem_fault_whitebox probe      print per-entry-point alloc counts
 * (The campaign run_whitebox harness runs the binary with NO arguments, so the
 * default action is the full sweep.)
 */

#include <wolfcrypt/src/wc_mlkem.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_HAVE_MLKEM) || \
    (defined(WOLFSSL_ARMASM) && defined(__aarch64__)) || defined(WC_NO_RNG)

int main(void)
{
    printf("wc_mlkem.c fault white-box: MLKEM off / ARMASM / no-RNG, "
           "nothing to do\n");
    return 0;
}

#else

/* Use the smallest parameter set so MakeKey/Encapsulate/Decapsulate stay cheap
 * across the sweeps; the residual decisions are parameter-set-independent. */
#define MLKEM_WB_TYPE   WC_ML_KEM_512

/* Build a fresh, fully populated (priv+pub[+cached A]) ML-KEM key. Must be
 * called DISARMED so every internal allocation succeeds. */
static int build_key(MlKemKey* key, WC_RNG* rng)
{
    int ret = wc_MlKemKey_Init(key, MLKEM_WB_TYPE, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_MlKemKey_MakeKey(key, rng);
        if (ret != 0)
            wc_MlKemKey_Free(key);
    }
    return ret;
}

int main(int argc, char** argv)
{
    int      do_sweep = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    WC_RNG   rng;
    MlKemKey key;
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ss[WC_ML_KEM_SS_SZ];
    byte     ss2[WC_ML_KEM_SS_SZ];
    word32   ctSz = 0;
    int      n;
    int      ret;

    printf("wc_mlkem.c fault white-box (%s)\n",
           (argc > 1 && strcmp(argv[1], "baseline") == 0) ? "baseline"
           : (argc > 1 && strcmp(argv[1], "probe") == 0) ? "probe" : "sweep");

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(ss, 0, sizeof(ss));
    XMEMSET(ss2, 0, sizeof(ss2));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    /* ---- baseline: one unarmed valid pass of each target so the ret==0 TRUE
     *      chains and the all-success cleanup halves are covered. ---- */
    ret = build_key(&key, &rng);
    if (ret != 0) {
        printf("  build_key failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
    if (wc_MlKemKey_CipherTextSize(&key, &ctSz) != 0
            || ctSz > (word32)sizeof(ct)) {
        printf("  CipherTextSize unexpected; skipping\n");
        wc_MlKemKey_Free(&key);
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
    (void)wc_MlKemKey_Encapsulate(&key, ct, ss, &rng);
    (void)wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
    /* check_h with the flag cleared so the encode-and-hash body runs. */
    key.flags &= ~(int)MLKEM_FLAG_H_SET;
    (void)wc_mlkemkey_check_h(&key);

#ifndef MCDC_FA_UNAVAILABLE
    if (argc > 1 && strcmp(argv[1], "probe") == 0) {
        /* Diagnostic: count the allocations each entry point performs WITHOUT
         * failing any (arm a huge index so the counter advances but never
         * trips). Use these counts to size each sweep's K. Exits without
         * sweeping. */
        MlKemKey k2;
        XMEMSET(&k2, 0, sizeof(k2));
        if (wc_MlKemKey_Init(&k2, MLKEM_WB_TYPE, NULL, INVALID_DEVID) == 0) {
            mcdc_fa_arm(1000000);
            (void)wc_MlKemKey_MakeKey(&k2, &rng);
            printf("  PROBE makekey allocs    = %lu\n", mcdc_fa_count);
            mcdc_fa_disarm();
            wc_MlKemKey_Free(&k2);
        }
        mcdc_fa_arm(1000000);
        (void)wc_MlKemKey_Encapsulate(&key, ct, ss, &rng);
        printf("  PROBE encapsulate allocs = %lu\n", mcdc_fa_count);
        mcdc_fa_arm(1000000);
        (void)wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
        printf("  PROBE decapsulate allocs = %lu\n", mcdc_fa_count);
        key.flags &= ~(int)MLKEM_FLAG_H_SET;
        mcdc_fa_arm(1000000);
        (void)wc_mlkemkey_check_h(&key);
        printf("  PROBE check_h allocs     = %lu\n", mcdc_fa_count);
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_MlKemKey_Free(&key);
        wc_FreeRng(&rng);
        return 0;
    }
#endif

    if (do_sweep) {
        /* --- wc_MlKemKey_MakeKey: sweeps priv/pub/[a]/e working-buffer XMALLOCs
         * (wc_mlkem.c:250/271/295/841..) so each MEMORY_E cleanup half is driven
         * with exactly one earlier alloc failed. Fresh key per iteration since a
         * faulted MakeKey leaves the object partially built. K=24 over-sweeps
         * the handful of make-key alloc sites (harmless past the last). --- */
        for (n = 1; n <= 24; n++) {
            MlKemKey mk;
            XMEMSET(&mk, 0, sizeof(mk));
            if (wc_MlKemKey_Init(&mk, MLKEM_WB_TYPE, NULL, INVALID_DEVID) == 0) {
                mcdc_fa_arm(n);
                (void)wc_MlKemKey_MakeKey(&mk, &rng);
                mcdc_fa_disarm();
                wc_MlKemKey_Free(&mk);
            }
        }

        /* --- wc_MlKemKey_Encapsulate: the up-front working buffer y
         * (wc_mlkem.c:1198) is the first allocation, so a low fail-index makes
         * ret==MEMORY_E before the noise/matrix/maths steps. Under the
         * WOLFSSL_MLKEM_CACHE_A arm this drives the ret==0 FALSE half of the
         * cached-matrix transpose guard (wc_mlkem.c:1226:...:0); under the other
         * arms it drives encapsulate's own alloc-cleanup halves. Encapsulate
         * does not mutate the key, so the baseline key is reused. K=24. --- */
        for (n = 1; n <= 24; n++) {
            mcdc_fa_arm(n);
            (void)wc_MlKemKey_Encapsulate(&key, ct, ss, &rng);
            mcdc_fa_disarm();
        }

        /* --- wc_MlKemKey_Decapsulate: sweeps its u working buffer
         * (wc_mlkem.c:1749) and re-encrypt compare buffer cmp
         * (wc_mlkem.c:1953). Also calls wc_mlkemkey_check_h internally, so low
         * indices additionally fault check_h's pubKey buffer. Decapsulate does
         * not mutate the key; baseline key reused. K=32. --- */
        for (n = 1; n <= 32; n++) {
            mcdc_fa_arm(n);
            (void)wc_MlKemKey_Decapsulate(&key, ss2, ct, ctSz);
            mcdc_fa_disarm();
        }

        /* --- wc_mlkemkey_check_h standalone: its single XMALLOC is the encoded
         * public-key buffer pubKey (wc_mlkem.c:1357). Clearing MLKEM_FLAG_H_SET
         * each iteration re-enters the encode-and-hash body; faulting pubKey
         * (n=1) leaves ret==MEMORY_E at the re-check (wc_mlkem.c:1373:...:0
         * FALSE half). K=6 covers the one site with margin. --- */
        for (n = 1; n <= 6; n++) {
            key.flags &= ~(int)MLKEM_FLAG_H_SET;
            mcdc_fa_arm(n);
            (void)wc_mlkemkey_check_h(&key);
            mcdc_fa_disarm();
        }

        WB_NOTE("fault-index sweeps over MakeKey / Encapsulate / Decapsulate / "
                "check_h done");
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_MlKemKey_Free(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* MLKEM available */
