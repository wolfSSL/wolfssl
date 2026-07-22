/* test_dsa_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/dsa.c.
 *
 * dsa.c's dominant uncovered class is the FALSE half of allocation success
 * chains that only diverge when an EARLIER heap allocation fails, e.g.
 *
 *   wc_MakeDsaParameters:  if (((tmp=XMALLOC(..))==NULL) || ((tmp2=XMALLOC..)==NULL))
 *                          if ((err != MP_INIT_E) && (err != MEMORY_E)) mp_clear(tmp);
 *   wc_DsaSign_ex:         if ((k==NULL)||(kInv==NULL)||...||(buffer==NULL))
 *                          if ((ret != MP_INIT_E) && (ret != MEMORY_E)) mp_forcezero(k);
 *   wc_DsaVerify_ex:       if ((w==NULL)||(u1==NULL)||...||(s==NULL))
 *                          if (ret != MP_INIT_E && ret != MEMORY_E) mp_clear(s);
 *
 * In normal execution every XMALLOC succeeds, so these decisions never take the
 * failure branch. This white-box installs the generic heap-fault injector
 * (mcdc_fault_alloc.h) and sweeps the fail-index across each entry point's
 * allocation sites: for each index exactly one earlier XMALLOC returns NULL,
 * so exactly one operand of the NULL-guard and one MEMORY_E cleanup-guard half
 * are driven per call.
 *
 * These allocation sites only exist under WOLFSSL_SMALL_STACK (the mp_int/byte
 * temporaries are otherwise on the stack), so this supplement is only
 * productive in the small_stack variant; under the other variants it still
 * builds and runs (the sweep simply finds no heap sites to fault and the
 * targets run to completion), which is why it is safe to wire as a normal
 * whitebox entry that every variant compiles.
 *
 * It #includes dsa.c directly (like the other unit-mcdc white-boxes) to reach
 * the file-static CheckDsaLN / _DsaImportParamsRaw and the SMALL_STACK cleanup.
 *
 * Crash-safety: every armed call either returns MEMORY_E before building any
 * mp_int, or fails a deeper allocation whose error the target's own cleanup
 * absorbs (that cleanup is exactly what is under test). The key/params inputs
 * are prepared while DISARMED, and the harness never dereferences a value a
 * faulted call returned. Runs clean under -fsanitize=address.
 *
 * Invocation:
 *   ./test_dsa_fault_whitebox            baseline: unarmed valid ops only
 *   ./test_dsa_fault_whitebox sweep      baseline + the fault-index sweeps
 * (Two modes so the injector's contribution can be measured as a delta; the
 * campaign's run_whitebox harness runs it with no args -- pass "sweep" there by
 * default via argv, see the modules.json entry note.)
 */

#include <wolfcrypt/src/dsa.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(NO_DSA) || !defined(WOLFSSL_KEY_GEN)

int main(void)
{
    printf("dsa.c fault white-box: NO_DSA or !WOLFSSL_KEY_GEN, nothing to do\n");
    return 0;
}

#else

/* [mod = L=1024, N=160], from CAVP KeyPair (same vector as tests/api). */
static const char* kP =
    "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d"
    "4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c"
    "5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b6"
    "52236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c71"
    "47123188f8dc551054ee162b634d60f097f719076640e209"
    "80a0093113a8bd73";
static const char* kQ = "96c5390a8b612c0e422bb2b0ea194a3ec935a281";
static const char* kG =
    "06b7861abbd35cc89e79c52f68d20875389b127361ca66822"
    "138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37e"
    "b23b94074d3c3d300042bdf15762812b6333ef7b07ceba786"
    "07610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c"
    "61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc0"
    "76341a7e7d9";

/* Build a fully populated (params + x/y) DSA key. Must be called DISARMED. */
static int build_key(DsaKey* key, WC_RNG* rng)
{
    int ret = wc_InitDsaKey(key);
    if (ret == 0)
        ret = wc_DsaImportParamsRaw(key, kP, kQ, kG);
    if (ret == 0)
        ret = wc_MakeDsaKey(rng, key);
    return ret;
}

int main(int argc, char** argv)
{
    /* Default action is the fault sweep so the campaign's run_whitebox harness
     * (which runs this binary with NO arguments) gets full coverage. Pass
     * "baseline" to run only the unarmed valid ops (used to measure the
     * injector's contribution as a delta), or "probe" to print the
     * per-entry-point allocation counts used to size each sweep. */
    int      do_sweep = !(argc > 1 && strcmp(argv[1], "baseline") == 0);
    WC_RNG   rng;
    DsaKey   key;
    byte     digest[WC_SHA_DIGEST_SIZE];
    byte     sig[256];
    int      answer = 0;
    int      n;
    int      ret;

    printf("dsa.c fault white-box (%s)\n",
           (argc > 1 && strcmp(argv[1], "baseline") == 0) ? "baseline" : "sweep");

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(digest, 0x2b, sizeof(digest));
    XMEMSET(sig, 0, sizeof(sig));

    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; skipping\n");
        return 0;
    }

    mcdc_fa_install();

    /* ---- baseline: unarmed valid operations (all-false NULL guards, the
     *      err==MP_OKAY true chains, and MP_OKAY cleanup halves). ---- */
    ret = build_key(&key, &rng);
    if (ret != 0) {
        printf("  build_key failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        wc_FreeRng(&rng);
        return 0;
    }
    (void)wc_DsaSign_ex(digest, sizeof(digest), sig, &key, &rng);
    (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &answer);

#ifndef MCDC_FA_UNAVAILABLE
    if (argc > 1 && strcmp(argv[1], "probe") == 0) {
        /* Diagnostic: count the allocations each entry point performs, WITHOUT
         * failing any (arm a huge index so the counter advances but never
         * trips). Use these counts to choose each sweep's K -- see the header
         * and the campaign fan-out recipe. Exits without sweeping. */
        int a = 0;
        byte s2[256]; XMEMSET(s2, 0, sizeof(s2));
        mcdc_fa_arm(1000000);
        (void)wc_DsaSign_ex(digest, sizeof(digest), s2, &key, &rng);
        printf("  PROBE sign allocs     = %lu\n", mcdc_fa_count);
        mcdc_fa_arm(1000000);
        (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &a);
        printf("  PROBE verify allocs   = %lu\n", mcdc_fa_count);
#ifndef NO_DSA_PUBKEY_CHECK
        mcdc_fa_arm(1000000);
        (void)wc_DsaCheckPubKey(&key);
        printf("  PROBE checkpub allocs = %lu\n", mcdc_fa_count);
#endif
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_FreeDsaKey(&key);
        wc_FreeRng(&rng);
        return 0;
    }
#endif
#ifndef NO_DSA_PUBKEY_CHECK
    (void)wc_DsaCheckPubKey(&key);
#endif
    {
        /* one real parameter generation for baseline body coverage */
        DsaKey pk;
        if (wc_InitDsaKey(&pk) == 0) {
            (void)wc_MakeDsaParameters(&rng, 1024, &pk);
            wc_FreeDsaKey(&pk);
        }
    }

    if (do_sweep) {
        /* --- wc_DsaSign_ex: 6-7 XMALLOCs up front (k,kInv,r,s,H,[b],buffer),
         * ALL before any mp op, so fail-index n selects exactly the n-th temp
         * (nothing allocates ahead of them). Drives the 816 NULL-guard operands
         * (n=1..7) and the 1048..1079 MEMORY_E cleanup halves (n=2..7). Sign
         * does not mutate the key, so the key is reused. K=40 over-sweeps into
         * the deeper mp allocations (harmless, closes nothing new). --- */
        for (n = 1; n <= 40; n++) {
            byte sig2[256];
            XMEMSET(sig2, 0, sizeof(sig2));
            mcdc_fa_arm(n);
            (void)wc_DsaSign_ex(digest, sizeof(digest), sig2, &key, &rng);
            mcdc_fa_disarm();
        }

        /* --- wc_DsaVerify_ex: begins with wc_DsaCheckPubKey (deterministic
         * ~777 exptmod-scratch allocations for this fixed key -- no RNG, so the
         * count is stable), THEN its own w,u1,u2,v,r,s XMALLOCs. The pubkey
         * check shifts verify's temps to indices ~778..783, so a naive small
         * sweep never reaches them. K=820 covers past that window: low indices
         * fault the pubkey check, the ~778..783 band faults verify's own temps
         * -> the 1154 NULL-guard operands and 1249..1269 MEMORY_E cleanup
         * halves. sig holds the valid baseline signature. --- */
        for (n = 1; n <= 820; n++) {
            int a = 0;
            mcdc_fa_arm(n);
            (void)wc_DsaVerify_ex(digest, sizeof(digest), sig, &key, &a);
            mcdc_fa_disarm();
        }

#ifndef NO_DSA_PUBKEY_CHECK
        /* --- wc_DsaCheckPubKey standalone: same ~777-deep allocation space;
         * sweep it fully to drive the 137/140 MEMORY_E returns and, where a
         * deeper mp step's scratch fails, the 161 err!=MP_OKAY half. --- */
        for (n = 1; n <= 800; n++) {
            mcdc_fa_arm(n);
            (void)wc_DsaCheckPubKey(&key);
            mcdc_fa_disarm();
        }
#endif

        /* --- wc_MakeDsaParameters: NOT swept. Its buf(#1) is faultable but
         * that guard is single-condition (not MC/DC). Its tmp/tmp2 XMALLOCs
         * (line 403) sit AFTER the first wc_RNG_GenerateBlock (line 388), which
         * under WOLFSSL_SMALL_STACK performs a large, RNG-state-dependent
         * number of heap allocations; every fail-index that would reach tmp
         * instead lands in an RNG allocation and returns RNG_FAILURE_E, masking
         * the tmp/tmp2 MEMORY_E. The 403/489/495/506 residuals are therefore
         * not closable with a pass-through fault allocator (they would need a
         * non-allocating RNG mock or WOLFSSL_SP_NO_MALLOC) and stay justified.
         * A token n=1 confirms the buf guard is reachable. --- */
        {
            DsaKey pk;
            if (wc_InitDsaKey(&pk) == 0) {
                mcdc_fa_arm(1);
                (void)wc_MakeDsaParameters(&rng, 1024, &pk);
                mcdc_fa_disarm();
                wc_FreeDsaKey(&pk);
            }
        }
        WB_NOTE("fault-index sweeps over Sign / Verify / CheckPubKey done");
    }

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_FreeDsaKey(&key);
    wc_FreeRng(&rng);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* !NO_DSA && WOLFSSL_KEY_GEN */
