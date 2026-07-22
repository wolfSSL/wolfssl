/* test_mldsa_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/wc_mldsa.c.
 *
 * wc_mldsa.c's dominant *alloc-related* uncovered class is the FALSE half of
 * "success chain" decisions of the shape
 *
 *   for (r = 0; (ret == 0) && (r < k); r++) ...        (drive ret==0 on FALSE)
 *   while ((ret == 0) && (!valid)) ...                 (drive ret==0 on FALSE)
 *   if ((ret == 0) && (*sigLen < params->sigSz)) ...   (drive ret==0 on FALSE)
 *
 * inside make-key / sign / verify / expand-matrix / expand-secret /
 * sample-in-ball and the encode/decode entry points. In normal execution every
 * XMALLOC succeeds, so `ret` stays 0 across the whole primitive and the FALSE
 * half of each of these `(ret == 0)` operands is never exercised. The only way
 * to make `ret` become non-zero mid-computation (so the loop/guard re-evaluates
 * to FALSE) is to make one of the many heap allocations these routines perform
 * fail.
 *
 * This white-box installs the generic heap-fault injector (mcdc_fault_alloc.h,
 * validated on dsa.c) and, for each entry point, sweeps the fail-index across
 * that routine's allocation sites: for fail-index n, exactly the n-th (and
 * every later) XMALLOC/XREALLOC returns NULL, so exactly one allocation on the
 * path fails and `ret` becomes MEMORY_E. Because ML-DSA allocates working
 * buffers not only up front but INSIDE the expand-A / expand-S / sample-in-ball
 * inner loops (rand/state SHAKE scratch), sweeping the whole index range drives
 * the `ret==0` FALSE half of the inner-loop guards too, not just the top-level
 * buffer guard.
 *
 * These working-buffer allocations exist in every variant with the base
 * campaign config (the WC_MLDSA_CACHE_* caching macros are OFF, so sign/verify
 * XMALLOC their scratch on every call); they multiply under the small-memory
 * arms (WOLFSSL_MLDSA_SIGN_SMALL_MEM / _VERIFY_SMALL_MEM /
 * _SIGN_SMALL_MEM_PRECALC_A), whose per-column recompute blocks add extra
 * `(ret==0)&&(...)` loops -- which is why this supplement is most productive
 * under the small-mem variants but builds and runs (closing the cached-path
 * chains) under every variant.
 *
 * NOT closable here (reported out of scope, left for a data-path effort):
 *   - the IS_INTEL_AVX2(cpuid_flags) && SAVE_VECTOR_REGISTERS2()==0 dispatch
 *     guards (AVX2 variant only; the host always has AVX2 -> C-fallback half is
 *     the intel-dispatch residual class, same as sha/chacha);
 *   - the rejection-sampling `while ((ctr0<MLDSA_N) || ...)` coefficient-count
 *     loops (data-path: which counter crosses MLDSA_N is a function of the
 *     sampled bytes, not of allocation);
 *   - the verify `valid` operand of `(ret==0) && valid` (needs a signature that
 *     fails an intermediate check -- data-path, not allocation);
 *   - NULL/param/length guards (need malformed inputs) and the OID-retry
 *     `(ret != 0) && (oidLen == ...)` decode cascade (wrong-OID data path).
 *
 * It #includes wc_mldsa.c directly (like the other unit-mcdc white-boxes) so
 * the file-static mldsa_expand_* / mldsa_sign_* / mldsa_verify_* helpers are in
 * scope and the working-buffer allocation sites are reachable.
 *
 * Crash-safety: every armed call either returns MEMORY_E before touching any
 * intermediate, or fails a deeper allocation whose error the routine's own
 * cleanup absorbs (that cleanup is exactly what is under test). All key/DER
 * inputs are prepared while DISARMED; the harness never dereferences a value a
 * faulted call returned, and rebuilds a fresh key for make-key / decode sweeps
 * (which write into the key) while reusing the read-only baseline key for
 * sign / verify / export. With the base config the WC_MLDSA_CACHE_* macros are
 * OFF, so sign/verify do not mutate the key. Runs clean under
 * -fsanitize=address.
 *
 * Invocation:
 *   ./test_mldsa_fault_whitebox            default: baseline + fault sweeps
 *   ./test_mldsa_fault_whitebox baseline   unarmed valid ops only (delta base)
 *   ./test_mldsa_fault_whitebox probe      print per-entry-point alloc counts
 * (The campaign run_whitebox harness runs this binary with NO arguments, so the
 * default action is the full sweep.)
 *
 * WHY WOLFSSL_SMALL_STACK IS FORCED BELOW
 * ---------------------------------------
 * ML-DSA does NOT allocate a temporary per operation the way dsa.c does under
 * WOLFSSL_SMALL_STACK. In the default / small-mem builds it performs ONE bulk
 * XMALLOC of a working buffer and then carves every intermediate out of it,
 * running the sampling/NTT/pack helpers on that buffer (or on stack scratch).
 * The `(ret == 0) && ...` success-chain loops are all nested inside an outer
 * `if (ret == 0)` that follows that single allocation, so failing it returns
 * MEMORY_E BEFORE the loops are reached -- their FALSE half is never exercised.
 *
 * The only shape in which an allocation failure can make `ret` become non-zero
 * *inside* an expand/sign loop is when the loop body itself allocates. That
 * happens exclusively in the file-static sampling helpers (mldsa_rej_ntt_poly,
 * mldsa_expand_s's per-poly path, the sign rejection loop) and ONLY under
 * WOLFSSL_SMALL_STACK -- the source comment on wc_mldsa_gen_matrix_*_avx2 spells
 * this out: "MEMORY_E ... Only possible when WOLFSSL_SMALL_STACK is defined."
 * Without SMALL_STACK those helpers use stack scratch and cannot fail, so the
 * ret==0 loop operands are loop-invariant and unreachable by any allocator.
 *
 * We therefore force WOLFSSL_SMALL_STACK for THIS translation unit's *included*
 * copy of wc_mldsa.c. WOLFSSL_SMALL_STACK gates no field of any struct that
 * crosses the wc_mldsa.c <-> library boundary (verified: no SMALL_STACK
 * conditional in wc_Sha3/wc_Shake/wc_MlDsaKey/WC_RNG), so linking this TU
 * against a variant library built WITHOUT SMALL_STACK is ABI-safe; only this
 * file's own mldsa temporaries move to the heap, where the injector can fail
 * them. (Defined before the include so wc_mldsa.c's function-body
 * `#if defined(WOLFSSL_SMALL_STACK)` scratch-allocation blocks compile in.)
 */

#ifndef WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK
#endif

#include <wolfcrypt/src/wc_mldsa.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_HAVE_MLDSA)

int main(void)
{
    printf("wc_mldsa.c fault white-box: WOLFSSL_HAVE_MLDSA not set, nothing to do\n");
    return 0;
}

#else

/* ML-DSA-44: smallest param set -> fastest keygen/sign under instrumentation. */
#define WB_LEVEL WC_ML_DSA_44

/* Fixed deterministic seeds so make-key / sign alloc counts are stable across
 * sweep iterations (no RNG allocation variance). MLDSA_SEED_SZ == MLDSA_RND_SZ
 * == 32. */
static byte s_keySeed[MLDSA_SEED_SZ];
static byte s_sigSeed[MLDSA_RND_SZ];
static byte s_msg[32];

/* Generously sized fixed output buffers (ML-DSA-44 sig ~2420, pub ~1312,
 * priv ~2560; DER adds header/OID overhead). File scope keeps them off the
 * ASAN stack. */
static byte s_sig[8192];
static byte s_pubRaw[4096];
static byte s_privRaw[8192];
static byte s_pubDer[8192];
static byte s_privDer[16384];

/* Sweep depths. Chosen a comfortable margin above the probed per-entry-point
 * allocation counts; over-sweeping past the site count is harmless (the target
 * then simply runs to completion / returns success and closes nothing new). */
#define K_MAKEKEY 64
#define K_SIGN    48
#define K_VERIFY  32
#define K_DECODE  32
#define K_EXPORT  16

/* Build a fully populated (params + private) ML-DSA key from the fixed seed.
 * Must be called DISARMED. */
static int build_key(wc_MlDsaKey* key)
{
    int ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(key, WB_LEVEL);
    }
    if (ret == 0) {
        ret = wc_MlDsaKey_MakeKeyFromSeed(key, s_keySeed);
    }
    return ret;
}

#ifndef MCDC_FA_UNAVAILABLE
/* Fault-sweep make-key: fresh key each iteration (make-key writes into the
 * key). Drives the make-key / expand-A / expand-S / sample `ret==0` chains. */
static void sweep_makekey(void)
{
    int n;
    for (n = 1; n <= K_MAKEKEY; n++) {
        wc_MlDsaKey k;
        if (wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID) == 0) {
            (void)wc_MlDsaKey_SetParams(&k, WB_LEVEL);
            mcdc_fa_arm(n);
            (void)wc_MlDsaKey_MakeKeyFromSeed(&k, s_keySeed);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&k);
        }
    }
}

/* Fault-sweep sign: reuse the valid baseline key (with the base config the
 * CACHE macros are OFF, so sign allocates all scratch fresh and does not mutate
 * the key). Deterministic seed -> stable rejection-sampling alloc count.
 * Drives the sign / expand / sample-in-ball / small-mem per-column `ret==0`
 * chains and the `(ret==0)&&(*sigLen<sigSz)` guard. */
static void sweep_sign(wc_MlDsaKey* key)
{
    int n;
    for (n = 1; n <= K_SIGN; n++) {
        word32 sigLen = (word32)sizeof(s_sig);
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_SignCtxWithSeed(key, NULL, 0, s_sig, &sigLen, s_msg,
            (word32)sizeof(s_msg), s_sigSeed);
        mcdc_fa_disarm();
    }
}

/* Fault-sweep verify: reuse the valid baseline key + a valid baseline
 * signature. Deterministic. Drives verify / expand-A / small-mem per-column
 * `ret==0` chains. */
static void sweep_verify(wc_MlDsaKey* key, const byte* sig, word32 sigLen)
{
    int n;
    for (n = 1; n <= K_VERIFY; n++) {
        int res = 0;
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_VerifyCtx(key, sig, sigLen, NULL, 0, s_msg,
            (word32)sizeof(s_msg), &res);
        mcdc_fa_disarm();
    }
}

/* Fault-sweep the read-only export entry points (reuse the baseline key). */
static void sweep_export(wc_MlDsaKey* key)
{
    int n;
    for (n = 1; n <= K_EXPORT; n++) {
        word32 l1 = (word32)sizeof(s_pubRaw);
        word32 l2 = (word32)sizeof(s_privRaw);
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_ExportPubRaw(key, s_pubRaw, &l1);
        mcdc_fa_disarm();
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_ExportPrivRaw(key, s_privRaw, &l2);
        mcdc_fa_disarm();
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_PublicKeyToDer(key, s_pubDer, (word32)sizeof(s_pubDer),
            1);
        mcdc_fa_disarm();
        mcdc_fa_arm(n);
        (void)wc_MlDsaKey_PrivateKeyToDer(key, s_privDer,
            (word32)sizeof(s_privDer));
        mcdc_fa_disarm();
    }
}

/* Fault-sweep the decode entry points: fresh key each iteration (decode writes
 * into the key). Valid DER prepared while disarmed. Drives the decode
 * `(ret==0) && (length==0)` and import `ret==0` chains. */
static void sweep_decode(const byte* pubDer, word32 pubDerLen,
    const byte* privDer, word32 privDerLen)
{
    int n;
    for (n = 1; n <= K_DECODE; n++) {
        wc_MlDsaKey k;
        if ((pubDerLen > 0) && (wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID) == 0)) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&k, WB_LEVEL);
            mcdc_fa_arm(n);
            (void)wc_MlDsaKey_PublicKeyDecode(&k, pubDer, pubDerLen, &idx);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&k);
        }
        if ((privDerLen > 0) && (wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID) == 0)) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&k, WB_LEVEL);
            mcdc_fa_arm(n);
            (void)wc_MlDsaKey_PrivateKeyDecode(&k, privDer, privDerLen, &idx);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&k);
        }
    }
}
#endif /* !MCDC_FA_UNAVAILABLE */

int main(int argc, char** argv)
{
    int      do_baseline_only =
                 (argc > 1 && strcmp(argv[1], "baseline") == 0);
    int      do_probe = (argc > 1 && strcmp(argv[1], "probe") == 0);
    wc_MlDsaKey key;
    word32   sigLen = (word32)sizeof(s_sig);
    int      pubDerLen = 0;
    int      privDerLen = 0;
    int      res = 0;
    int      ret;

    printf("wc_mldsa.c fault white-box (%s)\n",
           do_baseline_only ? "baseline" : (do_probe ? "probe" : "sweep"));

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(s_keySeed, 0x2b, sizeof(s_keySeed));
    XMEMSET(s_sigSeed, 0x5c, sizeof(s_sigSeed));
    XMEMSET(s_msg,     0xa7, sizeof(s_msg));
    XMEMSET(s_sig,     0, sizeof(s_sig));

    mcdc_fa_install();

    /* ---- baseline: unarmed valid operations (all-false chains, the ret==0
     *      TRUE halves, the success cleanup halves). ---- */
    ret = build_key(&key);
    if (ret != 0) {
        printf("  build_key failed (%d); skipping\n", ret);
        mcdc_fa_restore();
        return 0;
    }

    ret = wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, s_sig, &sigLen, s_msg,
        (word32)sizeof(s_msg), s_sigSeed);
    if (ret != 0) {
        printf("  baseline sign failed (%d)\n", ret);
        wb_fail = 1;
    }
    res = 0;
    (void)wc_MlDsaKey_VerifyCtx(&key, s_sig, sigLen, NULL, 0, s_msg,
        (word32)sizeof(s_msg), &res);

    {
        word32 l = (word32)sizeof(s_pubRaw);
        (void)wc_MlDsaKey_ExportPubRaw(&key, s_pubRaw, &l);
        l = (word32)sizeof(s_privRaw);
        (void)wc_MlDsaKey_ExportPrivRaw(&key, s_privRaw, &l);
    }

    pubDerLen  = wc_MlDsaKey_PublicKeyToDer(&key, s_pubDer,
        (word32)sizeof(s_pubDer), 1);
    if (pubDerLen < 0) {
        pubDerLen = 0;
    }
    privDerLen = wc_MlDsaKey_PrivateKeyToDer(&key, s_privDer,
        (word32)sizeof(s_privDer));
    if (privDerLen < 0) {
        privDerLen = 0;
    }
    /* one unarmed round trip through the decode paths for baseline coverage */
    if (pubDerLen > 0) {
        wc_MlDsaKey dk;
        if (wc_MlDsaKey_Init(&dk, NULL, INVALID_DEVID) == 0) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&dk, WB_LEVEL);
            (void)wc_MlDsaKey_PublicKeyDecode(&dk, s_pubDer,
                (word32)pubDerLen, &idx);
            wc_MlDsaKey_Free(&dk);
        }
    }
    if (privDerLen > 0) {
        wc_MlDsaKey dk;
        if (wc_MlDsaKey_Init(&dk, NULL, INVALID_DEVID) == 0) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&dk, WB_LEVEL);
            (void)wc_MlDsaKey_PrivateKeyDecode(&dk, s_privDer,
                (word32)privDerLen, &idx);
            wc_MlDsaKey_Free(&dk);
        }
    }

#ifndef MCDC_FA_UNAVAILABLE
    if (do_probe) {
        /* Diagnostic: count the allocations each entry point performs WITHOUT
         * tripping any (arm a huge index so the counter advances but never
         * fails). Use these counts to size each sweep's K. Exits without
         * sweeping. */
        wc_MlDsaKey pk;
        word32 sl = (word32)sizeof(s_sig);
        int r = 0;

        if (wc_MlDsaKey_Init(&pk, NULL, INVALID_DEVID) == 0) {
            (void)wc_MlDsaKey_SetParams(&pk, WB_LEVEL);
            mcdc_fa_arm(1000000);
            (void)wc_MlDsaKey_MakeKeyFromSeed(&pk, s_keySeed);
            printf("  PROBE makekey allocs = %lu\n", mcdc_fa_count);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&pk);
        }
        mcdc_fa_arm(1000000);
        (void)wc_MlDsaKey_SignCtxWithSeed(&key, NULL, 0, s_sig, &sl, s_msg,
            (word32)sizeof(s_msg), s_sigSeed);
        printf("  PROBE sign allocs    = %lu\n", mcdc_fa_count);
        mcdc_fa_arm(1000000);
        (void)wc_MlDsaKey_VerifyCtx(&key, s_sig, sigLen, NULL, 0, s_msg,
            (word32)sizeof(s_msg), &r);
        printf("  PROBE verify allocs  = %lu\n", mcdc_fa_count);
        if (pubDerLen > 0 &&
                wc_MlDsaKey_Init(&pk, NULL, INVALID_DEVID) == 0) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&pk, WB_LEVEL);
            mcdc_fa_arm(1000000);
            (void)wc_MlDsaKey_PublicKeyDecode(&pk, s_pubDer,
                (word32)pubDerLen, &idx);
            printf("  PROBE pubdecode allocs = %lu\n", mcdc_fa_count);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&pk);
        }
        if (privDerLen > 0 &&
                wc_MlDsaKey_Init(&pk, NULL, INVALID_DEVID) == 0) {
            word32 idx = 0;
            (void)wc_MlDsaKey_SetParams(&pk, WB_LEVEL);
            mcdc_fa_arm(1000000);
            (void)wc_MlDsaKey_PrivateKeyDecode(&pk, s_privDer,
                (word32)privDerLen, &idx);
            printf("  PROBE privdecode allocs = %lu\n", mcdc_fa_count);
            mcdc_fa_disarm();
            wc_MlDsaKey_Free(&pk);
        }
        mcdc_fa_disarm();
        mcdc_fa_restore();
        wc_MlDsaKey_Free(&key);
        return 0;
    }
#endif

#ifndef MCDC_FA_UNAVAILABLE
    if (!do_baseline_only) {
        sweep_makekey();
        sweep_sign(&key);
        sweep_verify(&key, s_sig, sigLen);
        sweep_export(&key);
        sweep_decode(s_pubDer, (word32)pubDerLen, s_privDer,
            (word32)privDerLen);
        WB_NOTE("fault-index sweeps over MakeKey / Sign / Verify / Export / "
                "Decode done");
    }
#else
    WB_NOTE("fault injector unavailable in this variant (static/debug memory)");
#endif

    mcdc_fa_disarm();
    mcdc_fa_restore();
    wc_MlDsaKey_Free(&key);

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* WOLFSSL_HAVE_MLDSA */
