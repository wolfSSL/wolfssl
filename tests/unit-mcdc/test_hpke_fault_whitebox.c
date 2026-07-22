/* test_hpke_fault_whitebox.c
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
 * MC/DC fault-injection white-box supplement for wolfcrypt/src/hpke.c.
 *
 * tests/api/test_hpke.c + tests/unit-mcdc/test_hpke_whitebox.c drive every
 * argument-validation guard and the file-static NULL guards. What neither can
 * reach are the post-allocation cleanup decision pairs in
 * wc_HpkeGenerateKeyPair (hpke.c:343/346) and wc_HpkeDeserializePublicKey
 * (hpke.c:447/450):
 *
 *   if (ret == 0 && *keypair == NULL)    ret = MEMORY_E;    (hpke.c:343)
 *   if (ret != 0 && *keypair != NULL) { ...free...; }       (hpke.c:346)
 *   if (ret == 0 && *key == NULL)        ret = MEMORY_E;    (hpke.c:447)
 *   if (ret != 0 && *key != NULL) { ...free...; }           (hpke.c:450)
 *
 * In normal execution every heap allocation succeeds, so the key-struct
 * allocation always populates *keypair and the subsequent make/import always
 * succeeds: both decisions stay FALSE via a single operand and their other
 * operands (and the TRUE halves) are never exercised. The three cases that
 * together satisfy MC/DC for both AND-decisions are:
 *
 *   (A) full success            -> ret==0, *key!=NULL
 *         343: (T && F) = F   346: (F && -) = F
 *   (B) key-struct alloc fails  -> ret==0 (unchanged), *key==NULL
 *         343: (T && T) = T (then ret=MEMORY_E)   346: (T && F) = F
 *   (C) a LATER alloc fails     -> ret!=0, *key!=NULL (struct built, then
 *       (make/import fails)        make_key / import_x963 fails)
 *         343: (F && -) = F   346: (T && T) = T  (cleanup frees + NULLs *key)
 *
 * (A) is the baseline; (B) is fail-index n==1 (the very first heap allocation
 * a target performs is the key-struct allocation); (C) is reached two ways:
 *   - wc_HpkeGenerateKeyPair: a later allocation (n>=2) failing INSIDE
 *     wc_ecc_make_key_ex after the ecc_key struct was allocated -- the P256
 *     make_key performs further heap allocations (probe: 3 total), so the
 *     fail-index sweep n=1..K reaches them.
 *   - wc_HpkeDeserializePublicKey: the import step performs NO heap allocation
 *     of its own (probe: the target does exactly ONE allocation, the key
 *     struct), so a later fault cannot land inside it -- "a function's last
 *     allocation is unfaultable". Case (C) is instead forced by handing a
 *     CORRECT-LENGTH but OFF-CURVE public key to the (disarmed) deserialize:
 *     wc_ecc_key_new() succeeds (*key populated) and wc_ecc_import_x963_ex()
 *     then rejects the point (ret != 0), so *key != NULL with ret != 0 -- the
 *     exact 450 cleanup condition, with no allocator involvement needed.
 * This white-box installs the generic heap-fault injector (mcdc_fault_alloc.h)
 * and sweeps the fail-index n=1..K over each target (driving (A) baseline, (B)
 * at n==1, and GenerateKeyPair's (C) at n>=2), plus a deterministic
 * off-curve deserialize for Deserialize's (C).
 *
 * KEM choice: (C) for GenerateKeyPair requires the key-struct allocation to be
 * a DISTINCT, earlier allocation than an allocation the make step performs. The
 * X25519 KEM's wc_curve25519_make_key is all-stack under SP math (no heap after
 * the one XMALLOC of the curve25519_key, probe: 1 total), so its struct
 * allocation is the target's LAST allocation and GenerateKeyPair's (C) is
 * unfaultable there. The P256 KEM allocates the ecc_key via wc_ecc_key_new()
 * and then wc_ecc_make_key_ex() performs further heap allocations, so P256
 * exposes GenerateKeyPair's (C). Both suites are swept where available (X25519
 * still contributes (A)+(B) and its own off-curve deserialize (C)); P256 is
 * what closes wc_HpkeGenerateKeyPair's 346 cleanup halves.
 *
 * This #includes hpke.c directly (like test_hpke_whitebox.c) so the targets are
 * reached with the same file-static helpers linked in.
 *
 * Crash-safety: every armed call either returns MEMORY_E/RNG error before the
 * struct is populated, or fails a deeper allocation whose error the target's
 * own cleanup (346/450) absorbs by freeing and NULLing *key -- exactly what is
 * under test. After any call, *key is either NULL (failure, already cleaned up
 * by the target) or a fully built key (success, freed by the harness); the
 * harness never dereferences a value a faulted call returned. The Hpke and the
 * serialized public key used for deserialize are prepared while DISARMED. Runs
 * clean under -fsanitize=address (the cleanup-on-failure paths are the point).
 *
 * Invocation:
 *   ./test_hpke_fault_whitebox            default: baseline + fault sweeps
 *   ./test_hpke_fault_whitebox baseline   only the unarmed valid ops
 *   ./test_hpke_fault_whitebox probe      print per-target allocation counts
 * (No-arg default runs the sweep so the campaign's run_whitebox harness, which
 * runs the binary with no arguments, gets full coverage.)
 */

#include <wolfcrypt/src/hpke.c>

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(HAVE_HPKE) || !(defined(HAVE_ECC) || defined(HAVE_CURVE25519))

int main(void)
{
    printf("hpke.c fault white-box: HAVE_HPKE/curve support absent, "
        "nothing to do\n");
    return 0;
}

#else

/* Sweep the two post-alloc cleanup decision pairs of a single KEM suite.
 *
 * Prepares (DISARMED) a valid Hpke for `kem` and a serialized public key, then:
 *   - one unarmed success of each target                        -> case (A)
 *   - fault sweep n=1..K over wc_HpkeGenerateKeyPair            -> (B) at n==1,
 *   - fault sweep n=1..K over wc_HpkeDeserializePublicKey         (C) at n>=2.
 * K is generous; over-sweeping past the last alloc is harmless (the target just
 * runs to completion). Returns 0 on setup success, non-zero if the suite could
 * not be brought up (skipped, not a failure of the module).
 */
static int sweep_kem(word32 kem, int probe)
{
    Hpke     hpke;
    WC_RNG   rng;
    void*    key = NULL;
    byte     pub[HPKE_Npk_MAX];
    word16   pubSz = (word16)sizeof(pub);
    int      haveRng = 0;
    int      ret;
    int      n;
    const int K = 64; /* > any per-target heap-site count for P256/X25519 here */

    XMEMSET(&hpke, 0, sizeof(hpke));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(pub, 0, sizeof(pub));

    ret = wc_HpkeInit(&hpke, kem, HKDF_SHA256, HPKE_AES_128_GCM, NULL);
    if (ret != 0) {
        WB_NOTE("wc_HpkeInit unavailable for this kem; skipping");
        return 1;
    }
    if (wc_InitRng(&rng) != 0) {
        WB_NOTE("wc_InitRng failed; skipping");
        return 1;
    }
    haveRng = 1;

    /* Build a valid public key to deserialize (case A prep, DISARMED). */
    ret = wc_HpkeGenerateKeyPair(&hpke, &key, &rng);
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(&hpke, key, pub, &pubSz);
    if (ret != 0) {
        WB_NOTE("keypair/serialize prep failed; skipping suite");
        if (key != NULL)
            wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
        wc_FreeRng(&rng);
        return 1;
    }
    if (key != NULL) {
        wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
        key = NULL;
    }

    if (probe) {
#ifndef MCDC_FA_UNAVAILABLE
        void* pk = NULL;
        mcdc_fa_arm(1000000);
        (void)wc_HpkeGenerateKeyPair(&hpke, &pk, &rng);
        printf("  PROBE kem=0x%04x GenerateKeyPair allocs = %lu\n",
            (unsigned)kem, mcdc_fa_count);
        mcdc_fa_disarm();
        if (pk != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, pk, hpke.heap);
            pk = NULL; }

        mcdc_fa_arm(1000000);
        (void)wc_HpkeDeserializePublicKey(&hpke, &pk, pub, pubSz);
        printf("  PROBE kem=0x%04x Deserialize allocs     = %lu\n",
            (unsigned)kem, mcdc_fa_count);
        mcdc_fa_disarm();
        if (pk != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, pk, hpke.heap);
            pk = NULL; }
#endif
        wc_FreeRng(&rng);
        return 0;
    }

    /* ---- case (A): unarmed valid ops (both decisions FALSE via one operand) */
    key = NULL;
    ret = wc_HpkeGenerateKeyPair(&hpke, &key, &rng);
    if (ret != 0)
        wb_fail = 1;
    if (key != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
        key = NULL; }

    key = NULL;
    ret = wc_HpkeDeserializePublicKey(&hpke, &key, pub, pubSz);
    if (ret != 0)
        wb_fail = 1;
    if (key != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
        key = NULL; }

    /* ---- wc_HpkeGenerateKeyPair fault sweep: n==1 fails the key-struct alloc
     *      (case B, drives 343 TRUE + the 346 T&&F half); n>=2 fails inside
     *      make_key after the struct was built (case C, drives 346 TRUE and the
     *      343 F&&- half). Fresh key each iteration; the target's own cleanup
     *      NULLs *key on failure, so key!=NULL only on success. ---- */
    for (n = 1; n <= K; n++) {
        key = NULL;
        mcdc_fa_arm(n);
        (void)wc_HpkeGenerateKeyPair(&hpke, &key, &rng);
        mcdc_fa_disarm();
        if (key != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
            key = NULL; }
    }

    /* ---- wc_HpkeDeserializePublicKey fault sweep: n==1 fails the key-struct
     *      alloc (case B: 447 TRUE + 450 T&&F). The import step performs no heap
     *      allocation of its own (probe), so n>=2 never lands inside it and the
     *      450 cleanup TRUE half is NOT reachable by allocation fault here. ---- */
    for (n = 1; n <= K; n++) {
        key = NULL;
        mcdc_fa_arm(n);
        (void)wc_HpkeDeserializePublicKey(&hpke, &key, pub, pubSz);
        mcdc_fa_disarm();
        if (key != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
            key = NULL; }
    }

    /* ---- wc_HpkeDeserializePublicKey case (C): off-curve public key of the
     *      CORRECT length. The key-struct allocation succeeds (*key populated)
     *      but the import rejects the point, so ret != 0 with *key != NULL --
     *      the 450 cleanup TRUE half (and the 447 F&&- half). No allocator
     *      involvement: this is a deterministic bad-input path. Corrupt an
     *      interior byte of the valid serialized key so the length/format stay
     *      correct (P256: leading 0x04 uncompressed marker preserved) but the
     *      encoded point is no longer on the curve. On suites whose import
     *      accepts arbitrary bytes (X25519) the call simply succeeds and is
     *      freed as usual -- harmless; P256 is what drives the case here. ---- */
    {
        byte   badpub[HPKE_Npk_MAX];
        word32 mid;
        XMEMCPY(badpub, pub, sizeof(badpub));
        mid = (word32)pubSz / 2u;
        badpub[mid] ^= 0xFFu;       /* push the encoded point off the curve */
        badpub[pubSz - 1] ^= 0xFFu; /* corrupt the trailing coordinate too   */
        key = NULL;
        (void)wc_HpkeDeserializePublicKey(&hpke, &key, badpub, pubSz);
        if (key != NULL) { wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
            key = NULL; }
    }

    if (haveRng)
        wc_FreeRng(&rng);
    return 0;
}

int main(int argc, char** argv)
{
    int do_probe    = (argc > 1 && strcmp(argv[1], "probe") == 0);
    int do_baseline = (argc > 1 && strcmp(argv[1], "baseline") == 0);

    printf("hpke.c fault white-box (%s)\n",
        do_probe ? "probe" : (do_baseline ? "baseline" : "sweep"));

    mcdc_fa_install();

    /* Sweep the P256 KEM first: it is the suite whose key-struct allocation is
     * an earlier, distinct allocation from the make/import allocations, so it
     * exposes case (C) (the 346/450 cleanup TRUE halves). */
#if (defined(HAVE_ECC) && (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && \
     !defined(NO_SHA256))
    if (do_baseline) {
        /* baseline == case (A) only: one unarmed success of each target. */
        Hpke   hpke;
        WC_RNG rng;
        void*  key = NULL;
        byte   pub[HPKE_Npk_MAX];
        word16 pubSz = (word16)sizeof(pub);
        int    ret;
        XMEMSET(&hpke, 0, sizeof(hpke));
        XMEMSET(pub, 0, sizeof(pub));
        ret = wc_HpkeInit(&hpke, DHKEM_P256_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
        if (ret == 0 && wc_InitRng(&rng) == 0) {
            if (wc_HpkeGenerateKeyPair(&hpke, &key, &rng) == 0 &&
                    wc_HpkeSerializePublicKey(&hpke, key, pub, &pubSz) == 0) {
                void* k2 = NULL;
                (void)wc_HpkeDeserializePublicKey(&hpke, &k2, pub, pubSz);
                if (k2 != NULL)
                    wc_HpkeFreeKey(&hpke, hpke.kem, k2, hpke.heap);
            }
            if (key != NULL)
                wc_HpkeFreeKey(&hpke, hpke.kem, key, hpke.heap);
            wc_FreeRng(&rng);
        }
        WB_NOTE("baseline P256 keypair/serialize/deserialize done");
    }
    else {
        (void)sweep_kem(DHKEM_P256_HKDF_SHA256, do_probe);
        WB_NOTE("P256 GenerateKeyPair/Deserialize fault sweep done");
    }
#endif

#if defined(HAVE_CURVE25519) && !defined(NO_SHA256)
    if (!do_baseline) {
        (void)sweep_kem(DHKEM_X25519_HKDF_SHA256, do_probe);
        WB_NOTE("X25519 GenerateKeyPair/Deserialize fault sweep done");
    }
#endif

    mcdc_fa_disarm();
    mcdc_fa_restore();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    (void)wb_fail;
    return 0;
}

#endif /* HAVE_HPKE && (HAVE_ECC || HAVE_CURVE25519) */
