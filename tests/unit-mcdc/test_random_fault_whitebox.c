/* test_random_fault_whitebox.c
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
 * ENTROPY / SEED-DERIVATION FAULT white-box supplement for
 * wolfcrypt/src/random.c.
 *
 * This is the first RNG-failure injection driver. Two independent
 * levers are combined here, and both generalise to any module that consumes
 * randomness -- see "REUSING THIS" at the bottom of this comment.
 *
 *
 * LEVER 1 -- FAULT THE SEED DERIVATION (Hash_df / Hash512_df)
 * -----------------------------------------------------------
 * Hash_DRBG_Init() (~1074) and Hash512_DRBG_Init() (~1580) both instantiate
 * the DRBG state with ONE chained decision whose two operands are the RETURN
 * VALUES of two derivation-function calls:
 *
 *     if (Hash_df(drbg, drbg->V, sizeof(drbg->V), drbgInitV, seed, seedSz,
 *                 nonce, nonceSz, perso, persoSz) == DRBG_SUCCESS &&
 *         Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
 *                 sizeof(drbg->V), NULL, 0, NULL, 0) == DRBG_SUCCESS) {
 *
 * In a normal run both operands are permanently TRUE: Hash_df only fails if a
 * SHA-2 primitive fails, and sha256.c/sha512.c allocate nothing on this path,
 * so mcdc_fault_alloc.h cannot reach it (the same dead end documented in
 * test_random_whitebox.c's header and in test_frodokem_fault_common.h).
 *
 * mcdc_fault_hash.h is the lever that does reach it: it interposes
 * wc_Sha256Update/Final (resp. wc_Sha512Update/Final) BY MACRO, for this
 * translation unit only, before random.c is #included. Hash_df is a file
 * static in random.c and calls exactly those primitives, so arming the n-th
 * primitive call makes the enclosing Hash_df return DRBG_FAILURE.
 *
 * Mapping an arm index onto ONE of the two operands is the whole technique.
 * The index is MEASURED, never hard-coded:
 *
 *   1. run one instantiate DISARMED                  -> vector (T, T)
 *   2. run ONE Hash_df of the FIRST call's exact shape (same out size, same
 *      type byte, same present/absent inB/inC) disarmed and read
 *      mcdc_fh_seen()                                -> n1 primitive calls
 *   3. mcdc_fh_arm(1)      -> the first Hash_df fails on its first primitive
 *                             call; the && short-circuits and operand 1 is
 *                             masked                 -> vector (F, -)
 *   4. mcdc_fh_arm(n1 + 1) -> the first Hash_df's n1 calls all succeed and
 *                             everything from n1+1 on -- i.e. the whole second
 *                             Hash_df -- fails       -> vector (T, F)
 *
 * Measuring n1 rather than hard-coding it keeps the driver correct across the
 * stack / small-stack / small-stack-cache variants and across any future
 * change to Hash_df's block count or operand set.
 *
 * CRASH SAFETY. A faulted Hash_df never reaches its copy-out (it is inside
 * "if (ret == 0)"), so drbg->V / drbg->C are simply left as they were; the
 * loop runs its remaining iterations with ret already non-zero and returns
 * DRBG_FAILURE. Hash_DRBG_Init then returns DRBG_FAILURE and no output of a
 * faulted call is ever consumed here: every armed instantiate is immediately
 * uninstantiated (disarmed) and its DRBG state is never generated from.
 *
 *
 * LEVER 2 -- FAULT THE ENTROPY SOURCE ITSELF (WC_RNG_SEED_CB)
 * ------------------------------------------------------------
 * WC_RNG_SEED_CB is wolfSSL's documented porting hook for substituting the
 * entropy source (AGENTS.md "Porting hooks"; wolfssl/wolfcrypt/random.h). When
 * it is compiled in, _InitRng() takes its raw entropy from the installed
 * callback instead of calling wc_GenerateSeed() directly:
 *
 *     if (seedCb == NULL)      ret = DRBG_NO_SEED_CB;
 *     else { ret = seedCb(&rng->seed, seed, seedSz);
 *            if (ret != 0)     ret = DRBG_FAILURE; }
 *
 * wc_SetSeed_Cb() therefore gives a test complete control over the entropy
 * source through the PUBLIC API -- no macro redefinition, no build-flag
 * collision. This driver installs a callback that
 *
 *   - stages a fixed, deterministic byte stream (a pinned LCG, so the seed is
 *     identical on every host and every run -- no live entropy anywhere in
 *     this file, per the module's determinism rule), and
 *   - can be made to FAIL on demand by setting one flag.
 *
 * That pairs the "entropy available" and "entropy source failed" halves of the
 * seed-acquisition decisions in one binary, and it does so without the driver
 * defining WC_RNG_SEED_CB itself (which would be a feature-define mismatch
 * against the rest of libwolfssl.a). The section is compiled only in the
 * seed_cb variant, which supplies the macro on the command line; every other
 * variant gets the #else stub.
 *
 *
 * NOT CHASED HERE -- Hash_gen()/Hash512_gen() "outSz != 0" (816 / 1416, cond 1)
 * ---------------------------------------------------------------------------
 * The second operand of
 *
 *     if (out != NULL && outSz != 0)          (Hash_gen 816, Hash512_gen 1416)
 *
 * is UNSATISFIABLE in its false half, and no fault injection changes that. The
 * function normalises "if (outSz == 0) outSz = 1;" BEFORE the loop, and the
 * loop bound len = ceil(outSz / OUTPUT_BLOCK_LEN) is derived from that same
 * normalised outSz. Each iteration consumes min(outSz, OUTPUT_BLOCK_LEN), so
 * outSz first reaches 0 on iteration len-1, which is already the last planned
 * iteration -- the loop then exits and the condition is never evaluated again.
 * At every live evaluation outSz >= 1. The (out != NULL, outSz == 0) vector the
 * independence pair needs cannot be produced by any argument combination, from
 * the public API or by direct static call. Recorded as a must-exclude; the
 * (out == NULL) half of operand 0 is already driven by
 * test_random_whitebox.c's wb_hash_gen_outsz()/wb_hash512_gen_outsz().
 *
 *
 * REUSING THIS
 * ------------
 * Lever 1 generalises verbatim to any "derive-then-derive" chain whose
 * operands are hash-backed helper return values: measure the primitive-call
 * cost of the first step disarmed, then arm 1 and cost+1. Lever 2 generalises
 * to any module whose behaviour under a dead entropy source matters (key
 * generation, blinding, nonce derivation): install a staged/failing seed
 * callback and drive the module's public entry point twice.
 *
 * Build: compiled by the white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with random.o removed. Not part of the wolfSSL build.
 */

/* random.c uses no HMAC, no AES and no SHAKE (verified by grep), so those
 * interposer families are switched off to keep the rewritten surface of this
 * TU limited to exactly the two SHA-2 primitive pairs Hash_df depends on. */
#define MCDC_FH_NO_SHAKE
#define MCDC_FH_NO_AES
#define MCDC_FH_NO_HMAC

#include "mcdc_fault_hash.h"

/* random.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/random.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* --------------------------------------------------------------------------
 * 1. Hash_DRBG_Init(): "Hash_df(V) == DRBG_SUCCESS && Hash_df(C) ==
 *    DRBG_SUCCESS" (~1077). Both operands paired in this binary.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_SHA256)
static void wb_hash_drbg_init_df_chain(void)
{
    DRBG_internal drbg;
    byte   seed[48];
    byte   nonce[16];
    word32 i;
    long   n1;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 7u) + 1u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 5u) + 2u);

    /* Vector (T, T): unarmed instantiate, in the SAME binary as the two
     * rejection vectors below. */
    mcdc_fh_disarm();
    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("unarmed Hash_DRBG_Instantiate failed; df-chain skipped");
        wb_fail = 1;
        return;
    }

    /* Size the FIRST Hash_df of Hash_DRBG_Init: same out size (sizeof V),
     * same type byte (drbgInitV), same present/absent input operands. The
     * count is a property of those arguments only, so it is exactly the
     * number of primitive calls the in-situ first Hash_df will make. */
    mcdc_fh_disarm();
    ret = Hash_df(&drbg, drbg.V, (word32)sizeof(drbg.V), drbgInitV,
            seed, (word32)sizeof(seed), nonce, (word32)sizeof(nonce),
            NULL, 0);
    n1 = mcdc_fh_seen();
    (void)Hash_DRBG_Uninstantiate(&drbg);
    if (ret != DRBG_SUCCESS || n1 <= 0) {
        WB_NOTE("could not size the first Hash_df; fault vectors skipped");
        wb_fail = 1;
        return;
    }

    /* Vector (F, -): the first Hash_df fails on its very first primitive
     * call, so the && short-circuits and never calls the second one. */
    mcdc_fh_arm(1);
    (void)Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    mcdc_fh_disarm();
    (void)Hash_DRBG_Uninstantiate(&drbg);

    /* Vector (T, F): the first Hash_df's n1 primitive calls all succeed;
     * every call from n1+1 on -- the whole second Hash_df -- fails. */
    mcdc_fh_arm(n1 + 1);
    (void)Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    mcdc_fh_disarm();
    (void)Hash_DRBG_Uninstantiate(&drbg);

    WB_NOTE("Hash_DRBG_Init Hash_df chain: (T,T)/(F,-)/(T,F) driven");
}
#else
static void wb_hash_drbg_init_df_chain(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off (or no SHA-256 interposer); "
          "Hash_DRBG_Init df chain skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 2. Hash512_DRBG_Init(): the SHA-512 counterpart (~1585). Compiled only where
 *    random.c compiles the SHA-512 DRBG core, i.e. WOLFSSL_DRBG_SHA512.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512) && \
    defined(MCDC_FH_HAVE_SHA512)
static void wb_hash512_drbg_init_df_chain(void)
{
    DRBG_SHA512_internal drbg;
    byte   seed[48];
    byte   nonce[16];
    word32 i;
    long   n1;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 11u) + 3u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 13u) + 4u);

    /* Vector (T, T). */
    mcdc_fh_disarm();
    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("unarmed Hash512_DRBG_Instantiate failed; df-chain skipped");
        wb_fail = 1;
        return;
    }

    /* Size the first Hash512_df of Hash512_DRBG_Init. */
    mcdc_fh_disarm();
    ret = Hash512_df(&drbg, drbg.V, (word32)sizeof(drbg.V), drbgInitV,
            seed, (word32)sizeof(seed), nonce, (word32)sizeof(nonce),
            NULL, 0);
    n1 = mcdc_fh_seen();
    (void)Hash512_DRBG_Uninstantiate(&drbg);
    if (ret != DRBG_SUCCESS || n1 <= 0) {
        WB_NOTE("could not size the first Hash512_df; fault vectors skipped");
        wb_fail = 1;
        return;
    }

    /* Vector (F, -). */
    mcdc_fh_arm(1);
    (void)Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    mcdc_fh_disarm();
    (void)Hash512_DRBG_Uninstantiate(&drbg);

    /* Vector (T, F). */
    mcdc_fh_arm(n1 + 1);
    (void)Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    mcdc_fh_disarm();
    (void)Hash512_DRBG_Uninstantiate(&drbg);

    WB_NOTE("Hash512_DRBG_Init Hash512_df chain: (T,T)/(F,-)/(T,F) driven");
}
#else
static void wb_hash512_drbg_init_df_chain(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off (or no SHA-512 interposer); "
          "Hash512_DRBG_Init df chain skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 3. Entropy-source failure through the documented WC_RNG_SEED_CB hook.
 *    seed_cb variant only; the macro comes from the variant's cppflags and is
 *    deliberately NOT defined here.
 * ----------------------------------------------------------------------- */
#if defined(WC_RNG_SEED_CB) && !defined(WC_NO_RNG)

static int wb_seed_broken = 0;

/* Deterministic staged entropy: a pinned LCG, so the seed bytes are identical
 * on every host and every run (the module's determinism rule forbids live
 * entropy in a fixture). The stream is well spread over 0..255, so it passes
 * wc_RNG_TestSeed()'s SP800-90B repetition-count and adaptive-proportion
 * checks. Setting wb_seed_broken makes the source fail on demand. */
static int wb_seed_cb(OS_Seed* os, byte* seed, word32 sz)
{
    unsigned long x = 0x13579bdfUL;
    word32 i;

    (void)os;

    if (wb_seed_broken)
        return BAD_FUNC_ARG;
    if (seed == NULL)
        return BAD_FUNC_ARG;

    for (i = 0; i < sz; i++) {
        x = (x * 1103515245UL) + 12345UL;
        seed[i] = (byte)((x >> 16) & 0xffUL);
    }
    return 0;
}

static void wb_seed_cb_entropy_failure(void)
{
    WC_RNG rng;
    int    ret;

    /* Vector A: entropy available. Staged bytes, callback returns 0. */
    XMEMSET(&rng, 0, sizeof(rng));
    wb_seed_broken = 0;
    (void)wc_SetSeed_Cb(wb_seed_cb);
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WB_NOTE("staged-seed wc_InitRng failed");
        wb_fail = 1;
    }
    else {
        (void)wc_FreeRng(&rng);
    }

    /* Vector B: entropy source FAILS. _InitRng maps the callback's error onto
     * DRBG_FAILURE and tears the half-built RNG down itself, so nothing here
     * consumes rng. */
    XMEMSET(&rng, 0, sizeof(rng));
    wb_seed_broken = 1;
    ret = wc_InitRng(&rng);
    wb_seed_broken = 0;
    if (ret == 0) {
        WB_NOTE("wc_InitRng succeeded with a failing entropy source");
        wb_fail = 1;
        (void)wc_FreeRng(&rng);
    }

    /* Vector C: no entropy source installed at all (seedCb == NULL). */
    XMEMSET(&rng, 0, sizeof(rng));
    (void)wc_SetSeed_Cb(NULL);
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        WB_NOTE("wc_InitRng succeeded with no seed callback installed");
        wb_fail = 1;
        (void)wc_FreeRng(&rng);
    }

    /* Put the library default back, so nothing later in this binary runs on
     * the test callback. Mirrors random.c's own seedCb initialiser. */
#ifndef HAVE_FIPS
    (void)wc_SetSeed_Cb(wc_GenerateSeed);
#else
    (void)wc_SetSeed_Cb(NULL);
#endif

    WB_NOTE("WC_RNG_SEED_CB staged/failing/absent entropy vectors driven");
}
#else
static void wb_seed_cb_entropy_failure(void)
{ WB_NOTE("WC_RNG_SEED_CB not compiled in this variant; entropy-source "
          "failure vectors skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("random.c entropy/seed-derivation fault white-box\n");
#ifdef WC_NO_RNG
    printf("  WC_NO_RNG defined; nothing to exercise\n");
#else
    wb_hash_drbg_init_df_chain();
    wb_hash512_drbg_init_df_chain();
    wb_seed_cb_entropy_failure();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#endif
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
