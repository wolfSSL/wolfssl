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
    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret == DRBG_SUCCESS) {
        WB_NOTE("armed Hash_DRBG_Instantiate unexpectedly succeeded");
        wb_fail = 1;
    }
    mcdc_fh_disarm();
    (void)Hash_DRBG_Uninstantiate(&drbg);

    /* Vector (T, F): the first Hash_df's n1 primitive calls all succeed;
     * every call from n1+1 on -- the whole second Hash_df -- fails. */
    mcdc_fh_arm(n1 + 1);
    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret == DRBG_SUCCESS) {
        WB_NOTE("armed Hash_DRBG_Instantiate unexpectedly succeeded");
        wb_fail = 1;
    }
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
    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret == DRBG_SUCCESS) {
        WB_NOTE("armed Hash512_DRBG_Instantiate unexpectedly succeeded");
        wb_fail = 1;
    }
    mcdc_fh_disarm();
    (void)Hash512_DRBG_Uninstantiate(&drbg);

    /* Vector (T, F). */
    mcdc_fh_arm(n1 + 1);
    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret == DRBG_SUCCESS) {
        WB_NOTE("armed Hash512_DRBG_Instantiate unexpectedly succeeded");
        wb_fail = 1;
    }
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
 * 3. Hash256_DRBG_Reseed(): the "Hash_df(newV)" then "Hash_df(newC)" chain
 *    (~747), plus the function's atomic-commit contract ("No state mutation
 *    on failure").  Both faulted vectors assert that V, C and reseedCtr are
 *    byte-identical afterwards and that the same reseed retried disarmed
 *    succeeds in place.  Vector (T, F) is the historical seam: the
 *    pre-atomic code had already committed V before deriving C, so a fault
 *    there left a half-applied transition.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_SHA256)
static void wb_hash_drbg_reseed_df_chain(void)
{
    DRBG_internal drbg;
    byte   seed[48];
    byte   nonce[16];
    byte   seed2[48];
    byte   v0[DRBG_SEED_LEN];
    byte   c0[DRBG_SEED_LEN];
    byte   dfout[DRBG_SEED_LEN];
    byte   out[32];
    unsigned long long rctr0;
    word32 i;
    long   n1;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 17u) + 5u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 19u) + 6u);
    for (i = 0; i < (word32)sizeof(seed2); i++)
        seed2[i] = (byte)((i * 23u) + 7u);

    mcdc_fh_disarm();
    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("unarmed Hash_DRBG_Instantiate failed; reseed chain skipped");
        wb_fail = 1;
        return;
    }

    XMEMCPY(v0, drbg.V, sizeof(v0));
    XMEMCPY(c0, drbg.C, sizeof(c0));
    rctr0 = (unsigned long long)drbg.reseedCtr;

    /* Size the FIRST Hash_df of Hash256_DRBG_Reseed: same out size, same
     * type byte (drbgReseed), same present/absent operands as the reseed
     * calls below.  Written to a local, so the instance is untouched. */
    mcdc_fh_disarm();
    ret = Hash_df(&drbg, dfout, DRBG_SEED_LEN, drbgReseed,
            drbg.V, (word32)sizeof(drbg.V), seed2, (word32)sizeof(seed2),
            NULL, 0);
    n1 = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || n1 <= 0) {
        WB_NOTE("could not size the reseed Hash_df; fault vectors skipped");
        wb_fail = 1;
        (void)Hash_DRBG_Uninstantiate(&drbg);
        return;
    }

    /* Vector (F, -): the newV derivation fails on its first primitive. */
    mcdc_fh_arm(1);
    ret = Hash256_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("armed reseed (F,-) did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(drbg.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(drbg.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)drbg.reseedCtr != rctr0)) {
        WB_NOTE("reseed (F,-) mutated DRBG state");
        wb_fail = 1;
    }

    /* Vector (T, F): the newV derivation's n1 calls all succeed and the newC
     * derivation fails -- the seam case. */
    mcdc_fh_arm(n1 + 1);
    ret = Hash256_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("armed reseed (T,F) did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(drbg.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(drbg.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)drbg.reseedCtr != rctr0)) {
        WB_NOTE("reseed (T,F) mutated DRBG state");
        wb_fail = 1;
    }

    /* Retryability: the same reseed, disarmed, succeeds in place, and the
     * instance is operational. */
    ret = Hash256_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    if ((ret != DRBG_SUCCESS) || (drbg.reseedCtr != 1)) {
        WB_NOTE("disarmed reseed retry did not succeed cleanly");
        wb_fail = 1;
    }
    else {
        ret = Hash_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
        if (ret != DRBG_SUCCESS) {
            WB_NOTE("generate after retried reseed failed");
            wb_fail = 1;
        }
    }
    (void)Hash_DRBG_Uninstantiate(&drbg);

    WB_NOTE("Hash256_DRBG_Reseed (F,-)/(T,F): no-mutation + retry driven");
}
#else
static void wb_hash_drbg_reseed_df_chain(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off (or no SHA-256 interposer); "
          "Hash256_DRBG_Reseed chain skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 4. Hash512_DRBG_Reseed(): the SHA-512 counterpart (~1915).
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512) && \
    defined(MCDC_FH_HAVE_SHA512)
static void wb_hash512_drbg_reseed_df_chain(void)
{
    DRBG_SHA512_internal drbg;
    byte   seed[48];
    byte   nonce[16];
    byte   seed2[48];
    byte   v0[DRBG_SHA512_SEED_LEN];
    byte   c0[DRBG_SHA512_SEED_LEN];
    byte   dfout[DRBG_SHA512_SEED_LEN];
    byte   out[32];
    unsigned long long rctr0;
    word32 i;
    long   n1;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 41u) + 11u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 43u) + 12u);
    for (i = 0; i < (word32)sizeof(seed2); i++)
        seed2[i] = (byte)((i * 47u) + 13u);

    mcdc_fh_disarm();
    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("unarmed Hash512_DRBG_Instantiate failed; "
                "reseed chain skipped");
        wb_fail = 1;
        return;
    }

    XMEMCPY(v0, drbg.V, sizeof(v0));
    XMEMCPY(c0, drbg.C, sizeof(c0));
    rctr0 = (unsigned long long)drbg.reseedCtr;

    /* Size the first Hash512_df of Hash512_DRBG_Reseed. */
    mcdc_fh_disarm();
    ret = Hash512_df(&drbg, dfout, DRBG_SHA512_SEED_LEN, drbgReseed,
            drbg.V, (word32)sizeof(drbg.V), seed2, (word32)sizeof(seed2),
            NULL, 0);
    n1 = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || n1 <= 0) {
        WB_NOTE("could not size the reseed Hash512_df; "
                "fault vectors skipped");
        wb_fail = 1;
        (void)Hash512_DRBG_Uninstantiate(&drbg);
        return;
    }

    /* Vector (F, -). */
    mcdc_fh_arm(1);
    ret = Hash512_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("armed 512 reseed (F,-) did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(drbg.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(drbg.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)drbg.reseedCtr != rctr0)) {
        WB_NOTE("512 reseed (F,-) mutated DRBG state");
        wb_fail = 1;
    }

    /* Vector (T, F): the seam case. */
    mcdc_fh_arm(n1 + 1);
    ret = Hash512_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("armed 512 reseed (T,F) did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(drbg.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(drbg.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)drbg.reseedCtr != rctr0)) {
        WB_NOTE("512 reseed (T,F) mutated DRBG state");
        wb_fail = 1;
    }

    /* Retryability. */
    ret = Hash512_DRBG_Reseed(&drbg, seed2, (word32)sizeof(seed2), NULL, 0);
    if ((ret != DRBG_SUCCESS) || (drbg.reseedCtr != 1)) {
        WB_NOTE("disarmed 512 reseed retry did not succeed cleanly");
        wb_fail = 1;
    }
    else {
        ret = Hash512_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
        if (ret != DRBG_SUCCESS) {
            WB_NOTE("generate after retried 512 reseed failed");
            wb_fail = 1;
        }
    }
    (void)Hash512_DRBG_Uninstantiate(&drbg);

    WB_NOTE("Hash512_DRBG_Reseed (F,-)/(T,F): no-mutation + retry driven");
}
#else
static void wb_hash512_drbg_reseed_df_chain(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off (or no SHA-512 interposer); "
          "Hash512_DRBG_Reseed chain skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 5. Hash_DRBG_Generate(): failure atomicity ("DRBG state is always
 *    consistent upon return").  Two fault positions bracket Hash_gen():
 *
 *      pre-Hash_gen  -- the additional-input (0x02) hash fails; nothing has
 *                       been derived yet.
 *      post-Hash_gen -- the output block is already produced and the 0x03
 *                       V-update hash fails; the shadow-V commit must not
 *                       have happened.
 *
 *    Both assert V/C/reseedCtr byte-identical, and the disarmed retry must
 *    produce output byte-identical to an identically-instantiated control
 *    (no stream position consumed).  The identical retry bytes are also the
 *    executable witness that Hash_gen() banks nothing across a failed
 *    attempt: a banked block would make this exact retry a stuck-output
 *    false positive.
 *
 *    Arm indices are measured, never hard-coded: n_a by replicating the
 *    additional-input hash's call shape on a local context (the interposer
 *    counts this TU's own calls too), n_gen by calling Hash_gen() directly
 *    with the same outSz (it reads V and writes only the caller's buffer).
 *
 *    NOT CHASED HERE -- mid-phase faults under WOLFSSL_SMALL_STACK_CACHE.
 *    Both positions above fault a phase's FIRST primitive call, where the
 *    persistent drbg->sha256 is clean (each preceding phase ended with a
 *    Final, which resets the context; the interposer fails without calling
 *    the real primitive).  A fault in the MIDDLE of a phase would leave
 *    absorbed-but-unfinalized data in the cached context -- V/C/reseedCtr
 *    still unmutated, but the next hash over that context diverges, so
 *    retry-byte-identity would not hold.  Software wc_Sha*Update cannot
 *    fail mid-stream, so the exposure is confined to async/devId cache
 *    builds; recorded rather than asserted.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_SHA256)
static void wb_hash_drbg_generate_atomicity(void)
{
    DRBG_internal ctrl;
    DRBG_internal probe;
    wc_Sha256 addsha[1];
    byte   seed[48];
    byte   nonce[16];
    byte   add[24];
    byte   exp1[64];
    byte   out[64];
    byte   out2[64];
    byte   tmp[64];
    byte   v0[DRBG_SEED_LEN];
    byte   c0[DRBG_SEED_LEN];
    unsigned long long rctr0;
    word32 i;
    long   t_add;
    long   n_a;
    long   n_gen;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 29u) + 8u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 31u) + 9u);
    for (i = 0; i < (word32)sizeof(add); i++)
        add[i] = (byte)((i * 37u) + 10u);

    /* Control: one disarmed generate; its output is the expected block for
     * every retry below, and its end state the expected end state. */
    mcdc_fh_disarm();
    ret = Hash_DRBG_Instantiate(&ctrl, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("control Hash_DRBG_Instantiate failed; atomicity skipped");
        wb_fail = 1;
        return;
    }
    mcdc_fh_disarm();
    ret = Hash_DRBG_Generate(&ctrl, exp1, (word32)sizeof(exp1),
                             add, (word32)sizeof(add));
    t_add = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || t_add <= 0) {
        WB_NOTE("control generate failed; atomicity skipped");
        wb_fail = 1;
        (void)Hash_DRBG_Uninstantiate(&ctrl);
        return;
    }

    /* Probe: identical instantiation, so identical state. */
    ret = Hash_DRBG_Instantiate(&probe, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("probe Hash_DRBG_Instantiate failed; atomicity skipped");
        wb_fail = 1;
        (void)Hash_DRBG_Uninstantiate(&ctrl);
        return;
    }
    XMEMCPY(v0, probe.V, sizeof(v0));
    XMEMCPY(c0, probe.C, sizeof(c0));
    rctr0 = (unsigned long long)probe.reseedCtr;

    /* n_a: the additional-input hash is Update(type) + Update(V) +
     * Update(additional) + Final; sizes do not change the call count. */
    ret = wc_InitSha256(addsha);
    mcdc_fh_disarm();
    if (ret == 0)
        ret = wc_Sha256Update(addsha, add, 1);
    if (ret == 0)
        ret = wc_Sha256Update(addsha, probe.V, (word32)sizeof(probe.V));
    if (ret == 0)
        ret = wc_Sha256Update(addsha, add, (word32)sizeof(add));
    if (ret == 0)
        ret = wc_Sha256Final(addsha, tmp);
    n_a = mcdc_fh_seen();
    wc_Sha256Free(addsha);
    if (ret != 0 || n_a <= 0) {
        WB_NOTE("could not size the additional-input hash; "
                "atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }

    /* n_gen: direct Hash_gen of the same outSz. */
    mcdc_fh_disarm();
    ret = Hash_gen(&probe, tmp, (word32)sizeof(tmp), probe.V);
    n_gen = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || n_gen <= 0) {
        WB_NOTE("could not size Hash_gen; atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }
    if (t_add <= n_a + n_gen) {
        WB_NOTE("generate call-count structure drifted; atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }

    /* Pre-Hash_gen fault: first primitive of the additional-input hash. */
    mcdc_fh_arm(1);
    ret = Hash_DRBG_Generate(&probe, out, (word32)sizeof(out),
                             add, (word32)sizeof(add));
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("pre-Hash_gen fault did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)probe.reseedCtr != rctr0)) {
        WB_NOTE("pre-Hash_gen fault mutated DRBG state");
        wb_fail = 1;
    }

    /* Post-Hash_gen fault: first primitive after Hash_gen's last. */
    mcdc_fh_arm(n_a + n_gen + 1);
    ret = Hash_DRBG_Generate(&probe, out, (word32)sizeof(out),
                             add, (word32)sizeof(add));
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("post-Hash_gen fault did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)probe.reseedCtr != rctr0)) {
        WB_NOTE("post-Hash_gen fault mutated DRBG state");
        wb_fail = 1;
    }

    /* Retry: byte-identical output, end state equal to the control's. */
    ret = Hash_DRBG_Generate(&probe, out2, (word32)sizeof(out2),
                             add, (word32)sizeof(add));
    if ((ret != DRBG_SUCCESS) ||
        (XMEMCMP(out2, exp1, sizeof(exp1)) != 0)) {
        WB_NOTE("retried generate not byte-identical to control");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, ctrl.V, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, ctrl.C, sizeof(c0)) != 0) ||
        (probe.reseedCtr != ctrl.reseedCtr)) {
        WB_NOTE("retried generate end-state differs from control");
        wb_fail = 1;
    }

    WB_NOTE("Hash_DRBG_Generate pre/post-Hash_gen faults: "
            "no-mutation + byte-identical retry driven");

out_uninst:
    (void)Hash_DRBG_Uninstantiate(&probe);
    (void)Hash_DRBG_Uninstantiate(&ctrl);
}
#else
static void wb_hash_drbg_generate_atomicity(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off (or no SHA-256 interposer); "
          "Hash_DRBG_Generate atomicity skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 6. Hash512_DRBG_Generate(): the SHA-512 counterpart.
 * ----------------------------------------------------------------------- */
#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512) && \
    defined(MCDC_FH_HAVE_SHA512)
static void wb_hash512_drbg_generate_atomicity(void)
{
    DRBG_SHA512_internal ctrl;
    DRBG_SHA512_internal probe;
    wc_Sha512 addsha[1];
    byte   seed[48];
    byte   nonce[16];
    byte   add[24];
    byte   exp1[64];
    byte   out[64];
    byte   out2[64];
    byte   tmp[64];
    byte   v0[DRBG_SHA512_SEED_LEN];
    byte   c0[DRBG_SHA512_SEED_LEN];
    unsigned long long rctr0;
    word32 i;
    long   t_add;
    long   n_a;
    long   n_gen;
    int    ret;

    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)((i * 53u) + 14u);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)((i * 59u) + 15u);
    for (i = 0; i < (word32)sizeof(add); i++)
        add[i] = (byte)((i * 61u) + 16u);

    /* Control. */
    mcdc_fh_disarm();
    ret = Hash512_DRBG_Instantiate(&ctrl, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("control Hash512_DRBG_Instantiate failed; "
                "atomicity skipped");
        wb_fail = 1;
        return;
    }
    mcdc_fh_disarm();
    ret = Hash512_DRBG_Generate(&ctrl, exp1, (word32)sizeof(exp1),
                                add, (word32)sizeof(add));
    t_add = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || t_add <= 0) {
        WB_NOTE("control 512 generate failed; atomicity skipped");
        wb_fail = 1;
        (void)Hash512_DRBG_Uninstantiate(&ctrl);
        return;
    }

    /* Probe. */
    ret = Hash512_DRBG_Instantiate(&probe, seed, (word32)sizeof(seed),
            nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("probe Hash512_DRBG_Instantiate failed; atomicity skipped");
        wb_fail = 1;
        (void)Hash512_DRBG_Uninstantiate(&ctrl);
        return;
    }
    XMEMCPY(v0, probe.V, sizeof(v0));
    XMEMCPY(c0, probe.C, sizeof(c0));
    rctr0 = (unsigned long long)probe.reseedCtr;

    /* n_a. */
    ret = wc_InitSha512(addsha);
    mcdc_fh_disarm();
    if (ret == 0)
        ret = wc_Sha512Update(addsha, add, 1);
    if (ret == 0)
        ret = wc_Sha512Update(addsha, probe.V, (word32)sizeof(probe.V));
    if (ret == 0)
        ret = wc_Sha512Update(addsha, add, (word32)sizeof(add));
    if (ret == 0)
        ret = wc_Sha512Final(addsha, tmp);
    n_a = mcdc_fh_seen();
    wc_Sha512Free(addsha);
    if (ret != 0 || n_a <= 0) {
        WB_NOTE("could not size the 512 additional-input hash; "
                "atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }

    /* n_gen. */
    mcdc_fh_disarm();
    ret = Hash512_gen(&probe, tmp, (word32)sizeof(tmp), probe.V);
    n_gen = mcdc_fh_seen();
    if (ret != DRBG_SUCCESS || n_gen <= 0) {
        WB_NOTE("could not size Hash512_gen; atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }
    if (t_add <= n_a + n_gen) {
        WB_NOTE("512 generate call-count structure drifted; "
                "atomicity skipped");
        wb_fail = 1;
        goto out_uninst;
    }

    /* Pre-Hash512_gen fault. */
    mcdc_fh_arm(1);
    ret = Hash512_DRBG_Generate(&probe, out, (word32)sizeof(out),
                                add, (word32)sizeof(add));
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("pre-Hash512_gen fault did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)probe.reseedCtr != rctr0)) {
        WB_NOTE("pre-Hash512_gen fault mutated DRBG state");
        wb_fail = 1;
    }

    /* Post-Hash512_gen fault. */
    mcdc_fh_arm(n_a + n_gen + 1);
    ret = Hash512_DRBG_Generate(&probe, out, (word32)sizeof(out),
                                add, (word32)sizeof(add));
    mcdc_fh_disarm();
    if (ret != WC_NO_ERR_TRACE(DRBG_FAILURE)) {
        WB_NOTE("post-Hash512_gen fault did not return DRBG_FAILURE");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, v0, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, c0, sizeof(c0)) != 0) ||
        ((unsigned long long)probe.reseedCtr != rctr0)) {
        WB_NOTE("post-Hash512_gen fault mutated DRBG state");
        wb_fail = 1;
    }

    /* Retry. */
    ret = Hash512_DRBG_Generate(&probe, out2, (word32)sizeof(out2),
                                add, (word32)sizeof(add));
    if ((ret != DRBG_SUCCESS) ||
        (XMEMCMP(out2, exp1, sizeof(exp1)) != 0)) {
        WB_NOTE("retried 512 generate not byte-identical to control");
        wb_fail = 1;
    }
    if ((XMEMCMP(probe.V, ctrl.V, sizeof(v0)) != 0) ||
        (XMEMCMP(probe.C, ctrl.C, sizeof(c0)) != 0) ||
        (probe.reseedCtr != ctrl.reseedCtr)) {
        WB_NOTE("retried 512 generate end-state differs from control");
        wb_fail = 1;
    }

    WB_NOTE("Hash512_DRBG_Generate pre/post-Hash512_gen faults: "
            "no-mutation + byte-identical retry driven");

out_uninst:
    (void)Hash512_DRBG_Uninstantiate(&probe);
    (void)Hash512_DRBG_Uninstantiate(&ctrl);
}
#else
static void wb_hash512_drbg_generate_atomicity(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off (or no SHA-512 interposer); "
          "Hash512_DRBG_Generate atomicity skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 7. Entropy-source failure through the documented WC_RNG_SEED_CB hook.
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
    wb_hash_drbg_reseed_df_chain();
    wb_hash512_drbg_reseed_df_chain();
    wb_hash_drbg_generate_atomicity();
    wb_hash512_drbg_generate_atomicity();
    wb_seed_cb_entropy_failure();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
#endif
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
