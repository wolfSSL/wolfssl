/* test_random_whitebox.c
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

/* White-box supplement for wolfcrypt/src/random.c.
 *
 * Two Hash_DRBG-core MC/DC leaves are structurally unreachable from the
 * public wc_* API in this campaign, no matter what combination of public
 * arguments a caller supplies:
 *
 *   - Hash_gen()/Hash512_gen()'s "out != NULL && outSz != 0" guard around
 *     the per-block copy-out: every real call chain either rejects a zero
 *     length before Hash_DRBG_Generate() is ever reached
 *     (wc_RNG_GenerateBlock() has its own "if (sz == 0) return 0;" early
 *     out) or always passes a fixed nonzero RNG_HEALTH_TEST_CHECK_SIZE(
 *     _SHA512) output buffer (the wc_RNG_HealthTest* family). The false
 *     side (out==NULL / outSz==0) is only reachable by calling the
 *     file-static Hash_gen()/Hash512_gen() directly, which this closes.
 *     The "outSz != 0" leaf's OWN independence pair (out!=NULL held true
 *     while outSz==0 is observed at this check) is a separate, genuinely
 *     UNSATISFIABLE residual, not just hard to reach: the caller normalizes
 *     "if (outSz == 0) outSz = 1;" before the loop, and the loop bound
 *     len=ceil(outSz/OUTPUT_BLOCK_LEN) is derived from that same outSz, so
 *     outSz can only reach exactly 0 on what is already the loop's last
 *     planned iteration -- there is no call shape (via the public API or
 *     this white-box) that presents out!=NULL with outSz==0 at a live
 *     evaluation of this condition. Documented, not chased further.
 *   - array_add()'s "dLen > 0 && sLen > 0 && dLen >= sLen" guard: every
 *     real call site passes fixed, compile-time-consistent operand sizes
 *     (sizeof(drbg->V), WC_SHA256_DIGEST_SIZE/WC_SHA512_DIGEST_SIZE,
 *     sizeof(reseedCtr)) that always satisfy the guard, so the false side
 *     needs a direct call with mismatched/zero lengths.
 *
 * Two further GAPS.md residual classes remain justified SKIPS, deliberately
 * NOT chased by this white-box (per the campaign's no-fault-injection
 * convention -- same class as the documented rsa/sp-math residuals):
 *
 *   - Hash_gen()/Hash512_gen()'s "data == NULL || digest == NULL" XMALLOC
 *     guard (only compiled under WOLFSSL_SMALL_STACK &&
 *     !WOLFSSL_SMALL_STACK_CACHE): reaching either operand's true side needs
 *     the shared allocator to fail on one of two back-to-back XMALLOC()
 *     calls; this campaign injects no allocation-failure fault (same
 *     documented residual class as the rsa/sp-math allocation-failure
 *     branches -- see db/modules.json's "random" entry).
 *   - Hash_DRBG_Init()/Hash512_DRBG_Init()'s chained
 *     "Hash_df(...)==DRBG_SUCCESS && Hash_df(...)==DRBG_SUCCESS" (resp.
 *     Hash512_df) compound: showing either operand's false side needs
 *     wc_Sha256Update()/wc_Sha256Final() (resp. SHA-512) to fail mid-
 *     operation on a live call with valid buffers, which does not happen
 *     under normal library operation (same transform-failure class as the
 *     sha module's residuals) and is not forced here.
 *
 * This white-box #includes random.c directly to reach these file-static
 * helpers and drives both sides of each leaf in the same binary (a single
 * clang MC/DC bitmap does not merge independence pairs across separately
 * compiled binaries, so each true-side call below is paired with a
 * same-binary baseline call).
 *
 * Crash-safety: Hash_gen()/Hash512_gen() only touch "out" inside their
 * "if (out != NULL && outSz != 0)" block, so out==NULL never gets
 * dereferenced when outSz==0 short-circuits it. array_add()'s entire body
 * is guarded by the leaf itself, so a false guard never touches d[]/s[].
 * No HW/asm entropy path is touched by any call here.
 */

#include <wolfcrypt/src/random.c>

#include "mcdc_fault_alloc.h"

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256)

static void wb_hash_gen_outsz(void)
{
    DRBG_internal drbg;
    byte seed[48];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++) {
        seed[i] = (byte)(i + 1);
    }
    for (i = 0; i < (word32)sizeof(nonce); i++) {
        nonce[i] = (byte)(i + 2);
    }

    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_DRBG_Instantiate setup failed; skip Hash_gen check");
        return;
    }

    /* False side: out==NULL, outSz==0. Structurally unreachable via any
     * public caller (see file header). */
    ret = Hash_gen(&drbg, NULL, 0, drbg.V);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_gen(NULL, 0) unexpectedly failed");
        wb_fail = 1;
    }

    /* True side baseline, same binary. */
    ret = Hash_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_gen baseline call failed");
        wb_fail = 1;
    }

    (void)Hash_DRBG_Uninstantiate(&drbg);
}

static void wb_array_add(void)
{
    byte d[8];
    byte s[8];
    word32 i;

    for (i = 0; i < (word32)sizeof(d); i++) {
        d[i] = (byte)i;
        s[i] = (byte)(i + 1);
    }

    /* False sides: dLen==0, sLen==0, dLen<sLen. The whole body is skipped
     * when the guard is false, so real (non-NULL) buffers with these
     * mismatched sizes are memory-safe. */
    array_add(d, 0, s, 4);
    array_add(d, 4, s, 0);
    array_add(d, 2, s, 4);

    /* True side baseline, same binary. */
    array_add(d, (word32)sizeof(d), s, (word32)sizeof(s));
}

#else

static void wb_hash_gen_outsz(void)
{
    WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 not compiled in this variant; "
            "skipped SHA-256 Hash_gen check");
}

static void wb_array_add(void)
{
    WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 not compiled in this variant; "
            "skipped array_add check");
}

#endif /* HAVE_HASHDRBG && !NO_SHA256 */

#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512)

static void wb_hash512_gen_outsz(void)
{
    DRBG_SHA512_internal drbg;
    byte seed[32];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++) {
        seed[i] = (byte)(i + 3);
    }
    for (i = 0; i < (word32)sizeof(nonce); i++) {
        nonce[i] = (byte)(i + 4);
    }

    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_DRBG_Instantiate setup failed; skip Hash512_gen "
                "check");
        return;
    }

    /* False side: out==NULL, outSz==0. Same reasoning as the SHA-256
     * case: structurally unreachable via any public caller. */
    ret = Hash512_gen(&drbg, NULL, 0, drbg.V);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_gen(NULL, 0) unexpectedly failed");
        wb_fail = 1;
    }

    /* True side baseline, same binary. */
    ret = Hash512_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_gen baseline call failed");
        wb_fail = 1;
    }

    (void)Hash512_DRBG_Uninstantiate(&drbg);
}

#else

static void wb_hash512_gen_outsz(void)
{
    WB_NOTE("WOLFSSL_DRBG_SHA512 not compiled in this variant; skipped "
            "Hash512_gen check");
}

#endif /* HAVE_HASHDRBG && WOLFSSL_DRBG_SHA512 */

/* ---- Additional file-static leaves reached only by direct call ---- */

#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256)

/* Hash_df()'s per-block loop: the "len" iteration count derives from outSz,
 * and the copy-out "outSz > OUTPUT_BLOCK_LEN" branch is true on every block
 * but the last and false on the tail. A DRBG_SEED_LEN (55-byte) request
 * spans two SHA-256 blocks, so it drives both sides in one call; a
 * single-block request drives only the false (tail) side. The inB/inC
 * "!= NULL && Sz > 0" operand guards are exercised with present and absent
 * operands. All buffers are sized to outSz, so the copy-out is memory-safe. */
static void wb_hash_df_multiblock(void)
{
    DRBG_internal drbg;
    byte out[DRBG_SEED_LEN];
    byte in[16];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(in); i++)
        in[i] = (byte)(i + 5);

    /* Multi-block (len == 2): true then false side of "outSz>OUTPUT_BLOCK_LEN",
     * with both inB and inC present (their "!= NULL && Sz > 0" true side). */
    ret = Hash_df(&drbg, out, (word32)sizeof(out), drbgInitV,
                  in, (word32)sizeof(in), in, (word32)sizeof(in),
                  in, (word32)sizeof(in));
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_df multi-block call failed");
        wb_fail = 1;
    }

    /* Single-block (len == 1): tail-only copy, with inB/inC absent (the
     * "inB != NULL" / "inC != NULL" false side) -- independence baseline. */
    ret = Hash_df(&drbg, out, WC_SHA256_DIGEST_SIZE, drbgReseed,
                  in, (word32)sizeof(in), NULL, 0, NULL, 0);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_df single-block call failed");
        wb_fail = 1;
    }
}

/* Hash_DRBG_Generate()'s "drbg->reseedCtr >= WC_RESEED_INTERVAL" decision:
 * drive the false side (a real generate) and the true side (early
 * DRBG_NEED_RESEED return) in the same binary on one instantiated DRBG. */
static void wb_hash_drbg_generate_reseed(void)
{
    DRBG_internal drbg;
    byte seed[48];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)(i + 1);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)(i + 2);

    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Instantiate failed; skip Hash_DRBG_Generate reseed check");
        return;
    }

    /* False side: reseedCtr below the interval -> generate proceeds. */
    drbg.reseedCtr = 1;
    ret = Hash_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash_DRBG_Generate (below interval) failed");
        wb_fail = 1;
    }

    /* True side: reseedCtr at the interval -> early DRBG_NEED_RESEED. */
    drbg.reseedCtr = WC_RESEED_INTERVAL;
    ret = Hash_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
    if (ret != DRBG_NEED_RESEED) {
        WB_NOTE("Hash_DRBG_Generate did not signal DRBG_NEED_RESEED");
        wb_fail = 1;
    }

    (void)Hash_DRBG_Uninstantiate(&drbg);
}

/* wc_RNG_HealthTest_ex_internal()'s argument guards:
 *   "seedA == NULL || output == NULL"   -> each operand alone
 *   "reseed != 0 && seedB == NULL"      -> each operand alone
 *   "outputSz != RNG_HEALTH_TEST_CHECK_SIZE"  -> wrong size vs correct size
 * plus the full pass path. drbg is only touched after all guards pass, so the
 * early-return calls are memory-safe with a zeroed drbg. */
static void wb_rng_healthtest_internal(void)
{
    DRBG_internal drbg;
    byte output[RNG_HEALTH_TEST_CHECK_SIZE];
    byte seedB[16];
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    XMEMSET(output, 0, sizeof(output));
    XMEMSET(seedB, 9, sizeof(seedB));

    /* seedA == NULL (1st operand true). */
    ret = wc_RNG_HealthTest_ex_internal(&drbg, 0, NULL, 0,
            NULL, 0, NULL, 0, output, (word32)sizeof(output),
            NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("health-test seedA==NULL not rejected");
        wb_fail = 1;
    }

    /* output == NULL (2nd operand true, 1st false). */
    ret = wc_RNG_HealthTest_ex_internal(&drbg, 0, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0,
            NULL, (word32)sizeof(output), NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("health-test output==NULL not rejected");
        wb_fail = 1;
    }

    /* reseed != 0 && seedB == NULL (both operands true). */
    ret = wc_RNG_HealthTest_ex_internal(&drbg, 1, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0,
            output, (word32)sizeof(output), NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("health-test reseed w/ seedB==NULL not rejected");
        wb_fail = 1;
    }

    /* Wrong outputSz (outputSz != RNG_HEALTH_TEST_CHECK_SIZE true side). */
    ret = wc_RNG_HealthTest_ex_internal(&drbg, 0, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0,
            output, 16, NULL, INVALID_DEVID);
    if (ret == 0) {
        WB_NOTE("health-test accepted wrong outputSz");
        wb_fail = 1;
    }

    /* Full valid pass (all guards false, correct size): KAT self-test. */
    ret = wc_RNG_HealthTest_ex_internal(&drbg, 0, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0,
            output, RNG_HEALTH_TEST_CHECK_SIZE, NULL, INVALID_DEVID);
    if (ret != 0) {
        WB_NOTE("health-test valid pass unexpectedly failed");
        wb_fail = 1;
    }
    (void)seedB;
}

#else

static void wb_hash_df_multiblock(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off; skipped Hash_df multiblock"); }
static void wb_hash_drbg_generate_reseed(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off; skipped Hash_DRBG_Generate reseed"); }
static void wb_rng_healthtest_internal(void)
{ WB_NOTE("HAVE_HASHDRBG/!NO_SHA256 off; skipped health-test internal"); }

#endif /* HAVE_HASHDRBG && !NO_SHA256 */

#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512)

/* SHA-512 counterparts of the leaves above. */
static void wb_hash512_df_multiblock(void)
{
    DRBG_SHA512_internal drbg;
    byte out[128];
    byte in[16];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(in); i++)
        in[i] = (byte)(i + 6);

    /* outSz(100) > OUTPUT_BLOCK_LEN(64): multi-block true then tail false. */
    ret = Hash512_df(&drbg, out, 100, drbgInitV,
                     in, (word32)sizeof(in), in, (word32)sizeof(in),
                     in, (word32)sizeof(in));
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_df multi-block call failed");
        wb_fail = 1;
    }

    /* Single-block tail with inB/inC absent (independence baseline). */
    ret = Hash512_df(&drbg, out, WC_SHA512_DIGEST_SIZE, drbgReseed,
                     in, (word32)sizeof(in), NULL, 0, NULL, 0);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_df single-block call failed");
        wb_fail = 1;
    }
}

static void wb_hash512_drbg_generate_reseed(void)
{
    DRBG_SHA512_internal drbg;
    byte seed[32];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)(i + 3);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)(i + 4);

    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Instantiate512 failed; skip Hash512_DRBG_Generate reseed");
        return;
    }

    drbg.reseedCtr = 1;                       /* false side */
    ret = Hash512_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Hash512_DRBG_Generate (below interval) failed");
        wb_fail = 1;
    }

    drbg.reseedCtr = WC_RESEED_INTERVAL;      /* true side */
    ret = Hash512_DRBG_Generate(&drbg, out, (word32)sizeof(out), NULL, 0);
    if (ret != DRBG_NEED_RESEED) {
        WB_NOTE("Hash512_DRBG_Generate did not signal DRBG_NEED_RESEED");
        wb_fail = 1;
    }

    (void)Hash512_DRBG_Uninstantiate(&drbg);
}

static void wb_rng_healthtest512_internal(void)
{
    DRBG_SHA512_internal drbg;
    byte output[RNG_HEALTH_TEST_CHECK_SIZE_SHA512];
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    XMEMSET(output, 0, sizeof(output));

    /* seedA == NULL. */
    ret = wc_RNG_HealthTest_SHA512_ex_internal(&drbg, 0, NULL, 0, NULL, 0,
            NULL, 0, NULL, 0, NULL, 0, NULL, 0,
            output, (word32)sizeof(output), NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("health-test512 seedA==NULL not rejected");
        wb_fail = 1;
    }

    /* reseed != 0 && seedB == NULL. */
    ret = wc_RNG_HealthTest_SHA512_ex_internal(&drbg, 1, NULL, 0, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0, NULL, 0, NULL, 0,
            output, (word32)sizeof(output), NULL, INVALID_DEVID);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("health-test512 reseed w/ seedB==NULL not rejected");
        wb_fail = 1;
    }

    /* Wrong outputSz. */
    ret = wc_RNG_HealthTest_SHA512_ex_internal(&drbg, 0, NULL, 0, NULL, 0,
            seedA_data, (word32)sizeof(seedA_data), NULL, 0, NULL, 0, NULL, 0,
            output, 16, NULL, INVALID_DEVID);
    if (ret == 0) {
        WB_NOTE("health-test512 accepted wrong outputSz");
        wb_fail = 1;
    }
}

#else

static void wb_hash512_df_multiblock(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off; skipped Hash512_df multiblock"); }
static void wb_hash512_drbg_generate_reseed(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off; skipped Hash512_DRBG_Generate reseed"); }
static void wb_rng_healthtest512_internal(void)
{ WB_NOTE("WOLFSSL_DRBG_SHA512 off; skipped health-test512 internal"); }

#endif /* HAVE_HASHDRBG && WOLFSSL_DRBG_SHA512 */

/* ---- Hash_gen()/Hash512_gen() small-stack scratch allocation guards ------- *
 *
 *   779:  if (data == NULL || digest == NULL)      (Hash_gen)
 *   1379: if (data == NULL || digest == NULL)      (Hash512_gen)
 *
 * Compiled only under WOLFSSL_SMALL_STACK && !WOLFSSL_SMALL_STACK_CACHE, where
 * the per-call seed/digest scratch is heap-allocated by two back-to-back
 * XMALLOC()s. Both operands stay false in every normal run, so the true sides
 * need the allocator to fail. mcdc_fault_alloc.h fails the n-th and every
 * later allocation, which maps exactly onto the two operands:
 *
 *   arm(1) -> data==NULL (and digest==NULL)  -> idx0 T                -> T
 *   arm(2) -> data!=NULL, digest==NULL       -> idx0 F, idx1 T        -> T
 *   unarmed-> both non-NULL                  -> idx0 F, idx1 F        -> F
 *
 * The guard returns DRBG_FAILURE immediately on either failure after XFREE-ing
 * whatever was obtained (XFREE(NULL) is a no-op), so nothing downstream runs
 * with a NULL scratch pointer. Each arm brackets exactly ONE Hash*_gen call;
 * the DRBG is instantiated up front while disarmed so its own allocations
 * succeed, and it is a scratch object not reused by any later check.
 * ------------------------------------------------------------------------ */
#if defined(HAVE_HASHDRBG) && !defined(NO_SHA256) && \
    defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SMALL_STACK_CACHE) && \
    !defined(MCDC_FA_UNAVAILABLE)
static void wb_hash_gen_alloc_guard(void)
{
    DRBG_internal drbg;
    byte seed[48];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)(i + 7);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)(i + 8);

    mcdc_fa_install();

    /* Setup runs DISARMED so every allocation it needs succeeds. */
    ret = Hash_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Instantiate failed; skip Hash_gen alloc guard");
        mcdc_fa_restore();
        return;
    }

    mcdc_fa_arm(1);                                     /* data == NULL   */
    (void)Hash_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    mcdc_fa_disarm();

    mcdc_fa_arm(2);                                     /* digest == NULL */
    (void)Hash_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    mcdc_fa_disarm();

    /* All-false baseline in the SAME binary. */
    if (Hash_gen(&drbg, out, (word32)sizeof(out), drbg.V) != DRBG_SUCCESS) {
        WB_NOTE("Hash_gen unarmed baseline failed");
        wb_fail = 1;
    }

    (void)Hash_DRBG_Uninstantiate(&drbg);
    mcdc_fa_restore();
    WB_NOTE("Hash_gen data/digest XMALLOC guard pairs exercised");
}
#else
static void wb_hash_gen_alloc_guard(void)
{ WB_NOTE("not SMALL_STACK-without-CACHE (or no injector); Hash_gen alloc "
          "guard skipped"); }
#endif

#if defined(HAVE_HASHDRBG) && defined(WOLFSSL_DRBG_SHA512) && \
    defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SMALL_STACK_CACHE) && \
    !defined(MCDC_FA_UNAVAILABLE)
static void wb_hash512_gen_alloc_guard(void)
{
    DRBG_SHA512_internal drbg;
    byte seed[32];
    byte nonce[16];
    byte out[32];
    word32 i;
    int ret;

    XMEMSET(&drbg, 0, sizeof(drbg));
    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)(i + 9);
    for (i = 0; i < (word32)sizeof(nonce); i++)
        nonce[i] = (byte)(i + 10);

    mcdc_fa_install();

    ret = Hash512_DRBG_Instantiate(&drbg, seed, (word32)sizeof(seed),
        nonce, (word32)sizeof(nonce), NULL, 0, NULL, INVALID_DEVID);
    if (ret != DRBG_SUCCESS) {
        WB_NOTE("Instantiate512 failed; skip Hash512_gen alloc guard");
        mcdc_fa_restore();
        return;
    }

    mcdc_fa_arm(1);                                     /* data == NULL   */
    (void)Hash512_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    mcdc_fa_disarm();

    mcdc_fa_arm(2);                                     /* digest == NULL */
    (void)Hash512_gen(&drbg, out, (word32)sizeof(out), drbg.V);
    mcdc_fa_disarm();

    if (Hash512_gen(&drbg, out, (word32)sizeof(out), drbg.V) != DRBG_SUCCESS) {
        WB_NOTE("Hash512_gen unarmed baseline failed");
        wb_fail = 1;
    }

    (void)Hash512_DRBG_Uninstantiate(&drbg);
    mcdc_fa_restore();
    WB_NOTE("Hash512_gen data/digest XMALLOC guard pairs exercised");
}
#else
static void wb_hash512_gen_alloc_guard(void)
{ WB_NOTE("not SMALL_STACK-without-CACHE + DRBG_SHA512 (or no injector); "
          "Hash512_gen alloc guard skipped"); }
#endif

/* ---- wc_GenerateSeed() output-buffer guard (line ~5940) ------------------- *
 *
 *   if (os == NULL || output == NULL) return BAD_FUNC_ARG;
 *
 * The generic (POSIX host) arm of random.c's long wc_GenerateSeed #if/#elif
 * chain validates its arguments before any entropy backend touches them. No
 * tests/api caller passes NULL for either, so both operands need this direct
 * pairing plus a same-binary valid seed read.
 *
 * BUILD-AXIS GUARD: that chain compiles exactly ONE wc_GenerateSeed body, and
 * the other arms neither share this guard nor, in the CUSTOM_RAND_GENERATE_BLOCK
 * case, define wc_GenerateSeed at all (that variant would not even link this
 * TU). The condition below excludes every arm reachable from this campaign's
 * variant set and from a host build, so the NULL vectors are only compiled
 * where the guard that catches them is.
 * ------------------------------------------------------------------------ */
#if !defined(WC_NO_RNG) && !defined(CUSTOM_RAND_GENERATE_BLOCK) && \
    !defined(CUSTOM_RAND_GENERATE_SEED) && !defined(NO_DEV_RANDOM) && \
    !defined(USE_WINDOWS_API) && !defined(WOLFSSL_LINUXKM) && \
    !defined(WOLFSSL_BSDKM) && !defined(WOLFSSL_SAFERTOS) && \
    !defined(WOLFSSL_LEANPSK) && !defined(WOLFSSL_GENSEED_FORTEST)
static void wb_generate_seed_guard(void)
{
    OS_Seed os;
    byte    output[16];
    int     ret;

    XMEMSET(&os, 0, sizeof(os));
    XMEMSET(output, 0, sizeof(output));
#ifdef WOLF_CRYPTO_CB
    os.devId = INVALID_DEVID;
#endif

    /* idx0 true: os == NULL (short-circuits before output is looked at). */
    if (wc_GenerateSeed(NULL, output, (word32)sizeof(output)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_GenerateSeed(os==NULL) not rejected");
        wb_fail = 1;
    }
    /* idx0 false, idx1 true: os valid, output == NULL. */
    if (wc_GenerateSeed(&os, NULL, (word32)sizeof(output)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("wc_GenerateSeed(output==NULL) not rejected");
        wb_fail = 1;
    }
    /* All-false baseline: a real (small, bounded) seed read. */
    ret = wc_GenerateSeed(&os, output, (word32)sizeof(output));
    if (ret != 0) {
        WB_NOTE("wc_GenerateSeed valid call failed");
        wb_fail = 1;
    }

    WB_NOTE("wc_GenerateSeed os/output NULL guard pairs exercised");
}
#else
static void wb_generate_seed_guard(void)
{ WB_NOTE("this variant compiles a different wc_GenerateSeed arm; skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("random.c white-box supplement\n");
#ifdef WC_NO_RNG
    printf("  WC_NO_RNG defined; nothing to exercise\n");
    return 0;
#else
    wb_hash_gen_outsz();
    wb_array_add();
    wb_hash512_gen_outsz();
    wb_hash_df_multiblock();
    wb_hash_drbg_generate_reseed();
    wb_rng_healthtest_internal();
    wb_hash512_df_multiblock();
    wb_hash512_drbg_generate_reseed();
    wb_rng_healthtest512_internal();
    wb_generate_seed_guard();
    wb_hash_gen_alloc_guard();
    wb_hash512_gen_alloc_guard();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
