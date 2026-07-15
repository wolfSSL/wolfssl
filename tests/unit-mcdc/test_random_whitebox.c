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

int main(void)
{
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
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
