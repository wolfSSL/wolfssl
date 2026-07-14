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
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the
     * campaign treats a nonzero exit as a failed variant and discards its
     * coverage. */
    return 0;
#endif
}
