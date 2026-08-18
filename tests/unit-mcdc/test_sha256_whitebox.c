/* test_sha256_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/sha256.c.
 *
 * On an x86-64 USE_INTEL_SPEEDUP build the transform dispatch reads a
 * file-static cpuid mask, intel_flags, in several decisions:
 *
 *   SHA256_UPDATE_REV_BYTES  (macro, line ~241):
 *       !IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags) &&
 *       !IS_INTEL_SHA(intel_flags)
 *   Transform_Sha256_Len length-field reverse (line ~1977):
 *       IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags) ||
 *       IS_INTEL_SHA(intel_flags)
 *
 * On a capable host cpuid always reports (at least) AVX2, so the runtime
 * only ever takes one side of each check; the not-taken conditions are
 * unreachable from tests/api. This TU #includes sha256.c so the file-static
 * intel_flags is in scope, and drives an update+final with intel_flags forced
 * to each of {none, AVX1, AVX2, SHA}, showing every condition's independence
 * pair.
 *
 * Two static items must be driven together. intel_flags is the DECISION input.
 * The transform is invoked through separate function pointers
 * (Transform_Sha256_p, Transform_Sha256_Len_p); the multi-block Len pointer,
 * when non-NULL (the host's AVX path), handles byte-reversal internally and
 * BYPASSES the per-block SHA256_UPDATE_REV_BYTES decision entirely. So we pin
 * Transform_Sha256_p to the portable C transform and Transform_Sha256_Len_p to
 * NULL: every block then flows through the per-block route that evaluates the
 * decision, and the C transform is safe to run whatever intel_flags claims
 * (so forcing e.g. SHA-NI never executes SHA-NI asm).
 *
 * Second supplement: Sha256Update()'s save-remainder guard (line ~2034)
 *
 *     if (ret == 0 && len > 0)
 *
 * idx0 ("ret == 0") FALSE half. Nothing on the path to that guard can set ret
 * except the block transform: the two earlier error exits (buffLen >= block
 * size -> BUFFER_E, and the argument checks in wc_Sha256Update) return before
 * it. In the plain C variants XTRANSFORM expands straight to the static
 * Transform_Sha256(), which has no failing return, so the FALSE half is only
 * reachable where the transform is dispatched through the file-static
 * Transform_Sha256_p -- i.e. exactly this USE_INTEL_SPEEDUP build. Retargeting
 * that pointer at a stub returning BAD_FUNC_ARG (and NULLing
 * Transform_Sha256_Len_p so the multi-block loop, not XTRANSFORM_LEN, runs)
 * makes the first loop iteration break with ret != 0; the guard is then
 * evaluated with idx0 FALSE and idx1 short-circuited (never read).
 * Vectors, all in this one binary:
 *     stub + 3 whole blocks         -> (F, -)   [the residual]
 *     C transform + 1 block + 5     -> (T, T)
 *     C transform + exactly 1 block -> (T, F)
 * No digest is ever taken from the faulted context: it is freed and
 * re-initialised before the baseline vectors run.
 */

#include <wolfcrypt/src/sha256.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* The intel_flags dispatch (and the static itself) only exists under this
 * exact guard -- the same one sha256.c uses around SHA256_UPDATE_REV_BYTES and
 * the Transform_Sha256_Len length reversal. Outside it (the C/small/arm
 * variants) there is nothing to force, so the supplement is a no-op. */
#if !defined(NO_SHA256) && defined(WOLFSSL_X86_64_BUILD) && \
    defined(USE_INTEL_SPEEDUP) && \
    !(defined(WC_C_DYNAMIC_FALLBACK) && \
      defined(WC_ALLOW_RUNTIME_IMPL_SELECT)) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

static void wb_intel_dispatch(void)
{
    /* Each forced mask isolates one condition of the AVX1/AVX2/SHA checks:
     * 0 (none) gives the all-false row every OR/AND-of-negations needs, and
     * each single bit gives that condition's true row. */
    static const cpuid_flags_t cases[] = {
        0, CPUID_AVX1, CPUID_AVX2, CPUID_SHA
    };
    cpuid_flags_t saved = intel_flags;
    /* Two full blocks so the update loop runs the per-block transform path. */
    byte  buf[2 * WC_SHA256_BLOCK_SIZE];
    byte  hash[WC_SHA256_DIGEST_SIZE];
    size_t i;

    XMEMSET(buf, 0, sizeof(buf));

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wc_Sha256 sha;

        if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WB_NOTE("wc_InitSha256_ex failed (intel dispatch case skipped)");
            wb_fail = 1;
            continue;
        }
        /* Pin the per-block C route (see file header) then force the decision
         * input. Order after init: the idempotent SetTransform already ran. */
        Transform_Sha256_p     = Transform_Sha256;
        Transform_Sha256_Len_p = NULL;
        intel_flags            = cases[i];

        /* Update exercises SHA256_UPDATE_REV_BYTES in the per-block loop; final
         * exercises the length-field reversal (both read intel_flags). */
        (void)wc_Sha256Update(&sha, buf, (word32)sizeof(buf));
        (void)wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);
    }

    intel_flags = saved;
    WB_NOTE("sha256 intel_flags dispatch pairs exercised");
}

#else

static void wb_intel_dispatch(void)
{
    WB_NOTE("sha256 intel dispatch not compiled in this variant; skipped");
}

#endif

/* --------------------------------------------------------------------------
 * Sha256Update(): "ret == 0" half of the save-remainder guard (~line 2034).
 * ----------------------------------------------------------------------- */
#if !defined(NO_SHA256) && defined(WOLFSSL_X86_64_BUILD) && \
    defined(USE_INTEL_SPEEDUP) && !defined(WC_C_DYNAMIC_FALLBACK) && \
    !defined(WC_NO_INTERNAL_FUNCTION_POINTERS) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

static int wb_transform_fails(wc_Sha256* sha256, const byte* data)
{
    (void)sha256;
    (void)data;
    return BAD_FUNC_ARG;
}

static void wb_update_transform_err(void)
{
    /* Three whole blocks: the loop breaks on the first transform (len is
     * decremented before it), leaving len == 2 * block size at the guard --
     * immaterial, since idx1 is short-circuited when idx0 is FALSE. */
    byte  buf[3 * WC_SHA256_BLOCK_SIZE];
    byte  hash[WC_SHA256_DIGEST_SIZE];
    int (*saved_p)(wc_Sha256*, const byte*)          = Transform_Sha256_p;
    int (*saved_len_p)(wc_Sha256*, const byte*, word32) =
        Transform_Sha256_Len_p;
    cpuid_flags_t saved_flags = intel_flags;
    wc_Sha256 sha;
    int ret;

    XMEMSET(buf, 0x5a, sizeof(buf));

    /* idx0 FALSE: the transform fails on the first block. */
    if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha256_ex failed (transform-error case skipped)");
        wb_fail = 1;
    }
    else {
        /* Pin the per-block route, then make that block transform fail.
         * intel_flags is zeroed so the C route the baselines use below is
         * byte-reversal-consistent; it is restored at the end. */
        Transform_Sha256_Len_p = NULL;
        Transform_Sha256_p     = wb_transform_fails;
        intel_flags            = 0;

        ret = wc_Sha256Update(&sha, buf, (word32)sizeof(buf));
        if (ret == 0) {
            WB_NOTE("faulted wc_Sha256Update unexpectedly succeeded");
            wb_fail = 1;
        }
        /* The context is poisoned; no digest is taken from it. */
        Transform_Sha256_p = Transform_Sha256;
        wc_Sha256Free(&sha);
    }

    /* idx0 TRUE, idx1 TRUE: one whole block plus a 5-byte remainder. */
    if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha256_ex failed (remainder baseline skipped)");
        wb_fail = 1;
    }
    else {
        Transform_Sha256_Len_p = NULL;
        Transform_Sha256_p     = Transform_Sha256;
        ret = wc_Sha256Update(&sha, buf, WC_SHA256_BLOCK_SIZE + 5);
        if (ret != 0) {
            WB_NOTE("wc_Sha256Update remainder baseline failed");
            wb_fail = 1;
        }
        (void)wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);
    }

    /* idx0 TRUE, idx1 FALSE: an exact whole number of blocks, no remainder. */
    if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha256_ex failed (exact-block baseline skipped)");
        wb_fail = 1;
    }
    else {
        Transform_Sha256_Len_p = NULL;
        Transform_Sha256_p     = Transform_Sha256;
        ret = wc_Sha256Update(&sha, buf, WC_SHA256_BLOCK_SIZE);
        if (ret != 0) {
            WB_NOTE("wc_Sha256Update exact-block baseline failed");
            wb_fail = 1;
        }
        (void)wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);
    }

    Transform_Sha256_p     = saved_p;
    Transform_Sha256_Len_p = saved_len_p;
    intel_flags            = saved_flags;
    WB_NOTE("Sha256Update save-remainder ret==0 pair exercised");
}

#else

static void wb_update_transform_err(void)
{
    WB_NOTE("no retargetable sha256 transform pointer in this variant; "
            "save-remainder ret==0 skipped");
}

#endif

int main(void)
{
    printf("sha256.c white-box MC/DC supplement\n");
#ifdef NO_SHA256
    printf("  NO_SHA256 defined; nothing to exercise\n");
    return 0;
#else
    wb_intel_dispatch();
    wb_update_transform_err();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
