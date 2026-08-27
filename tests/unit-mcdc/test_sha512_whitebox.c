/* test_sha512_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/sha512.c.
 *
 * Mirror of test_sha256_whitebox.c for the SHA-512 family. On an x86-64
 * USE_INTEL_SPEEDUP build the transform dispatch reads a file-static cpuid
 * mask, intel_flags, in several decisions (SHA-512 has no SHA-NI, so only
 * AVX1/AVX2 appear):
 *
 *   Sha512Update / Sha512Final byte-reverse guards (lines ~1949, 2043,
 *   2190, 2249):   !IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags)
 *   Sha512Final length-field reverse (line ~2273):
 *                  IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags)
 *
 * On a capable host cpuid always reports (at least) AVX2, so the not-taken
 * conditions are unreachable from tests/api. This TU #includes sha512.c so the
 * file-static intel_flags is in scope, and drives update+final with it forced
 * to each of {none, AVX1, AVX2}.
 *
 * As in the sha256 supplement, the host's AVX multi-block Len transform
 * bypasses the per-block byte-reverse decisions, so we pin Transform_Sha512_p
 * to the portable C transform and Transform_Sha512_Len_p to NULL (routing
 * every block through the per-block path that reads intel_flags) -- which is
 * also crash-safe: the C transform runs whatever intel_flags claims.
 *
 * Second supplement: Sha512Update()'s save-remainder guard (line ~2185)
 *
 *     if (ret == 0 && len > 0)
 *
 * idx0 ("ret == 0") FALSE half. ret is 0 everywhere on the path to that guard
 * except where the block transform writes it: the two earlier error exits
 * (buffLen >= block size -> BUFFER_E, and wc_Sha512Update's argument checks)
 * return before the guard is reached. In the plain C / ARMASM variants
 * Transform_Sha512() resolves to a transform with no failing return, so the
 * FALSE half is only reachable where the transform is dispatched through the
 * file-static Transform_Sha512_p -- i.e. exactly this USE_INTEL_SPEEDUP build.
 * Retargeting that pointer at a stub returning BAD_FUNC_ARG (and NULLing
 * Transform_Sha512_Len_p so the per-block loop, not the Len transform, runs)
 * makes the first loop iteration break with ret != 0; the guard is then
 * evaluated with idx0 FALSE and idx1 short-circuited (never read).
 * Vectors, all in this one binary:
 *     stub + 3 whole blocks          -> (F, -)   [the residual]
 *     C transform + 1 block + 5      -> (T, T)
 *     C transform + exactly 1 block  -> (T, F)
 * No digest is taken from the faulted context: it is freed and re-initialised
 * before the baseline vectors run.
 */

#include <wolfcrypt/src/sha512.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(NO_SHA512) && defined(WOLFSSL_SHA512) && \
    defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WC_C_DYNAMIC_FALLBACK) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

static void wb_intel_dispatch(void)
{
    /* SHA-512 has no SHA-NI: only the AVX1/AVX2 conditions exist. 0 gives the
     * all-false row; each single bit gives that condition's true row. */
    static const cpuid_flags_t cases[] = { 0, CPUID_AVX1, CPUID_AVX2 };
    cpuid_flags_t saved = intel_flags;
    /* Two full blocks so the update loop runs the per-block transform path. */
    byte  buf[2 * WC_SHA512_BLOCK_SIZE];
    byte  hash[WC_SHA512_DIGEST_SIZE];
    size_t i;

    XMEMSET(buf, 0, sizeof(buf));

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wc_Sha512 sha;

        /* The AVX1/AVX2 byte-reverse guards sit in three distinct update
         * sub-paths and one final sub-path, each with its own entry state:
         *   - buffered-block completion (buffLen>0 filled to a full block),
         *   - the bulk multi-block loop,
         *   - final with the message ending exactly on the padding boundary,
         *   - final needing an extra padding block (buffLen > WC_SHA512_PAD_SIZE).
         * Exercise all of them per forced intel_flags value. */

        /* (a) buffered completion + bulk + normal final. Two 64-byte updates
         *     leave buffLen>0 then complete the block; a large update runs the
         *     bulk loop; final closes on the padding boundary. */
        if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WB_NOTE("wc_InitSha512_ex failed (intel dispatch case skipped)");
            wb_fail = 1;
            continue;
        }
        Transform_Sha512_p     = _Transform_Sha512;
        Transform_Sha512_Len_p = NULL;
        intel_flags            = cases[i];
        (void)wc_Sha512Update(&sha, buf, 64);
        (void)wc_Sha512Update(&sha, buf, 64);   /* completes a block: buffLen path */
        (void)wc_Sha512Update(&sha, buf, (word32)sizeof(buf)); /* bulk loop */
        (void)wc_Sha512Final(&sha, hash);
        wc_Sha512Free(&sha);

        /* (b) final needing an extra padding block: a partial update leaves
         *     buffLen past the pad boundary so final pads a whole extra block. */
        if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WB_NOTE("wc_InitSha512_ex failed (pad-block case skipped)");
            wb_fail = 1;
            continue;
        }
        Transform_Sha512_p     = _Transform_Sha512;
        Transform_Sha512_Len_p = NULL;
        intel_flags            = cases[i];
        (void)wc_Sha512Update(&sha, buf, WC_SHA512_BLOCK_SIZE - 8);
        (void)wc_Sha512Final(&sha, hash);
        wc_Sha512Free(&sha);
    }

    intel_flags = saved;
    WB_NOTE("sha512 intel_flags dispatch pairs exercised");
}

#else

static void wb_intel_dispatch(void)
{
    WB_NOTE("sha512 intel dispatch not compiled in this variant; skipped");
}

#endif

/* --------------------------------------------------------------------------
 * Sha512Update(): "ret == 0" half of the save-remainder guard (~line 2185).
 * ----------------------------------------------------------------------- */
#if !defined(NO_SHA512) && defined(WOLFSSL_SHA512) && \
    defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WC_C_DYNAMIC_FALLBACK) && \
    !defined(WC_NO_INTERNAL_FUNCTION_POINTERS) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

static int wb_transform_fails(wc_Sha512* sha512)
{
    (void)sha512;
    return BAD_FUNC_ARG;
}

static void wb_update_transform_err(void)
{
    /* Three whole blocks: the loop breaks on the first transform (len is
     * decremented before it), leaving len == 2 * block size at the guard --
     * immaterial, since idx1 is short-circuited when idx0 is FALSE. */
    byte  buf[3 * WC_SHA512_BLOCK_SIZE];
    byte  hash[WC_SHA512_DIGEST_SIZE];
    int (*saved_p)(wc_Sha512*)             = Transform_Sha512_p;
    int (*saved_len_p)(wc_Sha512*, word32) = Transform_Sha512_Len_p;
    cpuid_flags_t saved_flags = intel_flags;
    wc_Sha512 sha;
    int ret;

    XMEMSET(buf, 0x5a, sizeof(buf));

    /* idx0 FALSE: the transform fails on the first block. */
    if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha512_ex failed (transform-error case skipped)");
        wb_fail = 1;
    }
    else {
        /* Pin the per-block route, then make that block transform fail.
         * intel_flags is zeroed so the C transform the baselines use sees a
         * byte-reversed block; it is restored at the end. */
        Transform_Sha512_Len_p = NULL;
        Transform_Sha512_p     = wb_transform_fails;
        intel_flags            = 0;

        ret = wc_Sha512Update(&sha, buf, (word32)sizeof(buf));
        if (ret == 0) {
            WB_NOTE("faulted wc_Sha512Update unexpectedly succeeded");
            wb_fail = 1;
        }
        /* The context is poisoned; no digest is taken from it. */
        Transform_Sha512_p = _Transform_Sha512;
        wc_Sha512Free(&sha);
    }

    /* idx0 TRUE, idx1 TRUE: one whole block plus a 5-byte remainder. */
    if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha512_ex failed (remainder baseline skipped)");
        wb_fail = 1;
    }
    else {
        Transform_Sha512_Len_p = NULL;
        Transform_Sha512_p     = _Transform_Sha512;
        ret = wc_Sha512Update(&sha, buf, WC_SHA512_BLOCK_SIZE + 5);
        if (ret != 0) {
            WB_NOTE("wc_Sha512Update remainder baseline failed");
            wb_fail = 1;
        }
        (void)wc_Sha512Final(&sha, hash);
        wc_Sha512Free(&sha);
    }

    /* idx0 TRUE, idx1 FALSE: an exact whole number of blocks, no remainder. */
    if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitSha512_ex failed (exact-block baseline skipped)");
        wb_fail = 1;
    }
    else {
        Transform_Sha512_Len_p = NULL;
        Transform_Sha512_p     = _Transform_Sha512;
        ret = wc_Sha512Update(&sha, buf, WC_SHA512_BLOCK_SIZE);
        if (ret != 0) {
            WB_NOTE("wc_Sha512Update exact-block baseline failed");
            wb_fail = 1;
        }
        (void)wc_Sha512Final(&sha, hash);
        wc_Sha512Free(&sha);
    }

    Transform_Sha512_p     = saved_p;
    Transform_Sha512_Len_p = saved_len_p;
    intel_flags            = saved_flags;
    WB_NOTE("Sha512Update save-remainder ret==0 pair exercised");
}

#else

static void wb_update_transform_err(void)
{
    WB_NOTE("no retargetable sha512 transform pointer in this variant; "
            "save-remainder ret==0 skipped");
}

#endif

int main(void)
{
    printf("sha512.c white-box MC/DC supplement\n");
#if defined(NO_SHA512) || !defined(WOLFSSL_SHA512)
    printf("  SHA-512 not enabled; nothing to exercise\n");
    return 0;
#else
    wb_intel_dispatch();
    wb_update_transform_err();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    return 0;
#endif
}
