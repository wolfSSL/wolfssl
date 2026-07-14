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

int main(void)
{
    printf("sha512.c white-box MC/DC supplement\n");
#if defined(NO_SHA512) || !defined(WOLFSSL_SHA512)
    printf("  SHA-512 not enabled; nothing to exercise\n");
    return 0;
#else
    wb_intel_dispatch();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    return 0;
#endif
}
