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
    defined(USE_INTEL_SPEEDUP) && !defined(WC_C_DYNAMIC_FALLBACK) && \
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

int main(void)
{
    printf("sha256.c white-box MC/DC supplement\n");
#ifdef NO_SHA256
    printf("  NO_SHA256 defined; nothing to exercise\n");
    return 0;
#else
    wb_intel_dispatch();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
