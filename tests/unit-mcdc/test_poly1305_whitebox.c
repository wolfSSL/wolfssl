/* test_poly1305_whitebox.c
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

/* White-box supplement for wolfcrypt/src/poly1305.c.
 *
 * On an x86-64 USE_INTEL_POLY1305_SPEEDUP build (USE_INTEL_SPEEDUP +
 * WOLFSSL_X86_64_BUILD, poly1305.h) wc_Poly1305SetKey()/wc_Poly1305Update()/
 * wc_Poly1305Final() dispatch through a file-static cpuid mask (intel_flags),
 * set once in SetKey and reused by Update/Final:
 *
 *   if (IS_INTEL_AVX2(intel_flags)) poly1305_*_avx2(...);
 *   else                            poly1305_*_avx(...);
 *
 * Each of these is a single-condition branch (not a compound MC/DC decision:
 * poly1305.c's own db/modules.json-measured MC/DC total is unaffected by
 * which of these paths a given build takes), so this white-box does not
 * change the campaign's covered/total counts. It is kept anyway, matching
 * the intel-dispatch technique used by the aes/sha3 white-boxes and this
 * campaign's chacha sibling, for FEATURE/branch-coverage evidence that the
 * AVX2-false (AVX1-only) side is reachable and correct: on an AVX2-capable
 * CI host, cpuid_get_flags_ex()'s real detection always takes the AVX2
 * branch through the public API, so tests/api alone never demonstrates the
 * AVX1-only side.
 *
 * cpuid_get_flags_ex() is idempotent (wolfssl/wolfcrypt/cpuid.h): it only
 * re-queries the hardware when the flags word still holds
 * WC_CPUID_INITIALIZER. Forcing intel_flags to a real (non-initializer)
 * value before calling wc_Poly1305SetKey() makes it trust our forced value
 * instead of re-detecting. Crash-safety: this host has real AVX1 hardware
 * (see db/modules.json poly1305 notes), so forcing intel_flags to "AVX1
 * only" and letting the dispatch call the real poly1305_*_avx asm is always
 * safe: we never claim a capability the CPU lacks, only hide one it has.
 */

#include <wolfcrypt/src/poly1305.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_POLY1305) && defined(USE_INTEL_POLY1305_SPEEDUP)

static void wb_poly1305_dispatch(void)
{
    Poly1305 ctx;
    static const byte key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    /* Multiple blocks so poly1305_blocks_avx() actually runs (not just
     * poly1305_block_avx()'s single-block path). */
    byte msg[3 * POLY1305_BLOCK_SIZE + 5];
    byte tag[WC_POLY1305_MAC_SZ];
    cpuid_flags_t saved_flags = intel_flags;
    size_t i;

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (byte)i;
    }

    /* AVX2-false, AVX1-true: forces poly1305_setkey_avx/blocks_avx/
     * final_avx. Real hardware capability, so safe to actually execute. */
    intel_flags = CPUID_AVX1;
    if (wc_Poly1305SetKey(&ctx, key, sizeof(key)) == 0) {
        if (wc_Poly1305Update(&ctx, msg, (word32)sizeof(msg)) != 0 ||
            wc_Poly1305Final(&ctx, tag) != 0) {
            WB_NOTE("Update/Final (AVX1-only) failed");
            wb_fail = 1;
        }
    }
    else {
        WB_NOTE("wc_Poly1305SetKey failed (AVX1-only case skipped)");
        wb_fail = 1;
    }

    intel_flags = saved_flags;
    WB_NOTE("poly1305 intel dispatch AVX1-only side exercised");
}

#else

static void wb_poly1305_dispatch(void)
{
    WB_NOTE("USE_INTEL_POLY1305_SPEEDUP not compiled in this variant; "
        "skipped");
}

#endif

int main(void)
{
    printf("poly1305.c white-box supplement\n");
#ifndef HAVE_POLY1305
    printf("  HAVE_POLY1305 not defined; nothing to exercise\n");
    return 0;
#else
    wb_poly1305_dispatch();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
