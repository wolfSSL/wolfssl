/* test_sha3_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/sha3.c.
 *
 * On an x86-64 USE_INTEL_SPEEDUP build sha3.c dispatches the Keccak block
 * function through file-static function pointers (sha3_block, sha3_block_n)
 * chosen from a file-static cpuid mask (cpuid_flags) in InitSha3, and a
 * per-update fast path keyed on the multi-block pointer:
 *
 *   InitSha3 dispatch (line ~737):
 *       (! cpuid_flags_were_updated) && (SHA3_BLOCK != NULL)
 *   InitSha3 BMI selection (line ~745):
 *       IS_INTEL_BMI1(cpuid_flags) && IS_INTEL_BMI2(cpuid_flags)
 *   Sha3Update multi-block fast path (line ~874):
 *       (sha3_block_n != NULL) && (blocks > 0)
 *
 * On a capable host cpuid reports AVX2, so the runtime always takes the AVX2
 * branch: the "cached", BMI, and non-fast-path conditions are unreachable from
 * tests/api. This TU #includes sha3.c so those static items are in scope and drives
 * InitSha3 / Update with cpuid_flags and the block pointers forced.
 *
 * (The identical "cached" decision in the __aarch64__ dispatch, line ~759, is
 * a different translation unit's code compiled only in the ARM lane; a native
 * white-box cannot reach it -- it is left to the aarch64 lane and recorded as
 * a residual.)
 *
 * Crash-safety: cpuid_flags is forced only around InitSha3 calls that we do
 * NOT follow with a hash, so no asm block ever runs from a claimed-but-absent
 * feature; the one path that hashes (the 874 case) pins sha3_block to the
 * portable C BlockSha3 and sha3_block_n to NULL.
 */

#include <wolfcrypt/src/sha3.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(WOLFSSL_NO_SHA3) && defined(WOLFSSL_SHA3) && \
    defined(USE_INTEL_SPEEDUP) && !defined(WC_C_DYNAMIC_FALLBACK)

/* Run InitSha3 once with cpuid_flags/sha3_block forced, without hashing. The
 * selection decisions (737, 745) evaluate during init; not hashing means no
 * asm block executes even when a feature is claimed the host lacks. */
static void wb_init_with(cpuid_flags_t flags, void (*block)(word64*))
{
    wc_Sha3 s;
    cpuid_flags = flags;
    sha3_block  = block;
    if (wc_InitSha3_256(&s, NULL, INVALID_DEVID) == 0) {
        wc_Sha3_256_Free(&s);
    }
    else {
        WB_NOTE("wc_InitSha3_256 failed (dispatch case skipped)");
        wb_fail = 1;
    }
}

static void wb_sha3_dispatch(void)
{
    cpuid_flags_t saved_flags   = cpuid_flags;
    void (*saved_block)(word64*) = sha3_block;
    void (*saved_block_n)(word64*, const byte*, word32, word64) = sha3_block_n;
    byte data[3 * WC_SHA3_256_BLOCK_SIZE];

    XMEMSET(data, 0, sizeof(data));

    /* 737: (! updated) && (sha3_block != NULL)
     *   cond0 false  -> flags == INITIALIZER makes cpuid_get_flags_ex report
     *                   "updated" (returns 1), short-circuiting cond1. */
    wb_init_with(WC_CPUID_INITIALIZER, sha3_block);
    /*   cond0 true, cond1 true  -> flags real (already read, updated=0) and a
     *   non-NULL block leaves the cached selection in place. */
    wb_init_with(CPUID_AVX2, BlockSha3);
    /*   cond0 true, cond1 false -> updated=0 but block NULL forces re-select. */
    wb_init_with(CPUID_AVX2, NULL);

    /* 745: IS_INTEL_BMI1 && IS_INTEL_BMI2 (reached when 737 false and !AVX2).
     *   sha3_block NULL keeps 737 false; vary the BMI bits. */
    wb_init_with(CPUID_BMI1 | CPUID_BMI2, NULL);   /* [T,T] -> select BMI2 */
    wb_init_with(CPUID_BMI1,              NULL);   /* [T,F] */
    wb_init_with(0,                       NULL);   /* [F,-] -> C block */

    /* 874: (sha3_block_n != NULL) && (blocks > 0), in Sha3Update. MC/DC needs
     *   cond0's independence pair -- both the NULL and non-NULL multi-block
     *   rows -- demonstrated in THIS binary (the variant sees only the AVX2
     *   non-NULL side), so run both with blocks > 0. */

    /* cond0 TRUE: reset to real cpuid so InitSha3 re-selects the host's
     *   multi-block pointer (AVX2 on a capable host), then multi-block update. */
    {
        wc_Sha3 s;
        cpuid_flags  = WC_CPUID_INITIALIZER;   /* force a fresh real selection */
        sha3_block   = NULL;
        sha3_block_n = NULL;
        if (wc_InitSha3_256(&s, NULL, INVALID_DEVID) == 0) {
            (void)wc_Sha3_256_Update(&s, data, (word32)sizeof(data));
            wc_Sha3_256_Free(&s);
        }
        else {
            WB_NOTE("wc_InitSha3_256 failed (874 non-NULL case skipped)");
            wb_fail = 1;
        }
    }
    /* cond0 FALSE: force the multi-block pointer NULL and run a multi-block
     *   update over the portable per-block C route (sha3_block = BlockSha3). */
    {
        wc_Sha3 s;
        if (wc_InitSha3_256(&s, NULL, INVALID_DEVID) == 0) {
            sha3_block   = BlockSha3;
            sha3_block_n = NULL;
            (void)wc_Sha3_256_Update(&s, data, (word32)sizeof(data));
            wc_Sha3_256_Free(&s);
        }
        else {
            WB_NOTE("wc_InitSha3_256 failed (874 NULL case skipped)");
            wb_fail = 1;
        }
    }

    cpuid_flags  = saved_flags;
    sha3_block   = saved_block;
    sha3_block_n = saved_block_n;
    WB_NOTE("sha3 dispatch pairs exercised");
}

#else

static void wb_sha3_dispatch(void)
{
    WB_NOTE("sha3 intel dispatch not compiled in this variant; skipped");
}

#endif

/* The __aarch64__ twin of the dispatch above (line ~759, inside
 * `#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)`), compiled only in
 * the qemu-aarch64 emulator lane (db/lanes.json):
 *
 *   InitSha3 dispatch (line ~759):
 *       (! cpuid_flags_were_updated) && (SHA3_BLOCK != NULL)
 *
 * cond0 (! cpuid_flags_were_updated) is already reached both ways from
 * tests/api: the process's very first InitSha3 call sees the file-static
 * cpuid_flags at its WC_CPUID_INITIALIZER seed (cond0 false), and every
 * call after that sees the cached real value (cond0 true). The residual is
 * cond1 (SHA3_BLOCK != NULL): on a qemu -cpu max host every real detection
 * already leaves SHA3_BLOCK non-NULL, so with cond0 held true (a real,
 * cached cpuid_flags) the FALSE half of cond1 -- SHA3_BLOCK forced NULL,
 * forcing a re-select -- never happens through the public API.
 *
 * Mirrors wb_init_with()/wb_sha3_dispatch() above: force cpuid_flags to a
 * real (non-INITIALIZER) value and vary sha3_block, without hashing, so no
 * asm block ever executes.
 */
#if !defined(WOLFSSL_NO_SHA3) && defined(WOLFSSL_SHA3) && \
    defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WC_C_DYNAMIC_FALLBACK)

static void wb_init_with_aarch64(cpuid_flags_t flags, void (*block)(word64*))
{
    wc_Sha3 s;
    cpuid_flags = flags;
    sha3_block  = block;
    if (wc_InitSha3_256(&s, NULL, INVALID_DEVID) == 0) {
        wc_Sha3_256_Free(&s);
    }
    else {
        WB_NOTE("wc_InitSha3_256 failed (aarch64 dispatch case skipped)");
        wb_fail = 1;
    }
}

static void wb_sha3_dispatch_aarch64(void)
{
    cpuid_flags_t saved_flags    = cpuid_flags;
    void (*saved_block)(word64*) = sha3_block;

    /* 759: (! updated) && (SHA3_BLOCK != NULL), cond1 (SHA3_BLOCK != NULL).
     * Hold cond0 true throughout (flags a real, non-INITIALIZER value on
     * every call), flip sha3_block. */
    wb_init_with_aarch64((cpuid_flags_t)0, BlockSha3_base); /* cond1 T: cached,
                                                              * no re-select */
    wb_init_with_aarch64((cpuid_flags_t)0, NULL);           /* cond1 F: NULL
                                                              * forces re-select */

    cpuid_flags = saved_flags;
    sha3_block  = saved_block;
    WB_NOTE("aarch64 sha3 dispatch (line 759) cond1 pair exercised");
}

#else

static void wb_sha3_dispatch_aarch64(void)
{
    WB_NOTE("sha3 aarch64 dispatch not compiled in this variant; skipped");
}

#endif

int main(void)
{
    printf("sha3.c white-box MC/DC supplement\n");
#if defined(WOLFSSL_NO_SHA3) || !defined(WOLFSSL_SHA3)
    printf("  SHA-3 not enabled; nothing to exercise\n");
    return 0;
#else
    wb_sha3_dispatch();
    wb_sha3_dispatch_aarch64();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    return 0;
#endif
}
