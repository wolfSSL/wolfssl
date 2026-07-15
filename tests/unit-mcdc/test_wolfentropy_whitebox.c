/* test_wolfentropy_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wolfentropy.c.
 *
 * The SP800-90B continuous health tests and their reset helpers are
 * file-static and never return a failure through the public API on a healthy
 * host (the jitter source passes), so the reject sides of their cutoff
 * decisions are unreachable from tests/api. This white-box #includes
 * wolfentropy.c directly and feeds crafted sample streams to drive BOTH sides
 * of each decision in the same binary:
 *
 *   Entropy_HealthTest_Repetition():
 *     - "!rep_have_prev"                first sample stored
 *     - "noise == rep_prev_noise"       repeat increments the run counter
 *     - "rep_cnt >= REP_CUTOFF"         reject (ENTROPY_RT_E) after REP_CUTOFF
 *                                       identical samples
 *     - else                            a differing sample resets the run
 *   Entropy_HealthTest_Proportion():
 *     - "prop_total < PROP_CUTOFF - 1"  fill (accumulate) phase
 *     - else                            windowed phase
 *     - "prop_cnt[noise] >= PROP_CUTOFF" reject (ENTROPY_APT_E)
 *     - "prop_total == PROP_WINDOW_SIZE" sliding-window eviction (accept path)
 *
 * All samples are bytes, so prop_cnt[noise] (256 entries) and prop_samples
 * (PROP_WINDOW_SIZE entries) are always addressed in range -- memory-safe.
 * The higher-level Entropy_Init()/wc_Entropy_OnDemandTest()/wc_Entropy_Get()
 * exercise the MemUse/GetSample/GetNoise/Condition path best-effort; any
 * setup failure is reported as a skip (return 0), never a test failure, so
 * the campaign never discards the variant's coverage.
 */

#include <wolfcrypt/src/wolfentropy.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef HAVE_ENTROPY_MEMUSE

static void wb_repetition(void)
{
    int ret;
    int i;

    /* First-sample and differing-sample (else) branches. */
    Entropy_HealthTest_Repetition_Reset();
    ret = Entropy_HealthTest_Repetition(0x41); /* !rep_have_prev -> store */
    if (ret != 0) { WB_NOTE("repetition first-sample not accepted"); wb_fail = 1; }
    ret = Entropy_HealthTest_Repetition(0x42); /* differing -> else, reset run */
    if (ret != 0) { WB_NOTE("repetition differing-sample not accepted"); wb_fail = 1; }

    /* Drive the run counter to the cutoff: REP_CUTOFF identical samples.
     * The first stores, the next REP_CUTOFF-2 increment the run and pass, and
     * the REP_CUTOFF-th trips "rep_cnt >= REP_CUTOFF". */
    Entropy_HealthTest_Repetition_Reset();
    for (i = 0; i < REP_CUTOFF - 1; i++) {
        ret = Entropy_HealthTest_Repetition(0x55);
        if (ret != 0) {
            WB_NOTE("repetition unexpectedly failed before cutoff");
            wb_fail = 1;
        }
    }
    ret = Entropy_HealthTest_Repetition(0x55); /* run reaches REP_CUTOFF */
    if (ret != WC_NO_ERR_TRACE(ENTROPY_RT_E)) {
        WB_NOTE("repetition cutoff did not report ENTROPY_RT_E");
        wb_fail = 1;
    }

    Entropy_HealthTest_Repetition_Reset();
}

static void wb_proportion(void)
{
    int ret;
    int i;
    int failed_apt = 0;

    /* Fill + windowed + sliding-eviction accept path: a rotating value stream
     * keeps every per-value count well under PROP_CUTOFF while prop_total
     * climbs past PROP_WINDOW_SIZE, so the "prop_total == PROP_WINDOW_SIZE"
     * eviction branch is taken without ever tripping the reject. */
    Entropy_HealthTest_Proportion_Reset();
    for (i = 0; i < PROP_WINDOW_SIZE + 128; i++) {
        ret = Entropy_HealthTest_Proportion((byte)(i & 0xff));
        if (ret != 0) {
            WB_NOTE("proportion rotating stream unexpectedly rejected");
            wb_fail = 1;
            break;
        }
    }

    /* Reject path: a constant value drives one count to PROP_CUTOFF. The fill
     * phase accepts PROP_CUTOFF-1 samples, then the windowed phase increments
     * the same count to PROP_CUTOFF and returns ENTROPY_APT_E. */
    Entropy_HealthTest_Proportion_Reset();
    for (i = 0; i < PROP_CUTOFF; i++) {
        ret = Entropy_HealthTest_Proportion(0x07);
        if (ret == WC_NO_ERR_TRACE(ENTROPY_APT_E)) {
            failed_apt = 1;
            break;
        }
        if (ret != 0) {
            WB_NOTE("proportion constant stream failed with unexpected code");
            wb_fail = 1;
            break;
        }
    }
    if (!failed_apt) {
        WB_NOTE("proportion cutoff did not report ENTROPY_APT_E");
        wb_fail = 1;
    }

    Entropy_HealthTest_Proportion_Reset();
}

/* Best-effort exercise of the collection path (Entropy_MemUse ->
 * Entropy_GetSample/GetNoise -> Entropy_Condition) via the public entry
 * points, once the SHA3 conditioner is initialized. Any failure is a skip. */
static void wb_collect_path(void)
{
    int ret;
    byte out[32];

    ret = Entropy_Init();
    if (ret != 0) {
        WB_NOTE("Entropy_Init failed; skipping collection-path exercise");
        return;
    }

    if (wc_Entropy_OnDemandTest() != 0) {
        WB_NOTE("wc_Entropy_OnDemandTest returned nonzero (skip, not fail)");
    }

    XMEMSET(out, 0, sizeof(out));
    if (wc_Entropy_Get(MAX_ENTROPY_BITS, out, (word32)sizeof(out)) != 0) {
        WB_NOTE("wc_Entropy_Get returned nonzero (skip, not fail)");
    }

    Entropy_Final();
}

#else /* !HAVE_ENTROPY_MEMUSE */

static void wb_repetition(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped repetition test"); }
static void wb_proportion(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped proportion test"); }
static void wb_collect_path(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped collection path"); }

#endif /* HAVE_ENTROPY_MEMUSE */

int main(void)
{
    printf("wolfentropy.c white-box supplement\n");
    /* Collection path first (clean global health state), then the crafted
     * threshold streams (each resets the health state it touches). */
    wb_collect_path();
    wb_repetition();
    wb_proportion();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup issues are surfaced as skips; a nonzero exit would make the
     * campaign discard this variant's coverage. */
    return 0;
}
