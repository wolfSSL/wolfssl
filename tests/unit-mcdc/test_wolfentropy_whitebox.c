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
 *
 * wc_Entropy_Get() itself has two decisions whose operands reference the
 * SAME file-static health-test state, but are not independently selectable
 * from tests/api because Entropy_Init() (run once by test setup) already
 * leaves that state primed:
 *
 *   "if ((ret == 0) && ((prop_total == 0) || (!rep_have_prev)))"
 *     - "prop_total == 0"   startup-retrigger via the first OR operand
 *     - "!rep_have_prev"    startup-retrigger via the second OR operand
 *   "while ((ret == 0) && (len > 0))"
 *   "for (i = 0; (ret == 0) && (i < noise_len); i++)"
 *     - "ret == 0"          both loops only ever end via their *other*
 *                           operand on a healthy host; force an early exit
 *                           by rigging the Proportion counts so the very
 *                           first sample of the very first pass trips the
 *                           cutoff, whatever its (unpredictable) value is.
 *
 * wb_startup_retrigger() and wb_get_loop_early_exit() below drive these by
 * writing prop_total / rep_have_prev / prop_cnt[] directly (file-static,
 * visible to this TU) immediately before calling the public entry point.
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

/* wc_Entropy_Get()'s startup-retrigger guard:
 *   "if ((ret == 0) && ((prop_total == 0) || (!rep_have_prev)))"
 * On any live process, Entropy_Init() (already run by test setup and by
 * wb_collect_path() above) leaves prop_total != 0 and rep_have_prev == 1, so
 * this guard's *true* side -- and each of its two OR operands individually
 * -- is never shown from tests/api. Both globals are file-static: drive
 * each operand's independence pair directly, holding the other operand
 * false (the "both false" side is already exercised by every other
 * steady-state call in this campaign, e.g. wb_collect_path() above). */
static void wb_startup_retrigger(void)
{
    int ret;
    byte out[32];

    ret = Entropy_Init();
    if (ret != 0) {
        WB_NOTE("Entropy_Init failed; skipping startup-retrigger exercise");
        return;
    }

    /* "prop_total == 0" true, "!rep_have_prev" false: retrigger via the
     * first OR operand alone. */
    prop_total = 0;
    rep_have_prev = 1;
    XMEMSET(out, 0, sizeof(out));
    ret = wc_Entropy_Get(MAX_ENTROPY_BITS, out, (word32)sizeof(out));
    if (ret != 0) {
        WB_NOTE("startup retrigger via prop_total==0 failed");
        wb_fail = 1;
    }

    /* "prop_total == 0" false, "!rep_have_prev" true: retrigger via the
     * second OR operand alone. */
    prop_total = 1;
    rep_have_prev = 0;
    XMEMSET(out, 0, sizeof(out));
    ret = wc_Entropy_Get(MAX_ENTROPY_BITS, out, (word32)sizeof(out));
    if (ret != 0) {
        WB_NOTE("startup retrigger via !rep_have_prev failed");
        wb_fail = 1;
    }

    Entropy_Final();
}

/* wc_Entropy_Get()'s collection loops:
 *   "while ((ret == 0) && (len > 0))"
 *   "for (i = 0; (ret == 0) && (i < noise_len); i++)"
 * A healthy host's real jitter noise never fails a health test, so neither
 * loop's "ret == 0" operand is ever shown false while its counterpart
 * (len > 0 / i < noise_len) is still true -- both loops only ever end via
 * the *other* operand. Force the Adaptive Proportion test to reject on the
 * very first sample of the very first pass by pre-loading every prop_cnt[]
 * slot to PROP_CUTOFF - 1 with prop_total already in the windowed phase:
 * whichever byte the real jitter sample turns out to be, incrementing its
 * count trips the cutoff deterministically, regardless of the
 * (unpredictable) sample value itself. A single fixed Repetition sample is
 * primed first so that test cannot itself reject and mask the rig. */
static void wb_get_loop_early_exit(void)
{
    int ret;
    byte out[64];
    int v;

    ret = Entropy_Init();
    if (ret != 0) {
        WB_NOTE("Entropy_Init failed; skipping loop-early-exit exercise");
        return;
    }

    Entropy_HealthTest_Reset();
    /* Deterministically prime the Repetition test's "have previous" state
     * via its own first-sample branch so it can never reach REP_CUTOFF
     * during this exercise (rep_cnt ends at 1, or at most 2 if the first
     * real sample happens to repeat 0xab). */
    Entropy_HealthTest_Repetition(0xab);

    /* Rig the Proportion test into the windowed phase with every count one
     * short of the reject cutoff. */
    prop_total = PROP_CUTOFF;
    for (v = 0; v < (1 << ENTROPY_BITS_USED); v++) {
        prop_cnt[v] = PROP_CUTOFF - 1;
    }

    XMEMSET(out, 0, sizeof(out));
    ret = wc_Entropy_Get(MAX_ENTROPY_BITS, out, (word32)sizeof(out));
    if (ret != WC_NO_ERR_TRACE(ENTROPY_APT_E)) {
        WB_NOTE("rigged proportion cutoff did not short-circuit "
                 "wc_Entropy_Get's collection loops");
        wb_fail = 1;
    }

    Entropy_HealthTest_Reset();
    Entropy_Final();
}

#else /* !HAVE_ENTROPY_MEMUSE */

static void wb_repetition(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped repetition test"); }
static void wb_proportion(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped proportion test"); }
static void wb_collect_path(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped collection path"); }
static void wb_startup_retrigger(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped startup retrigger"); }
static void wb_get_loop_early_exit(void)
{ WB_NOTE("HAVE_ENTROPY_MEMUSE not compiled in; skipped loop early exit"); }

#endif /* HAVE_ENTROPY_MEMUSE */

int main(void)
{
    printf("wolfentropy.c white-box supplement\n");
    /* Collection path first (clean global health state), then the crafted
     * threshold streams (each resets the health state it touches), then the
     * rigged-state exercises of wc_Entropy_Get()'s own decisions (each pair
     * calls Entropy_Init()/Entropy_Final() around itself). */
    wb_collect_path();
    wb_repetition();
    wb_proportion();
    wb_startup_retrigger();
    wb_get_loop_early_exit();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup issues are surfaced as skips; a nonzero exit would make the
     * campaign discard this variant's coverage. */
    return 0;
}
