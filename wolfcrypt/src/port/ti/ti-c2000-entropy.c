/* port/ti/ti-c2000-entropy.c
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

/* Oscillator-jitter entropy source for the TI C2000 (C28x).  Model and build
 * options: wolfssl/wolfcrypt/port/ti/ti-c2000-entropy.h.  Characterization:
 * IDE/C2000/README.md.
 *
 * This file owns only the hardware: DCC setup, one measurement, and the noise
 * bit.  The SP800-90B startup and continuous health tests, the entropy budget,
 * the SHA-256 conditioner and the latched failure state are the generic
 * wc_NoiseSrc_* layer in wolfcrypt/src/random.c, which this configures.
 *
 * Noise bit = LSB of a DCC measurement (PLL edges counted inside a window of
 * INTOSC cycles), i.e. the relative phase drift of two independent
 * oscillators.  Both sources are hashed in, but only source 0 is credited with
 * entropy: source 1 estimates lower and fails a chi-square uniformity check,
 * so it is defence-in-depth only.  Extra hash input can never subtract
 * entropy, and because source 1 is unbudgeted the generic layer drops it
 * rather than failing closed if its health tests trip - see the latch policy
 * in wolfcrypt/src/random.c.
 *
 * Build options (all #ifndef-guarded in ti-c2000-entropy.h, documented with
 * defaults in IDE/C2000/README.md):
 *   WOLFSSL_C2000_ENTROPY            enable this source
 *   ..._NUM_SRC                      1 to use source 0 only, freeing a DCC
 *   ..._SRC0_DCC / ..._SRC1_DCC      DCC instance per source
 *   ..._SRC0_CLK / ..._SRC1_CLK      slow (window) clock per source
 *   ..._REF_CLK                      fast clock counted (PLL or SYSCLK)
 *   ..._NO_CLK_INIT                  application owns the DCC clocks
 *   ..._WINDOW                       slow-clock cycles per noise bit
 *   ..._HMIN / ..._MARGIN            assumed min-entropy and oversample
 *   ..._RCT_CUTOFF                   SP800-90B 4.4.1 cutoff
 *   ..._APT_WINDOW / ..._APT_CUTOFF  SP800-90B 4.4.2 window and cutoff
 *   ..._STARTUP_OCTETS               SP800-90B 4.3 startup size per source
 *   ..._NO_LOCK                      assert an external lock instead of
 *                                    requiring SINGLE_THREADED
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_C2000_ENTROPY

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#include "dcc.h"
#include "sysctl.h"

#include <wolfssl/wolfcrypt/port/ti/ti-c2000-entropy.h>

/* Counter1 seed; the window must not exhaust it. */
#define C2000_CNT1_SEED   0xFFFFFUL
#define C2000_NUM_SRC     WOLFSSL_C2000_ENTROPY_NUM_SRC

/* Raw octets the generic layer gathers per source per chunk, from the entropy
 * budget.  Sizes the work buffer; wc_NoiseSrc_Init() rederives and checks it. */
#define C2000_RAW_PER_SRC                                                     \
    WC_NOISE_RAW_PER_SRC(WOLFSSL_C2000_ENTROPY_HMIN,                          \
                         WOLFSSL_C2000_ENTROPY_MARGIN)

/* Domain separation from any other SHA-256 use in the system. */
static const char c2000_entropyTag[] = "wolfssl-c2000-osc-entropy-v1";

/* .bss, not stack: the C28x stack is 16 KW below 0x10000. */
static byte c2000_work[C2000_NUM_SRC * C2000_RAW_PER_SRC];

static wc_NoiseSrc c2000_src;
#ifndef WOLFSSL_C2000_ENTROPY_NO_CLK_INIT
static int c2000_clkOn = 0;
#endif


#ifndef WOLFSSL_C2000_ENTROPY_NO_CLK_INIT
/* Map a DCC base to its peripheral-clock enum, so the SRC*_DCC overrides
 * decide which clocks are touched instead of hardcoding both instances. */
static void c2000_clkEnable(uint32_t base)
{
    if (base == DCC0_BASE) {
        SysCtl_enablePeripheral(SYSCTL_PERIPH_CLK_DCC0);
    }
    else {
        SysCtl_enablePeripheral(SYSCTL_PERIPH_CLK_DCC1);
    }
}
static void c2000_clkDisable(uint32_t base)
{
    if (base == DCC0_BASE) {
        SysCtl_disablePeripheral(SYSCTL_PERIPH_CLK_DCC0);
    }
    else {
        SysCtl_disablePeripheral(SYSCTL_PERIPH_CLK_DCC1);
    }
}
#endif


/* One DCC measurement.  Driven at register level rather than through
 * DCC_measureClockFrequency(), which uses float32_t - no FP in the RNG path.
 *
 * STATUS.ERR is expected, not a fault: the DCC verifies a clock ratio and
 * flags an error when counter0 expires with counter1 far from zero, which is
 * every measurement here since counter1 is seeded at maximum.  The count is
 * still valid; driverlib itself waits on (DONE || ERR) and reads it either
 * way.  Only a real timeout returns WC_HW_E - folding one in as a zero would
 * silently inject a deterministic bit. */
static int c2000_dccSample(uint32_t base, DCC_Count0ClockSource src0,
                           uint32_t* outCnt)
{
    uint32_t guard;
    uint32_t limit;

    DCC_clearErrorFlag(base);
    DCC_clearDoneFlag(base);
    DCC_disableModule(base);
    DCC_disableErrorSignal(base);
    DCC_disableDoneSignal(base);

    DCC_setCounter0ClkSource(base, src0);
    DCC_setCounter1ClkSource(base, WOLFSSL_C2000_ENTROPY_REF_CLK);
    DCC_setCounterSeeds(base, (uint32_t)WOLFSSL_C2000_ENTROPY_WINDOW,
                        DCC_VALIDSEED_MIN, C2000_CNT1_SEED);
    DCC_enableSingleShotMode(base, DCC_MODE_COUNTER_ZERO);

    /* DONE only latches with the done/error signals enabled. */
    DCC_enableErrorSignal(base);
    DCC_enableDoneSignal(base);
    DCC_enableModule(base);

    limit = ((uint32_t)WOLFSSL_C2000_ENTROPY_WINDOW * 256UL) + 100000UL;
    for (guard = 0; guard < limit; guard++) {
        if (DCC_getSingleShotStatus(base) || DCC_getErrorStatus(base)) {
            *outCnt = (C2000_CNT1_SEED -
                       (DCC_getCounter1Value(base) & C2000_CNT1_SEED));
            return 0;
        }
    }

    return WC_HW_E;
}


/* wc_NoiseSampleCb: one raw octet, one LSB per measurement, 8 per octet. */
static int c2000_sampleOctet(void* ctx, int srcIdx, byte* octet)
{
    uint32_t base;
    uint32_t cnt;
    DCC_Count0ClockSource s0;
    int b;
    int ret;
    word16 acc;

    (void)ctx;

    if (srcIdx == 0) {
        base = WOLFSSL_C2000_ENTROPY_SRC0_DCC;
        s0   = WOLFSSL_C2000_ENTROPY_SRC0_CLK;
    }
    else {
        base = WOLFSSL_C2000_ENTROPY_SRC1_DCC;
        s0   = WOLFSSL_C2000_ENTROPY_SRC1_CLK;
    }

    acc = 0;
    for (b = 0; b < 8; b++) {
        ret = c2000_dccSample(base, s0, &cnt);
        if (ret != 0) {
            return ret;
        }
        acc = (word16)(acc | (word16)((cnt & 1U) << b));
    }
    *octet = WC_OCTET(acc);

    return 0;
}


int wc_c2000_Entropy_Init(void)
{
    if (c2000_src.inited) {
        return 0;
    }

#ifndef WOLFSSL_C2000_ENTROPY_NO_CLK_INIT
    if (!c2000_clkOn) {
        c2000_clkEnable(WOLFSSL_C2000_ENTROPY_SRC0_DCC);
#if C2000_NUM_SRC > 1
        c2000_clkEnable(WOLFSSL_C2000_ENTROPY_SRC1_DCC);
#endif
        SysCtl_delay(100);
        c2000_clkOn = 1;
    }
#endif

    /* Refilled on every attempt: _Free() zeroes the instance. */
    c2000_src.sampleCb      = c2000_sampleOctet;
    c2000_src.ctx           = NULL;
    c2000_src.tag           = c2000_entropyTag;
    c2000_src.work          = c2000_work;
    c2000_src.workSz        = (word32)sizeof(c2000_work);
    c2000_src.startupOctets = (word32)WOLFSSL_C2000_ENTROPY_STARTUP_OCTETS;
    c2000_src.numSrc        = (byte)C2000_NUM_SRC;
    c2000_src.hmin          = (byte)WOLFSSL_C2000_ENTROPY_HMIN;
    c2000_src.margin        = (byte)WOLFSSL_C2000_ENTROPY_MARGIN;
    c2000_src.rctCutoff     = (word16)WOLFSSL_C2000_ENTROPY_RCT_CUTOFF;
    c2000_src.aptWindow     = (word16)WOLFSSL_C2000_ENTROPY_APT_WINDOW;
    c2000_src.aptCutoff     = (word16)WOLFSSL_C2000_ENTROPY_APT_CUTOFF;

    return wc_NoiseSrc_Init(&c2000_src);
}


void wc_c2000_Entropy_Free(void)
{
    /* Not gated on inited: a startup-test failure returns before that is set,
     * and the clocks are already on by then. */
    DCC_disableModule(WOLFSSL_C2000_ENTROPY_SRC0_DCC);
#if C2000_NUM_SRC > 1
    DCC_disableModule(WOLFSSL_C2000_ENTROPY_SRC1_DCC);
#endif
#ifndef WOLFSSL_C2000_ENTROPY_NO_CLK_INIT
    c2000_clkDisable(WOLFSSL_C2000_ENTROPY_SRC0_DCC);
#if C2000_NUM_SRC > 1
    c2000_clkDisable(WOLFSSL_C2000_ENTROPY_SRC1_DCC);
#endif
    c2000_clkOn = 0;
#endif

    wc_NoiseSrc_Free(&c2000_src);
    XMEMSET(&c2000_src, 0, sizeof(c2000_src));
}


int wc_c2000_Entropy_GetRaw(byte* out, word32 len, int srcIdx)
{
    int ret;

    ret = wc_c2000_Entropy_Init();
    if (ret != 0) {
        return ret;
    }

    return wc_NoiseSrc_GetRaw(&c2000_src, out, len, srcIdx);
}


int wc_c2000_GenerateSeed(byte* output, word32 sz)
{
    int ret;

    ret = wc_c2000_Entropy_Init();
    if (ret != 0) {
        return ret;
    }

    return wc_NoiseSrc_GenerateSeed(&c2000_src, output, sz);
}


int wc_c2000_Entropy_SelfTest(void)
{
    int ret;

    ret = wc_c2000_Entropy_Init();
    if (ret != 0) {
        return ret;
    }

    return wc_NoiseSrc_SelfTest(&c2000_src);
}

#endif /* WOLFSSL_C2000_ENTROPY */
