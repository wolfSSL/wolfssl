/* asu_util.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "xil_cache.h"
#include "xstatus.h"

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC
    #include "xiltimer.h"
    #include "xrtcpsu.h"
    #include "xparameters.h"

    #ifndef COUNTS_PER_SECOND
        #define COUNTS_PER_SECOND XPAR_CPU_TIMESTAMP_CLK_FREQ
    #endif
#endif

/* Shared response handler registered with every ASU request. The ASU client
 * passes the AsuWait record back through the callback reference. */
static void wc_AsuResponseHandler(void* ref, u32 status)
{
    AsuWait* wait = (AsuWait*)ref;

    if (wait != NULL) {
        wait->Status = (word32)status;
        wait->Done   = 1;
    }
}

void wc_AsuWaitPrepare(AsuWait* wait, XAsu_ClientParams* params)
{
    wait->Done   = 0;
    wait->Status = (word32)XST_FAILURE;

    params->Priority         = XASU_PRIORITY_HIGH;
    params->SecureFlag       = XASU_CMD_SECURE;
    params->CallBackFuncPtr  = (XAsuClient_ResponseHandler)wc_AsuResponseHandler;
    params->CallBackRefPtr   = (void*)wait;
    params->AdditionalStatus = (u32)XST_FAILURE;
}

word32 wc_AsuWaitDone(AsuWait* wait)
{
    while (wait->Done == 0) {
        /* busy wait for the single threaded baremetal client */
    }

    return wait->Status;
}

/* When WC_ASU_DISABLE_CACHE is set (mirrored from XASU_DISABLE_CACHE in
 * asu_settings.h) the data cache is off for the whole application, so buffer
 * maintenance is unnecessary and these become no ops. Otherwise the cache is on
 * and the port cleans inputs and invalidates outputs around each ASU access. */
void wc_AsuCacheFlush(const void* addr, word32 len)
{
#ifdef WC_ASU_DISABLE_CACHE
    (void)addr;
    (void)len;
#else
    Xil_DCacheFlushRange((INTPTR)addr, (INTPTR)len);
#endif
}

void wc_AsuCacheInvalidate(void* addr, word32 len)
{
#ifdef WC_ASU_DISABLE_CACHE
    (void)addr;
    (void)len;
#else
    Xil_DCacheInvalidateRange((INTPTR)addr, (INTPTR)len);
#endif
}


/* ----------------------------------------------------------------------- */
/* Transaction and concurrency (ticketing)                                 */
/* ----------------------------------------------------------------------- */
/* The ASU associates a unique id with each call and routes its completion back
 * to the request's own callback, so that id is the ticket: every transaction
 * gets its own AsuWait and several run concurrently. The only shared state that
 * needs guarding is the submit, since the client request allocation is not
 * thread safe. Locking uses the wolfSSL crypto hardware mutex (enabled for the
 * multi threaded build in asu_settings.h, a no op otherwise) and is held only
 * across the submit, never across the wait. */
word32 wc_AsuTransact(AsuSubmitFn submit, void* ctx, word32* additionalStatus)
{
    XAsu_ClientParams params;
    AsuWait wait;
    s32 status;

    if (submit == NULL) {
        return (word32)XST_FAILURE;
    }

    /* The prepared params carry this request's completion context, which the
     * ASU associates with the unique id it assigns. */
    wc_AsuWaitPrepare(&wait, &params);

    wolfSSL_CryptHwMutexLock();
    status = submit(&params, ctx);
    wolfSSL_CryptHwMutexUnLock();

    if (status != XST_SUCCESS) {
        WC_ASU_PRINTF("[ASU] submit failed status=%d\r\n", (int)status);
        return (word32)status;
    }

    /* Wait on our own completion outside the lock, so other callers submit and
     * run concurrently up to the ASU queue depth. */
    status = (s32)wc_AsuWaitDone(&wait);

    WC_ASU_PRINTF("[ASU] op done status=%d\r\n", (int)status);

    if (additionalStatus != NULL) {
        *additionalStatus = params.AdditionalStatus;
    }

    return (word32)status;
}

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC

/* Timer and RTC. The benchmark time base is the Cortex A78 generic timer, which
 * is free running and needs no init. The system RTC is brought up by
 * wc_AsuTimerInit and read with wc_AsuRtcSeconds for wall clock timestamps. */

static XRtcPsu asuRtc;
static int     asuRtcReady = 0;

int wc_AsuTimerInit(void)
{
    XRtcPsu_Config* cfg;

    if (asuRtcReady) {
        return 0;
    }

    cfg = XRtcPsu_LookupConfig(XPAR_XRTCPSU_0_BASEADDR);
    if (cfg == NULL) {
        return WC_HW_E;
    }

    if (XRtcPsu_CfgInitialize(&asuRtc, cfg, XPAR_XRTCPSU_0_BASEADDR)
            != XST_SUCCESS) {
        return WC_HW_E;
    }

    asuRtcReady = 1;
    return 0;
}

word64 wc_AsuTimerCount(void)
{
    XTime now = 0;

    XTime_GetTime(&now);

    return (word64)now;
}

double wc_AsuTimerSeconds(void)
{
    return (double)wc_AsuTimerCount() / (double)COUNTS_PER_SECOND;
}

word32 wc_AsuRtcSeconds(void)
{
    if (!asuRtcReady && wc_AsuTimerInit() != 0) {
        return 0;
    }

    return (word32)XRtcPsu_GetCurrentTime(&asuRtc);
}

#if defined(WOLFSSL_USER_CURRTIME)

/* Benchmark time source. benchmark.c declares this extern when
 * WOLFSSL_USER_CURRTIME is set and calls it to time each operation. */
double current_time(int reset)
{
    (void)reset; /* the generic timer counter is free running */

    return wc_AsuTimerSeconds();
}

#endif /* WOLFSSL_USER_CURRTIME */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RTC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU */
