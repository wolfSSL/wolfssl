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
#include "xil_util.h"
#include "xstatus.h"

#ifndef WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT
    #include "xilmailbox.h"
    #include "xparameters.h"

    /* IPI channel the client reaches the ASU on. */
    #ifndef WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR
        #define WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR XPAR_XIPIPSU_0_BASEADDR
    #endif
#endif

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC
    #include "xiltimer.h"
    #include "xrtcpsu.h"
    #include "xparameters.h"

    #ifndef COUNTS_PER_SECOND
        #define COUNTS_PER_SECOND XPAR_CPU_TIMESTAMP_CLK_FREQ
    #endif
#endif

#ifndef WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT

int wc_AsuClientInit(void)
{
    /* The client keeps the mailbox for every later request; ready makes a
     * repeat register a no-op. */
    static XMailbox mailbox;
    static int      ready = 0;
    s32 status;

    if (ready) {
        return 0;
    }

    status = (s32)XMailbox_Initialize(&mailbox,
                                      WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR);
    if (status != XST_SUCCESS) {
        WC_ASU_PRINTF("ASU mailbox initialize failed: %08x\r\n",
                      (unsigned int)status);
        return WC_HW_E;
    }

    status = (s32)XAsu_ClientInit(&mailbox);
    if (status != XST_SUCCESS) {
        WC_ASU_PRINTF("ASU client initialize failed: %08x\r\n",
                      (unsigned int)status);
        return WC_HW_E;
    }

    ready = 1;
    return 0;
}

#endif /* !WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT */

/* Called when an ASU request finishes. The client hands our record back. */
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

#ifndef WC_ASU_WAIT_TIMEOUT_US
    /* How long each wait lasts. A timeout just waits again, it is not an
     * error. */
    #define WC_ASU_WAIT_TIMEOUT_US 1000000U
#endif

word32 wc_AsuWaitDone(AsuWait* wait)
{
    while (wait->Done == 0) {
    #ifdef XYIELD
        /* Let the scheduler run if the app defines XYIELD. */
        XYIELD();
    #else
        /* Wait for the done flag. It is one byte, so mask the low byte of the
         * word this call reads. */
        (void)Xil_WaitForEvent((UINTPTR)&wait->Done, 0xFFU, 1U,
            WC_ASU_WAIT_TIMEOUT_US);
    #endif
    }

    return wait->Status;
}

/* With the cache off these do nothing. With it on they push inputs out and
 * reload outputs around each ASU call. */

void wc_AsuCacheFlush(const void* addr, word32 len)
{
    if (addr == NULL || len == 0) {
        return;
    }
#ifdef WC_ASU_DISABLE_CACHE
    (void)addr;
    (void)len;
#else
    Xil_DCacheFlushRange((INTPTR)addr, (INTPTR)len);
#endif
}

/* Callers flush before the operation, so the end lines hold nothing stale and
 * nearby data keeps its value. */
void wc_AsuCacheInvalidate(void* addr, word32 len)
{
    if (addr == NULL || len == 0) {
        return;
    }
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
/* Each call gets its own id and its own wait record, so several can run at
 * once. Only the submit needs a lock, and the lock is dropped before waiting. */
word32 wc_AsuTransact(AsuSubmitFn submit, void* ctx, word32* additionalStatus)
{
    XAsu_ClientParams params;
    AsuWait wait;
    s32 status;

    if (submit == NULL) {
        return (word32)XST_FAILURE;
    }

    /* These params carry the record the ASU hands back when it is done. */
    wc_AsuWaitPrepare(&wait, &params);

    wolfSSL_CryptHwMutexLock();
    status = submit(&params, ctx);
    wolfSSL_CryptHwMutexUnLock();

    if (status != XST_SUCCESS) {
        WC_ASU_PRINTF("[ASU] submit failed status=%d\r\n", (int)status);
        return (word32)status;
    }

    /* Wait outside the lock so other callers can submit while we wait. */
    status = (s32)wc_AsuWaitDone(&wait);

    WC_ASU_PRINTF("[ASU] op done status=%d\r\n", (int)status);

    if (additionalStatus != NULL) {
        *additionalStatus = params.AdditionalStatus;
    }

    return (word32)status;
}

#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC

/* Timer and clock. The A78 timer always runs and needs no setup. The system
 * clock is started here and read for wall clock times. */

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

/* Time source the benchmark uses to time each operation. */
double current_time(int reset)
{
    (void)reset; /* the timer always runs, nothing to reset */

    return wc_AsuTimerSeconds();
}

#endif /* WOLFSSL_USER_CURRTIME */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RTC */

#endif /* WOLFSSL_VERSAL_GEN2_ASU */
