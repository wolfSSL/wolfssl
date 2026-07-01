/* asu_util.h
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

/* Shared helpers for the Versal Gen2 ASU port: the asynchronous request to
 * synchronous completion bridge and cache maintenance for ASU buffers. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_UTIL_H
#define WOLFSSL_VERSAL_GEN2_ASU_UTIL_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/types.h>
#include "xasu_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Debug print to confirm operations are going through the ASU port. Enable by
 * defining WOLFSSL_VERSAL_GEN2_ASU_DEBUG in user_settings.h. Prints over the
 * standalone console (xil_printf); compiles out otherwise. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_DEBUG
    #include "xil_printf.h"
    #define WC_ASU_PRINTF(...) xil_printf(__VA_ARGS__)
#else
    #define WC_ASU_PRINTF(...) ((void)0)
#endif

/* Completion record for one asynchronous ASU request. The ASU client invokes
 * the shared response handler from its mailbox path, which fills this record;
 * the submitting code then spins until Done is set. */
typedef struct AsuWait {
    volatile byte   Done;   /* set when the response handler has run */
    volatile word32 Status; /* server status captured by the handler */
} AsuWait;

/* Initialize Wait and point ClientParams at the shared response handler. The
 * request is configured as high priority and secure by default. */
WOLFSSL_LOCAL void wc_AsuWaitPrepare(AsuWait* wait, XAsu_ClientParams* params);

/* Block until the request bound to Wait completes and return the server
 * status. Single threaded baremetal client, so a busy wait is correct. */
WOLFSSL_LOCAL word32 wc_AsuWaitDone(AsuWait* wait);

/* Clean a buffer out to memory so the ASU sees the latest CPU writes. */
WOLFSSL_LOCAL void wc_AsuCacheFlush(const void* addr, word32 len);

/* Invalidate a buffer so the CPU reads what the ASU wrote to memory. */
WOLFSSL_LOCAL void wc_AsuCacheInvalidate(void* addr, word32 len);


/* ----------------------------------------------------------------------- */
/* Transaction and concurrency (ticketing)                                 */
/* ----------------------------------------------------------------------- */
/* Submit function for one ASU transaction. The implementation fills its
 * request from ctx and calls the matching XAsu_* client API with the prepared
 * ClientParams, returning the client submission status (XST_SUCCESS when the
 * request was queued). It is called with the submit lock held, so it must only
 * queue the request, never wait. */
typedef int (*AsuSubmitFn)(XAsu_ClientParams* params, void* ctx);

/* Run one ASU transaction and return the server status (XST_SUCCESS on success,
 * otherwise a failure status). If additionalStatus is not NULL it receives the
 * server AdditionalStatus field, used by operations like AES GCM tag checks.
 *
 * With WOLFSSL_VERSAL_GEN2_ASU_SINGLE_THREADED this is submit then wait under
 * the wolfSSL crypto hardware mutex. Otherwise it takes a FIFO ticket, submits
 * under the short submit lock so the non thread safe client allocation is
 * serialized, hands the turn to the next waiter, then waits on its own
 * completion outside the lock, so up to the ASU queue depth of requests run
 * concurrently across threads. */
WOLFSSL_LOCAL word32 wc_AsuTransact(AsuSubmitFn submit, void* ctx,
    word32* additionalStatus);


/* ----------------------------------------------------------------------- */
/* Timer and RTC (optional, for benchmarking)                              */
/* ----------------------------------------------------------------------- */
/* The entire timer and RTC facility is gated by WOLFSSL_VERSAL_GEN2_ASU_RTC,
 * turned on in user_settings.h, so it compiles out completely for a build that
 * does not benchmark. When enabled it provides the benchmark current_time()
 * hook from the Cortex A78 generic timer and an optional system RTC wall clock
 * read. */
#ifdef WOLFSSL_VERSAL_GEN2_ASU_RTC

/* Bring up the time source. Returns 0 on success. */
WOLFSSL_LOCAL int wc_AsuTimerInit(void);

/* Raw monotonic count from the generic timer. */
WOLFSSL_LOCAL word64 wc_AsuTimerCount(void);

/* Monotonic time in seconds from the generic timer. This is what the benchmark
 * current_time() hook reports. */
WOLFSSL_LOCAL double wc_AsuTimerSeconds(void);

/* Wall clock time in seconds from the system RTC. One second resolution, so it
 * is for timestamps, not per operation timing. */
WOLFSSL_LOCAL word32 wc_AsuRtcSeconds(void);

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RTC */

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_UTIL_H */
