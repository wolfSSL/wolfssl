/* mcdc_fault_mutex.h
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

/*
 * mcdc_fault_mutex.h -- mutex-fault injector for the per-module MC/DC campaign.
 *
 * PURPOSE
 * -------
 * Every SP backend guards its FP-ECC point cache with
 *
 *     if ((err == MP_OKAY) && (wc_LockMutex(&sp_cache_<n>_lock) != 0))
 *         err = BAD_MUTEX_E;
 *
 * A live, correctly initialised mutex always locks, so an ordinary run only
 * ever observes (T,F). Both operands therefore stay uncovered. The two missing
 * vectors are:
 *
 *   (T,T)  the lock is refused        -> covers the wc_LockMutex operand
 *   (F,-)  err is already not MP_OKAY -> covers the err operand
 *
 * In these functions err can only be non-MP_OKAY at that point when the
 * one-shot wc_InitMutex above it failed, so both hooks are needed.
 *
 * USAGE
 * -----
 * Two-phase include, in the white-box TU:
 *
 *     #include "mcdc_fault_mutex.h"
 *     #include <wolfcrypt/src/sp_c32.c>
 *     #define MCDC_FM_IMPL
 *     #include "mcdc_fault_mutex.h"
 *
 * The first phase redirects this TU's wc_InitMutex/wc_LockMutex calls; the
 * prototypes in wc_port.h expand into the hooks' own declarations. The second
 * phase defines the hooks, reaching the real functions through the #undef'd
 * names.
 *
 * Drive with:
 *
 *     mcdc_fm_init_fail = 1;  <first call into the cached path>   (F,-)
 *     mcdc_fm_init_fail = 0; mcdc_fm_lock_fail = 1; <call again>  (T,T)
 *     mcdc_fm_lock_fail = 0; <call again>                         (T,F)
 *
 * The init hook must fail on the FIRST call that reaches the cache: the
 * initialisation is one-shot behind an atomic, and resets to "uninitialised"
 * on failure so a later call retries.
 *
 * A failed lock leaves err = BAD_MUTEX_E, so the caller skips the block that
 * would wc_UnLockMutex() a mutex this hook never locked.
 *
 * Compiles to inert no-ops where the guarded code does not exist or the mutex
 * ops are not plain functions (MCDC_FM_UNAVAILABLE).
 */

#if defined(SINGLE_THREADED) || defined(HAVE_THREAD_LS) || \
    defined(WC_MUTEX_OPS_INLINE) || defined(HAVE_FIPS)
    #define MCDC_FM_UNAVAILABLE
#endif

#ifndef MCDC_FM_IMPL

#ifndef MCDC_FAULT_MUTEX_H
#define MCDC_FAULT_MUTEX_H

static int mcdc_fm_init_fail = 0;
static int mcdc_fm_lock_fail = 0;
/* One-shot: fail the next lock only, then disarm. For guards whose first
 * operand is an error a *different*, earlier lock produced -- arming the whole
 * process would short-circuit the very decision under test. */
static int mcdc_fm_lock_once = 0;

#ifndef MCDC_FM_UNAVAILABLE
    #define wc_InitMutex(m) mcdc_fm_init(m)
    #define wc_LockMutex(m) mcdc_fm_lock(m)
#endif

#endif /* MCDC_FAULT_MUTEX_H */

#else /* MCDC_FM_IMPL */

#ifndef MCDC_FM_UNAVAILABLE

#undef wc_InitMutex
#undef wc_LockMutex

extern int wc_InitMutex(wolfSSL_Mutex* m);
extern int wc_LockMutex(wolfSSL_Mutex* m);

int mcdc_fm_init(wolfSSL_Mutex* m)
{
    if (mcdc_fm_init_fail) {
        return BAD_MUTEX_E;
    }
    return wc_InitMutex(m);
}

int mcdc_fm_lock(wolfSSL_Mutex* m)
{
    if (mcdc_fm_lock_once) {
        mcdc_fm_lock_once = 0;
        return BAD_MUTEX_E;
    }
    if (mcdc_fm_lock_fail) {
        return BAD_MUTEX_E;
    }
    return wc_LockMutex(m);
}

#endif /* !MCDC_FM_UNAVAILABLE */

#endif /* MCDC_FM_IMPL */
