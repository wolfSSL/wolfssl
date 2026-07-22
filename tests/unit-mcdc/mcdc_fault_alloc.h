/* mcdc_fault_alloc.h
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
 * mcdc_fault_alloc.h -- header-only, self-contained heap-fault injector for the
 * per-module MC/DC campaign.
 *
 * PURPOSE
 * -------
 * The dominant justified-residual class across the campaign is the FALSE half
 * of success-chain guards shaped
 *
 *     if ((err == MP_OKAY) && <next step>) ...          (drive on FALSE)
 *     if ((tmp = XMALLOC(...)) == NULL || ...) ...       (drive each operand)
 *     if ((ret != MP_INIT_E) && (ret != MEMORY_E)) ...   (drive the MEMORY_E half)
 *
 * In normal execution every allocation succeeds, so err/ret stays MP_OKAY and
 * these decisions never take the failure branch. The only way to exercise the
 * failure half is to make an EARLIER allocation/init fail so the success chain
 * is broken with ret == MEMORY_E.
 *
 * wolfSSL routes ALL heap traffic through XMALLOC/XREALLOC/XFREE, which in a
 * default (non-static, non-debug) build dispatch to the process-wide allocator
 * callbacks installed via wolfSSL_SetAllocators() (see
 * wolfssl/wolfcrypt/memory.h). This header installs a callback that fails the
 * N-th (and every subsequent) heap allocation, letting a white-box sweep the
 * fail-index across a function's allocation sites so that, for each index,
 * exactly one earlier allocation returns NULL and drives one guard's FALSE
 * half. The real libc malloc/free/realloc are used underneath.
 *
 * INTENDED SWEEP PATTERN
 * ----------------------
 *     mcdc_fa_install();                     // once, up front
 *     ...prepare valid inputs (NOT armed)... // allocations here must succeed
 *     for (n = 1; n <= K; n++) {             // K >= number of alloc sites
 *         mcdc_fa_arm(n);                    // n-th alloc (and later) -> NULL
 *         (void)Target(args...);            // exercise one failure position
 *         mcdc_fa_disarm();                  // let cleanup / next prep alloc
 *     }
 *     mcdc_fa_disarm();
 *     mcdc_fa_restore();                     // put the originals back
 *
 * Pick K a few larger than the count of XMALLOC sites reachable in the target
 * (over-sweeping is harmless: once n exceeds the site count the target simply
 * runs to completion). Each armed call must be crash-safe: a NULL from a
 * mid-operation allocation may leave a partially built structure, so the target
 * MUST clean up after itself (exercising that cleanup is exactly the point) and
 * the harness must not dereference anything the failed call returned.
 *
 * PORTABILITY
 * -----------
 * The wolfSSL_Malloc_cb / _Free_cb / _Realloc_cb typedefs have several
 * signature variants (WOLFSSL_STATIC_MEMORY, WOLFSSL_DEBUG_MEMORY). This mock
 * implements ONLY the plain default-build signatures
 *     void *(*)(size_t) / void (*)(void*) / void *(*)(void*, size_t)
 * When a build selects a wider signature, the mock is compiled out and its API
 * becomes a set of no-ops guarded by MCDC_FA_UNAVAILABLE, so a TU that includes
 * this header still builds under every variant (it just does not inject faults
 * in the incompatible ones -- those variants close their residuals elsewhere or
 * are justified).
 */

#ifndef MCDC_FAULT_ALLOC_H
#define MCDC_FAULT_ALLOC_H

#include <stdlib.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>

/* The plain callback signatures this mock provides only match a build that
 * selects neither the static-memory nor debug-memory allocator prototypes. */
#if defined(WOLFSSL_STATIC_MEMORY) || defined(WOLFSSL_DEBUG_MEMORY)
    #define MCDC_FA_UNAVAILABLE 1
#endif

#ifndef MCDC_FA_UNAVAILABLE

/* file-static injector state (one TU per white-box, so file scope is fine) */
static unsigned long   mcdc_fa_count   = 0;  /* allocations seen since arm    */
static unsigned long   mcdc_fa_fail_at = 0;  /* fail from this index; 0 = off  */
static int             mcdc_fa_saved   = 0;  /* originals captured?            */
static wolfSSL_Malloc_cb  mcdc_fa_orig_mf = NULL;
static wolfSSL_Free_cb    mcdc_fa_orig_ff = NULL;
static wolfSSL_Realloc_cb mcdc_fa_orig_rf = NULL;

/* n-th (and every later) allocation returns NULL while armed. */
static void* mcdc_fa_malloc(size_t size)
{
    if (mcdc_fa_fail_at != 0 && ++mcdc_fa_count >= mcdc_fa_fail_at)
        return NULL;
    return malloc(size);
}

static void mcdc_fa_free(void* ptr)
{
    free(ptr);
}

/* realloc honours the same fail counter so growth paths can be faulted too. */
static void* mcdc_fa_realloc(void* ptr, size_t size)
{
    if (mcdc_fa_fail_at != 0 && ++mcdc_fa_count >= mcdc_fa_fail_at)
        return NULL;
    return realloc(ptr, size);
}

/* Install the injector, saving whatever allocators were active. */
static void mcdc_fa_install(void)
{
    if (!mcdc_fa_saved) {
        (void)wolfSSL_GetAllocators(&mcdc_fa_orig_mf, &mcdc_fa_orig_ff,
                                    &mcdc_fa_orig_rf);
        mcdc_fa_saved = 1;
    }
    mcdc_fa_fail_at = 0;
    mcdc_fa_count   = 0;
    (void)wolfSSL_SetAllocators(mcdc_fa_malloc, mcdc_fa_free, mcdc_fa_realloc);
}

/* Arm: the n-th allocation from now on returns NULL (n >= 1). */
static void mcdc_fa_arm(int n)
{
    mcdc_fa_count   = 0;
    mcdc_fa_fail_at = (n > 0) ? (unsigned long)n : 0;
}

/* Disarm: allocations succeed again (counter reset). */
static void mcdc_fa_disarm(void)
{
    mcdc_fa_fail_at = 0;
    mcdc_fa_count   = 0;
}

/* Restore the originally-installed allocators, if they were non-NULL. A
 * default build has non-NULL wolfSSL internal callbacks; if the originals were
 * NULL (allocators never set) SetAllocators would reject them, so the mock is
 * simply left disarmed-and-installed for the remainder of the process. */
static void mcdc_fa_restore(void)
{
    mcdc_fa_disarm();
    if (mcdc_fa_saved && mcdc_fa_orig_mf != NULL && mcdc_fa_orig_ff != NULL
            && mcdc_fa_orig_rf != NULL) {
        (void)wolfSSL_SetAllocators(mcdc_fa_orig_mf, mcdc_fa_orig_ff,
                                    mcdc_fa_orig_rf);
    }
}

#else /* MCDC_FA_UNAVAILABLE: incompatible allocator signature -- no-op API */

static void mcdc_fa_install(void) {}
static void mcdc_fa_arm(int n)    { (void)n; }
static void mcdc_fa_disarm(void)  {}
static void mcdc_fa_restore(void) {}

#endif /* MCDC_FA_UNAVAILABLE */

#endif /* MCDC_FAULT_ALLOC_H */
