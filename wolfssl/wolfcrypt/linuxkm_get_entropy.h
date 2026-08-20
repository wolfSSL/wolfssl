/* linuxkm_get_entropy.h
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

/* In-boundary service for the Linux kernel's get_random_bytes().  The
 * SP 800-90C Sec. 7 DRBG tree it implements is described in
 * wolfcrypt/src/linuxkm_get_entropy.c. */

#ifndef WOLF_CRYPT_LINUXKM_GET_ENTROPY_H
#define WOLF_CRYPT_LINUXKM_GET_ENTROPY_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(WOLFSSL_LINUXKM) && defined(LINUXKM_RBGC)

/* Contexts the counters are indexed by: process, softirq, hardirq, nmi. */
#define WC_GRB_CTX_N 4

/* Index-addressed snapshot rather than a struct: a consumer links to this out
 * of tree, so a mismatched layout would corrupt silently.  Appending never
 * shifts an existing index, and the call returns how many it wrote. */
enum wc_grb_stat_idx {
    WC_GRB_ST_CALLS         = 0,   /* + context, 4 slots each */
    WC_GRB_ST_SERVED        = 4,
    WC_GRB_ST_FAILED        = 8,
    WC_GRB_ST_DECLINED      = 12,
    WC_GRB_ST_RESEEDS       = 16,
    WC_GRB_ST_RESEED_FAILED = 17,
    WC_GRB_ST_SINCE_RESEED  = 18,
    WC_GRB_ST_RESEED_AT     = 19,
    WC_GRB_ST_LAST_ERR      = 20,
    WC_GRB_ST_REGISTERED    = 21,
    WC_GRB_ST_RNG_READY     = 22,
    /* The root refreshed from the noise source, as against the leaf reseeds
     * above: different events, and very different costs. */
    WC_GRB_ST_ROOT_RESEEDS  = 23,
    WC_GRB_ST_ROOT_FAILED   = 24,
    WC_GRB_ST_CTX_RESEEDS   = 25,  /* + context, 4 slots */
    WC_GRB_STAT_N           = 29
};

/* Bring the tree up and tear it down.  These do not install the kernel hook:
 * the container must have no unresolved symbols, so an in-boundary file cannot
 * call wc_grb_hook_register().  The glue does that. */
WOLFSSL_API int wc_grb_init(int ncpus);
WOLFSSL_API void wc_grb_cleanup(void);

/* The service.  Signature matches wc_grb_hook_fn from <linux/random.h>.
 * Returns 0 if it filled buf; non-zero lets the kernel's own CRNG answer. */
WOLFSSL_API int wc_grb_service(void *buf, size_t len);

/* Told to us by the glue after a successful registration. */
WOLFSSL_API void wc_grb_set_registered(int on);

/* Nonzero once the hook is installed.  A consumer must assert this before
 * trusting a clean run: zero failures from an unregistered hook look exactly
 * like zero failures from a working one. */
WOLFSSL_API int wc_grb_service_active(void);

/* Nonzero once a leaf has spent its reseed allowance.  The glue polls this and
 * calls wc_grb_maintain(); nothing reseeds on the service path. */
WOLFSSL_API int wc_grb_reseed_due(void);

/* Reseed every due leaf from the root.  Process context only: the root's own
 * generate may gather entropy, and that has to be able to block. */
WOLFSSL_API int wc_grb_maintain(void);

/* One maintenance tick.  The root refreshes from the noise source on its own
 * jittered schedule, independent of leaf demand. */
WOLFSSL_API int wc_grb_root_tick(void);

/* Root reseed period in maintenance ticks.  Set by the glue, which owns the
 * tick rate; the jitter around it is chosen in-boundary. */
WOLFSSL_API void wc_grb_set_root_period(unsigned long ticks);

/* Separates boot-time demand from steady state in the counters. */
WOLFSSL_API void wc_grb_mark_boot_done(void);

/* Live snapshot, so a consumer can report while a run is in progress rather
 * than only at unload.  64-bit throughout: a 32-bit count wraps within hours
 * at the rate this path is driven. */
WOLFSSL_API int wc_grb_stat_snapshot(long long *out, int n);

/* Dump the per-context counters to the kernel log. */
WOLFSSL_API void wc_grb_report(void);

#endif /* WOLFSSL_LINUXKM && LINUXKM_RBGC */

#ifdef __cplusplus
    }
#endif

#endif /* WOLF_CRYPT_LINUXKM_GET_ENTROPY_H */
