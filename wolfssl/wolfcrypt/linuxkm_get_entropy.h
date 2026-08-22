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
 * linuxkm/RBGC-design.md and in wolfcrypt/src/linuxkm_get_entropy.c.
 *
 * WOLFSSL_LOCAL throughout: none of this is module API.  Every caller is
 * linuxkm/module_hooks.c in the same module, and the kernel reaches
 * wc_grb_service() through a registered function pointer, not a symbol.  The
 * cryptographic service these run is wc_RNG_GenerateBlock(), which is already
 * the fips.c wrapper and already carries the FipsAllowed() and AlgoAllowed()
 * checks, so nothing here needs wrapping a second time. */

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
    /* Only the NMI generation check declines, and only if a leaf were
     * reseeded underneath a read.  Zero on every measured run. */
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
    /* Interrupts-off duration per chunk, + context.  -1 when the module was
     * not built with WC_GRB_MEASURE, which is the shipping default: the
     * measurement costs two clock reads per chunk. */
    WC_GRB_ST_IRQ_MAXNS     = 29,
    WC_GRB_ST_CHUNKS        = 33,
    /* Maintenance reseeds skipped because hotplug moved the work off the CPU
     * whose leaf it targets.  Not a decline: no caller was turned away. */
    WC_GRB_ST_MAINT_DEFERRED = 37,
    /* NMI requests answered by the leaf's other instantiation because the live
     * one could not.  Each one is a request that would otherwise have been
     * handed back to the kernel's own generator, so this is the count of
     * fall-throughs avoided, not a count of errors. */
    WC_GRB_ST_NMI_ALT        = 38,
    WC_GRB_STAT_N           = 39
};

/* Interrupts-off histogram for one context.  Bucket k is [2^(k-1), 2^k) units
 * of 1024 ns; bucket 0 is under 1024 ns.  Returns how many it wrote, 0 when
 * the module was not built with WC_GRB_MEASURE. */
#define WC_GRB_IRQ_BUCKETS 16
WOLFSSL_LOCAL int wc_grb_irq_hist(int ctx, long long *out, int n);

/* Bring the tree up and tear it down.  These do not install the kernel hook:
 * the container must have no unresolved symbols, so an in-boundary file cannot
 * call wolfssl_linuxkm_register_random_bytes_handlers().  The glue does
 * that. */
WOLFSSL_LOCAL int wc_grb_init(int ncpus);
WOLFSSL_LOCAL void wc_grb_cleanup(void);

/* The service.  Signature matches _get_random_bytes_cb_t from
 * <linux/random.h>, i.e. the ._get_random_bytes member of
 * struct wolfssl_linuxkm_random_bytes_handlers. */
WOLFSSL_LOCAL int wc_grb_service(void *buf, size_t len);

/* Told to us by the glue after a successful registration. */
WOLFSSL_LOCAL void wc_grb_set_registered(int on);

/* Nonzero once the hook is installed.  A consumer must assert this before
 * trusting a clean run: zero failures from an unregistered hook look exactly
 * like zero failures from a working one. */
WOLFSSL_LOCAL int wc_grb_service_active(void);

/* Reseed the leaves belonging to one CPU, from the root.  Process context
 * only: the root's own generate may gather entropy, and that has to be able to
 * block.  The glue pins this to cpu; a negative cpu means "wherever this call
 * happens to be", which the service path's self-help uses. */
WOLFSSL_LOCAL int wc_grb_maintain_cpu(int cpu);

/* One maintenance tick.  The root refreshes from the noise source on its own
 * jittered schedule, independent of leaf demand. */
WOLFSSL_LOCAL int wc_grb_root_tick(void);

/* Separates boot-time demand from steady state in the counters. */
WOLFSSL_LOCAL void wc_grb_mark_boot_done(void);

/* Live snapshot, so a consumer can report while a run is in progress rather
 * than only at unload.  64-bit throughout: a 32-bit count wraps within hours
 * at the rate this path is driven. */
WOLFSSL_LOCAL int wc_grb_stat_snapshot(long long *out, int n);

#endif /* WOLFSSL_LINUXKM && LINUXKM_RBGC */

#ifdef __cplusplus
    }
#endif

#endif /* WOLF_CRYPT_LINUXKM_GET_ENTROPY_H */
