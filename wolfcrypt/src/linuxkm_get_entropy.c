/* linuxkm_get_entropy.c
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

/* Serves the Linux kernel's get_random_bytes() from inside the FIPS module
 * cryptographic boundary.
 *
 * SP 800-90C Sec. 7 DRBG tree.  A root DRBG reseeds 2*ncpu leaf DRBGs: one
 * leaf per CPU for process, softirq and hardirq, and one leaf per CPU for NMI.
 * Only the root ever touches the entropy source: leaves are instantiated and
 * reseeded from it.  Everything here is SHA-512.
 *
 * The root seeding a leaf is one instantiated DRBG serving a second,
 * separately instantiated DRBG, which is what SP 800-90C Sec. 7.2.3.2.1 calls
 * for: a leaf reseeds by asking its parent to generate, not by asking the
 * entropy source.  SP 800-90A Sec. 8.6.9 bars a DRBG from reseeding itself,
 * and that is a rule about one instantiation, so it does not reach a parent
 * feeding a child.  Each leaf reseed takes its own fresh root generate
 * (Sec. 7.3.1 req 15), no leaf output ever reaches the root (req 16), and
 * prediction resistance is not claimed for the leaves (Sec. 7.2.3.2.1).
 *
 * One root, not one per leaf: wolfentropy.c has a single noise source, one
 * mutex and one shared SP 800-90B RCT/APT state, so extra roots would
 * serialize on it and share its health verdict for 3x the cost.
 *
 * Concurrency: the critical section runs with interrupts off, so on one CPU
 * process, softirq and hardirq cannot overlap.  NMI is not masked and gets its
 * own leaf.  A leaf can therefore only be held by the maintenance reseed of
 * that same leaf, so callers try once and give way; a non-zero return sends
 * the caller to the kernel's own CRNG.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_LINUXKM) && defined(LINUXKM_RBGC)

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/linuxkm_get_entropy.h>

/* ForceZero.  misc.c is inlined into the including translation unit unless
 * NO_INLINE, the same idiom random.c uses. */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* No raw <linux/...> includes: linuxkm_wc_port.h already pulls <linux/random.h>
 * inside a _Pragma guard that suppresses warnings wolfSSL builds with -Werror. */

/* Cap on the leaf reseed threshold, so a build whose WC_RESEED_INTERVAL is the
 * SP 800-90A maximum still refreshes at a sane rate.  Runtime and not #if: the
 * interval may carry a cast the preprocessor cannot evaluate. */
#define WC_GRB_RESEED_CAP 500000UL

/* Root reseed period, in maintenance ticks. */
#define WC_GRB_ROOT_PERIOD 1200UL

/* Guard against an absurd allocation from a bogus CPU count. */
#define WC_GRB_MAX_CPU 512

enum {
    WC_GRB_PROC = 0,
    WC_GRB_SOFTIRQ,
    WC_GRB_HARDIRQ,
    WC_GRB_NMI
};

/* 64-bit counter built from two 32-bit atomics.  atomic64_t is not inline on
 * 32-bit x86: it calls out-of-line cx8 helpers, and an in-boundary file must
 * have no unresolved symbols (linuxkm/Kbuild).  A 32-bit counter would wrap
 * within hours at the rate this path is driven. */
struct wc_grb_ctr {
    atomic_t lo;
    atomic_t hi;
};

/* Per-context counters, one struct rather than nine parallel arrays: the
 * service path then touches one cache line instead of nine.  The _boot pair
 * keeps start-up demand apart from steady state, which an aggregate hides. */
struct wc_grb_ctx_stats {
    struct wc_grb_ctr calls;
    struct wc_grb_ctr served;
    struct wc_grb_ctr failed;
    struct wc_grb_ctr inhibit;
    struct wc_grb_ctr notready;
    struct wc_grb_ctr declined;
    struct wc_grb_ctr calls_boot;
    struct wc_grb_ctr failed_boot;
    struct wc_grb_ctr reseeds;
};

/* One leaf: its DRBG, its exclusion flag, generates since its last reseed and
 * the jittered count at which the next reseed is requested. */
struct wc_grb_slot {
    WC_RNG           rng;
    atomic_t         inuse;
    atomic_t         pending;
    struct wc_grb_ctr since;
    unsigned long    at;
};

static struct wc_grb_ctx_stats wc_grb_stat[WC_GRB_CTX_N];
static atomic_t               wc_grb_last_err;
static int                    wc_grb_boot_done;

static WC_RNG             wc_grb_root;
static struct wc_grb_slot *wc_grb_cpu;
static struct wc_grb_slot *wc_grb_nmi;
static int                wc_grb_ncpu;

static unsigned long    wc_grb_reseed_base;
static struct wc_grb_ctr wc_grb_reseeds;
static struct wc_grb_ctr wc_grb_reseed_failed;

/* Summary of every leaf's pending flag.  wc_grb_reseed_due() is polled by the
 * glue and is also consulted on the service path, so it must be one read and
 * not a scan of 2*ncpu atomics. */
static atomic_t wc_grb_any_pending;

static struct wc_grb_ctr wc_grb_root_reseeds;
static struct wc_grb_ctr wc_grb_root_reseed_failed;
static unsigned long    wc_grb_root_ticks;
static unsigned long    wc_grb_root_period = WC_GRB_ROOT_PERIOD;
static unsigned long    wc_grb_root_at = WC_GRB_ROOT_PERIOD;
static atomic_t         wc_grb_maint_busy;

static int wc_grb_rng_ready;
static int wc_grb_registered;

static void wc_grb_ctr_inc(struct wc_grb_ctr *c)
{
    if ((unsigned int) atomic_inc_return(&c->lo) == 0u) {
        atomic_inc(&c->hi);
    }
}

static long long wc_grb_ctr_inc_return(struct wc_grb_ctr *c)
{
    unsigned int lo = (unsigned int) atomic_inc_return(&c->lo);
    unsigned int hi;

    if (lo == 0u) {
        hi = (unsigned int) atomic_inc_return(&c->hi);
    }
    else {
        hi = (unsigned int) atomic_read(&c->hi);
    }

    return (long long) (((unsigned long long) hi << 32) | lo);
}

/* Re-read hi around lo so a carry landing mid-read cannot pair a new hi with
 * an old lo. */
static long long wc_grb_ctr_read(struct wc_grb_ctr *c)
{
    unsigned int hi1, lo, hi2;

    do {
        hi1 = (unsigned int) atomic_read(&c->hi);
        lo  = (unsigned int) atomic_read(&c->lo);
        hi2 = (unsigned int) atomic_read(&c->hi);
    } while (hi1 != hi2);

    return (long long) (((unsigned long long) hi1 << 32) | lo);
}

static void wc_grb_ctr_zero(struct wc_grb_ctr *c)
{
    atomic_set(&c->lo, 0);
    atomic_set(&c->hi, 0);
}

static int wc_grb_ctx(void)
{
    if (in_nmi()) {
        return WC_GRB_NMI;
    }

    if (in_irq()) {
        return WC_GRB_HARDIRQ;
    }

    if (in_softirq()) {
        return WC_GRB_SOFTIRQ;
    }

    return WC_GRB_PROC;
}

/* This CPU's leaf.  Safe to cache: the caller holds interrupts off, so it
 * cannot migrate before it releases the flag. */
static struct wc_grb_slot *wc_grb_my_slot(int ctx)
{
    int cpu = wc_linuxkm_cpu_id();

    if ((cpu < 0) || (cpu >= wc_grb_ncpu)) {
        cpu = 0;
    }

    return (ctx == WC_GRB_NMI) ? &wc_grb_nmi[cpu] : &wc_grb_cpu[cpu];
}

/* Draw the next reseed point from the root.  Firing at exactly half the seed
 * life would put the refresh on an externally observable schedule. */
static void wc_grb_set_next_threshold(struct wc_grb_slot *sl)
{
    /* Not an SSP: root output used only to jitter a reseed counter, never as
     * seed material, so it is not zeroized. */
    byte          b[2];
    unsigned long span = wc_grb_reseed_base / 4;
    unsigned long j = 0;

    if ((span != 0) &&
        (wc_RNG_GenerateBlock(&wc_grb_root, b, (word32) sizeof(b)) == 0)) {
        j = (((unsigned long) b[0] << 8) | (unsigned long) b[1]) % (span + 1);
    }

    sl->at = wc_grb_reseed_base - (span / 2) + j;
}

/* Reseed the root from the entropy source.  Process context only:
 * wc_GenerateSeed() takes a mutex it cannot take with interrupts disabled. */
static int wc_grb_reseed_root(void)
{
    byte seed[WC_DRBG_SEED_SZ];
    int  ret;

    ret = wc_GenerateSeed(&wc_grb_root.seed, seed, (word32) sizeof(seed));
    if (ret == 0) {
        ret = wc_RNG_DRBG_Reseed(&wc_grb_root, seed, (word32) sizeof(seed));
    }

    /* CSP: entropy-source output, and the root's seed material.  SP 800-90A
     * Sec. 8.6.6 makes the entropy input a CSP, so it dies with the reseed
     * rather than living on in this frame. */
    ForceZero(seed, sizeof(seed));

    if (ret != 0) {
        wc_grb_ctr_inc(&wc_grb_root_reseed_failed);
        atomic_set(&wc_grb_last_err, ret);
        return ret;
    }

    wc_grb_ctr_inc(&wc_grb_root_reseeds);

    return 0;
}

/* Reseed one leaf from its own fresh root generate, per SP 800-90C
 * Sec. 7.2.3.2.1 and Sec. 7.3.1 requirement 15. */
static int wc_grb_reseed_slot(struct wc_grb_slot *sl, int ctx)
{
    byte          seed[WC_DRBG_SEED_SZ];
    unsigned long flags;
    int           ret;

    ret = wc_RNG_GenerateBlock(&wc_grb_root, seed, (word32) sizeof(seed));
    if (ret == 0) {
        /* Interrupts off for the leaf half only; it is pure computation.  Try
         * once: a reseed has no deadline, the threshold sits at half the seed
         * life, and the next maintenance tick is milliseconds away. */
        flags = wc_linuxkm_irq_save();
        if (atomic_cmpxchg(&sl->inuse, 0, 1) != 0) {
            wc_linuxkm_irq_restore(flags);
            /* CSP: root output drawn as this leaf's seed material, now
             * unused.  SP 800-90C Sec. 7.3.1 req 15 bars reusing it for any
             * other instantiation, so the only thing to do with it is
             * destroy it. */
            ForceZero(seed, sizeof(seed));
            atomic_set(&wc_grb_any_pending, 1);
            return 0;
        }

        ret = wc_RNG_DRBG_Reseed(&sl->rng, seed, (word32) sizeof(seed));
        atomic_set(&sl->inuse, 0);
        wc_linuxkm_irq_restore(flags);
    }

    /* CSP: this leaf's seed material, consumed by the reseed above. */
    ForceZero(seed, sizeof(seed));

    if (ret != 0) {
        wc_grb_ctr_inc(&wc_grb_reseed_failed);
        atomic_set(&wc_grb_last_err, ret);
        return ret;
    }

    wc_grb_ctr_zero(&sl->since);
    wc_grb_set_next_threshold(sl);
    atomic_set(&sl->pending, 0);
    wc_grb_ctr_inc(&wc_grb_reseeds);
    wc_grb_ctr_inc(&wc_grb_stat[ctx].reseeds);

    return 0;
}

/* The hook.  Returns 0 if it filled buf; non-zero lets the kernel's own CRNG
 * answer.  Not static and does not self-register: wc_grb_hook_register() is a
 * kernel symbol outside the boundary and the container must resolve every
 * symbol it references, so the boundary provides this and
 * linuxkm/module_hooks.c registers it. */
int wc_grb_service(void *buf, size_t len)
{
    int ctx = wc_grb_ctx();
    int ret;

    wc_grb_ctr_inc(&wc_grb_stat[ctx].calls);
    if (!wc_grb_boot_done) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].calls_boot);
    }

    if (!wc_grb_rng_ready) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].notready);
        wc_grb_ctr_inc(&wc_grb_stat[ctx].failed);
        if (!wc_grb_boot_done) {
            wc_grb_ctr_inc(&wc_grb_stat[ctx].failed_boot);
        }

        return -1;
    }

    {
        struct wc_grb_slot *sl;
        unsigned long      flags;

        /* Interrupts off for the whole call.  This is what makes same-CPU
         * nesting impossible, and why nothing below may allocate or sleep. */
        flags = wc_linuxkm_irq_save();
        sl = wc_grb_my_slot(ctx);
        if (atomic_cmpxchg(&sl->inuse, 0, 1) != 0) {
            wc_linuxkm_irq_restore(flags);
            wc_grb_ctr_inc(&wc_grb_stat[ctx].declined);
            return -1;
        }

        ret = wc_RNG_GenerateBlock(&sl->rng, (byte *) buf, (word32) len);
        atomic_set(&sl->inuse, 0);
        if ((unsigned long) wc_grb_ctr_inc_return(&sl->since) >= sl->at) {
            atomic_set(&sl->pending, 1);
            atomic_set(&wc_grb_any_pending, 1);
        }

        wc_linuxkm_irq_restore(flags);
    }

    if (ret == 0) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].served);
        /* Self-help, so worker scheduling cannot starve the reseed.  Interrupts
         * are restored by now, wc_grb_maintain() is a root generate and not the
         * entropy gather, and can_block() rules out a caller holding a lock. */
        if ((ctx == WC_GRB_PROC) && wc_grb_reseed_due() &&
            wc_linuxkm_can_block()) {
            (void) wc_grb_maintain();
        }

        return 0;
    }

    wc_grb_ctr_inc(&wc_grb_stat[ctx].failed);
    if (!wc_grb_boot_done) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].failed_boot);
    }

    if (ret == WC_ACCEL_INHIBIT_E) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].inhibit);
    }

    atomic_set(&wc_grb_last_err, ret);

    return -1;
}

/* No EXPORT_SYMBOL_GPL in this file: it emits __UNIQUE_ID___addressable_*
 * objects into .discard.addressable, which containerization does not relocate.
 * Kbuild generates the export list from the WOLFSSL_API tags instead. */
int wc_grb_service_active(void)
{
    return wc_grb_registered;
}

void wc_grb_set_registered(int on)
{
    wc_grb_registered = on ? 1 : 0;
}

void wc_grb_set_root_period(unsigned long ticks)
{
    if (ticks != 0UL) {
        wc_grb_root_period = ticks;
    }
}

/* One maintenance tick.  The root refreshes from the noise source on its own
 * jittered schedule, never coupled to leaf demand. */
int wc_grb_root_tick(void)
{
    int ret = 0;

    if (!wc_grb_rng_ready) {
        return 0;
    }

    if (atomic_cmpxchg(&wc_grb_maint_busy, 0, 1) != 0) {
        return 0;
    }

    if (++wc_grb_root_ticks >= wc_grb_root_at) {
        byte          b[2];   /* not an SSP; see wc_grb_set_next_threshold() */
        unsigned long span = wc_grb_root_period / 4;
        unsigned long j = 0;

        ret = wc_grb_reseed_root();
        wc_grb_root_ticks = 0;
        if ((span != 0) &&
            (wc_RNG_GenerateBlock(&wc_grb_root, b, (word32) sizeof(b)) == 0)) {
            j = (((unsigned long) b[0] << 8) | (unsigned long) b[1]) % (span + 1);
        }

        wc_grb_root_at = wc_grb_root_period - (span / 2) + j;
    }

    atomic_set(&wc_grb_maint_busy, 0);

    return ret;
}

int wc_grb_reseed_due(void)
{
    if (!wc_grb_rng_ready) {
        return 0;
    }

    return atomic_read(&wc_grb_any_pending) ? 1 : 0;
}

/* Reseed every due leaf from the root.  Process context only: the root's own
 * generate may gather entropy, and that has to be able to block. */
int wc_grb_maintain(void)
{
    int ret = 0, i;

    if (!wc_grb_rng_ready) {
        return 0;
    }

    if (atomic_cmpxchg(&wc_grb_maint_busy, 0, 1) != 0) {
        return 0;
    }

    /* Cleared before the scan: anything already pending is still visible in
     * its own flag, and anything raised during the scan re-arms this. */
    atomic_set(&wc_grb_any_pending, 0);

    for (i = 0; i < wc_grb_ncpu; i++) {
        if (atomic_read(&wc_grb_cpu[i].pending)) {
            ret = wc_grb_reseed_slot(&wc_grb_cpu[i], WC_GRB_PROC);
            if (ret != 0) {
                break;
            }
        }

        if (atomic_read(&wc_grb_nmi[i].pending)) {
            ret = wc_grb_reseed_slot(&wc_grb_nmi[i], WC_GRB_NMI);
            if (ret != 0) {
                break;
            }
        }
    }

    atomic_set(&wc_grb_maint_busy, 0);

    return ret;
}

void wc_grb_mark_boot_done(void)
{
    wc_grb_boot_done = 1;
}

int wc_grb_stat_snapshot(long long *out, int n)
{
    long long v[WC_GRB_STAT_N];
    int       i;

    wc_static_assert(WC_GRB_NMI + 1 == WC_GRB_CTX_N);

    if ((out == NULL) || (n <= 0) || (wc_grb_cpu == NULL)) {
        return 0;
    }

    for (i = 0; i < WC_GRB_CTX_N; i++) {
        v[WC_GRB_ST_CALLS + i]       = wc_grb_ctr_read(&wc_grb_stat[i].calls);
        v[WC_GRB_ST_SERVED + i]      = wc_grb_ctr_read(&wc_grb_stat[i].served);
        v[WC_GRB_ST_FAILED + i]      = wc_grb_ctr_read(&wc_grb_stat[i].failed);
        v[WC_GRB_ST_DECLINED + i]    = wc_grb_ctr_read(&wc_grb_stat[i].declined);
        v[WC_GRB_ST_CTX_RESEEDS + i] = wc_grb_ctr_read(&wc_grb_stat[i].reseeds);
    }

    v[WC_GRB_ST_RESEEDS]       = wc_grb_ctr_read(&wc_grb_reseeds);
    v[WC_GRB_ST_RESEED_FAILED] = wc_grb_ctr_read(&wc_grb_reseed_failed);
    v[WC_GRB_ST_SINCE_RESEED]  = wc_grb_ctr_read(&wc_grb_cpu[0].since);
    v[WC_GRB_ST_RESEED_AT]     = (long long) wc_grb_cpu[0].at;
    v[WC_GRB_ST_LAST_ERR]      = atomic_read(&wc_grb_last_err);
    v[WC_GRB_ST_REGISTERED]    = wc_grb_registered;
    v[WC_GRB_ST_RNG_READY]     = wc_grb_rng_ready;
    v[WC_GRB_ST_ROOT_RESEEDS]  = wc_grb_ctr_read(&wc_grb_root_reseeds);
    v[WC_GRB_ST_ROOT_FAILED]   = wc_grb_ctr_read(&wc_grb_root_reseed_failed);

    if (n > WC_GRB_STAT_N) {
        n = WC_GRB_STAT_N;
    }

    for (i = 0; i < n; i++) {
        out[i] = v[i];
    }

    return n;
}

void wc_grb_report(void)
{
    /* 2-D, not an array of pointers: pointers need relocations and land in
     * .data, this lands in .rodata with none. */
    static const char ctx_name[WC_GRB_CTX_N][8] = {
        "process", "softirq", "hardirq", "nmi"
    };
    int i;

    for (i = 0; i < WC_GRB_CTX_N; i++) {
        pr_info("WCGRB: RESULT ctx=%s calls=%lld served=%lld failed=%lld"
                " inhibit=%lld notready=%lld declined=%lld boot_calls=%lld"
                " boot_failed=%lld\n",
                ctx_name[i],
                wc_grb_ctr_read(&wc_grb_stat[i].calls),
                wc_grb_ctr_read(&wc_grb_stat[i].served),
                wc_grb_ctr_read(&wc_grb_stat[i].failed),
                wc_grb_ctr_read(&wc_grb_stat[i].inhibit),
                wc_grb_ctr_read(&wc_grb_stat[i].notready),
                wc_grb_ctr_read(&wc_grb_stat[i].declined),
                wc_grb_ctr_read(&wc_grb_stat[i].calls_boot),
                wc_grb_ctr_read(&wc_grb_stat[i].failed_boot));
    }

    pr_info("WCGRB: root_reseeds=%lld root_failed=%lld period=%lu\n",
            wc_grb_ctr_read(&wc_grb_root_reseeds),
            wc_grb_ctr_read(&wc_grb_root_reseed_failed), wc_grb_root_period);
    pr_info("WCGRB: reseeds=%lld reseed_failed=%lld\n",
            wc_grb_ctr_read(&wc_grb_reseeds),
            wc_grb_ctr_read(&wc_grb_reseed_failed));
    if ((wc_grb_cpu != NULL) && (wc_grb_nmi != NULL)) {
        for (i = 0; i < wc_grb_ncpu; i++) {
            pr_info("WCGRB: leaf[cpu%d] since=%lld at=%lu"
                    " nmi_since=%lld nmi_at=%lu\n",
                    i, wc_grb_ctr_read(&wc_grb_cpu[i].since), wc_grb_cpu[i].at,
                    wc_grb_ctr_read(&wc_grb_nmi[i].since), wc_grb_nmi[i].at);
        }
    }

    pr_info("WCGRB: last_err=%d registered=%d rng_ready=%d\n",
            atomic_read(&wc_grb_last_err), wc_grb_registered, wc_grb_rng_ready);
}

/* wc_FreeRng() zeroizes each leaf's DRBG internal state (V, C, reseed
 * counter), which is the CSP this file holds for the life of the module. */
static void wc_grb_free_slots(struct wc_grb_slot **slots, int n)
{
    int i;

    if (*slots == NULL) {
        return;
    }

    for (i = 0; i < n; i++) {
        (void) wc_FreeRng(&(*slots)[i].rng);
    }

    XFREE(*slots, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    *slots = NULL;
}

static int wc_grb_alloc_slots(struct wc_grb_slot **slots, const char *what)
{
    size_t sz = sizeof(struct wc_grb_slot) * (size_t) wc_grb_ncpu;
    int    ret, i;

    *slots = (struct wc_grb_slot *) XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (*slots == NULL) {
        pr_err("WCGRB: no memory for %d %s leaves\n", wc_grb_ncpu, what);
        return MEMORY_E;
    }

    XMEMSET(*slots, 0, sz);
    for (i = 0; i < wc_grb_ncpu; i++) {
        ret = wc_InitRngRBGC(&(*slots)[i].rng, &wc_grb_root);
        if (ret != 0) {
            pr_err("WCGRB: wc_InitRngRBGC(%s cpu%d) failed: %d\n", what, i,
                   ret);
            wc_grb_free_slots(slots, i);
            return ret;
        }

        atomic_set(&(*slots)[i].inuse, 0);
        atomic_set(&(*slots)[i].pending, 0);
        wc_grb_ctr_zero(&(*slots)[i].since);
        (*slots)[i].at = wc_grb_reseed_base;
    }

    return 0;
}

int wc_grb_init(int ncpus)
{
    int ret, i;

    XMEMSET(wc_grb_stat, 0, sizeof(wc_grb_stat));
    atomic_set(&wc_grb_last_err, 0);
    atomic_set(&wc_grb_any_pending, 0);
    atomic_set(&wc_grb_maint_busy, 0);
    wc_grb_ctr_zero(&wc_grb_reseeds);
    wc_grb_ctr_zero(&wc_grb_reseed_failed);
    wc_grb_ctr_zero(&wc_grb_root_reseeds);
    wc_grb_ctr_zero(&wc_grb_root_reseed_failed);
    wc_grb_boot_done = 0;
    wc_grb_root_ticks = 0;
    wc_grb_root_at = wc_grb_root_period;

    wc_grb_reseed_base = (unsigned long) (WC_RESEED_INTERVAL / 2);
    if (wc_grb_reseed_base > WC_GRB_RESEED_CAP) {
        wc_grb_reseed_base = WC_GRB_RESEED_CAP;
    }

    if (wc_grb_reseed_base < 16UL) {
        wc_grb_reseed_base = 16UL;
    }

    wc_grb_ncpu = (ncpus > 0) ? ncpus : 1;
    if (wc_grb_ncpu > WC_GRB_MAX_CPU) {
        wc_grb_ncpu = WC_GRB_MAX_CPU;
    }

    ret = wc_InitRng(&wc_grb_root);
    if (ret != 0) {
        pr_err("WCGRB: wc_InitRng(root) failed: %d\n", ret);
        return ret;
    }

    /* The construction is SHA-512 throughout.  wc_InitRng() falls back to
     * SHA-256 when the SHA-512 DRBG is disabled, and a tree half built on the
     * other DRBG is not what was validated, so refuse and leave the kernel's
     * own CRNG serving. */
    if (wc_grb_root.drbgType != WC_DRBG_SHA512) {
        pr_err("WCGRB: root is not SHA-512 (drbgType=%d); not starting\n",
               (int) wc_grb_root.drbgType);
        (void) wc_FreeRng(&wc_grb_root);
        return BAD_STATE_E;
    }

    ret = wc_grb_alloc_slots(&wc_grb_cpu, "cpu");
    if (ret != 0) {
        (void) wc_FreeRng(&wc_grb_root);
        return ret;
    }

    ret = wc_grb_alloc_slots(&wc_grb_nmi, "nmi");
    if (ret != 0) {
        wc_grb_free_slots(&wc_grb_cpu, wc_grb_ncpu);
        (void) wc_FreeRng(&wc_grb_root);
        return ret;
    }

    wc_grb_rng_ready = 1;
    for (i = 0; i < wc_grb_ncpu; i++) {
        wc_grb_set_next_threshold(&wc_grb_cpu[i]);
        wc_grb_set_next_threshold(&wc_grb_nmi[i]);
    }

    /* The effective interval, not the threshold: the threshold is capped and
     * would read the same for 1e6 and for the SP 800-90A maximum. */
    pr_info("WCGRB: RBGC up, 1 root + %d cpu leaves + %d nmi leaves, SHA-512,"
            " WC_RESEED_INTERVAL=%llu\n",
            wc_grb_ncpu, wc_grb_ncpu, (unsigned long long) WC_RESEED_INTERVAL);

    return 0;
}

void wc_grb_cleanup(void)
{
    wc_grb_registered = 0;
    wc_grb_report();
    if (wc_grb_rng_ready) {
        wc_grb_rng_ready = 0;
        wc_grb_free_slots(&wc_grb_cpu, wc_grb_ncpu);
        wc_grb_free_slots(&wc_grb_nmi, wc_grb_ncpu);
        (void) wc_FreeRng(&wc_grb_root);
    }
}

#else /* !(WOLFSSL_LINUXKM && LINUXKM_RBGC) */

/* ISO C requires a translation unit to contain at least one declaration, and
 * several OEs build with -Wpedantic. */
typedef int wc_linuxkm_get_entropy_not_used;

#endif /* WOLFSSL_LINUXKM && LINUXKM_RBGC */
