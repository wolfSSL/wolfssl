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
 * Concurrency: a caller runs with interrupts off, so on one CPU process,
 * softirq and hardirq cannot overlap.  The maintenance reseed for a general
 * leaf runs ON THAT LEAF'S OWN CPU, also with interrupts off, so no caller can
 * be inside while it writes and no exclusion is needed at all.
 *
 * NMI is not masked by that, so an NMI leaf is two instantiations: the reseed
 * writes the spare and then publishes it with one atomic index store.  An NMI
 * reads either the old or the new instance, both fully instantiated, so a torn
 * state is not representable.  That reseed also runs on the leaf's own CPU, so
 * a stalled NMI stalls it too and it cannot come round twice underneath a read.
 * CPU hotplug is the one thing that can move it off that CPU; a per-instance
 * generation counter backstops that case and is the only path that declines.
 *
 * A request is served in WC_GRB_CHUNK_SZ pieces, so the interrupts-off window
 * is set by the chunk size rather than by the size the caller asked for.
 *
 * Nothing here waits.
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
 * inside a _Pragma guard suppressing warnings wolfSSL builds with -Werror. */

/* Cap on the leaf reseed threshold, so a build whose WC_RESEED_INTERVAL is the
 * SP 800-90A maximum still refreshes at a sane rate.  Runtime and not #if: the
 * interval may carry a cast the preprocessor cannot evaluate. */
#define WC_GRB_RESEED_CAP 500000UL

/* Root reseed period, in maintenance ticks. */
#define WC_GRB_ROOT_PERIOD 1200UL

/* Bytes generated per interrupts-off section.  The request length comes from
 * the caller and is not bounded: ip_rt_init() asks for 65536 in one call, which
 * as a single generate would hold interrupts off for roughly 2048 SHA-512
 * compressions.  The kernel's own CRNG takes its lock only to derive a key and
 * runs the bulk output unlocked for the same reason.  Large requests are
 * therefore served in chunks, releasing interrupts between them.
 *
 * Splitting is safe: each chunk is an independent generate, so a caller that
 * slips in between chunks merely advances the leaf and the next chunk
 * continues from the new state.  Output is validated DRBG output either way. */
#define WC_GRB_CHUNK_SZ 256

/* Reads to attempt before an NMI is turned away.  Each retry costs one more
 * chunk generate; a reseed lands about 7.6 times a second per CPU, so two in
 * succession inside one read is not reachable at any measured rate. */
#define WC_GRB_NMI_TRIES 3

/* Internal to the read loop, never returned: distinguishes "reseeded
 * underneath the read, try again" from a generator error. */
#define WC_GRB_RETRY 1

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

/* General leaf: process, softirq and hardirq on one CPU.  No exclusion flag,
 * because the only writer is the maintenance reseed running on this same CPU
 * with interrupts off. */
struct wc_grb_slot {
    WC_RNG            rng;
    atomic_t          pending;
    struct wc_grb_ctr since;
    unsigned long     at;
};

/* NMI leaf: two instantiations, one in service.  live is the index a caller
 * reads; the reseed writes the other and then stores the new index. */
struct wc_grb_nmi_slot {
    WC_RNG            rng[2];
    atomic_t          live;
    /* Bumped before an instance is reseeded.  An NMI reads it either side of
     * its generate and discards the result if it changed, which turns the
     * reuse interval from a timing assumption into a checked one: a vCPU
     * descheduled inside an NMI handler can outlive two flips, and 926 ms of
     * steal has been measured on this hardware. */
    atomic_t          gen[2];
    atomic_t          pending;
    struct wc_grb_ctr since;
    unsigned long     at;
};

static struct wc_grb_ctx_stats wc_grb_stat[WC_GRB_CTX_N];
static atomic_t               wc_grb_last_err;
static int                    wc_grb_boot_done;

static WC_RNG                  wc_grb_root;
static struct wc_grb_slot     *wc_grb_cpu;
static struct wc_grb_nmi_slot *wc_grb_nmi;
static int                     wc_grb_ncpu;

static unsigned long    wc_grb_reseed_base;
static struct wc_grb_ctr wc_grb_reseeds;
static struct wc_grb_ctr wc_grb_reseed_failed;

/* Summary of every leaf's pending flag.  wc_grb_reseed_due() is polled by the
 * glue and is also consulted on the service path, so it must be one read and
 * not a scan of 2*ncpu atomics. */
static atomic_t wc_grb_any_pending;


/* Maintenance reseeds skipped because CPU hotplug moved the work off the CPU
 * whose leaf it was going to write.  Not a decline: no caller was turned
 * away, and the leaf is picked up on the next tick. */
static struct wc_grb_ctr wc_grb_maint_deferred;

static struct wc_grb_ctr wc_grb_root_reseeds;
static struct wc_grb_ctr wc_grb_root_reseed_failed;
static unsigned long    wc_grb_root_ticks;
static const unsigned long wc_grb_root_period = WC_GRB_ROOT_PERIOD;
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

#ifdef WC_GRB_MEASURE
/* Interrupts-off duration per chunk, so the bound WC_GRB_CHUNK_SZ is supposed
 * to give can be checked rather than asserted.  Two clock reads per chunk, so
 * it is a harness build only; the shipped path reads no clock.
 *
 * Bucket k is [2^(k-1), 2^k) units of 1024 ns; bucket 0 is under 1024 ns.
 * ns >> 10 rather than ns / 1000 because a 64-bit division calls __udivdi3 on
 * i386 and the container must resolve every symbol. */
static atomic_t          wc_grb_irq_max_ns[WC_GRB_CTX_N];
static struct wc_grb_ctr wc_grb_irq_buckets[WC_GRB_CTX_N][WC_GRB_IRQ_BUCKETS];
static struct wc_grb_ctr wc_grb_chunks[WC_GRB_CTX_N];

static void wc_grb_note_irqoff(int ctx, unsigned long long ns)
{
    unsigned long long u = ns >> 10;
    int b = 0;

    while ((u != 0ULL) && (b < (WC_GRB_IRQ_BUCKETS - 1))) {
        u >>= 1;
        b++;
    }

    wc_grb_ctr_inc(&wc_grb_chunks[ctx]);
    wc_grb_ctr_inc(&wc_grb_irq_buckets[ctx][b]);
    if (ns > 0x7fffffffULL) {
        ns = 0x7fffffffULL;
    }
    if ((int) ns > atomic_read(&wc_grb_irq_max_ns[ctx])) {
        atomic_set(&wc_grb_irq_max_ns[ctx], (int) ns);
    }
}
#endif /* WC_GRB_MEASURE */

static int wc_grb_reseed_due(void);

/* in_irq() was removed in 6.19 and in_hardirq() only appeared in 5.11, so
 * neither spelling covers the supported range on its own. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    #define WC_GRB_IN_HARDIRQ() in_hardirq()
#else
    #define WC_GRB_IN_HARDIRQ() in_irq()
#endif

static int wc_grb_ctx(void)
{
    if (in_nmi()) {
        return WC_GRB_NMI;
    }

    if (WC_GRB_IN_HARDIRQ()) {
        return WC_GRB_HARDIRQ;
    }

    if (in_softirq()) {
        return WC_GRB_SOFTIRQ;
    }

    return WC_GRB_PROC;
}

/* This CPU's index.  Safe to use across the critical section: the caller holds
 * interrupts off, so it cannot migrate. */
static int wc_grb_this_cpu(void)
{
    int cpu = wc_linuxkm_cpu_id();

    return ((cpu < 0) || (cpu >= wc_grb_ncpu)) ? 0 : cpu;
}

/* Draw the next reseed point from the root.  Firing at exactly half the seed
 * life would put the refresh on an externally observable schedule. */
static void wc_grb_set_next_threshold(unsigned long *at)
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

    *at = wc_grb_reseed_base - (span / 2) + j;
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

/* Reseed THIS CPU's general leaf from its own fresh root generate, per
 * SP 800-90C Sec. 7.2.3.2.1 and Sec. 7.3.1 requirement 15.
 *
 * The CPU is re-read with interrupts off and checked against the one the glue
 * pinned this work to.  A worker that CPU hotplug migrated would otherwise
 * write a leaf another CPU is reading; here it simply skips and the leaf is
 * picked up on the next tick. */
static int wc_grb_reseed_local(int want_cpu)
{
    byte          seed[WC_DRBG_SEED_SZ];
    unsigned long flags;
    int           cpu, ret, done = 0;

    ret = wc_RNG_GenerateBlock(&wc_grb_root, seed, (word32) sizeof(seed));
    if (ret == 0) {
        flags = wc_linuxkm_irq_save();
        cpu = wc_grb_this_cpu();
        if (((want_cpu < 0) || (cpu == want_cpu)) &&
            atomic_read(&wc_grb_cpu[cpu].pending)) {
            ret = wc_RNG_DRBG_Reseed(&wc_grb_cpu[cpu].rng, seed,
                                     (word32) sizeof(seed));
            if (ret == 0) {
                wc_grb_ctr_zero(&wc_grb_cpu[cpu].since);
                atomic_set(&wc_grb_cpu[cpu].pending, 0);
                done = 1;
            }
        }
        wc_linuxkm_irq_restore(flags);
    }

    /* CSP: this leaf's seed material, consumed by the reseed above, or unused
     * because the leaf was not due.  SP 800-90C Sec. 7.3.1 req 15 bars reusing
     * it either way. */
    ForceZero(seed, sizeof(seed));

    if (ret != 0) {
        wc_grb_ctr_inc(&wc_grb_reseed_failed);
        atomic_set(&wc_grb_last_err, ret);

        return ret;
    }

    if (done) {
        /* Outside the critical section: this draws from the root.  A caller
         * reading the old threshold meanwhile gets a valid one. */
        wc_grb_set_next_threshold(&wc_grb_cpu[cpu].at);
        wc_grb_ctr_inc(&wc_grb_reseeds);
        wc_grb_ctr_inc(&wc_grb_stat[WC_GRB_PROC].reseeds);
    }

    return 0;
}

/* Reseed one NMI leaf.  No interrupts-off and no exclusion: the spare is not
 * in service, and the index store that publishes it is atomic, so an NMI sees
 * one instantiation or the other and never a partial one. */
static int wc_grb_reseed_nmi(int cpu)
{
    byte sl_seed[WC_DRBG_SEED_SZ];
    int  spare, ret;

    ret = wc_RNG_GenerateBlock(&wc_grb_root, sl_seed,
                               (word32) sizeof(sl_seed));
    if (ret == 0) {
        spare = atomic_read(&wc_grb_nmi[cpu].live) ? 0 : 1;
        ret = wc_RNG_DRBG_Reseed(&wc_grb_nmi[cpu].rng[spare], sl_seed,
                                 (word32) sizeof(sl_seed));
        if (ret == 0) {
            wc_grb_ctr_zero(&wc_grb_nmi[cpu].since);
            atomic_set(&wc_grb_nmi[cpu].pending, 0);
            atomic_set(&wc_grb_nmi[cpu].live, spare);
        }
    }

    /* CSP: this leaf's seed material; see wc_grb_reseed_local(). */
    ForceZero(sl_seed, sizeof(sl_seed));

    if (ret != 0) {
        wc_grb_ctr_inc(&wc_grb_reseed_failed);
        atomic_set(&wc_grb_last_err, ret);

        return ret;
    }

    wc_grb_set_next_threshold(&wc_grb_nmi[cpu].at);
    wc_grb_ctr_inc(&wc_grb_reseeds);
    wc_grb_ctr_inc(&wc_grb_stat[WC_GRB_NMI].reseeds);

    return 0;
}

/* The hook.  Returns 0 if it filled buf; non-zero lets the kernel's own CRNG
 * answer.  Not static and does not self-register: wc_grb_hook_register() is a
 * kernel symbol outside the boundary and the container must resolve every
 * symbol it references, so the boundary provides this and
 * linuxkm/module_hooks.c registers it. */
int wc_grb_service(void *buf, size_t len)
{
    int    ctx = wc_grb_ctx();
    int    ret = 0;
    size_t done = 0;

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

    while (done < len) {
        size_t        want = len - done;
        unsigned long flags;
        int           cpu;

        if (want > WC_GRB_CHUNK_SZ) {
            want = WC_GRB_CHUNK_SZ;
        }

        /* Interrupts off for one chunk.  This is what makes same-CPU nesting
         * impossible, and why nothing below may allocate or sleep. */
#ifdef WC_GRB_MEASURE
        {
            unsigned long long t0;
#endif
        flags = wc_linuxkm_irq_save();
#ifdef WC_GRB_MEASURE
        t0 = wc_linuxkm_mono_ns();
#endif
        cpu = wc_grb_this_cpu();

        if (ctx == WC_GRB_NMI) {
            struct wc_grb_nmi_slot *sl = &wc_grb_nmi[cpu];
            int                     live, g, tries;

            /* Straight into the caller's buffer.  Nothing is generated ahead
             * of demand and nothing is retained: these bytes belong to the
             * request being served, and the caller is blocked inside this
             * call until it returns.
             *
             * A changed generation means this instance was reseeded mid-read.
             * The other one is live now and fully instantiated, so read that
             * one, overwriting what the interrupted read left.  Only a return
             * of 0 tells the caller the bytes are good; on any other return
             * the kernel refills the whole buffer itself. */
            for (tries = 0; tries < WC_GRB_NMI_TRIES; tries++) {
                live = atomic_read(&sl->live);
                g = atomic_read(&sl->gen[live]);
                ret = wc_RNG_GenerateBlock(&sl->rng[live],
                                           (byte *) buf + done,
                                           (word32) want);
                if (ret != 0) {
                    break;
                }

                if (atomic_read(&sl->gen[live]) == g) {
                    break;
                }

                ret = WC_GRB_RETRY;
            }

            if (ret == WC_GRB_RETRY) {
                wc_linuxkm_irq_restore(flags);
                wc_grb_ctr_inc(&wc_grb_stat[ctx].declined);

                return -1;
            }

            if (ret == 0) {
                if ((unsigned long) wc_grb_ctr_inc_return(&sl->since) >=
                    sl->at) {
                    atomic_set(&sl->pending, 1);
                    atomic_set(&wc_grb_any_pending, 1);
                }
            }
        }
        else {
            struct wc_grb_slot *sl = &wc_grb_cpu[cpu];

            ret = wc_RNG_GenerateBlock(&sl->rng, (byte *) buf + done,
                                       (word32) want);
            if ((ret == 0) &&
                ((unsigned long) wc_grb_ctr_inc_return(&sl->since) >= sl->at)) {
                atomic_set(&sl->pending, 1);
                atomic_set(&wc_grb_any_pending, 1);
            }
        }

#ifdef WC_GRB_MEASURE
        wc_grb_note_irqoff(ctx, wc_linuxkm_mono_ns() - t0);
#endif
        wc_linuxkm_irq_restore(flags);
#ifdef WC_GRB_MEASURE
        }
#endif

        if (ret != 0) {
            break;
        }

        done += want;
    }

    if (ret == 0) {
        wc_grb_ctr_inc(&wc_grb_stat[ctx].served);
        /* Self-help, so worker scheduling cannot starve the reseed.  Interrupts
         * are restored by now, the maintenance call is a root generate not the
         * entropy gather, and can_block() rules out a caller holding a lock. */
        if ((ctx == WC_GRB_PROC) && wc_grb_reseed_due() &&
            wc_linuxkm_can_block()) {
            (void) wc_grb_maintain_cpu(-1);
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

int wc_grb_service_active(void)
{
    return wc_grb_registered;
}

void wc_grb_set_registered(int on)
{
    wc_grb_registered = on ? 1 : 0;
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
            j = (((unsigned long) b[0] << 8) | (unsigned long) b[1]) %
                (span + 1);
        }

        wc_grb_root_at = wc_grb_root_period - (span / 2) + j;
    }

    atomic_set(&wc_grb_maint_busy, 0);

    return ret;
}

static int wc_grb_reseed_due(void)
{
    if (!wc_grb_rng_ready) {
        return 0;
    }

    return atomic_read(&wc_grb_any_pending) ? 1 : 0;
}

/* Reseed the leaves belonging to one CPU.  Process context only: the root's
 * own generate may gather entropy, and that has to be able to block.
 *
 * cpu is the CPU the glue pinned this work to, or negative for "wherever this
 * call happens to be", which is what the service path's self-help uses. */
int wc_grb_maintain_cpu(int cpu)
{
    int ret = 0, target;

    if ((!wc_grb_rng_ready) || (wc_grb_cpu == NULL) || (cpu >= wc_grb_ncpu)) {
        return 0;
    }

    /* Cleared before the scan: anything already pending is still visible in
     * its own flag, and anything raised during the scan re-arms this. */
    atomic_set(&wc_grb_any_pending, 0);

    target = (cpu < 0) ? wc_grb_this_cpu() : cpu;

    if (atomic_read(&wc_grb_cpu[target].pending)) {
        ret = wc_grb_reseed_local(cpu);
    }

    if ((ret == 0) && atomic_read(&wc_grb_nmi[target].pending)) {
        ret = wc_grb_reseed_nmi(target);
    }

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
        v[WC_GRB_ST_DECLINED + i] = wc_grb_ctr_read(&wc_grb_stat[i].declined);
        v[WC_GRB_ST_CTX_RESEEDS + i] = wc_grb_ctr_read(&wc_grb_stat[i].reseeds);
#ifdef WC_GRB_MEASURE
        v[WC_GRB_ST_IRQ_MAXNS + i] = atomic_read(&wc_grb_irq_max_ns[i]);
        v[WC_GRB_ST_CHUNKS + i]    = wc_grb_ctr_read(&wc_grb_chunks[i]);
#else
        v[WC_GRB_ST_IRQ_MAXNS + i] = -1;
        v[WC_GRB_ST_CHUNKS + i]    = -1;
#endif
    }
    v[WC_GRB_ST_MAINT_DEFERRED] = wc_grb_ctr_read(&wc_grb_maint_deferred);

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

int wc_grb_irq_hist(int ctx, long long *out, int n)
{
#ifdef WC_GRB_MEASURE
    int i;

    if ((out == NULL) || (n <= 0) || (ctx < 0) || (ctx >= WC_GRB_CTX_N)) {
        return 0;
    }

    if (n > WC_GRB_IRQ_BUCKETS) {
        n = WC_GRB_IRQ_BUCKETS;
    }

    for (i = 0; i < n; i++) {
        out[i] = wc_grb_ctr_read(&wc_grb_irq_buckets[ctx][i]);
    }

    return n;
#else
    (void) ctx; (void) out; (void) n;

    return 0;
#endif
}

static void wc_grb_report(void)
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
            pr_info("WCGRB: leaf[cpu%d] since=%lld at=%lu nmi_since=%lld"
                    " nmi_at=%lu nmi_live=%d\n",
                    i, wc_grb_ctr_read(&wc_grb_cpu[i].since), wc_grb_cpu[i].at,
                    wc_grb_ctr_read(&wc_grb_nmi[i].since), wc_grb_nmi[i].at,
                    atomic_read(&wc_grb_nmi[i].live));
        }
    }

    pr_info("WCGRB: last_err=%d registered=%d rng_ready=%d\n",
            atomic_read(&wc_grb_last_err), wc_grb_registered, wc_grb_rng_ready);
}

/* wc_FreeRng() zeroizes each leaf's DRBG internal state (V, C, reseed
 * counter), which is the CSP this file holds for the life of the module. */
/* wc_FreeRng() zeroizes each leaf's DRBG internal state (V, C, reseed
 * counter), which is the CSP this file holds for the life of the module. */
static void wc_grb_free_cpu(int n)
{
    int i;

    if (wc_grb_cpu == NULL) {
        return;
    }

    for (i = 0; i < n; i++) {
        (void) wc_FreeRng(&wc_grb_cpu[i].rng);
    }

    XFREE(wc_grb_cpu, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_grb_cpu = NULL;
}

static void wc_grb_free_nmi(int n)
{
    int i;

    if (wc_grb_nmi == NULL) {
        return;
    }

    for (i = 0; i < n; i++) {
        (void) wc_FreeRng(&wc_grb_nmi[i].rng[0]);
        (void) wc_FreeRng(&wc_grb_nmi[i].rng[1]);
    }

    XFREE(wc_grb_nmi, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_grb_nmi = NULL;
}

static int wc_grb_alloc_cpu(void)
{
    size_t sz = sizeof(struct wc_grb_slot) * (size_t) wc_grb_ncpu;
    int    ret, i;

    wc_grb_cpu = (struct wc_grb_slot *) XMALLOC(sz, NULL,
                                                DYNAMIC_TYPE_TMP_BUFFER);
    if (wc_grb_cpu == NULL) {
        pr_err("WCGRB: no memory for %d cpu leaves\n", wc_grb_ncpu);

        return MEMORY_E;
    }

    XMEMSET(wc_grb_cpu, 0, sz);
    for (i = 0; i < wc_grb_ncpu; i++) {
        ret = wc_InitRngRBGC(&wc_grb_cpu[i].rng, &wc_grb_root);
        if (ret != 0) {
            pr_err("WCGRB: wc_InitRngRBGC(cpu%d) failed: %d\n", i, ret);
            wc_grb_free_cpu(i);

            return ret;
        }

        atomic_set(&wc_grb_cpu[i].pending, 0);
        wc_grb_ctr_zero(&wc_grb_cpu[i].since);
        wc_grb_cpu[i].at = wc_grb_reseed_base;
    }

    return 0;
}

/* Both NMI instantiations are seeded up front, so the spare is a complete
 * RBGC leaf from the moment the module starts and the first flip publishes a
 * fully instantiated DRBG rather than an empty one. */
static int wc_grb_alloc_nmi(void)
{
    size_t sz = sizeof(struct wc_grb_nmi_slot) * (size_t) wc_grb_ncpu;
    int    ret, i, k;

    wc_grb_nmi = (struct wc_grb_nmi_slot *) XMALLOC(sz, NULL,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (wc_grb_nmi == NULL) {
        pr_err("WCGRB: no memory for %d nmi leaves\n", wc_grb_ncpu);

        return MEMORY_E;
    }

    XMEMSET(wc_grb_nmi, 0, sz);
    for (i = 0; i < wc_grb_ncpu; i++) {
        for (k = 0; k < 2; k++) {
            ret = wc_InitRngRBGC(&wc_grb_nmi[i].rng[k], &wc_grb_root);
            if (ret != 0) {
                pr_err("WCGRB: wc_InitRngRBGC(nmi cpu%d/%d) failed: %d\n",
                       i, k, ret);
                while (--k >= 0) {
                    (void) wc_FreeRng(&wc_grb_nmi[i].rng[k]);
                }

                wc_grb_free_nmi(i);

                return ret;
            }
        }

        atomic_set(&wc_grb_nmi[i].live, 0);
        atomic_set(&wc_grb_nmi[i].gen[0], 0);
        atomic_set(&wc_grb_nmi[i].gen[1], 0);
        atomic_set(&wc_grb_nmi[i].pending, 0);
        wc_grb_ctr_zero(&wc_grb_nmi[i].since);
        wc_grb_nmi[i].at = wc_grb_reseed_base;
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

    ret = wc_grb_alloc_cpu();
    if (ret != 0) {
        (void) wc_FreeRng(&wc_grb_root);

        return ret;
    }

    ret = wc_grb_alloc_nmi();
    if (ret != 0) {
        wc_grb_free_cpu(wc_grb_ncpu);
        (void) wc_FreeRng(&wc_grb_root);

        return ret;
    }

    wc_grb_rng_ready = 1;
    for (i = 0; i < wc_grb_ncpu; i++) {
        wc_grb_set_next_threshold(&wc_grb_cpu[i].at);
        wc_grb_set_next_threshold(&wc_grb_nmi[i].at);
    }

    /* The effective interval, not the threshold: the threshold is capped and
     * would read the same for 1e6 and for the SP 800-90A maximum. */
    pr_info("WCGRB: RBGC up, 1 root + %d cpu leaves + %d x2 nmi leaves,"
            " SHA-512, WC_RESEED_INTERVAL=%llu\n",
            wc_grb_ncpu, wc_grb_ncpu, (unsigned long long) WC_RESEED_INTERVAL);

    return 0;
}

void wc_grb_cleanup(void)
{
    wc_grb_registered = 0;
    wc_grb_report();
    if (wc_grb_rng_ready) {
        wc_grb_rng_ready = 0;
        wc_grb_free_cpu(wc_grb_ncpu);
        wc_grb_free_nmi(wc_grb_ncpu);
        (void) wc_FreeRng(&wc_grb_root);
    }
}

#else /* !(WOLFSSL_LINUXKM && LINUXKM_RBGC) */

/* ISO C requires a translation unit to contain at least one declaration, and
 * several OEs build with -Wpedantic. */
typedef int wc_linuxkm_get_entropy_not_used;

#endif /* WOLFSSL_LINUXKM && LINUXKM_RBGC */
