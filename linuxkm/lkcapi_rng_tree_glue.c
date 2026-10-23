/* lkcapi_rng_tree_glue.c -- kernel RNG services from the FIPS v7 RBGC tree
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

/* included by linuxkm/lkcapi_glue.c, after lkcapi_sha_glue.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#if defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG) && defined(WC_RNG_TREE)

#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES
    #error The RBGC tree is served through the get_random callback patch only.
#endif

/* A generate must not allocate: NMI callers and the allocator itself. */
#ifndef WOLFSSL_SMALL_STACK_CACHE
    #error The RBGC tree requires WOLFSSL_SMALL_STACK_CACHE.
#endif

/* Without one, wc_GenerateSeed() seeds the root from get_random_bytes(). */
#if !(defined(HAVE_ENTROPY_MEMUSE) || defined(HAVE_INTEL_RDSEED) || \
      defined(HAVE_AMD_RDSEED))
    #error The RBGC tree requires wolfEntropy or RDSEED as its entropy source.
#endif

/* Root reseeds from the entropy source every 60 seconds. */
#define RNG_ROOT_DELAY (60 * HZ)
/* Task-lane bytes per stretch with preemption off. */
#define RNG_TASK_CHUNK 256
/* Retries for a caller that can sleep while the root reseeds. */
#define RNG_MAX_TRIES  1000
/* Polls, 1-2 ms apart, for requests to leave the tree at a hold or stop. */
#define RNG_DRAIN_TRIES 5000
/* A blocking user request's sleep between tries while the tree is held. */
#define RNG_USER_POLL_MS 2

static struct delayed_work rngRootWork;
static atomic_t rngReady = ATOMIC_INIT(0);
static int wc_linuxkm_drbg_loaded = 0;
static int rngUnregistered = 0;
/* Live tfms: unregistered, cra_refcnt with no holder is 0 or 1 by kernel
 * build (crypto_unregister_alg(), crypto/algapi.c), so count them here. */
static atomic_t rngTfms = ATOMIC_INIT(0);
/* Requests inside the tree: a hold or a stop waits for them to leave. */
static atomic_t rngInFlight = ATOMIC_INIT(0);
/* Hibernation: no output and no DRBG state until the image is behind us. */
static atomic_t rngHeld = ATOMIC_INIT(0);
#ifdef CONFIG_PM_SLEEP
/* After resume: the tree still to be built from the source. */
static atomic_t rngBuild = ATOMIC_INIT(0);
#endif
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
/* The ACPI VM Generation ID, found at startup and read on every request. */
static struct wc_linuxkm_vmgenid_poll_state rngVmGen;
static u8 rngGenSeen[16];
static atomic_t rngGenSeq = ATOMIC_INIT(0);
static atomic_t rngGenLive = ATOMIC_INIT(0);
#endif

/* Latched until reload: retrying cannot clear these.  Outside a hold,
 * BAD_STATE_E from the tree means a DRBG did not zeroize. */
static int RngLatched(int ret)
{
    return ret == WC_NO_ERR_TRACE(ENTROPY_RT_E) ||
           ret == WC_NO_ERR_TRACE(ENTROPY_APT_E) ||
           ret == WC_NO_ERR_TRACE(RNG_FAILURE_E) ||
           ret == WC_NO_ERR_TRACE(BAD_STATE_E);
}

/* A failed self-test waits for an operator: the usual period, not a retry. */
static int RngWaitsForOperator(int ret)
{
    return ret == WC_NO_ERR_TRACE(DRBG_SHA512_KAT_FIPS_E) ||
           ret == WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E);
}

#ifdef CONFIG_PM_SLEEP
/* The tree from the source after hibernation.  Entropy may be unavailable
 * for a while (SP 800-90A 9.1, 11.4.1): the hold stays and the root work
 * keeps trying.  A failed self-test or a latched error ends the hold, so
 * requests reach the tree and see the error (ISO/IEC 19790 [02.30]). */
static void RngBuild(void)
{
    int ret, again, opwait;

    if (!atomic_read(&rngReady))
        return;   /* stopped: nothing to build */
    ret = wc_RNG_TreeInit((int)nr_cpu_ids, NULL);
    again = (ret != 0 && !RngLatched(ret));
    opwait = RngWaitsForOperator(ret);
    atomic_set(&rngBuild, again);   /* before any return: the root work's cue */
    if (again) {
        pr_err_ratelimited("libwolfssl: RNG tree not built yet (%d)\n", ret);
        queue_delayed_work(system_highpri_wq, &rngRootWork,
                           opwait ? RNG_ROOT_DELAY : HZ / 10);
        if (!opwait)
            return;
    }
    else if (ret != 0) {
        pr_err("libwolfssl: RNG error state (%d) after hibernation, stopped "
               "until reload\n", ret);
    }
    smp_mb();   /* the tree before the hold's end, for the request path */
    atomic_set(&rngHeld, 0);
    if (ret == 0)
        queue_delayed_work(system_highpri_wq, &rngRootWork, RNG_ROOT_DELAY);
}
#endif

static void RngRootWork(struct work_struct* work)
{
    unsigned long delay = RNG_ROOT_DELAY;
    int ret;

    (void)work;

    if (!atomic_read(&rngReady))
        return;
#ifdef CONFIG_PM_SLEEP
    if (atomic_read(&rngBuild)) {
        RngBuild();
        return;
    }
#endif
    if (atomic_read(&rngHeld))
        return;
    ret = wc_RNG_TreeReseed(1);
    if (RngLatched(ret)) {
        pr_err_ratelimited("libwolfssl: RNG error state (%d), stopped until "
                           "reload\n", ret);
        return;
    }
    if (ret == WC_NO_ERR_TRACE(BUSY_E)) {
        delay = 1;
    }
    else if (ret != 0) {
        pr_err_ratelimited("libwolfssl: root DRBG reseed failed: %d\n", ret);
        if (!RngWaitsForOperator(ret))
            delay = HZ / 10;
    }

    queue_delayed_work(system_highpri_wq, &rngRootWork, delay);
}

/* Start a root reseed now. */
static void RngKickRoot(void)
{
#ifdef CONFIG_PM_SLEEP
    if (atomic_read(&rngBuild))
        return;   /* the build keeps its own period */
#endif
    if (atomic_read(&rngReady) && !atomic_read(&rngHeld))
        mod_delayed_work(system_highpri_wq, &rngRootWork, 0);
}

/* VM fork or hibernation resume: every DRBG state is suspect. */
static WC_MAYBE_UNUSED void RngInvalidate(void)
{
    wc_RNG_TreeInvalidate();
    RngKickRoot();
}

#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
/* The 16-byte ID against the copy, lock-free and NMI safe.  1: changed, this
 * caller recorded it; -1: changed, another caller is recording it.  Either
 * way this caller invalidated the tree.  The copy is read like a seqcount:
 * same sequence before and after, or the compare does not count. */
static int RngGenChanged(void)
{
    unsigned long flags;
    int seq, same;

    if (!atomic_read(&rngGenLive))
        return 0;
    seq = atomic_read(&rngGenSeq);
    if (seq & 1)
        return -1;
    smp_rmb();
    same = (XMEMCMP(rngVmGen.map, rngGenSeen, sizeof(rngGenSeen)) == 0);
    smp_rmb();
    if (same)
        return (atomic_read(&rngGenSeq) == seq) ? 0 : -1;
    /* Every reader that sees the change invalidates before anyone records
     * it, so no retry serves copied state; a second bump costs nothing. */
    wc_RNG_TreeInvalidate();
    /* The write side runs with interrupts off (Documentation/locking/
     * seqlock.rst): readers in hardirq decline meanwhile, NMI ones too. */
    local_irq_save(flags);
    if (atomic_cmpxchg(&rngGenSeq, seq, seq + 1) != seq) {
        local_irq_restore(flags);
        return -1;
    }
    XMEMCPY(rngGenSeen, rngVmGen.map, sizeof(rngGenSeen));
    smp_wmb();
    atomic_set(&rngGenSeq, seq + 2);
    local_irq_restore(flags);
    return 1;
}
#endif

/* A clone seen on this request (SP 800-90C A.3.2): every DRBG state is
 * suspect, the tree is invalidated and this request is declined. */
static int RngGenStale(void)
{
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    int gen = RngGenChanged();

    if (gen > 0 && !in_nmi())
        RngKickRoot();
    return gen != 0;
#else
    return 0;
#endif
}

/* A lane never nests within itself on one CPU, so each leaf has one user. */
static int RngLane(void)
{
    if (in_nmi())
        return WC_RNG_TREE_LANE_NMI;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    if (in_irq())
#else
    if (in_hardirq())
#endif
        return WC_RNG_TREE_LANE_HARDIRQ;
    if (in_serving_softirq())
        return WC_RNG_TREE_LANE_SOFTIRQ;
    return WC_RNG_TREE_LANE_TASK;
}

/* Fill dst from this CPU's leaf with preemption off, so a leaf or root holder
 * is never preempted (softirq and hardirq lanes are preemptible on RT); the
 * task lane goes one chunk at a time. */
static int RngFill(const u8* addl, size_t addlSz, u8* dst, size_t len)
{
    int lane = RngLane();
    size_t max = RNG_MAX_BLOCK_LEN;
    size_t n;
    int ret = 0;

    if (lane == WC_RNG_TREE_LANE_TASK)
        max = RNG_TASK_CHUNK;

    while (ret == 0 && len > 0) {
        n = min_t(size_t, len, max);

        preempt_disable();
        ret = wc_RNG_TreeGenerate(raw_smp_processor_id(), lane, addl,
                                  (word32)addlSz, dst, (word32)n);
        preempt_enable();

        addl = NULL;
        addlSz = 0;
        dst += n;
        len -= n;
    }

    return ret;
}

#ifdef HAVE_FIPS
/* Worth a retry: another task runs an on-demand self-test (module_hooks.c),
 * or one has just ended and the module is back in service. */
static int RngSelfTestWait(void)
{
    int tester = WOLFSSL_ATOMIC_LOAD(in_fips_test);

    return (tester != -1 && tester != (int)task_pid_nr(current)) ||
           wolfCrypt_GetStatus_fips() == 0;
}
#endif

/* A caller that can sleep waits for the root to reseed instead of failing.
 * maySleep is 0 for callers that may hold a lock the kernel cannot see. */
static int RngGetBytesAddl(const u8* addl, size_t addlSz, void* buf,
                           size_t len, int maySleep)
{
    int tries = 0;
    int stale = 0;
    int ret;

    /* Stopped: for good.  Held for hibernation: served again after it; the
     * kernel's void get_random_bytes() answers itself, user callers wait. */
    if (!atomic_read(&rngReady))
        return -ENODEV;
    if (atomic_read(&rngHeld))
        return -EAGAIN;
    /* Counted, then checked again: a hold or stop that sees zero in flight
     * is seen by every request that was not counted. */
    atomic_inc(&rngInFlight);
    smp_mb__after_atomic();
    if (!atomic_read(&rngReady)) {
        atomic_dec(&rngInFlight);
        return -ENODEV;
    }
    if (atomic_read(&rngHeld)) {
        atomic_dec(&rngInFlight);
        return -EAGAIN;
    }
    smp_rmb();   /* the tree a release published before ending its hold */

    /* A clone seen on this request: a sleeper rebuilds in the loop below. */
    if (RngGenStale()) {
        stale = 1;
        ret = WC_NO_ERR_TRACE(NOT_READY_E);
    }
    else {
        ret = RngFill(addl, addlSz, buf, len);
    }
    while (ret != 0 && maySleep && atomic_read(&rngReady) &&
           !atomic_read(&rngHeld) &&
           wc_linuxkm_can_block() && tries < RNG_MAX_TRIES) {
        if (ret == WC_NO_ERR_TRACE(NOT_READY_E) ||
            ret == WC_NO_ERR_TRACE(BUSY_E)) {
            /* A busy leaf, or a root that could not be renewed: wait. */
            if (ret == WC_NO_ERR_TRACE(BUSY_E) ||
                    wc_RNG_TreeReseed(0) != 0)
                usleep_range(100, 200);
        }
#ifdef HAVE_FIPS
        else if (ret == WC_NO_ERR_TRACE(DRBG_SHA512_KAT_FIPS_E)) {
            /* Only a reseed runs a pending CAST or re-instantiates the tree
             * after one passed again; a failed CAST refuses it. */
            int rret = wc_RNG_TreeReseed(0);

            if (rret == WC_NO_ERR_TRACE(BUSY_E) ||
                (rret == WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E) &&
                 RngSelfTestWait()))
                usleep_range(100, 200);
            else if (rret != 0)
                break;
        }
        else if (ret == WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E) &&
                 RngSelfTestWait()) {
            usleep_range(1000, 2000);
        }
#endif
        else {
            break;
        }
        if (RngGenStale())   /* a clone during the wait: no copied state */
            ret = WC_NO_ERR_TRACE(NOT_READY_E);
        else
            ret = RngFill(addl, addlSz, buf, len);
        tries++;
    }
    if (ret != 0) {
        /* The root's renewal, wipe or recovery waits for this kick, not the
         * next 60 s reseed.  Queueing work is not NMI safe. */
        if (!in_nmi())
            RngKickRoot();
        ForceZero(buf, len);
    }
    atomic_dec(&rngInFlight);   /* after the kick: a stop waits for it too */
    if (ret == 0)
        return 0;
    if (!atomic_read(&rngReady))
        return -ENODEV;
    if (atomic_read(&rngHeld) || stale)
        return -EAGAIN;   /* a hold or a clone met mid-request: wait it out */
    return -EIO;
}

/* crypto API stdrng: src is SP 800-90A additional input, as in crypto/drbg.c */
static int RngTfmGenerate(struct crypto_rng* tfm, const u8* src,
                          unsigned int slen, u8* dst, unsigned int dlen)
{
    (void)tfm;
    return RngGetBytesAddl(src, slen, dst, dlen, 1);
}

/* By design: seed bytes are refused, never used; only the root's entropy
 * source seeds the tree. The kernel's default RNG reset passes 0 bytes.
 * SP 800-90A r1 9.2; crypto/rng.c crypto_rng_reset() */
static int RngTfmSeed(struct crypto_rng* tfm, const u8* seed,
                      unsigned int slen)
{
    (void)tfm;
    (void)seed;
    if (slen != 0)
        return -EINVAL;
    return 0;
}

static int RngTfmInit(struct crypto_tfm* tfm)
{
    (void)tfm;
    atomic_inc(&rngTfms);
    return 0;
}

static void RngTfmExit(struct crypto_tfm* tfm)
{
    (void)tfm;
    atomic_dec(&rngTfms);
}

static struct rng_alg wc_linuxkm_drbg = {
    .generate = RngTfmGenerate,
    .seed     = RngTfmSeed,
    .seedsize = 0,
    .base = {
        .cra_name        = WOLFKM_STDRNG_NAME,
        .cra_driver_name = WOLFKM_STDRNG_DRIVER,
        .cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
        .cra_ctxsize     = 0,
        .cra_init        = RngTfmInit,
        .cra_exit        = RngTfmExit,
        .cra_module      = THIS_MODULE
    }
};

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
static int rngDefault = 0;

int wc_linux_kernel_rng_is_wolfcrypt(struct crypto_rng* rng)
{
    if (rng == NULL || !rngDefault)
        return 0;
    return rng->base.__crt_alg == &wc_linuxkm_drbg.base;
}
#endif

#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
/* Watch the ACPI VM generation counter, as the extras do: before 5.18 there is
 * no vmgenid notifier, and a modular vmgenid may not be loaded. */
#define RNG_VMGEN_DELAY (HZ / 10)
static struct delayed_work rngVmGenWork;
/* Discovery runs once, in task context, under this lock. */
static DEFINE_MUTEX(rngVmGenLock);

/* The first call only finds the device (its result is then 0); the copy is
 * taken from the mapped ID and requests compare against it from here on. */
static void RngGenDiscover(void)
{
    if (rngVmGen.state == 0 && wc_linuxkm_vmgenid_changed(&rngVmGen) == 0 &&
            rngVmGen.state == 1) {
        XMEMCPY(rngGenSeen, rngVmGen.map, sizeof(rngGenSeen));
        smp_wmb();
        atomic_set(&rngGenLive, 1);
    }
}

static void RngVmGenWork(struct work_struct* work)
{
    int watching;

    (void)work;
    mutex_lock(&rngVmGenLock);
    RngGenDiscover();
    watching = (rngVmGen.state == 1);   /* 0 on bare metal: nothing to watch */
    mutex_unlock(&rngVmGenLock);
    if (watching) {
        if (RngGenChanged() > 0)   /* recorded and invalidated: renew now */
            RngKickRoot();
        queue_delayed_work(system_highpri_wq, &rngVmGenWork, RNG_VMGEN_DELAY);
    }
}
#endif

#if IS_ENABLED(CONFIG_VMGENID)
static int RngVmForkNotify(struct notifier_block* nb, unsigned long action,
                           void* data)
{
    (void)nb;
    (void)action;
    (void)data;
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    /* A request or the poll may have seen this clone: one invalidation. */
    if (atomic_read(&rngGenLive)) {
        if (RngGenChanged() > 0)
            RngKickRoot();
        return NOTIFY_OK;
    }
#endif
    RngInvalidate();
    return NOTIFY_OK;
}

static struct notifier_block rngVmForkNb = {
    .notifier_call = RngVmForkNotify
};
static int rngVmForkNbUp = 0;
#endif

#ifdef CONFIG_PM_SLEEP
/* Build the tree again after hibernation, on the root work, the one builder
 * (a pending build restarts with it).  A restore that was never held (a
 * failed resume in the booted kernel) is only suspect. */
static void RngRelease(void)
{
    if (!atomic_read(&rngHeld)) {
        RngInvalidate();
        return;
    }
    wc_RNG_TreeInvalidate();   /* WC_RNG children kept their state */
    wc_RNG_TreeHold(0);
    atomic_set(&rngBuild, 1);
    mod_delayed_work(system_highpri_wq, &rngRootWork, 0);
}

/* SP 800-90C 7.3.1 item 11: no DRBG state reaches the hibernation image.
 * Output stops, the tree is wiped, nothing rebuilds it before RngRelease(). */
static int RngHold(void)
{
    int tries = 0;
    int ret = 0;

    atomic_set(&rngHeld, 1);
    smp_mb();
    cancel_delayed_work_sync(&rngRootWork);
    atomic_set(&rngHeld, 1);   /* a build inside the cancel may have ended it */
    smp_mb();
    while (atomic_read(&rngInFlight) != 0 && tries++ < RNG_DRAIN_TRIES)
        usleep_range(1000, 2000);
    if (atomic_read(&rngInFlight) != 0) {
        pr_err("libwolfssl: RNG tree still in use, hibernation refused\n");
        if (atomic_read(&rngBuild)) {   /* a pending build keeps its hold */
            queue_delayed_work(system_highpri_wq, &rngRootWork, HZ / 10);
            return -EBUSY;
        }
        atomic_set(&rngHeld, 0);
        RngKickRoot();
        return -EBUSY;
    }
    wc_RNG_TreeHold(1);   /* no root is made or renewed from here */
    ret = wc_RNG_TreeZeroize();
    if (ret != 0) {
        /* A DRBG did not zeroize: the tree stays held until reload, and
         * requests reach it for their error (ISO/IEC 19790 [02.30]). */
        pr_err("libwolfssl: RNG tree wipe failed before hibernation (%d)\n",
               ret);
        smp_mb();
        atomic_set(&rngHeld, 0);
        return ret;
    }
    pr_info("libwolfssl: RNG tree wiped for hibernation.\n");
    return 0;
}

/* Hibernation writes RNG state to disk; suspend to RAM does not. */
static int RngPmNotify(struct notifier_block* nb, unsigned long action,
                       void* data)
{
    (void)nb;
    (void)data;
    if (action == PM_HIBERNATION_PREPARE)
        return (RngHold() == 0) ? NOTIFY_OK : NOTIFY_BAD;
    if (action == PM_POST_HIBERNATION || action == PM_POST_RESTORE)
        RngRelease();
    return NOTIFY_OK;
}

static struct notifier_block rngPmNb = {
    .notifier_call = RngPmNotify
};
static int rngPmNbUp = 0;
#endif

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES

/* get_random_bytes() callers wait only where preempt_count() and the RCU
 * nesting count show every spinlock and RCU read side held (PREEMPT_RT
 * spinlocks take rcu_read_lock(), kernel/locking/spinlock_rt.c). */
static int RngGetBytes(void* buf, size_t len)
{
    int maySleep = IS_ENABLED(CONFIG_PREEMPT_COUNT);

#ifdef CONFIG_PREEMPT_RCU
    /* rcu_preempt_depth(), read plainly: only this task writes it. */
    if (current->rcu_read_lock_nesting != 0)
        maySleep = 0;
#endif
    return RngGetBytesAddl(NULL, 0, buf, len, maySleep);
}

/* A blocking user request waits out a hold or a clone's rebuild, as
 * getrandom(2) documents; a signal, the freezer's included, ends the wait. */
static int RngUserFill(u8* block, size_t n)
{
    int ret;

    for (;;) {
        ret = RngGetBytesAddl(NULL, 0, block, n, 1);
        if (ret != -WC_NO_ERR_TRACE(EAGAIN))
            return ret;
        if (msleep_interruptible(RNG_USER_POLL_MS) != 0)
            return -ERESTARTSYS;
    }
}

/* What a user request returns: the bytes copied, else the error.  With the
 * service down it is EAGAIN, the retry getrandom(2) documents; never ENODEV. */
static ssize_t RngUserResult(size_t total, int ret)
{
    if (total > 0)
        return (ssize_t)total;
    if (ret == -WC_NO_ERR_TRACE(ENODEV))
        return -EAGAIN;
    return (ret != 0) ? ret : -EFAULT;
}

/* getrandom() and /dev/urandom where random.c has get_random_bytes_user() */
static ssize_t RngGetBytesUser(struct iov_iter* iter)
{
    u8 block[RNG_TASK_CHUNK];
    size_t n, copied;
    size_t total = 0;
    int ret = 0;

    while (iov_iter_count(iter) > 0) {
        n = min_t(size_t, iov_iter_count(iter), sizeof(block));
        ret = RngUserFill(block, n);
        if (ret != 0)
            break;
        copied = copy_to_iter(block, n, iter);
        total += copied;
        if (copied != n || signal_pending(current))
            break;
        cond_resched();
    }
    ForceZero(block, sizeof(block));
    return RngUserResult(total, ret);
}

/* getrandom() and /dev/urandom where random.c has extract_crng_user() */
static ssize_t RngExtractUser(void __user* buf, size_t nbytes)
{
    u8 block[RNG_TASK_CHUNK];
    size_t n, copied;
    size_t total = 0;
    int ret = 0;

    /* getrandom(buf, 0) reaches here (drivers/char/random.c,
     * urandom_read_nowarn); get_random_bytes_user() returns 0 first. */
    if (nbytes == 0)
        return 0;

    while (total < nbytes) {
        n = min_t(size_t, nbytes - total, sizeof(block));
        ret = RngUserFill(block, n);
        if (ret != 0)
            break;
        copied = n - copy_to_user((u8 __user*)buf + total, block, n);
        total += copied;
        if (copied != n || signal_pending(current))
            break;
        cond_resched();
    }
    ForceZero(block, sizeof(block));
    return RngUserResult(total, ret);
}

/* The tree takes no outside input: the root reads only its entropy source. */
static int RngMixPoolBytes(const void* buf, size_t len)
{
    (void)buf;
    (void)len;
    return 0;
}

/* Reseeds the root from its registered entropy source only (wolfEntropy,
 * RDSEED or the seed callback); each leaf reseeds from it at its own count.
 * SP 800-90C 7.2.3.1, 7.2.3.2.1: reseeding from a parent adds no entropy */
static int RngCrngReseed(void)
{
    RngKickRoot();
    return 0;
}

static const struct wolfssl_linuxkm_random_bytes_handlers
    random_bytes_handlers = {
    ._get_random_bytes     = RngGetBytes,
    .get_random_bytes_user = RngGetBytesUser,
    .extract_crng_user     = RngExtractUser,
    .mix_pool_bytes        = RngMixPoolBytes,
    .crng_reseed           = RngCrngReseed,
};

static int rngHandlers = 0;

#endif /* LINUXKM_DRBG_GET_RANDOM_BYTES */

/* The registered stdrng must be ours and must serve. */
static int RngCheckRegistered(void)
{
    struct crypto_rng* tfm;
    u8 buf[16];
    int ret = 0;

    tfm = crypto_alloc_rng(wc_linuxkm_drbg.base.cra_name, 0, 0);
    if (IS_ERR(tfm))
        return (int)PTR_ERR(tfm);

#ifndef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    if (strcmp(crypto_tfm_alg_driver_name(crypto_rng_tfm(tfm)),
               wc_linuxkm_drbg.base.cra_driver_name) != 0)
        ret = -ENOENT;
#endif
    if (ret == 0)
        ret = crypto_rng_generate(tfm, NULL, 0, buf, sizeof(buf));

    crypto_free_rng(tfm);
    ForceZero(buf, sizeof(buf));
    return ret;
}

static void RngZeroize(void)
{
    if (wc_RNG_TreeZeroize() != 0)
        pr_err("ERROR: wc_RNG_TreeZeroize() could not zeroize every DRBG.\n");
}

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
static int RngGiveBack(void);
#endif

static void RngStop(void)
{
    int tries = 0;

    atomic_set(&rngReady, 0);
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    atomic_set(&rngGenLive, 0);   /* the map goes away below */
#endif
    smp_mb();
    /* Every request leaves first, or the map and the leaves go away under
     * one; a wait past a reseed gather is reported, never cut short. */
    while (atomic_read(&rngInFlight) != 0) {
        usleep_range(1000, 2000);
        if (++tries % RNG_DRAIN_TRIES == 0)   /* a report, not a limit */
            pr_err("libwolfssl: %d requests still in the RNG tree at stop\n",
                   atomic_read(&rngInFlight));
    }
#ifdef CONFIG_PM_SLEEP
    if (rngPmNbUp)
        unregister_pm_notifier(&rngPmNb);
    rngPmNbUp = 0;
#endif
#if IS_ENABLED(CONFIG_VMGENID)
    if (rngVmForkNbUp)
        unregister_random_vmfork_notifier(&rngVmForkNb);
    rngVmForkNbUp = 0;
#endif
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    cancel_delayed_work_sync(&rngVmGenWork);
    wc_linuxkm_vmgenid_poll_teardown(&rngVmGen);
#endif
    cancel_delayed_work_sync(&rngRootWork);
#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    /* Stopped: stuck handler callers return, so retry a refused unregister. */
    if (rngDefault && RngGiveBack() != 0)
        pr_err("ERROR: default rng or get_random_bytes handlers left in a "
               "stopped tree.\n");
#endif
    RngZeroize();
#ifdef CONFIG_PM_SLEEP
    /* Stopped inside a hold (deinstall before the freeze): undo it. */
    atomic_set(&rngBuild, 0);
    if (atomic_read(&rngHeld)) {
        wc_RNG_TreeHold(0);
        atomic_set(&rngHeld, 0);
    }
#endif
}

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
/* Make our stdrng the system default and take over get_random_bytes(). */
static int RngTakeOver(void)
{
    int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 0)
    ret = crypto_del_default_rng();
    if (ret == 0)
        ret = crypto_get_default_rng();
    if (ret == 0) {
        if (crypto_default_rng == NULL ||
            crypto_default_rng->base.__crt_alg != &wc_linuxkm_drbg.base)
            ret = -EINVAL;
        crypto_put_default_rng();
    }
#elif defined(CONFIG_CRYPTO_FIPS)
    ret = 0;
    if (fips_enabled)
        ret = crypto_del_default_rng();
#else
    ret = 0;
#endif
    if (ret != 0) {
        pr_err("ERROR: %s not made the default stdrng: %d\n",
               wc_linuxkm_drbg.base.cra_driver_name, ret);
        return ret;
    }
    rngDefault = 1;
    pr_info("%s registered as systemwide default stdrng.\n",
            wc_linuxkm_drbg.base.cra_driver_name);

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES
    ret = wolfssl_linuxkm_register_random_bytes_handlers(THIS_MODULE,
              &random_bytes_handlers);
    if (ret != 0) {
        pr_err("ERROR: get_random_bytes handlers not installed: %d\n", ret);
        return ret;
    }
    rngHandlers = 1;
    pr_info("libwolfssl: kernel global random_bytes handlers installed.\n");
#endif

    return 0;
}

/* Undo RngTakeOver(), get_random_bytes() first so no caller races it. */
static int RngGiveBack(void)
{
    int ret = 0;

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES
    if (rngHandlers) {
        ret = wolfssl_linuxkm_unregister_random_bytes_handlers();
        if (ret != 0) {
            pr_err("ERROR: get_random_bytes handlers not removed: %d\n", ret);
            return ret;
        }
        rngHandlers = 0;
    }
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 0)
    ret = crypto_del_default_rng();
#elif defined(CONFIG_CRYPTO_FIPS)
    if (fips_enabled)
        ret = crypto_del_default_rng();
#endif
    if (ret != 0) {
        pr_err("ERROR: crypto_del_default_rng failed: %d\n", ret);
        return ret;
    }

    rngDefault = 0;
    return 0;
}
#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

static int wc_linuxkm_drbg_cleanup(void);

static int wc_linuxkm_drbg_startup(void)
{
    int ret;

    if (wc_linuxkm_drbg_loaded)
        return -EBUSY;

    ret = wc_RNG_TreeInit((int)nr_cpu_ids, NULL);
    if (ret != 0) {
        pr_err("ERROR: wc_RNG_TreeInit() failed: %d\n", ret);
        RngZeroize();   /* a root it instantiated before the failure */
        return -ECANCELED;
    }
    INIT_DELAYED_WORK(&rngRootWork, RngRootWork);
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    INIT_DELAYED_WORK(&rngVmGenWork, RngVmGenWork);
    /* Found before the first request, so that request already compares. */
    mutex_lock(&rngVmGenLock);
    RngGenDiscover();
    mutex_unlock(&rngVmGenLock);
#endif
    atomic_set(&rngReady, 1);
    /* Armed before the tree can serve: a clone or restore from here on is
     * seen.  RngStop() undoes them on every failure path below. */
#ifdef WC_LINUXKM_HAVE_VMGENID_ACPI
    queue_delayed_work(system_highpri_wq, &rngVmGenWork, 0);
#endif
#if IS_ENABLED(CONFIG_VMGENID)
    if (register_random_vmfork_notifier(&rngVmForkNb) != 0)
        pr_warn("libwolfssl: no VM-fork notifier, VM clones go undetected.\n");
    else
        rngVmForkNbUp = 1;
#endif
#ifdef CONFIG_PM_SLEEP
    if (register_pm_notifier(&rngPmNb) != 0)
        pr_warn("libwolfssl: no PM notifier, hibernation goes undetected.\n");
    else
        rngPmNbUp = 1;
#endif

    ret = crypto_register_rng(&wc_linuxkm_drbg);
    if (ret != 0) {
        pr_err("ERROR: crypto_register_rng: %d\n", ret);
        RngStop();
        return ret;
    }

    ret = RngCheckRegistered();
    if (ret != 0) {
        pr_err("ERROR: %s failed its registration check: %d\n",
               wc_linuxkm_drbg.base.cra_driver_name, ret);
        crypto_unregister_rng(&wc_linuxkm_drbg);
        /* A holder keeps the tree; cleanup frees it once released.  A failed
         * module init frees the module anyway (kernel/module/main.c). */
        if (atomic_read(&rngTfms) != 0) {
            atomic_set(&rngReady, 0);   /* no reseeds; notifiers stay */
            rngUnregistered = 1;
            wc_linuxkm_drbg_loaded = 1;
            return ret;
        }
        RngStop();
        return ret;
    }

    queue_delayed_work(system_highpri_wq, &rngRootWork, RNG_ROOT_DELAY);
    wc_linuxkm_drbg_loaded = 1;
    WOLFKM_INSTALL_NOTICE(wc_linuxkm_drbg);

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    ret = RngTakeOver();
    if (ret != 0) {
        /* Nothing outside undoes this when stdrng is the only algorithm. */
        if (wc_linuxkm_drbg_cleanup() != 0)
            pr_err("ERROR: wc_linuxkm_drbg startup not undone.\n");
        return ret;
    }
    pr_info("libwolfssl: to unload module, first echo 1 > "
            "/sys/module/libwolfssl/deinstall_algs\n");
#endif

    return 0;
}

static int wc_linuxkm_drbg_cleanup(void)
{
    int ret;

    if (!wc_linuxkm_drbg_loaded)
        return -EINVAL;

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    if (rngDefault) {
        ret = RngGiveBack();
        if (ret != 0)
            return ret;
    }
#endif

    if (!rngUnregistered) {
        ret = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);
        if (ret != 1) {
            pr_err("ERROR: wc_linuxkm_drbg_cleanup with refcnt %d\n", ret);
            return -EBUSY;
        }
        crypto_unregister_rng(&wc_linuxkm_drbg);
        rngUnregistered = 1;
        if (!(wc_linuxkm_drbg.base.cra_flags & CRYPTO_ALG_DEAD)) {
            pr_warn("WARNING: wc_linuxkm_drbg not dead after unregister.\n");
            return -EBUSY;
        }
    }
    /* Unregistered, no new tfm can start; wait for the last one to go. */
    ret = atomic_read(&rngTfms);
    if (ret != 0) {
        pr_err("ERROR: wc_linuxkm_drbg still held, %d tfms\n", ret);
        return -EBUSY;
    }

    RngStop();
    rngUnregistered = 0;
    wc_linuxkm_drbg_loaded = 0;
    return 0;
}

/* The kernel frees a going module whatever holds it (kernel/module/main.c,
 * do_init_module fail:): after a refused cleanup, stop what it armed anyway. */
static int wc_linuxkm_drbg_abandon(void)
{
    int ret;

    /* Unregistering unlinks the alg whatever holds it (crypto/algapi.c,
     * crypto_remove_alg): no new holder from here; the module refcount
     * protects the rest.  Then the stop, then the orderly cleanup again. */
    if (!rngUnregistered) {
        crypto_unregister_rng(&wc_linuxkm_drbg);
        rngUnregistered = 1;
    }
    RngStop();
    ret = wc_linuxkm_drbg_cleanup();   /* stopped, so a stuck caller is gone */
    if (ret != 0)
        wc_linuxkm_drbg_loaded = 0;    /* still held: freed under the holder */
    return ret;
}

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG && WC_RNG_TREE */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
