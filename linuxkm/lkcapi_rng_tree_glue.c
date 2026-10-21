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

static struct delayed_work rngRootWork;
static int rngReady = 0;
static int wc_linuxkm_drbg_loaded = 0;
static int rngUnregistered = 0;
/* cra_refcnt with no holder once unregistered: 6.16 drops the registration's
 * own reference in crypto_unregister_alg() (crypto/algapi.c). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
    #define RNG_UNHELD_REFCNT 0
#else
    #define RNG_UNHELD_REFCNT 1
#endif

static void RngRootWork(struct work_struct* work)
{
    unsigned long delay = RNG_ROOT_DELAY;
    int ret;

    (void)work;

    ret = wc_RNG_TreeReseed(1);
    /* Latched until reload: retrying cannot clear these. */
    if (ret == WC_NO_ERR_TRACE(ENTROPY_RT_E) ||
        ret == WC_NO_ERR_TRACE(ENTROPY_APT_E) ||
        ret == WC_NO_ERR_TRACE(RNG_FAILURE_E)) {
        pr_err("libwolfssl: RNG error state (%d), stopped until reload\n",
               ret);
        return;
    }
    if (ret == WC_NO_ERR_TRACE(BUSY_E)) {
        delay = 1;
    }
    else if (ret != 0) {
        pr_err_ratelimited("libwolfssl: root DRBG reseed failed: %d\n", ret);
        /* A failed self-test waits for an operator: keep the usual period. */
        if (ret != WC_NO_ERR_TRACE(DRBG_SHA512_KAT_FIPS_E) &&
            ret != WC_NO_ERR_TRACE(FIPS_NOT_ALLOWED_E))
            delay = HZ / 10;
    }

    queue_delayed_work(system_highpri_wq, &rngRootWork, delay);
}

/* Start a root reseed now. */
static void RngKickRoot(void)
{
    if (rngReady)
        mod_delayed_work(system_highpri_wq, &rngRootWork, 0);
}

/* VM fork or hibernation resume: every DRBG state is suspect. */
static WC_MAYBE_UNUSED void RngInvalidate(void)
{
    wc_RNG_TreeInvalidate();
    RngKickRoot();
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

/* Fill dst from this CPU's leaf.  The task lane keeps its CPU with
 * preemption off, one chunk at a time. */
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

        if (lane == WC_RNG_TREE_LANE_TASK)
            preempt_disable();
        ret = wc_RNG_TreeGenerate(raw_smp_processor_id(), lane, addl,
                                  (word32)addlSz, dst, (word32)n);
        if (lane == WC_RNG_TREE_LANE_TASK)
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
    int ret;

    if (!rngReady)
        return -ENODEV;

    ret = RngFill(addl, addlSz, buf, len);
    while (ret != 0 && maySleep && wc_linuxkm_can_block() &&
           tries < RNG_MAX_TRIES) {
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
        ret = RngFill(addl, addlSz, buf, len);
        tries++;
    }

    if (ret != 0) {
        /* A stale root waits for this kick, not the next 60 s reseed.
         * Queueing work is not NMI safe. */
        if (ret == WC_NO_ERR_TRACE(NOT_READY_E) && !in_nmi())
            RngKickRoot();
        memzero_explicit(buf, len);
        return -EIO;
    }
    return 0;
}

/* crypto API stdrng: src is SP 800-90A additional input, as in crypto/drbg.c */
static int RngTfmGenerate(struct crypto_rng* tfm, const u8* src,
                          unsigned int slen, u8* dst, unsigned int dlen)
{
    (void)tfm;
    return RngGetBytesAddl(src, slen, dst, dlen, 1);
}

/* Only the root's entropy source seeds the tree. */
static int RngTfmSeed(struct crypto_rng* tfm, const u8* seed,
                      unsigned int slen)
{
    (void)tfm;
    (void)seed;
    if (slen != 0)
        return -EINVAL;
    return 0;
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

#if IS_ENABLED(CONFIG_VMGENID)
static int RngVmForkNotify(struct notifier_block* nb, unsigned long action,
                           void* data)
{
    (void)nb;
    (void)action;
    (void)data;
    RngInvalidate();
    return NOTIFY_OK;
}

static struct notifier_block rngVmForkNb = {
    .notifier_call = RngVmForkNotify
};
static int rngVmForkNbUp = 0;
#endif

#ifdef CONFIG_PM_SLEEP
/* Hibernation writes RNG state to disk; suspend to RAM does not. */
static int RngPmNotify(struct notifier_block* nb, unsigned long action,
                       void* data)
{
    (void)nb;
    (void)data;
    if (action == PM_POST_HIBERNATION || action == PM_POST_RESTORE)
        RngInvalidate();
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

/* getrandom() and /dev/urandom where random.c has get_random_bytes_user() */
static ssize_t RngGetBytesUser(struct iov_iter* iter)
{
    u8 block[RNG_TASK_CHUNK];
    size_t n, copied;
    size_t total = 0;
    int ret = 0;

    while (iov_iter_count(iter) > 0) {
        n = min_t(size_t, iov_iter_count(iter), sizeof(block));
        ret = RngGetBytesAddl(NULL, 0, block, n, 1);
        if (ret != 0)
            break;
        copied = copy_to_iter(block, n, iter);
        total += copied;
        if (copied != n || signal_pending(current))
            break;
        cond_resched();
    }
    ForceZero(block, sizeof(block));

    if (total > 0)
        return (ssize_t)total;
    if (ret != 0)
        return ret;
    return -EFAULT;
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
        ret = RngGetBytesAddl(NULL, 0, block, n, 1);
        if (ret != 0)
            break;
        copied = n - copy_to_user((u8 __user*)buf + total, block, n);
        total += copied;
        if (copied != n || signal_pending(current))
            break;
        cond_resched();
    }
    ForceZero(block, sizeof(block));

    if (total > 0)
        return (ssize_t)total;
    if (ret != 0)
        return ret;
    return -EFAULT;
}

/* The tree takes no outside input: the root reads only its entropy source. */
static int RngMixPoolBytes(const void* buf, size_t len)
{
    (void)buf;
    (void)len;
    return 0;
}

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

static void RngStop(void)
{
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
    rngReady = 0;
    cancel_delayed_work_sync(&rngRootWork);
    if (wc_RNG_TreeZeroize() != 0)
        pr_err("ERROR: wc_RNG_TreeZeroize() could not zeroize every DRBG.\n");
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

static int wc_linuxkm_drbg_startup(void)
{
    int ret;

    if (wc_linuxkm_drbg_loaded)
        return -EBUSY;

    ret = wc_RNG_TreeInit((int)nr_cpu_ids, NULL);
    if (ret != 0) {
        pr_err("ERROR: wc_RNG_TreeInit() failed: %d\n", ret);
        return -ECANCELED;
    }
    INIT_DELAYED_WORK(&rngRootWork, RngRootWork);
    rngReady = 1;

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
        if (WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt) !=
                RNG_UNHELD_REFCNT) {
            rngUnregistered = 1;
            wc_linuxkm_drbg_loaded = 1;
            return ret;
        }
        RngStop();
        return ret;
    }

    queue_delayed_work(system_highpri_wq, &rngRootWork, RNG_ROOT_DELAY);
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
    wc_linuxkm_drbg_loaded = 1;
    WOLFKM_INSTALL_NOTICE(wc_linuxkm_drbg);

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    ret = RngTakeOver();
    if (ret != 0)
        return ret;
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
    /* Unregistered, the count only drops: to RNG_UNHELD_REFCNT once the last
     * user frees its tfm. */
    ret = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);
    if (ret != RNG_UNHELD_REFCNT) {
        pr_err("ERROR: wc_linuxkm_drbg still held, refcnt %d\n", ret);
        return -EBUSY;
    }

    RngStop();
    rngUnregistered = 0;
    wc_linuxkm_drbg_loaded = 0;
    return 0;
}

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG && WC_RNG_TREE */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
