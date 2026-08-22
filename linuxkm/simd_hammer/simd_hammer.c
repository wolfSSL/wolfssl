/* simd_hammer.c -- stress testing for kernel FPU/SIMD context handling
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
 * simd_hammer -- simulate a heavy multithreaded kernel workload to test SIMD
 * handling in libwolfssl.ko.
 *
 * Hammer modes (per-CPU pinned kthreads):
 *   hammer_mode=wolfcrypt  sync-skcipher traffic through the LKCAPI.
 *                          NOTE: wolfSSL's SVR glue brackets its own FPU
 *                          sections with local_bh_disable(), so this mode
 *                          doesn't create softirq-visible collisions -- it
 *                          exists to demonstrate that fact, and to measure
 *                          probe lateness (softirq blackout) caused by
 *                          bh-disabled crypto sections.
 *   hammer_mode=rawfpu     bare kernel_fpu_begin()/udelay/kernel_fpu_end()
 *                          sections, emulating foreign FPU users (raid6,
 *                          ZFS, other crypto modules).  On pre-6.15 kernels
 *                          these sections are softirq-interruptible, so the
 *                          probe collides with them at rate ~= HZ x duty.
 *                          On 6.15+ kernel_fpu_begin() itself disables bh
 *                          (commit d02198550423) and the collision class is
 *                          structurally extinct -- expect zero, on any build.
 *
 * Probe contexts (per-CPU, pinned):
 *   probe_ctx=softirq      TIMER_SOFTIRQ (timer_list) -- ESP-receive-class.
 *   probe_ctx=hardirq      hrtimer in hard-interrupt context -- emulates
 *                          get_random_bytes()-from-irq-handler-class callers.
 *
 * Each probe samples may_use_simd() at entry (the interrupted context is
 * frozen underneath, so the sample holds for the whole call), then performs
 * a sync shash digest through the LKCAPI and records the result.  Against a
 * with-fallback module: !simd probes succeed via the C path (errs stays 0).
 * Against a no-fallback module: !simd probes fail (errs tracks no_simd, and
 * last_err records the mapped errno).
 *
 * Lateness stats: scheduled-vs-actual delta per probe, reported avg/max.
 * Under bh-disabled crypto sections, softirq probes are deferred until
 * local_bh_enable(); lateness quantifies that blackout.
 *
 * Note that the test is x86-only, non-PREEMPT_RT, with no CPU-hotplug handling.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/cpumask.h>
#include <linux/scatterlist.h>
#include <linux/smp.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/version.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/rng.h>
#include <asm/simd.h>
#include <asm/fpu/api.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
    /* self-rearm is gated on c->stop, so plain del_timer_sync is safe here */
    #define timer_shutdown_sync(t) del_timer_sync(t)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
    #define wc_simd_timer_container_of(var, t, field) timer_container_of(var, t, field)
#else
    #define wc_simd_timer_container_of(var, t, field) from_timer(var, t, field)
#endif

/* sidestep "flush-left function calls" warnings from check-source-text: */
#define MODULE_PARAM module_param

static char *hammer_mode = "rawfpu";
MODULE_PARAM(hammer_mode, charp, 0444);
MODULE_PARM_DESC(hammer_mode, "\"rawfpu\" (foreign-FPU-user emulation) or \"wolfcrypt\"");

static char *hammer_alg = "xts-aes-wolfcrypt";
MODULE_PARAM(hammer_alg, charp, 0444);
MODULE_PARM_DESC(hammer_alg, "sync skcipher driver name (hammer_mode=wolfcrypt)");

static unsigned int hammer_keylen = 64;
MODULE_PARAM(hammer_keylen, uint, 0444);

static unsigned int hammer_bytes = 64 * 1024;
MODULE_PARAM(hammer_bytes, uint, 0444);
MODULE_PARM_DESC(hammer_bytes, "bytes per wolfcrypt hammer op");

static unsigned int raw_section_us = 200;
MODULE_PARAM(raw_section_us, uint, 0444);
MODULE_PARM_DESC(raw_section_us, "kernel_fpu section length, us (hammer_mode=rawfpu)");

static unsigned int hammer_pause_us;
MODULE_PARAM(hammer_pause_us, uint, 0444);
MODULE_PARM_DESC(hammer_pause_us, "sleep between hammer ops (duty throttle; 0 = flat out)");

static char *probe_ctx = "softirq";
MODULE_PARAM(probe_ctx, charp, 0444);
MODULE_PARM_DESC(probe_ctx, "\"softirq\" (timer_list) or \"hardirq\" (hrtimer)");

static char *probe_alg = "sha256";
MODULE_PARAM(probe_alg, charp, 0444);
MODULE_PARM_DESC(probe_alg, "sync shash driver name for the probe");

static char *probe_kind = "shash";
MODULE_PARAM(probe_kind, charp, 0444);
MODULE_PARM_DESC(probe_kind,
                 "\"shash\" (probe_alg digest), \"rng\" (crypto_rng_get_bytes "
                 "on probe_alg, e.g. probe_alg=stdrng), or \"grb\" "
                 "(get_random_bytes, the kernel randomness path)");

static unsigned int probe_bytes = 4096;
MODULE_PARAM(probe_bytes, uint, 0444);

static unsigned int probe_interval = 1;
MODULE_PARAM(probe_interval, uint, 0444);
MODULE_PARM_DESC(probe_interval, "probe period in jiffies (both contexts)");

static unsigned int report_secs = 10;
MODULE_PARAM(report_secs, uint, 0444);

#define WC_SIMD_MAX_DIGEST 64

struct wc_simd_pcpu {
    int                     cpu;
    struct task_struct     *hammer;
    bool                    hammer_failed;
    struct timer_list       probe_timer;
    struct hrtimer          probe_hrtimer;
    ktime_t                 hr_period;
    bool                    timer_live;
    bool                    hrtimer_live;
    struct shash_desc      *desc;
    u8                     *pbuf;
    u8                      digest[WC_SIMD_MAX_DIGEST];
    bool                    stop;
    /* counters: written only by the respective CPUs' probe / hammer contexts */
    unsigned long           probes;
    unsigned long           simd_ok;
    unsigned long           no_simd;
    unsigned long           errs;
    int                     last_err;
    u64                     late_sum_us;
    u64                     late_max_us;
    /* Duration of the probe call itself.  Lateness says the probe was
     * delayed getting in; this says how long it took once inside, which is
     * what an unbounded wait or a long IRQs-off section actually looks
     * like.  A call that stalls and then succeeds is invisible to a
     * success count and obvious here. */
    u64                     dur_sum_ns;
    u64                     dur_max_ns;
};

static struct wc_simd_pcpu     *wc_simd_pc;
static struct crypto_shash *wc_simd_probe_tfm;
static struct crypto_rng   *wc_simd_probe_rng;
static struct task_struct  *wc_simd_report_task;
static bool                 wc_simd_raw_mode;
static bool                 wc_simd_hardirq_probe;

enum wc_simd_probe_kind {
    WC_SIMD_PROBE_SHASH = 0,
    WC_SIMD_PROBE_RNG,
    WC_SIMD_PROBE_GRB
};
static enum wc_simd_probe_kind wc_simd_probe_kind;

/* ---------------- probe core (any context) ---------------- */

static void wc_simd_probe_once(struct wc_simd_pcpu *c, u64 late_us)
{
    bool simd = may_use_simd();
    int ret;

    c->probes++;
    if (simd)
        c->simd_ok++;
    else
        c->no_simd++;

    c->late_sum_us += late_us;
    if (late_us > c->late_max_us)
        c->late_max_us = late_us;

    {
        u64 t0 = ktime_get_ns(), dur;

        switch (wc_simd_probe_kind) {
        case WC_SIMD_PROBE_RNG:
            /* Exercises the registered stdrng, i.e. wolfCrypt's DRBG when
             * the module is loaded at higher cra_priority. */
            ret = crypto_rng_get_bytes(wc_simd_probe_rng, c->pbuf, probe_bytes);
            break;
        case WC_SIMD_PROBE_GRB:
            /* Exercises the kernel randomness path itself, including any
             * get_random_bytes hook the module under test installs. */
            get_random_bytes(c->pbuf, probe_bytes);
            ret = 0;
            break;
        case WC_SIMD_PROBE_SHASH:
        default:
            ret = crypto_shash_digest(c->desc, c->pbuf, probe_bytes, c->digest);
            break;
        }

        dur = ktime_get_ns() - t0;
        c->dur_sum_ns += dur;
        if (dur > c->dur_max_ns)
            c->dur_max_ns = dur;
    }

    if (unlikely(ret)) {
        c->errs++;
        c->last_err = ret;
    }
}

/* ---------------- softirq probe (timer_list) ---------------- */

static void wc_simd_probe_timer_fn(struct timer_list *t)
{
    struct wc_simd_pcpu *c = wc_simd_timer_container_of(c, t, probe_timer);
    unsigned long sched_for = t->expires;
    u64 late_us = (u64)jiffies_to_usecs(jiffies - sched_for);

    wc_simd_probe_once(c, late_us);

    if (!READ_ONCE(c->stop))
        mod_timer(&c->probe_timer, jiffies + probe_interval);
}

/* ---------------- hardirq probe (hrtimer) ---------------- */

static enum hrtimer_restart wc_simd_probe_hrtimer_fn(struct hrtimer *t)
{
    struct wc_simd_pcpu *c = container_of(t, struct wc_simd_pcpu, probe_hrtimer);
    s64 late_ns = ktime_to_ns(ktime_sub(ktime_get(), hrtimer_get_expires(t)));

    wc_simd_probe_once(c, late_ns > 0 ? (u64)late_ns / 1000 : 0);

    if (READ_ONCE(c->stop))
        return HRTIMER_NORESTART;
    hrtimer_forward_now(t, c->hr_period);
    return HRTIMER_RESTART;
}

static void wc_simd_start_hrtimer_on_cpu(void *arg)
{
    struct wc_simd_pcpu *c = arg;

    hrtimer_start(&c->probe_hrtimer, c->hr_period, HRTIMER_MODE_REL_PINNED);
}

/* ---------------- hammers ---------------- */

/* Foreign-FPU-SIMD-user emulation: simulate workload from other modules that
 * use vector and FP registers wrapped in kernel_fpu_{begin,end}():
 *
 * raid6_pq -- vectorized RAID-6 P/Q parity calculation
 *
 * crc32c-intel / crc32-pclmul / crct10dif-pclmul -- ext4/btrfs metadata
 *     checksums, iSCSI and NVMe-TCP data digests, T10-DIF generation
 *
 * xor_blocks -- vectorized MD RAID5 parity and btrfs raid56
 *
 * EFI runtime services -- efi_fpu_begin() wraps every efi_call
 *
 * chacha20, poly1305, curve25519, etc. -- non-FIPS vectorized crypto
 *     implementations used by WireGuard etc.
 *
 * cached tfm handles bound to built-in vectorized implementations at kernel
 *     init -- IMA/EVM measurement hashes (in-tree vectorized SHA-256)
 *
 * Native accelerated FIPS-algorithm crypto implementations -- aesni-intel,
 *     sha*-ssse3/SHA-NI, ghash-clmulni, etc. -- these can be requested
 *     explicitly from both kernel and user (AF_ALG) space, bypassing algorithm
 *     priority, and inducing contention.  Raw GHASH in particular has no public
 *     support in wolfCrypt, hence no driver, so its vectorized in-tree
 *     implementations remain the sole accelerated providers for any
 *     ghash/gcm_base composition.
 *
 *******************************************************************************
 *
 * On 6.15+ kernels, kernel_fpu_begin() itself disables bh, precluding this
 * contention in practice, if not in principle.  Hard IRQs remain subject to
 * SIMD disablement, but no in-tree hard IRQ handlers call into the LKCAPI.
 *
 * On pre-6.15, crypto users are preempt-disabled but softirq-interruptible;
 *     impacted softirq handlers encounter SIMD-forbidden contexts.  This can be
 *     mitigated by backporting kernel commit d02198550423.
 *
 * On all kernels, LINUXKM_DRBG_GET_RANDOM_BYTES is subject to SIMD disablement,
 * as it is called from hard IRQ contexts, wherein SAVE_VECTOR_REGISTERS*()
 * always returns WC_ACCEL_INHIBIT_E.
 */

static int wc_simd_hammer_raw_fn(void *arg)
{
    (void)arg;

    while (!kthread_should_stop()) {
        kernel_fpu_begin();
        udelay(raw_section_us);
        kernel_fpu_end();

        if (hammer_pause_us)
            usleep_range(hammer_pause_us, hammer_pause_us + hammer_pause_us / 8 + 1);
        else
            cond_resched();
    }
    return 0;
}

static int wc_simd_hammer_wc_fn(void *arg)
{
    struct wc_simd_pcpu *c = arg;
    struct crypto_sync_skcipher *tfm = NULL;
    u8 *buf = NULL;
    u8 key[64];
    u8 iv[16];
    struct scatterlist sg;
    int ret;

    if (hammer_keylen > sizeof(key)) {
        pr_err("ERROR: %s: hammer_keylen %u > %zu\n", __func__, hammer_keylen, sizeof(key));
        goto fail_idle;
    }

    tfm = crypto_alloc_sync_skcipher(hammer_alg, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("ERROR: %s: cpu%d: crypto_alloc_sync_skcipher(\"%s\") = %ld "
               "(is the module under test loaded? check /proc/crypto)\n",
               __func__, c->cpu, hammer_alg, PTR_ERR(tfm));
        tfm = NULL;
        goto fail_idle;
    }

    get_random_bytes(key, hammer_keylen);
    ret = crypto_sync_skcipher_setkey(tfm, key, hammer_keylen);
    memzero_explicit(key, sizeof(key));
    if (ret) {
        pr_err("ERROR: %s: cpu%d: setkey(%u) = %d\n", __func__, c->cpu, hammer_keylen, ret);
        goto fail_idle;
    }

    buf = kmalloc(hammer_bytes, GFP_KERNEL);
    if (!buf) {
        pr_err("ERROR: %s: cpu%d: kmalloc(%u) failed\n", __func__, c->cpu, hammer_bytes);
        goto fail_idle;
    }
    get_random_bytes(buf, hammer_bytes);
    get_random_bytes(iv, sizeof(iv));

    while (!kthread_should_stop()) {
        SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

        sg_init_one(&sg, buf, hammer_bytes);
        skcipher_request_set_sync_tfm(req, tfm);
        skcipher_request_set_callback(req, 0, NULL, NULL);
        skcipher_request_set_crypt(req, &sg, &sg, hammer_bytes, iv);

        ret = crypto_skcipher_encrypt(req);
        skcipher_request_zero(req);
        if (unlikely(ret)) {
            c->errs++;
            c->last_err = ret;
        }

        if (hammer_pause_us)
            usleep_range(hammer_pause_us, hammer_pause_us + hammer_pause_us / 8 + 1);
        else
            cond_resched();
    }
    goto out;

fail_idle:
    c->hammer_failed = true;
    while (!kthread_should_stop())
        schedule_timeout_interruptible(HZ);
out:
    kfree(buf);
    if (tfm)
        crypto_free_sync_skcipher(tfm);
    return 0;
}

/* ---------------- reporting ---------------- */

struct wc_simd_totals {
    unsigned long p, s, n, e;
    u64 late_sum, late_max;
    u64 dur_sum, dur_max;
    int last_err;
    bool failed;
};

static void wc_simd_sum(struct wc_simd_totals *t)
{
    int cpu;

    memset(t, 0, sizeof(*t));
    for_each_online_cpu(cpu) {
        struct wc_simd_pcpu *c = &wc_simd_pc[cpu];
        u64 lm = READ_ONCE(c->late_max_us);
        int le = READ_ONCE(c->last_err);

        t->p += READ_ONCE(c->probes);
        t->s += READ_ONCE(c->simd_ok);
        t->n += READ_ONCE(c->no_simd);
        t->e += READ_ONCE(c->errs);
        t->late_sum += READ_ONCE(c->late_sum_us);
        if (lm > t->late_max)
            t->late_max = lm;
        t->dur_sum += READ_ONCE(c->dur_sum_ns);
        {
            u64 dm = READ_ONCE(c->dur_max_ns);

            if (dm > t->dur_max)
                t->dur_max = dm;
        }
        if (le)
            t->last_err = le;
        t->failed |= READ_ONCE(c->hammer_failed);
    }
}

static int wc_simd_report_fn(void *unused)
{
    unsigned long last_p = 0, last_n = 0, last_e = 0;

    while (!kthread_should_stop()) {
        struct wc_simd_totals t;
        unsigned long dp, dn, de, n_per_min_x100, e_per_min_x100;
        u64 late_avg, dur_avg;

        schedule_timeout_interruptible(report_secs * HZ);
        if (kthread_should_stop())
            break;

        wc_simd_sum(&t);
        dp = t.p - last_p;
        dn = t.n - last_n;
        de = t.e - last_e;
        last_p = t.p;
        last_n = t.n;
        last_e = t.e;
        n_per_min_x100 = report_secs ? (dn * 6000UL) / report_secs : 0;
        e_per_min_x100 = report_secs ? (de * 6000UL) / report_secs : 0;
        late_avg = t.p ? div64_u64(t.late_sum, t.p) : 0;
        dur_avg = t.p ? div64_u64(t.dur_sum, t.p) : 0;

        pr_info("simd_hammer summary: probes=%lu simd=%lu NO_SIMD=%lu ERRS=%lu(last=%d) "
                "late avg=%lluus max=%lluus dur avg=%lluns max=%lluns | "
                "last %us: +%lu NO_SIMD (%lu.%02lu/min), "
                "+%lu ERRS (%lu.%02lu/min)%s\n",
                t.p, t.s, t.n, t.e, t.last_err,
                late_avg, t.late_max, dur_avg, t.dur_max, report_secs,
                dn, n_per_min_x100 / 100, n_per_min_x100 % 100,
                de, e_per_min_x100 / 100, e_per_min_x100 % 100,
                t.failed ? " [HAMMER FAILED on >=1 cpu]" : "");
    }
    return 0;
}

/* ---------------- init / exit ---------------- */

static void wc_simd_teardown(void)
{
    int cpu;

    if (wc_simd_report_task) {
        kthread_stop(wc_simd_report_task);
        wc_simd_report_task = NULL;
    }

    if (wc_simd_pc) {
        for_each_online_cpu(cpu)
            WRITE_ONCE(wc_simd_pc[cpu].stop, true);

        for_each_online_cpu(cpu) {
            struct wc_simd_pcpu *c = &wc_simd_pc[cpu];

            if (c->timer_live) {
                timer_shutdown_sync(&c->probe_timer);
                c->timer_live = false;
            }
            if (c->hrtimer_live) {
                hrtimer_cancel(&c->probe_hrtimer);
                c->hrtimer_live = false;
            }
        }
        for_each_online_cpu(cpu) {
            struct wc_simd_pcpu *c = &wc_simd_pc[cpu];

            if (c->hammer) {
                kthread_stop(c->hammer);
                c->hammer = NULL;
            }
            kfree(c->desc);
            kfree(c->pbuf);
        }
        kfree(wc_simd_pc);
        wc_simd_pc = NULL;
    }

    if (wc_simd_probe_tfm) {
        crypto_free_shash(wc_simd_probe_tfm);
        wc_simd_probe_tfm = NULL;
    }

    if (wc_simd_probe_rng) {
        crypto_free_rng(wc_simd_probe_rng);
        wc_simd_probe_rng = NULL;
    }
}

static int __init wc_simd_init(void)
{
    int cpu, ret;
    int (*hammer_fn)(void *);

    if (!probe_bytes || !probe_interval)
        return -EINVAL;

    if (!strcmp(hammer_mode, "rawfpu")) {
        wc_simd_raw_mode = true;
        hammer_fn = wc_simd_hammer_raw_fn;
        if (!raw_section_us || raw_section_us > 1000) {
            pr_err("ERROR: %s: raw_section_us must be 1..1000\n", __func__);
            return -EINVAL;
        }
    } else if (!strcmp(hammer_mode, "wolfcrypt")) {
        wc_simd_raw_mode = false;
        hammer_fn = wc_simd_hammer_wc_fn;
        if (!hammer_bytes)
            return -EINVAL;
    } else {
        pr_err("ERROR: %s: hammer_mode must be \"rawfpu\" or \"wolfcrypt\"\n", __func__);
        return -EINVAL;
    }

    if (!strcmp(probe_ctx, "hardirq"))
        wc_simd_hardirq_probe = true;
    else if (!strcmp(probe_ctx, "softirq"))
        wc_simd_hardirq_probe = false;
    else {
        pr_err("ERROR: %s: probe_ctx must be \"softirq\" or \"hardirq\"\n", __func__);
        return -EINVAL;
    }

    if (!strcmp(probe_kind, "shash"))
        wc_simd_probe_kind = WC_SIMD_PROBE_SHASH;
    else if (!strcmp(probe_kind, "rng"))
        wc_simd_probe_kind = WC_SIMD_PROBE_RNG;
    else if (!strcmp(probe_kind, "grb"))
        wc_simd_probe_kind = WC_SIMD_PROBE_GRB;
    else {
        pr_err("ERROR: %s: probe_kind must be \"shash\", \"rng\" or \"grb\"\n",
               __func__);
        return -EINVAL;
    }

    if (wc_simd_probe_kind == WC_SIMD_PROBE_SHASH) {
        wc_simd_probe_tfm = crypto_alloc_shash(probe_alg, 0, 0);
        if (IS_ERR(wc_simd_probe_tfm)) {
            ret = PTR_ERR(wc_simd_probe_tfm);
            wc_simd_probe_tfm = NULL;
            pr_err("ERROR: %s: crypto_alloc_shash(\"%s\") = %d "
                   "(is the module under test loaded? check /proc/crypto)\n",
                   __func__, probe_alg, ret);
            return ret;
        }
        if (crypto_shash_digestsize(wc_simd_probe_tfm) > WC_SIMD_MAX_DIGEST) {
            ret = -EINVAL;
            goto err;
        }
    } else if (wc_simd_probe_kind == WC_SIMD_PROBE_RNG) {
        /* ONE shared tfm for every CPU, deliberately.  A tfm per CPU would
         * hand each probe its own private DRBG and measure nothing about
         * the shared path under test. */
        wc_simd_probe_rng = crypto_alloc_rng(probe_alg, 0, 0);
        if (IS_ERR(wc_simd_probe_rng)) {
            ret = PTR_ERR(wc_simd_probe_rng);
            wc_simd_probe_rng = NULL;
            pr_err("ERROR: %s: crypto_alloc_rng(\"%s\") = %d "
                   "(is the module under test loaded? check /proc/crypto)\n",
                   __func__, probe_alg, ret);
            return ret;
        }
    }

    wc_simd_pc = kcalloc(nr_cpu_ids, sizeof(*wc_simd_pc), GFP_KERNEL);
    if (!wc_simd_pc) {
        ret = -ENOMEM;
        goto err;
    }

    for_each_online_cpu(cpu) {
        struct wc_simd_pcpu *c = &wc_simd_pc[cpu];

        c->cpu = cpu;

        c->pbuf = kmalloc(probe_bytes, GFP_KERNEL);
        if (!c->pbuf) {
            ret = -ENOMEM;
            goto err;
        }
        get_random_bytes(c->pbuf, probe_bytes);

        if (wc_simd_probe_kind == WC_SIMD_PROBE_SHASH) {
            c->desc = kmalloc(sizeof(*c->desc) +
                              crypto_shash_descsize(wc_simd_probe_tfm),
                              GFP_KERNEL);
            if (!c->desc) {
                ret = -ENOMEM;
                goto err;
            }
            c->desc->tfm = wc_simd_probe_tfm;
        }

        c->hammer = kthread_create(hammer_fn, c, "wc_simd_hammer/%d", cpu);
        if (IS_ERR(c->hammer)) {
            ret = PTR_ERR(c->hammer);
            c->hammer = NULL;
            goto err;
        }
        kthread_bind(c->hammer, cpu);
        wake_up_process(c->hammer);

        if (wc_simd_hardirq_probe) {
            c->hr_period = ns_to_ktime((u64)jiffies_to_usecs(probe_interval)
                                       * NSEC_PER_USEC);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
            hrtimer_setup(&c->probe_hrtimer, wc_simd_probe_hrtimer_fn,
                          CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
#else
            hrtimer_init(&c->probe_hrtimer, CLOCK_MONOTONIC,
                         HRTIMER_MODE_REL_PINNED);
            c->probe_hrtimer.function = wc_simd_probe_hrtimer_fn;
#endif
            ret = smp_call_function_single(cpu, wc_simd_start_hrtimer_on_cpu, c, 1);
            if (ret)
                goto err;
            c->hrtimer_live = true;
        } else {
            timer_setup(&c->probe_timer, wc_simd_probe_timer_fn, TIMER_PINNED);
            c->probe_timer.expires = jiffies + probe_interval;
            add_timer_on(&c->probe_timer, cpu);
            c->timer_live = true;
        }
    }

    wc_simd_report_task = kthread_run(wc_simd_report_fn, NULL, "wc_simd_report");
    if (IS_ERR(wc_simd_report_task)) {
        ret = PTR_ERR(wc_simd_report_task);
        wc_simd_report_task = NULL;
        goto err;
    }

    pr_info("simd_hammer loaded: hammer=%s%s%s probe=%s:%s(%s) %u B every %u jiffies, "
            "%u cpus, HZ=%d\n",
            hammer_mode,
            wc_simd_raw_mode ? "" : " alg=", wc_simd_raw_mode ? "" : hammer_alg,
            probe_kind, probe_alg, probe_ctx, probe_bytes, probe_interval,
            num_online_cpus(), HZ);
    return 0;

err:
    wc_simd_teardown();
    return ret;
}

static void __exit wc_simd_exit(void)
{
    struct wc_simd_totals t;

    wc_simd_sum(&t);
    wc_simd_teardown();
    pr_info("simd_hammer unloaded: final probes=%lu simd=%lu NO_SIMD=%lu ERRS=%lu "
            "(last=%d) late max=%lluus dur max=%lluns\n",
            t.p, t.s, t.n, t.e, t.last_err, t.late_max, t.dur_max);
}

module_init(wc_simd_init);
module_exit(wc_simd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("!may_use_simd() collision generator + fallback-vs-error discriminator for wolfCrypt LKCAPI");
