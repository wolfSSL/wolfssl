/* module_hooks.c -- module load/unload hooks for libwolfssl.ko
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

#define WOLFSSL_LINUXKM_NEED_LINUX_CURRENT

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifndef WOLFSSL_LICENSE
    #define WOLFSSL_LICENSE "GPL"
#endif

#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif
#ifdef HAVE_FIPS
    #ifdef USE_CONTESTMUTEX
        #error USE_CONTESTMUTEX is incompatible with WOLFSSL_LINUXKM
    #endif
    #ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
        #include <wolfssl/wolfcrypt/hmac.h>
    #endif
    #include <wolfssl/wolfcrypt/fips_test.h>
    #if defined(WOLFSSL_FIPS_DEV_NO_POST) && !defined(WC_USE_PIE_FENCEPOSTS_FOR_FIPS)
        #define WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    #endif
#endif
#if !defined(NO_CRYPT_TEST) || defined(LINUXKM_LKCAPI_REGISTER)
    #include <wolfcrypt/test/test.h>
#endif
#ifdef HAVE_ENTROPY_MEMUSE
    #include <wolfssl/wolfcrypt/wolfentropy.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#ifdef LINUXKM_RBGC
    #include <wolfssl/wolfcrypt/linuxkm_get_entropy.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
    enum linux_errcodes {
        my_EINVAL = EINVAL,
        my_ENOMEM = ENOMEM,
        my_EBADMSG = EBADMSG
    };

    #undef EINVAL
    #undef ENOMEM
    #undef EBADMSG

    #define EINVAL WC_ERR_TRACE(my_EINVAL)
    #define ENOMEM WC_ERR_TRACE(my_ENOMEM)
    #define EBADMSG WC_ERR_TRACE(my_EBADMSG)
#endif

static int libwolfssl_cleanup(void) {
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0)
        pr_err("ERROR: wolfCrypt_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("ERROR: wolfSSL_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#endif

    return ret;
}

#if defined(HAVE_FIPS) && !defined(WOLFSSL_FIPS_DEV_NO_POST)
    /* failsafe definitions for FIPS <5.3 */
    #ifndef FIPS_IN_CORE_DIGEST_SIZE
        #ifndef NO_SHA256
            #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
            #define FIPS_IN_CORE_HASH_TYPE   WC_SHA256
        #elif defined(WOLFSSL_SHA384)
            #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA384_DIGEST_SIZE
            #define FIPS_IN_CORE_HASH_TYPE   WC_SHA384
        #else
            #error Unsupported FIPS hash alg.
        #endif
    #endif

    #ifndef FIPS_IN_CORE_KEY_SZ
        #define FIPS_IN_CORE_KEY_SZ FIPS_IN_CORE_DIGEST_SIZE
    #endif
    #ifndef FIPS_IN_CORE_VERIFY_SZ
        #define FIPS_IN_CORE_VERIFY_SZ FIPS_IN_CORE_DIGEST_SIZE
    #endif

    #if FIPS_VERSION3_GE(6,0,0) || defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE)
        extern char verifyCore[FIPS_IN_CORE_DIGEST_SIZE*2 + 1];
    #endif
#endif

#ifdef WC_SYM_RELOC_TABLES

#ifdef DEBUG_LINUXKM_PIE_SUPPORT

/* cheap portable ad-hoc hash function to confirm bitwise stability of the PIE
 * binary image.
 */
static unsigned int hash_span(const u8 *start, const u8 *end, unsigned int sum) {
    WC_SANITIZE_DISABLE();
    while (start < end) {
        unsigned int rotate_by;
        sum ^= *start++;
        rotate_by = (sum ^ (sum >> 5)) & 31;
        sum = (sum << rotate_by) | (sum >> (32 - rotate_by));
    }
    WC_SANITIZE_ENABLE();
    return sum;
}

struct wc_reloc_counts reloc_counts = {};

#endif /* DEBUG_LINUXKM_PIE_SUPPORT */

static int set_up_wolfssl_linuxkm_pie_redirect_table(void);

#ifdef HAVE_FIPS
extern const unsigned int wolfCrypt_FIPS_ro_start[];
extern const unsigned int wolfCrypt_FIPS_ro_end[];
#endif

#endif /* WC_SYM_RELOC_TABLES */

#ifdef HAVE_FIPS
static void lkmFipsCb(int ok, int err, const char* hash)
{
    if ((! ok) || (err != 0))
        pr_err("ERROR: libwolfssl FIPS error: %s\n", wc_GetErrorString(err));
    if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
        if (hash) {
            pr_err("In-core integrity hash check failure.\n"
                   "Update FIPS hash with \"make module-update-fips-hash FIPS_HASH=%s\".\n",
                   hash);
        }
        else {
            pr_err("In-core integrity hash check failure.\n");
            pr_err("ERROR: could not compute new hash.  Contact customer support.\n");
        }
    }
}

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
static int updateFipsHash(void);
#endif
#endif /* HAVE_FIPS */

#ifdef WOLFSSL_LINUXKM_BENCHMARKS
extern int wolfcrypt_benchmark_main(int argc, char** argv);
#endif /* WOLFSSL_LINUXKM_BENCHMARKS */

#ifndef WOLFSSL_LINUXKM_USE_MUTEXES
#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
/* Defined in linuxkm/x86_vector_register_glue.c, which is #included further
 * down this same translation unit.  Declared here so the lock primitive can
 * consult it; static so it adds nothing to the module's exported surface. */
static int wc_linuxkm_in_svr_bracket(void);
#endif

int wc_lkm_LockMutex(wolfSSL_Mutex* m)
{
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    if ((m == NULL) || (m->magic != WC_LINUXKM_SPINLOCK_MAGIC))
        return BAD_FUNC_ARG;
#endif
    /* spin_lock_bh() is the whole implementation.  There was previously a
     * hand-rolled acquire loop here, spin_trylock_irqsave(), then either
     * spin_lock_irqsave() or a retry loop calling cond_resched(), selected
     * by "irq_count() != 0".  That is wrong twice over:
     *
     *  - irq_count() is (preempt_count() & (NMI_MASK|HARDIRQ_MASK|SOFTIRQ_MASK))
     *    (include/linux/preempt.h).  It does not observe PREEMPT_MASK and does
     *    not observe irqs_disabled(), so it reads 0 for a task that is holding
     *    a spinlock or running with interrupts off.  The loop would then call
     *    cond_resched(), which may sleep, from atomic context.  The
     *    kernel's own "may I sleep here" predicate is preemptible(); this
     *    module already spells it correctly in wc_linuxkm_can_block().
     *  - A lock does not need a hand-rolled wait at all.  spin_lock_bh() is
     *    the kernel's mechanism for "contend for a lock that a bottom half
     *    also takes", and it queues fairly (qspinlock) instead of spinning on
     *    trylock.
     */
    /* Refuse the contexts spin_lock_bh() is not legal in, rather than taking
     * it and letting the kernel complain.
     *
     * spin_lock_bh()/spin_unlock_bh() reach __local_bh_disable_ip() and
     * __local_bh_enable_ip(), which open with WARN_ON_ONCE(in_hardirq()) and
     * lockdep_assert_irqs_enabled() (kernel/softirq.c, in BOTH the RT and
     * non-RT definitions).  So a hardirq, NMI, or IRQs-disabled caller was
     * never a working path here, it was an undiagnosed WARN, and on a kernel
     * without CONFIG_PROVE_LOCKING the IRQs-off case was silent, because
     * __local_bh_enable_ip() calls do_softirq(), whose handler loop runs
     * local_irq_enable() and hands the caller back its interrupts re-enabled.
     * Returning an error instead makes it diagnosable and propagable.
     *
     * This is the same predicate wc_save_vector_registers_x86() already
     * applies, so the lock and the FPU bracket now agree about which contexts
     * this module serves.  It matches the kernel's own contract for its crypto
     * API, Documentation/crypto/api-intro.rst: "cryptographic methods may
     * only be called from softirq and user contexts", and the enforcement
     * upstream uses for the same rule, crypto/skcipher.c's
     * "if (WARN_ON_ONCE(in_hardirq())) return -EDEADLK;".
     *
     * Softirq is deliberately NOT refused: the DRBG and hash paths are
     * genuinely entered from softirq, and spin_lock_bh() is exactly the
     * primitive for data shared between process and softirq context. */
    if (in_hardirq() || in_nmi() || irqs_disabled()) {
        /* Diagnosable on purpose.  irqs_disabled() is broader than the
         * in_hardirq() rule cited above, so a caller that merely wrapped a
         * crypto call in local_irq_save() is refused with no other symptom
         * than a failing hash.  Rate-limited, like the bracket check below. */
        pr_err_once("BUG: wc_LockMutex() called with IRQs off on CPU %d"
                    " (hardirq=%d nmi=%d) -- refusing, this is an atomic"
                    " region.\n",
                    raw_smp_processor_id(), (int)in_hardirq(), (int)in_nmi());
        return BAD_STATE_E;
    }

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
    /* A wolfSSL_Mutex may be HELD ACROSS a SAVE_VECTOR_REGISTERS() bracket.
     * It may never be TAKEN INSIDE one.
     *
     * Inside a bracket the module is in a truly atomic region on every
     * configuration, kernel_fpu_begin_mask() calls preempt_disable()
     * unconditionally (arch/x86/kernel/fpu/core.c), and this module adds
     * local_bh_disable() plus, on PREEMPT_RT, its own preempt_disable().  On
     * PREEMPT_RT spin_lock_bh() reaches rt_spin_lock(), an rt_mutex that
     * BLOCKS (kernel/locking/spinlock_rt.c), so taking one there is
     * "scheduling while atomic".  Documentation/locking/locktypes.rst states
     * the rule directly: sleeping lock types cannot nest inside spinning ones,
     * and PREEMPT_RT moves spinlock_t into the sleeping category.
     *
     * Upstream does not solve this with a different lock, a sweep of the
     * whole kernel finds no lock acquisition inside any kernel_fpu_begin() /
     * kernel_neon_begin() section at all.  It uses per-CPU or per-request
     * state, or closes the section first.
     *
     * This check is the module's own enforcement, keyed on the bracket depth
     * this file already maintains rather than on preempt_count(), so it is
     * exact and fires on non-RT too, meaning the existing lockdep operating
     * environment catches a regression without needing an RT kernel.
     *
     * FATAL.  This was diagnostic-only while the SP fixed-point ECC cache
     * locks were still taken inside the bracket; those now take the bracket
     * themselves, after the lock (see sp/ecc_mul.rb mul_mod_point() and
     * sp/ecc.rb in kh-fork-scripts), so there is no known violator left and
     * refusing is the correct response rather than a self-inflicted outage. */
    if (wc_linuxkm_in_svr_bracket()) {
        pr_err_once("BUG: wc_LockMutex() called inside SAVE_VECTOR_REGISTERS()"
                    " on CPU %d -- illegal, this is an atomic region.\n",
                    raw_smp_processor_id());
        WARN_ON_ONCE(1);
        return BAD_STATE_E;
    }
#endif /* WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

    spin_lock_bh(&m->lock);
    return 0;
}
#endif

WC_MAYBE_UNUSED static int linuxkm_lkcapi_sysfs_install_node(struct kobj_attribute *node, int *installed_flag)
{
    if ((installed_flag == NULL) || (! *installed_flag)) {
        int ret = sysfs_create_file(&THIS_MODULE->mkobj.kobj, &node->attr);
        if (ret) {
            pr_err("ERROR: sysfs_create_file failed for %s: %d\n", node->attr.name, ret);
            return ret;
        }
        if (installed_flag)
            *installed_flag = 1;
    }
    return 0;
}

WC_MAYBE_UNUSED static int linuxkm_lkcapi_sysfs_deinstall_node(struct kobj_attribute *node, int *installed_flag)
{
    if ((installed_flag == NULL) || *installed_flag) {
        sysfs_remove_file(&THIS_MODULE->mkobj.kobj, &node->attr);
        if (installed_flag)
            *installed_flag = 0;
    }
    return 0;
}

#ifdef WC_LINUXKM_SUPPORT_DUMP_TO_FILE
static ssize_t dump_to_file(const char *path, const u8 *buf, size_t buf_len)
{
    loff_t pos = 0;
    struct file *fp;
    ssize_t ret;
    char tmp;

    if (buf_len == 0) {
        pr_info("libwolfssl: dump_to_file() called with buf_len == 0.  Not dumping.\n");
        return 0;
    }

    WC_SANITIZE_DISABLE();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
    ret = probe_kernel_read(&tmp, buf, 1);
    if (ret == 0)
        ret = probe_kernel_read(&tmp, buf + buf_len - 1, 1);
#else
    ret = copy_from_kernel_nofault(&tmp, buf, 1);
    if (ret == 0)
        ret = copy_from_kernel_nofault(&tmp, buf + buf_len - 1, 1);
#endif
    WC_SANITIZE_ENABLE();
    if (ret != 0) {
        pr_err("libwolfssl: cannot safely read from buffer %px: %d\n", buf, (int)ret);
        return ret;
    }

    fp = filp_open(path, O_WRONLY | O_CREAT, 0644);
    if (IS_ERR(fp)) {
        pr_err("libwolfssl: cannot open %s: %d\n", path, (int)PTR_ERR(fp));
        return PTR_ERR(fp);
    }

    WC_SANITIZE_DISABLE();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    /* kernel_write() fixed by e13ec939e9 */
    ret = kernel_write(fp, buf, buf_len, &pos);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
    /* kernel_write() exported by 7bb307e894d51 */
    ret = kernel_write(fp, (char *)buf, buf_len, pos);
#else
    ret = vfs_write(fp, buf, buf_len, &pos);
#endif
    WC_SANITIZE_ENABLE();

    filp_close(fp, NULL);

    if (ret < 0)
        pr_err("libwolfssl: write to %s failed: %zd\n", path, ret);
    else if ((size_t)ret != buf_len)
        pr_warn("libwolfssl: short write to %s: %zd of %zu bytes\n", path, ret, buf_len);

    return ret;
}

static char *text_dump_path;
static char *rodata_dump_path;

    /* indent these so they don't look like flush-left function calls. */
    module_param(text_dump_path,   charp, 0444);
    module_param(rodata_dump_path, charp, 0444);

MODULE_PARM_DESC(text_dump_path,
    "Path to dump live .wolfcrypt_text section to (e.g. /tmp/wc_text.bin)");
MODULE_PARM_DESC(rodata_dump_path,
    "Path to dump live .wolfcrypt_rodata section to (e.g. /tmp/wc_rodata.bin)");

#endif /* WC_LINUXKM_SUPPORT_DUMP_TO_FILE */

#ifdef HAVE_FIPS
    static ssize_t FIPS_rerun_self_test_handler(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count);
    static struct kobj_attribute FIPS_rerun_self_test_attr = __ATTR(FIPS_rerun_self_test, 0220, NULL, FIPS_rerun_self_test_handler);
    static int installed_sysfs_FIPS_files = 0;
#endif

#ifdef LINUXKM_LKCAPI_REGISTER
    #include "linuxkm/lkcapi_glue.c"
#endif

#ifdef LINUXKM_RBGC

/* Out here in non-PIE glue so the arm64 ALTERNATIVE asm in local_irq_save()
 * compiles; see the declarations in linuxkm_wc_port.h. */
unsigned long wc_linuxkm_irq_save(void)
{
    unsigned long flags;

    local_irq_save(flags);

    return flags;
}

void wc_linuxkm_irq_restore(unsigned long flags)
{
    local_irq_restore(flags);
}

/* raw_ because every caller is already non-preemptible: the service path holds
 * interrupts off, and NMI cannot be preempted at all. */
int wc_linuxkm_cpu_id(void)
{
    return (int) raw_smp_processor_id();
}

/* Seqcount-latch reader, so it takes no lock and is legal with interrupts off
 * and from NMI (kernel/time/timekeeping.c). */
unsigned long long wc_linuxkm_mono_ns(void)
{
    return (unsigned long long) ktime_get_mono_fast_ns();
}

#endif /* LINUXKM_RBGC */

int wc_linuxkm_can_block(void) {
    /* preempt_count() is NOT an accurate "may I sleep here" test on its own.
     * In !CONFIG_PREEMPT_COUNT configs (PREEMPT_VOLUNTARY without
     * PREEMPT_DYNAMIC -- the default through 5.15) preempt_disable() expands to
     * barrier() and never touches __preempt_count
     * (include/linux/preempt.h), so a task inside kernel_fpu_begin() still
     * reads 0 here.  preempt_count() is exactly as blind as preemptible() in
     * that configuration; the earlier comment claimed the opposite.
     *
     * The hardirq/softirq masks ARE still maintained there, so the irqs and
     * interrupt-context halves of this test remain sound.  Only the
     * preempt-disabled half is blind, which is why an open vector-register
     * section has to be tested directly.
     *
     * Measured consequence when it was not: on 5.7.19 a cond_resched() from
     * WC_RELAX_LONG_LOOP() inside an open bracket slept, the task migrated,
     * and wc_restore_vector_registers_x86() ran on a CPU with no open section
     * -- stranding kernel_fpu_begin()'s section on the origin CPU for the life
     * of the module (1 event in 920,727 saves).
     */
    return (preempt_count() == 0) && (! irqs_disabled())
        && (! wc_linuxkm_in_svr_bracket());
}

/* for simplicity, we use a global count to suspend signal processing while any
 * thread is running fipsEntry(), wolfCrypt_IntegrityTest_fips(),
 * linuxkm_lkcapi_register(), or linuxkm_lkcapi_unregister().  This only affects
 * startup dynamics and the FIPS runtime.  Once the uninterruptible routine
 * completes, signal handling resumes, and any still-pending signal on
 * continuing threads will be processed in a timely fashion.
 */

static wolfSSL_Atomic_Int wc_linuxkm_sig_ignore_count = WOLFSSL_ATOMIC_INITIALIZER(0);

int wc_linuxkm_sig_ignore_begin(void) {
    return wolfSSL_Atomic_Int_AddFetch(&wc_linuxkm_sig_ignore_count, 1);
}

int wc_linuxkm_sig_ignore_end(void) {
    return wolfSSL_Atomic_Int_SubFetch(&wc_linuxkm_sig_ignore_count, 1);
}

int wc_linuxkm_check_for_intr_signals(void) {
    static const int intr_signals[] = WC_LINUXKM_INTR_SIGNALS;
    if (! wc_linuxkm_can_block())
        return 0;
    if (signal_pending(current)) {
        int i;
        for (i = 0;
             i < (int)sizeof(intr_signals) / (int)sizeof(intr_signals[0]);
             ++i)
        {
            if (sigismember(&current->pending.signal, intr_signals[i])) {
                if (WOLFSSL_ATOMIC_LOAD(wc_linuxkm_sig_ignore_count) > 0) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                    pr_info("INFO: wc_linuxkm_check_for_intr_signals ignoring "
                            "signal %d\n", intr_signals[i]);
#endif
                        return 0;
                }
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                pr_info("INFO: wc_linuxkm_check_for_intr_signals returning "
                       "INTERRUPTED_E on signal %d\n", intr_signals[i]);
#endif
                return INTERRUPTED_E;
            }
        }
    }
    return 0;
}

void wc_linuxkm_relax_long_loop(void) {
    #if WC_LINUXKM_MAX_NS_WITHOUT_YIELD >= 0
    if (wc_linuxkm_can_block()) {
        #if (WC_LINUXKM_MAX_NS_WITHOUT_YIELD == 0) || !defined(CONFIG_SCHED_INFO)
        cond_resched();
        #else
        /* note that local_clock() wraps a local_clock_noinstr() in a
         * preempt_disable_notrace(), which sounds expensive but isn't --
         * preempt_disable_notrace() is actually just a nonlocking integer
         * increment of current_thread_info()->preempt.count, protected only by
         * various compiler optimizer barriers.
         */
        u64 now = local_clock();
        u64 current_last_arrival = current->sched_info.last_arrival;
        s64 delta = (s64)(now - current_last_arrival);
        if (delta > WC_LINUXKM_MAX_NS_WITHOUT_YIELD) {
            cond_resched();
            /* if nothing else is runnable, cond_resched() is a no-op and
             * doesn't even update .last_arrival.  we could force update by
             * sleeping, but there's no need.  we've been nice enough by just
             * cond_resched()ing, and it's actually preferable to call
             * cond_resched() frequently once computation has looped
             * continuously for longer than WC_LINUXKM_MAX_NS_WITHOUT_YIELD.
             */
        }
        #endif
        return;
    }
    #endif
    cpu_relax();
}

#if defined(WC_LINUXKM_WOLFENTROPY_IN_GLUE_LAYER)

int wc_linuxkm_GenerateSeed_wolfEntropy(OS_Seed* os, byte* output, word32 sz)
{
    (void)os;
    return wc_Entropy_Get(MAX_ENTROPY_BITS, output, sz);
}

#elif defined(WC_LINUXKM_RDSEED_IN_GLUE_LAYER)

/* backported wc_GenerateSeed_IntelRD() for FIPS v5, before breakout of wolfentropy.c. */

#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/random.h>

static cpuid_flags_t intel_flags = WC_CPUID_INITIALIZER;
static inline void wc_InitRng_IntelRD(void)
{
    cpuid_get_flags_ex(&intel_flags);
}

#define INTELRD_RETRY 32

static WC_INLINE int IntelRDseed64(word64* seed)
{
    unsigned char ok;

    __asm__ volatile("rdseed %0; setc %1":"=r"(*seed), "=qm"(ok));
    return (ok) ? 0 : -1;
}

/* return 0 on success */
static WC_INLINE int IntelRDseed64_r(word64* rnd)
{
    int iters, retry_counter;
    word64 buf;
#if defined(HAVE_AMD_RDSEED)
    /* See "AMD RNG ESV Public Use Document".  Version 0.7 of October 24,
     * 2024 specifies 0.656 to 1.312 bits of entropy per 128 bit block of
     * RDSEED output, depending on CPU family.
     *
     * FIPS v5 random.c sets ENTROPY_SCALE_FACTOR to 1 for
     * HAVE_INTEL_RDSEED.
     */
    iters = 128;
#elif defined(HAVE_INTEL_RDSEED)
    /* The value of 2 applies to Intel's RDSEED which provides about
     * 0.5 bits minimum of entropy per bit. The value of 4 gives a
     * conservative margin for FIPS.
     *
     * FIPS v5 random.c sets ENTROPY_SCALE_FACTOR to 2 for
     * HAVE_INTEL_RDSEED.
     */
    iters = 2;
#else
    #error WC_LINUXKM_RDSEED_IN_GLUE_LAYER requires HAVE_INTEL_RDSEED or HAVE_AMD_RDSEED
#endif

    while (--iters >= 0) {
        for (retry_counter = 0; retry_counter < INTELRD_RETRY; retry_counter++) {
            if (IntelRDseed64(&buf) == 0)
                break;
        }
        if (retry_counter == INTELRD_RETRY)
            return -1;
        WC_SANITIZE_DISABLE();
        *rnd ^= buf; /* deliberately retain any garbage passed in the dest buffer. */
        WC_SANITIZE_ENABLE();
        buf = 0;
    }
    wc_ForceZero(&buf, sizeof buf);
    return 0;
}

/* return 0 on success */
int wc_linuxkm_GenerateSeed_IntelRD(struct OS_Seed* os, byte* output, word32 sz)
{
    int ret;
    word64 rndTmp;

    (void)os;

    wc_InitRng_IntelRD();

    if (!IS_INTEL_RDSEED(intel_flags)) {
        static wolfSSL_Atomic_Int warned_on_missing_RDSEED = WOLFSSL_ATOMIC_INITIALIZER(0);
        int expected_warned_on_missing_RDSEED = 0;
        if (wolfSSL_Atomic_Int_CompareExchange(
                &warned_on_missing_RDSEED, &expected_warned_on_missing_RDSEED, 1))
        {
            pr_err("ERROR: wc_linuxkm_GenerateSeed_IntelRD() called on CPU without RDSEED support.\n");
        }
        return -1;
    }

    for (; (sz / sizeof(word64)) > 0; sz -= sizeof(word64),
                                                    output += sizeof(word64)) {
        ret = IntelRDseed64_r((word64*)output);
        if (ret != 0) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            pr_err("ERROR: IntelRDseed64_r() returned code %d.\n", ret);
#endif
            return ret;
        }
    }
    if (sz == 0)
        return 0;

    /* handle unaligned remainder */
    ret = IntelRDseed64_r(&rndTmp);
    if (ret != 0) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        pr_err("ERROR: IntelRDseed64_r() returned code %d.\n", ret);
#endif
        return ret;
    }

    XMEMCPY(output, &rndTmp, sz);
    wc_ForceZero(&rndTmp, sizeof(rndTmp));

    return 0;
}

#endif /* WC_LINUXKM_RDSEED_IN_GLUE_LAYER */

#if defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) && \
    (defined(CONFIG_X86) || defined(CONFIG_ARM) || defined(CONFIG_ARM64))
    /* arch-generic vector save/restore (kernel_fpu_* x86, kernel_neon_* ARM) */
    #include "linuxkm/x86_vector_register_glue.c"
#endif

#ifdef CONFIG_HAVE_KPROBES
    static WC_MAYBE_UNUSED void *my_kallsyms_lookup_name(const char *name);
#endif

#ifdef FIPS_OPTEST
    #ifndef HAVE_FIPS
        #error FIPS_OPTEST requires HAVE_FIPS.
    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER
        #error FIPS_OPTEST is not allowed with LINUXKM_LKCAPI_REGISTER.
    #endif
    extern int linuxkm_op_test_1(int argc, const char* argv[]);
    extern int linuxkm_op_test_wrapper(void);
    static wolfSSL_Atomic_Int *conTestFailure_ptr = NULL;
    #ifdef HAVE_WC_FIPS_OPTEST_CONTESTFAILURE_EXPORT
        WOLFSSL_API extern wolfSSL_Atomic_Int wc_fips_optest_conTestFailure;
    #endif
    static ssize_t FIPS_optest_trig_handler(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count);
    static struct kobj_attribute FIPS_optest_trig_attr = __ATTR(FIPS_optest_run_code, 0220, NULL, FIPS_optest_trig_handler);
    static int installed_sysfs_FIPS_optest_trig_files = 0;
#endif

#ifdef LINUXKM_RBGC

/* cpus_read_lock()/cpus_read_unlock() around the per-CPU work setup. */
#include <linux/cpu.h>

/* The boundary cannot schedule work itself, so the glue drives it.
 *
 * One delayed work PER CPU, queued with queue_delayed_work_on() so it runs on
 * the CPU whose leaf it reseeds.  That is what lets the reseed take interrupts
 * off and know no caller on that CPU can be inside the leaf, which is what
 * removes the need for any exclusion flag in the boundary.
 *
 * The root's own refresh from the noise source is a separate, unpinned work:
 * it is the entropy gather and must not be coupled to leaf demand. */
#define WC_GRB_MAINT_POLL_MS 50

struct wc_grb_cpu_work {
    struct delayed_work dw;
    int                 cpu;
};

static struct wc_grb_cpu_work *wc_grb_cpu_works;
static struct delayed_work     wc_grb_root_work;
static int                     wc_grb_maint_running;

static void wc_grb_cpu_work_fn(struct work_struct *work)
{
    /* dw is the first member of wc_grb_cpu_work and work is the first member
     * of delayed_work, so the work pointer is the wrapper pointer.
     * container_of() cannot be used here: it does void* arithmetic and this
     * builds with -Werror=pointer-arith. */
    struct wc_grb_cpu_work *cw = (struct wc_grb_cpu_work *) work;
    int ret;

    wc_static_assert(offsetof(struct wc_grb_cpu_work, dw) == 0);
    wc_static_assert(offsetof(struct delayed_work, work) == 0);

    ret = wc_grb_maintain_cpu(cw->cpu);

    if (ret != 0) {
        pr_err("WCGRB: wc_grb_maintain_cpu(%d) failed: %d\n", cw->cpu, ret);
    }

    if (READ_ONCE(wc_grb_maint_running)) {
        /* queue_delayed_work_on() WARNs on an offline CPU (workqueue.c
         * WARN_ON_ONCE !cpu_online).  Tick unbound while it is down; the
         * leaf's guard defers the reseed, and this re-pins when it returns. */
        if (cpu_online(cw->cpu)) {
            queue_delayed_work_on(cw->cpu, system_wq, &cw->dw,
                                  msecs_to_jiffies(WC_GRB_MAINT_POLL_MS));
        }
        else {
            queue_delayed_work(system_wq, &cw->dw,
                               msecs_to_jiffies(WC_GRB_MAINT_POLL_MS));
        }
    }
}

static void wc_grb_root_work_fn(struct work_struct *work)
{
    int ret;

    (void)work;
    ret = wc_grb_root_tick();
    if (ret != 0) {
        pr_err("WCGRB: wc_grb_root_tick() failed: %d\n", ret);
    }

    if (READ_ONCE(wc_grb_maint_running)) {
        schedule_delayed_work(&wc_grb_root_work,
                              msecs_to_jiffies(WC_GRB_MAINT_POLL_MS));
    }
}

static void wc_grb_maint_stop(void)
{
    unsigned int cpu;

    WRITE_ONCE(wc_grb_maint_running, 0);
    cancel_delayed_work_sync(&wc_grb_root_work);

    if (wc_grb_cpu_works != NULL) {
        for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
            cancel_delayed_work_sync(&wc_grb_cpu_works[cpu].dw);
        }

        kfree(wc_grb_cpu_works);
        wc_grb_cpu_works = NULL;
    }
}

#ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS_FIPS

/* Userspace half of the service: /dev/urandom, /dev/random and getrandom(2)
 * all land here.  A bounce buffer is required because wc_grb_service() fills a
 * kernel buffer while copy_to_iter() may fault or sleep. */
static ssize_t wc_grb_user(struct iov_iter *iter)
{
    u8     buf[256];
    size_t done = 0;

    while (iov_iter_count(iter)) {
        size_t want = min_t(size_t, iov_iter_count(iter), sizeof(buf));
        size_t got;

        if (wc_grb_service(buf, want) != 0)
            break;

        got = copy_to_iter(buf, want, iter);
        done += got;
        if (got != want) {
            memzero_explicit(buf, sizeof(buf));

            return done ? (ssize_t)done : -EFAULT;
        }

        cond_resched();
    }

    memzero_explicit(buf, sizeof(buf));

    return done ? (ssize_t)done : -ENODEV;
}

/* Truthful readiness: the tree is usable only once wc_grb_init() has built the
 * root and the leaves.  Reporting ready early would let the kernel batch from
 * a service that is not yet answering. */
static bool wc_grb_ready(void)
{
    return wc_grb_service_active() ? true : false;
}

static const struct wolfssl_linuxkm_fips_random_bytes_handlers
wc_grb_handlers = {
    ._get_random_bytes     = wc_grb_service,
    .get_random_bytes_user = wc_grb_user,
    .crng_ready            = wc_grb_ready
    /* .extract_crng_user is the pre-5.17 userspace API; the RBGC targets
     * kernels carrying the newer one.  .mix_pool_bytes, .credit_init_bits and
     * .crng_reseed are not implemented yet: they let the module take part in
     * the kernel's entropy lifecycle and are the next step, not a
     * prerequisite for serving. */
};

#endif /* WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS_FIPS */

/* Diagnostics for the out-of-tree load generator, exported from the glue and
 * not from the boundary: the boundary has no module API, and a test affordance
 * is not a cryptographic service.  Prototyped here rather than in a header
 * because nothing in the tree includes them. */
int wc_grb_hook_is_active(void);
int wc_grb_hook_stats(long long *out, int n);
int wc_grb_hook_irq_hist(int ctx, long long *out, int n);

int wc_grb_hook_is_active(void)
{
    return wc_grb_service_active();
}
EXPORT_SYMBOL_GPL(wc_grb_hook_is_active);

int wc_grb_hook_stats(long long *out, int n)
{
    return wc_grb_stat_snapshot(out, n);
}
EXPORT_SYMBOL_GPL(wc_grb_hook_stats);

int wc_grb_hook_irq_hist(int ctx, long long *out, int n)
{
    return wc_grb_irq_hist(ctx, out, n);
}
EXPORT_SYMBOL_GPL(wc_grb_hook_irq_hist);

static int wc_grb_maint_start(void)
{
    unsigned int cpu;

    wc_grb_cpu_works = kcalloc(nr_cpu_ids, sizeof(*wc_grb_cpu_works),
                               GFP_KERNEL);
    if (wc_grb_cpu_works == NULL) {
        return -ENOMEM;
    }

    WRITE_ONCE(wc_grb_maint_running, 1);

    INIT_DELAYED_WORK(&wc_grb_root_work, wc_grb_root_work_fn);
    schedule_delayed_work(&wc_grb_root_work,
                          msecs_to_jiffies(WC_GRB_MAINT_POLL_MS));

    /* Runtime INIT_DELAYED_WORK, not the static initializer: that expands
     * TIMER_ENTRY_STATIC, whose void* arithmetic trips pointer-arith. */
    for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
        wc_grb_cpu_works[cpu].cpu = (int) cpu;
        INIT_DELAYED_WORK(&wc_grb_cpu_works[cpu].dw, wc_grb_cpu_work_fn);
    }

    /* Only online CPUs get a worker.  A CPU brought up later is covered by
     * the service path's self-help, which reseeds the leaf it is running on.
     * Held across the walk so a CPU cannot go down between the iteration and
     * the queue, which would WARN exactly as an offline requeue does. */
    cpus_read_lock();
    for_each_online_cpu(cpu) {
        queue_delayed_work_on((int) cpu, system_wq, &wc_grb_cpu_works[cpu].dw,
                              msecs_to_jiffies(WC_GRB_MAINT_POLL_MS));
    }
    cpus_read_unlock();

    return 0;
}

#endif /* LINUXKM_RBGC */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfssl_init(void)
#else
static int wolfssl_init(void)
#endif
{
    int ret;

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at entry to wolfssl_init(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    }
    #endif

#ifdef WC_SYM_RELOC_TABLES
    ret = set_up_wolfssl_linuxkm_pie_redirect_table();
    if (ret < 0)
        return ret;
#endif

#ifdef WC_LINUXKM_SUPPORT_DUMP_TO_FILE

#ifdef WC_SYM_RELOC_TABLES
    if (text_dump_path) {
        if (dump_to_file(text_dump_path,
                         (u8 *)__wc_text_start,
                         (size_t)((uintptr_t)__wc_text_end - (uintptr_t)__wc_text_start))
            > 0)
        {
            pr_info("libwolfssl: dumped .wolfcrypt_text (%zu bytes) to %s.\n",
                    (size_t)((uintptr_t)__wc_text_end - (uintptr_t)__wc_text_start),
                    text_dump_path);
        }
    }
    if (rodata_dump_path) {
        if (dump_to_file(rodata_dump_path,
                         (u8 *)__wc_rodata_start,
                         (size_t)((uintptr_t)__wc_rodata_end - (uintptr_t)__wc_rodata_start))
            > 0)
        {
            pr_info("libwolfssl: dumped .wolfcrypt_rodata (%zu bytes) to %s.\n",
                    (size_t)((uintptr_t)__wc_rodata_end - (uintptr_t)__wc_rodata_start),
                    rodata_dump_path);
        }
    }
#else
    if ((text_dump_path != NULL) ||
        (rodata_dump_path != NULL))
    {
        pr_info("libwolfssl: ignoring module dump path argument(s) -- module lacks WC_SYM_RELOC_TABLES.\n");
    }
#endif

#endif /* WC_LINUXKM_SUPPORT_DUMP_TO_FILE */

#ifdef WC_LINUXKM_TEST_INET_PTON
    {
        const char *src;
        byte dst[16] = { };
        int pton_ret;
        src = "1.2.3.4";
        pton_ret = wc_linuxkm_inet_pton(AF_INET, src, dst);
        printf("pton_ret=%d src=%s dst=%d.%d.%d.%d\n", pton_ret, src, (int)dst[0], (int)dst[1], (int)dst[2], (int)dst[3]);
        src = "89ab::cdef";
        pton_ret = wc_linuxkm_inet_pton(AF_INET6, src, dst);
        printf("pton_ret=%d src=%s dst=%02x%02x::%02x%02x\n", pton_ret, src, (int)dst[0], (int)dst[1], (int)dst[14], (int)dst[15]);
    }
#endif /* WC_LINUXKM_TEST_INET_PTON */

#if defined(HAVE_FIPS) && !defined(WOLFSSL_FIPS_DEV_NO_POST)
    /* The compiled-in verifycore must be the right length, else the module
     * geometry will change when the correct value is passed in, destabilizing
     * wc_linuxkm_pie_text_reloc_tab.  It also must be the right length for the
     * module-update-fips-hash recipe (in-place overwrite) to work, and for
     * updateFipsHash() (WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE) to be safe from
     * overruns.
     */
    {
        size_t verifyCore_len;
#if FIPS_VERSION3_GE(6,0,0) || defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE)
        verifyCore_len = strlen(verifyCore);
#else
#ifdef CONFIG_HAVE_KPROBES
        char *verifyCore_ptr = my_kallsyms_lookup_name("verifyCore");
        if (verifyCore_ptr)
            verifyCore_len = strlen(verifyCore_ptr);
        else
#endif /* CONFIG_HAVE_KPROBES */
        {
            /* can't check -- have to assume. */
#if defined(CONFIG_HAVE_KPROBES) && (defined(DEBUG_LINUXKM_PIE_SUPPORT) || defined(WOLFSSL_LINUXKM_VERBOSE_DEBUG))
            pr_err("INFO: couldn't get verifyCore_ptr -- skipping verifyCore length check.\n");
#endif
            verifyCore_len = FIPS_IN_CORE_DIGEST_SIZE*2;
        }
#endif
        if (verifyCore_len != FIPS_IN_CORE_DIGEST_SIZE*2) {
            pr_err("ERROR: compile-time FIPS hash is the wrong length (expected %d hex digits, got %zu).\n", FIPS_IN_CORE_DIGEST_SIZE*2, verifyCore_len);
            return -ECANCELED;
        }
    }

#ifdef WC_SYM_RELOC_TABLES
    if (((uintptr_t)__wc_text_start > (uintptr_t)wolfCrypt_FIPS_first) ||
        ((uintptr_t)__wc_text_end < (uintptr_t)wolfCrypt_FIPS_last) ||
        ((uintptr_t)__wc_rodata_start > (uintptr_t)wolfCrypt_FIPS_ro_start) ||
        ((uintptr_t)__wc_rodata_end < (uintptr_t)wolfCrypt_FIPS_ro_end))
    {
        pr_err("ERROR: ELF segment fenceposts and FIPS fenceposts conflict.\n");
        return -ECANCELED;
    }
#endif

#if defined(WC_LINUXKM_USE_HEAP_WRAPPERS) && defined(CONFIG_HAVE_KPROBES)
    /* cache the function pointer to find_vm_area(). */
    (void)wc_linuxkm_malloc_usable_size(NULL);
#endif

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
#ifdef CONFIG_MODULE_SIG
    if (THIS_MODULE->sig_ok == false) {
        pr_err("ERROR: wolfSSL module load aborted -- bad or missing module signature with FIPS dynamic hash.\n");
        return -ECANCELED;
    }
#endif
    #if defined(WC_SYM_RELOC_TABLES) && defined(DEBUG_LINUXKM_PIE_SUPPORT)
    reloc_counts.text = reloc_counts.rodata = reloc_counts.rwdata = reloc_counts.bss =
        reloc_counts.other = 0;
    #endif
    ret = updateFipsHash();
    if (ret < 0) {
        pr_err("ERROR: wolfSSL module load aborted -- updateFipsHash: %s\n",wc_GetErrorString(ret));
        return -ECANCELED;
    }

    #if defined(WC_SYM_RELOC_TABLES) && defined(DEBUG_LINUXKM_PIE_SUPPORT)
    pr_info("FIPS-bounded relocation normalizations from updateFipsHash(): text=%d, rodata=%d, rwdata=%d, bss=%d, other=%d\n",
            reloc_counts.text, reloc_counts.rodata, reloc_counts.rwdata, reloc_counts.bss, reloc_counts.other);
    #endif

#endif /* WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE */

#endif /* HAVE_FIPS */

#if defined(WC_SYM_RELOC_TABLES) && defined(DEBUG_LINUXKM_PIE_SUPPORT)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    /* see linux commit ac3b432839 */
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->mem[MOD_TEXT].base)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->mem[MOD_TEXT].size)
    #define THIS_MODULE_RO_BASE (THIS_MODULE->mem[MOD_RODATA].base)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->mem[MOD_RODATA].size)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->core_layout.base)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_layout.text_size)
    #define THIS_MODULE_RO_BASE ((char *)THIS_MODULE->core_layout.base + THIS_MODULE->core_layout.text_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_layout.ro_size)
#else
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->module_core)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_text_size)
    #define THIS_MODULE_RO_BASE ((char *)THIS_MODULE->module_core + THIS_MODULE->core_ro_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_ro_size)
#endif

    {
        unsigned int text_hash = hash_span((const u8 *)__wc_text_start, (const u8 *)__wc_text_end, 1);
        unsigned int rodata_hash = hash_span((const u8 *)__wc_rodata_start, (const u8 *)__wc_rodata_end, 1);
        u8 *canon_buf = malloc(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ);
        ssize_t cur_reloc_index;
        const u8 *text_p = (const u8 *)__wc_text_start;
        const u8 *rodata_p = (const u8 *)__wc_rodata_start;
        unsigned int stabilized_text_hash = 1;
        unsigned int stabilized_rodata_hash = 1;

        if (! canon_buf) {
            pr_err("ERROR: malloc(%d) for WOLFSSL_*_SEGMENT_CANONICALIZER failed.\n", WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ);
            return -ECANCELED;
        }

        reloc_counts.text = reloc_counts.rodata = reloc_counts.rwdata = reloc_counts.bss =
            reloc_counts.other = 0;

        cur_reloc_index = -1;
        while (text_p < (const u8 *)__wc_text_end) {
            size_t text_in_out_len = min(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ,
                                         (size_t)((const u8 *)__wc_text_end - text_p));
            ssize_t progress =
                WOLFSSL_SEGMENT_CANONICALIZER(
                    text_p,
                    &text_in_out_len,
                    canon_buf, &cur_reloc_index);
            if (progress <= 0) {
                pr_err("ERROR: progress=%ld from WOLFSSL_SEGMENT_CANONICALIZER() at offset %x (text=%x-%x).\n",
                       (long)progress,
                       (unsigned)(uintptr_t)text_p,
                       (unsigned)(uintptr_t)__wc_text_start,
                       (unsigned)(uintptr_t)__wc_text_end);
                free(canon_buf);
                return -ECANCELED;
            }
            stabilized_text_hash = hash_span(canon_buf, canon_buf + text_in_out_len, stabilized_text_hash);
            text_p += progress;
        }

        /* note verifyCore is hashed along with the rest of .rodata_wolfcrypt. */
        cur_reloc_index = -1;
        while (rodata_p < (const u8 *)__wc_rodata_end) {
            size_t rodata_in_out_len = min(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ,
                                         (size_t)((const u8 *)__wc_rodata_end - rodata_p));
            ssize_t progress =
                WOLFSSL_SEGMENT_CANONICALIZER(
                    rodata_p,
                    &rodata_in_out_len,
                    canon_buf, &cur_reloc_index);
            if (progress <= 0) {
                pr_err("ERROR: progress=%ld from WOLFSSL_SEGMENT_CANONICALIZER() at offset %x (rodata=%x-%x).\n",
                       (long)progress,
                       (unsigned)(uintptr_t)rodata_p,
                       (unsigned)(uintptr_t)__wc_rodata_start,
                       (unsigned)(uintptr_t)__wc_rodata_end);
                free(canon_buf);
                return -ECANCELED;
            }
            stabilized_rodata_hash = hash_span(canon_buf, canon_buf + rodata_in_out_len, stabilized_rodata_hash);
            rodata_p += progress;
        }

        free(canon_buf);
        canon_buf = 0;

        /* note, "%pK" conceals the actual layout information.  "%px" exposes
         * the true module start address, which is potentially useful to an
         * attacker.
         */
        pr_info("wolfCrypt segment hashes (spans): text 0x%x (%llu), rodata 0x%x (%llu), offset %c0x%llx, canon text 0x%x, canon rodata 0x%x\n",
                text_hash, (unsigned long long)((uintptr_t)__wc_text_end - (uintptr_t)__wc_text_start),
                rodata_hash, (unsigned long long)((uintptr_t)__wc_rodata_end - (uintptr_t)__wc_rodata_start),
                (uintptr_t)__wc_text_start < (uintptr_t)&__wc_rodata_start[0] ? '+' : '-',
                (uintptr_t)__wc_text_start < (uintptr_t)&__wc_rodata_start[0] ? (unsigned long long)((uintptr_t)&__wc_rodata_start[0] - (uintptr_t)__wc_text_start) : (unsigned long long)((uintptr_t)__wc_text_start - (uintptr_t)&__wc_rodata_start[0]),
                stabilized_text_hash,
                stabilized_rodata_hash);

        pr_info("wolfCrypt segments: text=%llx-%llx, rodata=%llx-%llx, "
                "rwdata=%llx-%llx, bss=%llx-%llx\n",
                (unsigned long long)(uintptr_t)__wc_text_start,
                (unsigned long long)(uintptr_t)__wc_text_end,
                (unsigned long long)(uintptr_t)__wc_rodata_start,
                (unsigned long long)(uintptr_t)__wc_rodata_end,
                (unsigned long long)(uintptr_t)__wc_rwdata_start,
                (unsigned long long)(uintptr_t)__wc_rwdata_end,
                (unsigned long long)(uintptr_t)__wc_bss_start,
                (unsigned long long)(uintptr_t)__wc_bss_end);

        pr_info("whole-segment relocation normalizations: text=%d, rodata=%d, rwdata=%d, bss=%d, other=%d\n",
                reloc_counts.text, reloc_counts.rodata, reloc_counts.rwdata, reloc_counts.bss, reloc_counts.other);
    }

#endif /* WC_SYM_RELOC_TABLES && DEBUG_LINUXKM_PIE_SUPPORT */

#ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by wolfssl_init() initial setup: %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
#endif

#ifdef HAVE_FIPS
    ret = wolfCrypt_SetCb_fips(lkmFipsCb);
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_SetCb_fips() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }

#if defined(WC_SYM_RELOC_TABLES) && defined(DEBUG_LINUXKM_PIE_SUPPORT)
    reloc_counts.text = reloc_counts.rodata = reloc_counts.rwdata = reloc_counts.bss =
        reloc_counts.other = 0;
#endif

    if (WC_SIG_IGNORE_BEGIN() >= 0) {
        fipsEntry();
        (void)WC_SIG_IGNORE_END();
    }
    else
        pr_err("ERROR: WC_SIG_IGNORE_BEGIN() failed.\n");

#if defined(WC_SYM_RELOC_TABLES) && defined(DEBUG_LINUXKM_PIE_SUPPORT)
    pr_info("FIPS-bounded relocation normalizations: text=%d, rodata=%d, rwdata=%d, bss=%d, other=%d\n",
            reloc_counts.text, reloc_counts.rodata, reloc_counts.rwdata, reloc_counts.bss, reloc_counts.other);
#endif

    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_GetStatus_fips() failed with code %d: %s\n", ret, wc_GetErrorString(ret));
        if (ret == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            if (newhash) {
                pr_err("In-core integrity hash check failure.\n"
                       "Update FIPS hash with \"make module-update-fips-hash FIPS_HASH=%s\".\n",
                       newhash);
            }
            else {
                pr_err("In-core integrity hash check failure.\n");
                pr_err("ERROR: could not compute new hash.  Contact customer support.\n");
            }
        }
        return -ECANCELED;
    }
#endif /* HAVE_FIPS */

#ifdef WC_RNG_SEED_CB
    ret = wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);

    if (ret < 0) {
        pr_err("ERROR: wc_SetSeed_Cb() failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
#endif /* WC_RNG_SEED_CB */

#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("ERROR: wolfSSL_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#if defined(HAVE_FIPS) && FIPS_VERSION3_GT(5,2,0)

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to wc_RunAllCast_fips(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif

    ret = wc_RunAllCast_fips();

#ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by wc_RunAllCast_fips(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
#endif

    if (ret != 0) {
        pr_err("ERROR: wc_RunAllCast_fips() failed with return value %d\n", ret);
        return -ECANCELED;
    }

    pr_info("FIPS 140-3 wolfCrypt-fips v%d.%d.%d%s%s startup "
            "self-test succeeded.\n",
#ifdef HAVE_FIPS_VERSION_MAJOR
            HAVE_FIPS_VERSION_MAJOR,
#else
            HAVE_FIPS_VERSION,
#endif
#ifdef HAVE_FIPS_VERSION_MINOR
            HAVE_FIPS_VERSION_MINOR,
#else
            0,
#endif
#ifdef HAVE_FIPS_VERSION_PATCH
            HAVE_FIPS_VERSION_PATCH,
#else
            0,
#endif
#ifdef HAVE_FIPS_VERSION_PORT
            "-",
            HAVE_FIPS_VERSION_PORT
#else
            "",
            ""
#endif
        );
#endif /* HAVE_FIPS && FIPS_VERSION3_GT(5,2,0) */

#ifdef FIPS_OPTEST
    #ifdef HAVE_WC_FIPS_OPTEST_CONTESTFAILURE_EXPORT
    conTestFailure_ptr = &wc_fips_optest_conTestFailure;
    #else
    conTestFailure_ptr = (wolfSSL_Atomic_Int *)my_kallsyms_lookup_name("conTestFailure");
    if (conTestFailure_ptr == NULL) {
        pr_err("ERROR: couldn't obtain conTestFailure_ptr.\n");
        return -ECANCELED;
    }
    #endif

    ret = linuxkm_lkcapi_sysfs_install_node(&FIPS_optest_trig_attr, &installed_sysfs_FIPS_optest_trig_files);
    if (ret != 0) {
        pr_err("ERROR: linuxkm_lkcapi_sysfs_install_node() failed for %s (code %d).\n", FIPS_optest_trig_attr.attr.name, ret);
        return -ECANCELED;
    }

#ifdef FIPS_OPTEST_FULL_RUN_AT_MODULE_INIT

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to linuxkm_op_test_wrapper(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif

    (void)linuxkm_op_test_wrapper();

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by linuxkm_op_test_wrapper(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
    #endif

    WOLFSSL_ATOMIC_STORE(*conTestFailure_ptr, 0);
    {
        int i;
        for (i = 0; i < FIPS_CAST_COUNT; ++i)
            fipsCastStatus_put(i, FIPS_CAST_STATE_INIT);
    }
    /* note, must call fipsEntry() here, not wolfCrypt_IntegrityTest_fips(),
     * because wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256) isn't available
     * anymore.
     */
    if (WC_SIG_IGNORE_BEGIN() >= 0) {
        fipsEntry();
        (void)WC_SIG_IGNORE_END();
    }
    else
        pr_err("ERROR: WC_SIG_IGNORE_BEGIN() failed.\n");
    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_GetStatus_fips() after reset failed with code %d: %s\n", ret, wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif
#endif /* FIPS_OPTEST */

#ifndef NO_CRYPT_TEST
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to wolfcrypt_test(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif
        ret = wolfcrypt_test(NULL);
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by wolfcrypt_test(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
    #endif
    if (ret < 0) {
        pr_err("ERROR: wolfcrypt self-test failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
    pr_info("wolfCrypt self-test passed.\n");
#else
#if !defined(HAVE_FIPS) || FIPS_VERSION3_LE(5,2,0)
    pr_info("skipping full wolfcrypt_test() "
            "(configure with --enable-crypttests to enable).\n");
#endif
#endif

#ifdef LINUXKM_LKCAPI_REGISTER
#ifdef LINUXKM_LKCAPI_REGISTER_ONLY_ON_COMMAND
    ret = linuxkm_lkcapi_sysfs_install();

    if (ret) {
        pr_err("ERROR: linuxkm_lkcapi_sysfs_install() failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
#else /* !LINUXKM_LKCAPI_REGISTER_ONLY_ON_COMMAND */
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to linuxkm_lkcapi_register(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif
        ret = linuxkm_lkcapi_register();
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by linuxkm_lkcapi_register(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
    #endif

    if (ret) {
        pr_err("ERROR: linuxkm_lkcapi_register() failed with return code %d.\n", ret);
        linuxkm_lkcapi_unregister();
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
#endif /* !LINUXKM_LKCAPI_REGISTER_ONLY_ON_COMMAND */
#endif /* LINUXKM_LKCAPI_REGISTER */

#ifdef HAVE_FIPS
    (void)linuxkm_lkcapi_sysfs_install_node(&FIPS_rerun_self_test_attr, &installed_sysfs_FIPS_files);
#endif

#ifdef WOLFSSL_LINUXKM_BENCHMARKS
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to wolfcrypt_benchmark_main(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif
        wolfcrypt_benchmark_main(0, (char**)NULL);
    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by wolfcrypt_benchmark_main(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
    #endif
#endif

#ifdef WOLFCRYPT_ONLY
    pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfCrypt Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#else
    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfSSL Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#endif

#ifdef LINUXKM_RBGC
    /* Hand get_random_bytes() to the in-boundary service.  A failure here is
     * reported but does not fail the module load: the kernel's own CRNG keeps
     * answering, so the rest of the module is still usable. */
    {
        int grb_ret = wc_grb_init(num_possible_cpus());

        if (grb_ret != 0) {
            pr_err("WCGRB: wc_grb_init() failed: %d\n", grb_ret);
        }
        else {
#ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS_FIPS
            grb_ret = wolfssl_linuxkm_fips_register_random_bytes_handlers(
                THIS_MODULE, &wc_grb_handlers);
#else
            grb_ret = wc_grb_hook_register(wc_grb_service);
#endif
            if (grb_ret != 0) {
                pr_err("WCGRB: wc_grb_hook_register() failed: %d\n", grb_ret);
                wc_grb_cleanup();
            }
            else {
                wc_grb_set_registered(1);
                if (wc_grb_maint_start() != 0) {
                    pr_err("WCGRB: no memory for per-CPU maintenance work\n");
                }
                pr_info("WCGRB: get_random_bytes() hook registered\n");
                /* Module init has finished, so all further demand is the
                 * running system rather than bring-up. */
                wc_grb_mark_boot_done();
            }
        }
    }
#endif /* LINUXKM_RBGC */

    return 0;
}

module_init(wolfssl_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfssl_exit(void)
#else
static void wolfssl_exit(void)
#endif
{
#ifdef LINUXKM_RBGC
    /* Unregister the hook before anything else is torn down, so no in-flight
     * caller can reach a half-freed DRBG.  wc_grb_hook_unregister() NULLs the
     * pointer then synchronize_rcu()s, which drains callers already inside. */
    if (wc_grb_service_active()) {
#ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS_FIPS
        (void)wolfssl_linuxkm_fips_unregister_random_bytes_handlers();
#else
        wc_grb_hook_unregister();
#endif
        wc_grb_set_registered(0);
    }
    wc_grb_maint_stop();
    wc_grb_cleanup();
#endif /* LINUXKM_RBGC */

#ifdef HAVE_FIPS
    int ret;

    (void)linuxkm_lkcapi_sysfs_deinstall_node(&FIPS_rerun_self_test_attr, &installed_sysfs_FIPS_files);
#ifdef FIPS_OPTEST
    (void)linuxkm_lkcapi_sysfs_deinstall_node(&FIPS_optest_trig_attr, &installed_sysfs_FIPS_optest_trig_files);
#endif
#endif

#ifdef LINUXKM_LKCAPI_REGISTER
    (void)linuxkm_lkcapi_unregister();
    (void)linuxkm_lkcapi_sysfs_deinstall();
#endif

#ifdef HAVE_FIPS
    ret = wc_RunAllCast_fips();
    if (ret != 0) {
        pr_err("ERROR: wc_RunAllCast_fips() failed at shutdown with return value %d\n", ret);
    }
    else
        pr_info("wolfCrypt FIPS re-self-test succeeded at unload: all algorithms re-verified.\n");
#endif

    (void)libwolfssl_cleanup();

    return;
}

module_exit(wolfssl_exit);

#if defined(LINUXKM_LKCAPI_REGISTER) || !defined(WOLFSSL_NO_ASM)
    /* When registering algorithms with crypto_register_skcipher() and friends,
     * or using kernel_fpu_begin_mask() and _end() to wrap vector register
     * usage, we use a "GPL" license unconditionally here to meet the GPL-only
     * requirements for those calls, satisfying license_is_gpl_compatible() (see
     * /usr/src/linux/include/linux/license.h).
     */
    MODULE_LICENSE("GPL");
#else
    MODULE_LICENSE(WOLFSSL_LICENSE);
#endif

MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);

#ifdef WC_SYM_RELOC_TABLES

extern const struct wc_reloc_table_ent wc_linuxkm_pie_text_reloc_tab[];
extern const unsigned int wc_linuxkm_pie_text_reloc_tab_length;
extern const struct wc_reloc_table_ent wc_linuxkm_pie_rodata_reloc_tab[];
extern const unsigned int wc_linuxkm_pie_rodata_reloc_tab_length;

static const struct wc_reloc_table_segments seg_map = {
    .start = 0, .end = 0,
    .text_start = (size_t)(uintptr_t)__wc_text_start,
    .text_end = (size_t)(uintptr_t)__wc_text_end,
    .text_reloc_tab.start = (size_t)(uintptr_t)wc_linuxkm_pie_text_reloc_tab,
    .text_reloc_tab.end = 0,
    .text_reloc_tab.len_start = (size_t)(uintptr_t)&wc_linuxkm_pie_text_reloc_tab_length,
    .text_reloc_tab.len_end = 0,
    .rodata_reloc_tab.start = (size_t)(uintptr_t)wc_linuxkm_pie_rodata_reloc_tab,
    .rodata_reloc_tab.end = 0,
    .rodata_reloc_tab.len_start = (size_t)(uintptr_t)&wc_linuxkm_pie_rodata_reloc_tab_length,
    .rodata_reloc_tab.len_end = 0,
#ifdef HAVE_FIPS
#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    .fips_text_start = (size_t)(uintptr_t)__wc_text_start,
    .fips_text_end = (size_t)(uintptr_t)__wc_text_end,
#else
    .fips_text_start = (size_t)(uintptr_t)wolfCrypt_FIPS_first,
    .fips_text_end = (size_t)(uintptr_t)wolfCrypt_FIPS_last,
#endif
#endif /* HAVE_FIPS */
    .rodata_start = (size_t)(uintptr_t)__wc_rodata_start,
    .rodata_end = (size_t)(uintptr_t)__wc_rodata_end,
#ifdef HAVE_FIPS
#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    .fips_rodata_start = (size_t)(uintptr_t)__wc_rodata_start,
    .fips_rodata_end = (size_t)(uintptr_t)__wc_rodata_end,
#else
    .fips_rodata_start = (size_t)(uintptr_t)wolfCrypt_FIPS_ro_start,
    .fips_rodata_end = (size_t)(uintptr_t)wolfCrypt_FIPS_ro_end,
#endif
    #if (FIPS_VERSION3_GE(6,0,0) || defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE)) && !defined(WOLFSSL_FIPS_DEV_NO_POST)
    .verifyCore_start = (uintptr_t)verifyCore,
    .verifyCore_end = (uintptr_t)verifyCore + FIPS_IN_CORE_DIGEST_SIZE*2 + 1,
    #endif
#endif /* HAVE_FIPS */
    .data_start = (size_t)(uintptr_t)__wc_rwdata_start,
    .data_end = (size_t)(uintptr_t)__wc_rwdata_end,
    .bss_start = (size_t)(uintptr_t)__wc_bss_start,
    .bss_end = (size_t)(uintptr_t)__wc_bss_end,
    .text_is_live = 1
};

ssize_t wc_linuxkm_normalize_relocations(
    const u8 *seg_in,
    size_t *seg_in_out_len,
    u8 *seg_out,
    ssize_t *cur_index_p)
{
    return wc_reloc_normalize_segment(seg_in, seg_in_out_len, seg_out, cur_index_p, &seg_map,
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
                                   &reloc_counts
#else
                                   NULL
#endif
        );
}

ssize_t wc_linuxkm_normalize_relocations_noresize(
    const u8 *seg_in,
    size_t seg_in_len,
    u8 *seg_out,
    ssize_t *cur_index_p)
{
    ssize_t ret;
    ret = wc_reloc_normalize_segment(seg_in, &seg_in_len, seg_out, cur_index_p, &seg_map,
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
                                   &reloc_counts
#else
                                   NULL
#endif
        );
    if (ret < 0)
        return ret;
    if ((size_t)ret != seg_in_len)
        return -EINVAL;
    else
        return seg_in_len;
}

#elif defined(HAVE_FIPS)

static const struct wc_reloc_table_segments seg_map = {
    .start = 0, .end = 0,
#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    .fips_text_start = (size_t)(uintptr_t)__wc_text_start,
    .fips_text_end = (size_t)(uintptr_t)__wc_text_end,
#else
    .fips_text_start = (size_t)(uintptr_t)wolfCrypt_FIPS_first,
    .fips_text_end = (size_t)(uintptr_t)wolfCrypt_FIPS_last,
#endif
#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    .fips_rodata_start = (size_t)(uintptr_t)__wc_rodata_start,
    .fips_rodata_end = (size_t)(uintptr_t)__wc_rodata_end,
#else
    .fips_rodata_start = (size_t)(uintptr_t)wolfCrypt_FIPS_ro_start,
    .fips_rodata_end = (size_t)(uintptr_t)wolfCrypt_FIPS_ro_end,
#endif
    #if (FIPS_VERSION3_GE(6,0,0) || defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE)) && !defined(WOLFSSL_FIPS_DEV_NO_POST)
    .verifyCore_start = (uintptr_t)verifyCore,
    .verifyCore_end = (uintptr_t)verifyCore + FIPS_IN_CORE_DIGEST_SIZE*2 + 1
    #endif
};

#endif /* !WC_SYM_RELOC_TABLES && HAVE_FIPS */

#ifdef WC_LINUXKM_USE_HEAP_WRAPPERS

#ifndef USE_KVREALLOC
    #error WC_LINUXKM_USE_HEAP_WRAPPERS requires USE_KVREALLOC
#endif

void *wc_linuxkm_malloc(size_t size)
{
    return kvmalloc_node(WC_LINUXKM_ROUND_UP_P_OF_2(size), (wc_linuxkm_can_block() ? GFP_KERNEL : GFP_ATOMIC), NUMA_NO_NODE);
}

void wc_linuxkm_free(void *ptr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
    if (wc_linuxkm_can_block())
        kvfree(ptr);
    else
        kvfree_atomic(ptr);
#else
    kvfree(ptr);
#endif
}

void *wc_linuxkm_realloc(void *ptr, size_t newsize)
{
    return kvrealloc(ptr, WC_LINUXKM_ROUND_UP_P_OF_2(newsize), (wc_linuxkm_can_block() ? GFP_KERNEL : GFP_ATOMIC));
}

size_t wc_linuxkm_malloc_usable_size(void *ptr)
{
    if ((ptr == NULL) || is_vmalloc_addr(ptr)) {
#ifdef CONFIG_HAVE_KPROBES
        static typeof(find_vm_area) *find_vm_area_ptr = NULL;
        if (find_vm_area_ptr == NULL) {
            find_vm_area_ptr = my_kallsyms_lookup_name("find_vm_area");
            if (find_vm_area_ptr == NULL)
                return 0;
        }
        if (ptr == NULL)
            return 0;
        else {
            struct vm_struct *vm = find_vm_area_ptr(ptr);
            if (vm)
                return get_vm_area_size(vm);
            else
                return 0;
        }
#else
        return 0;
#endif
    }
    else {
        return ksize(ptr);
    }
}

#endif /* WC_LINUXKM_USE_HEAP_WRAPPERS */

#ifdef WC_SYM_RELOC_TABLES

/* get_current() is an inline or macro, depending on the target -- sidestep the
 * whole issue with a wrapper func.
 */
static struct task_struct *my_get_current_thread(void) {
    return get_current();
}

/* preempt_count() is an inline function in arch/x86/include/asm/preempt.h that
 * accesses __preempt_count, which is an int array declared with
 * DECLARE_PER_CPU_CACHE_HOT.
 */
static int my_preempt_count(void) {
    return preempt_count();
}

static int set_up_wolfssl_linuxkm_pie_redirect_table(void) {
    XMEMSET(
        &wolfssl_linuxkm_pie_redirect_table,
        0,
        sizeof wolfssl_linuxkm_pie_redirect_table);

#ifdef HAVE_FIPS
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_normalize_relocations =
        wc_linuxkm_normalize_relocations;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_normalize_relocations_noresize =
        wc_linuxkm_normalize_relocations_noresize;
#endif

#ifndef __ARCH_MEMCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcmp = memcmp;
#endif
#ifndef CONFIG_FORTIFY_SOURCE
#ifndef __ARCH_MEMCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcpy = memcpy;
#endif
#ifndef __ARCH_MEMSET_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memset = memset;
#endif
#ifndef __ARCH_MEMMOVE_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memmove = memmove;
#endif
#endif /* !CONFIG_FORTIFY_SOURCE */
#ifndef __ARCH_STRCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcmp = strcmp;
#endif
#ifndef __ARCH_STRNCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncmp = strncmp;
#endif
#ifndef __ARCH_STRCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcasecmp = strcasecmp;
#endif
#ifndef __ARCH_STRNCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncasecmp = strncasecmp;
#endif
#ifndef __ARCH_STRLEN_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strlen = strlen;
#endif
#ifndef __ARCH_STRSTR_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strstr = strstr;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0)
#ifndef __ARCH_STRNCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncpy = strncpy;
#endif
#endif
#ifndef __ARCH_STRNCAT_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncat = strncat;
#endif
    wolfssl_linuxkm_pie_redirect_table.kstrtoll = kstrtoll;

    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)) || \
        (defined(RHEL_MAJOR) && \
         ((RHEL_MAJOR > 9) || ((RHEL_MAJOR == 9) && (RHEL_MINOR >= 5))))
        wolfssl_linuxkm_pie_redirect_table._printk = _printk;
    #else
        wolfssl_linuxkm_pie_redirect_table.printk = printk;
    #endif

#ifdef CONFIG_FORTIFY_SOURCE
    wolfssl_linuxkm_pie_redirect_table.__warn_printk = __warn_printk;
#endif

    wolfssl_linuxkm_pie_redirect_table.snprintf = snprintf;

    wolfssl_linuxkm_pie_redirect_table._ctype = _ctype;

#ifdef WC_LINUXKM_USE_HEAP_WRAPPERS
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_malloc = wc_linuxkm_malloc;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_free = wc_linuxkm_free;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_realloc = wc_linuxkm_realloc;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_malloc_usable_size = wc_linuxkm_malloc_usable_size;
#else /* !WC_LINUXKM_USE_HEAP_WRAPPERS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
    wolfssl_linuxkm_pie_redirect_table.kmalloc_noprof = kmalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.krealloc_node_align_noprof = krealloc_node_align_noprof;
    wolfssl_linuxkm_pie_redirect_table.kzalloc_noprof = kzalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.__kvmalloc_node_noprof = __kvmalloc_node_noprof;
    wolfssl_linuxkm_pie_redirect_table.__kmalloc_cache_noprof = __kmalloc_cache_noprof;
#ifdef HAVE_KVREALLOC
    wolfssl_linuxkm_pie_redirect_table.kvrealloc_node_align_noprof = kvrealloc_node_align_noprof;
#endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    wolfssl_linuxkm_pie_redirect_table.kmalloc_noprof = kmalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.krealloc_noprof = krealloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.kzalloc_noprof = kzalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.__kvmalloc_node_noprof = __kvmalloc_node_noprof;
    wolfssl_linuxkm_pie_redirect_table.__kmalloc_cache_noprof = __kmalloc_cache_noprof;
#ifdef HAVE_KVREALLOC
    wolfssl_linuxkm_pie_redirect_table.kvrealloc_noprof = kvrealloc_noprof;
#endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
    wolfssl_linuxkm_pie_redirect_table.kmalloc_noprof = kmalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.krealloc_noprof = krealloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.kzalloc_noprof = kzalloc_noprof;
    wolfssl_linuxkm_pie_redirect_table.kvmalloc_node_noprof = kvmalloc_node_noprof;
    wolfssl_linuxkm_pie_redirect_table.kmalloc_trace_noprof = kmalloc_trace_noprof;
#ifdef HAVE_KVREALLOC
    wolfssl_linuxkm_pie_redirect_table.kvrealloc_noprof = kvrealloc_noprof;
#endif
#else
    wolfssl_linuxkm_pie_redirect_table.kmalloc = kmalloc;
    wolfssl_linuxkm_pie_redirect_table.krealloc = krealloc;
#ifdef HAVE_KVMALLOC
    wolfssl_linuxkm_pie_redirect_table.kvmalloc_node = kvmalloc_node;
#endif
#ifdef HAVE_KVREALLOC
    wolfssl_linuxkm_pie_redirect_table.kvrealloc = kvrealloc;
#endif
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) || \
        (defined(RHEL_MAJOR) &&                                    \
         ((RHEL_MAJOR > 9) || ((RHEL_MAJOR == 9) && (RHEL_MINOR >= 5))))
        wolfssl_linuxkm_pie_redirect_table.kmalloc_trace =
            kmalloc_trace;
    #else
        wolfssl_linuxkm_pie_redirect_table.kmem_cache_alloc_trace =
            kmem_cache_alloc_trace;
        wolfssl_linuxkm_pie_redirect_table.kmalloc_order_trace =
            kmalloc_order_trace;
    #endif
#endif

    wolfssl_linuxkm_pie_redirect_table.kfree = kfree;
    wolfssl_linuxkm_pie_redirect_table.ksize = ksize;
#ifdef HAVE_KVMALLOC
    wolfssl_linuxkm_pie_redirect_table.kvfree = kvfree;
#endif

#endif /* !WC_LINUXKM_USE_HEAP_WRAPPERS */

#ifndef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    wolfssl_linuxkm_pie_redirect_table.get_random_bytes = get_random_bytes;
#endif
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.getnstimeofday =
            getnstimeofday;
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.current_kernel_time64 =
            current_kernel_time64;
    #else
        wolfssl_linuxkm_pie_redirect_table.ktime_get_coarse_real_ts64 =
            ktime_get_coarse_real_ts64;
    #endif

    wolfssl_linuxkm_pie_redirect_table.get_current = my_get_current_thread;

#if defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) && \
    (defined(CONFIG_X86) || defined(CONFIG_ARM) || defined(CONFIG_ARM64))
    wolfssl_linuxkm_pie_redirect_table.allocate_wolfcrypt_linuxkm_fpu_states = allocate_wolfcrypt_linuxkm_fpu_states;
    wolfssl_linuxkm_pie_redirect_table.wc_can_save_vector_registers_x86 = wc_can_save_vector_registers_x86;
    wolfssl_linuxkm_pie_redirect_table.free_wolfcrypt_linuxkm_fpu_states = free_wolfcrypt_linuxkm_fpu_states;
    wolfssl_linuxkm_pie_redirect_table.wc_restore_vector_registers_x86 = wc_restore_vector_registers_x86;
    wolfssl_linuxkm_pie_redirect_table.wc_save_vector_registers_x86 = wc_save_vector_registers_x86;
#elif defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS)
    #error WOLFSSL_USE_SAVE_VECTOR_REGISTERS is set for an unsupported architecture.
#endif /* WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

    #ifndef CONFIG_PREEMPT_RT
        wolfssl_linuxkm_pie_redirect_table.__mutex_init = __mutex_init;
    #else
        wolfssl_linuxkm_pie_redirect_table.__rt_mutex_init = __rt_mutex_init;
        wolfssl_linuxkm_pie_redirect_table.rt_mutex_base_init = rt_mutex_base_init;
        wolfssl_linuxkm_pie_redirect_table.rt_spin_lock = rt_spin_lock;
        wolfssl_linuxkm_pie_redirect_table.rt_spin_unlock = rt_spin_unlock;
        /* Used by the open-coded PREEMPT_RT spin_lock_bh()/spin_unlock_bh() in
         * linuxkm_wc_port.h, see the matching fields there. */
        wolfssl_linuxkm_pie_redirect_table.__local_bh_disable_ip =
            __local_bh_disable_ip;
        wolfssl_linuxkm_pie_redirect_table.__local_bh_enable_ip =
            __local_bh_enable_ip;
        /* CONFIG_DEBUG_LOCK_ALLOC, not CONFIG_PREEMPT_RT, the guard has to
         * match the field and the #define exactly.  See linuxkm_wc_port.h. */
        #ifdef CONFIG_DEBUG_LOCK_ALLOC
        wolfssl_linuxkm_pie_redirect_table.__rt_spin_lock_init =
            __rt_spin_lock_init;
        #endif
    #endif
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0) || \
        defined(CONFIG_DEBUG_LOCK_ALLOC)
        wolfssl_linuxkm_pie_redirect_table.mutex_lock_nested = mutex_lock_nested;
    #else
        wolfssl_linuxkm_pie_redirect_table.mutex_lock = mutex_lock;
    #endif
    wolfssl_linuxkm_pie_redirect_table.mutex_unlock = mutex_unlock;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.mutex_destroy = mutex_destroy;
    #endif

#ifdef HAVE_FIPS

#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    /* use __wc_text_start and __wc_text_end, not wolfCrypt_FIPS_first and
     * wolfCrypt_FIPS_last, thereby including the whole container in the HMAC
     * span.  Note there are runtime asserts at entry to wolfssl_init() above
     * confirming that __wc_*_{start,end} correctly contain the wolfCrypt_FIPS_*
     * fenceposts.
     */
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_first =
        __wc_text_start;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_last =
        __wc_text_end;
    /* ditto for wolfCrypt_FIPS_ro_start and wolfCrypt_FIPS_ro_end. */
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ro_start =
        &__wc_rodata_start;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ro_end =
        &__wc_rodata_end;
#else
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_first =
        wolfCrypt_FIPS_first;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_last =
        wolfCrypt_FIPS_last;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ro_start =
        &wolfCrypt_FIPS_ro_start;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ro_end =
        &wolfCrypt_FIPS_ro_end;
#endif

    #if FIPS_VERSION3_GE(6,0,0)
#ifndef NO_AES
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_AES_sanity =
        wolfCrypt_FIPS_AES_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_aes_ro_sanity =
        &wolfCrypt_FIPS_aes_ro_sanity;
#if defined(WOLFSSL_CMAC) && defined(WOLFSSL_AES_DIRECT)
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_CMAC_sanity =
        wolfCrypt_FIPS_CMAC_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_cmac_ro_sanity =
        &wolfCrypt_FIPS_cmac_ro_sanity;
#endif
#endif
#ifndef NO_DH
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_DH_sanity =
        wolfCrypt_FIPS_DH_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_dh_ro_sanity =
        &wolfCrypt_FIPS_dh_ro_sanity;
#endif
#ifdef HAVE_ECC
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ECC_sanity =
        wolfCrypt_FIPS_ECC_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ecc_ro_sanity =
        &wolfCrypt_FIPS_ecc_ro_sanity;
#endif
#ifdef HAVE_ED25519
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ED25519_sanity =
        wolfCrypt_FIPS_ED25519_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ed25519_ro_sanity =
        &wolfCrypt_FIPS_ed25519_ro_sanity;
#endif
#ifdef HAVE_ED448
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ED448_sanity =
        wolfCrypt_FIPS_ED448_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ed448_ro_sanity =
        &wolfCrypt_FIPS_ed448_ro_sanity;
#endif
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_HMAC_sanity =
        wolfCrypt_FIPS_HMAC_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_hmac_ro_sanity =
        &wolfCrypt_FIPS_hmac_ro_sanity;
#ifndef NO_KDF
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_KDF_sanity =
        wolfCrypt_FIPS_KDF_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_kdf_ro_sanity =
        &wolfCrypt_FIPS_kdf_ro_sanity;
#endif
#ifdef HAVE_PBKDF2
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_PBKDF_sanity =
        wolfCrypt_FIPS_PBKDF_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_pbkdf_ro_sanity =
        &wolfCrypt_FIPS_pbkdf_ro_sanity;
#endif
#ifdef HAVE_HASHDRBG
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_DRBG_sanity =
        wolfCrypt_FIPS_DRBG_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_drbg_ro_sanity =
        &wolfCrypt_FIPS_drbg_ro_sanity;
#endif
#ifndef NO_RSA
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_RSA_sanity =
        wolfCrypt_FIPS_RSA_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_rsa_ro_sanity =
        &wolfCrypt_FIPS_rsa_ro_sanity;
#endif
#ifndef NO_SHA
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_SHA_sanity =
        wolfCrypt_FIPS_SHA_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_sha_ro_sanity =
        &wolfCrypt_FIPS_sha_ro_sanity;
#endif
#ifndef NO_SHA256
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_SHA256_sanity =
        wolfCrypt_FIPS_SHA256_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_sha256_ro_sanity =
        &wolfCrypt_FIPS_sha256_ro_sanity;
#endif
#ifdef WOLFSSL_SHA512
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_SHA512_sanity =
        wolfCrypt_FIPS_SHA512_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_sha512_ro_sanity =
        &wolfCrypt_FIPS_sha512_ro_sanity;
#endif
#ifdef WOLFSSL_SHA3
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_SHA3_sanity =
        wolfCrypt_FIPS_SHA3_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_sha3_ro_sanity =
        &wolfCrypt_FIPS_sha3_ro_sanity;
#endif

#ifndef WOLFSSL_FIPS_DEV_NO_POST
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_FT_sanity =
        wolfCrypt_FIPS_FT_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_ft_ro_sanity =
        &wolfCrypt_FIPS_ft_ro_sanity;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_f_ro_sanity =
        &wolfCrypt_FIPS_f_ro_sanity;
    wolfssl_linuxkm_pie_redirect_table.wc_RunAllCast_fips =
        wc_RunAllCast_fips;
#endif /* !WOLFSSL_FIPS_DEV_NO_POST */

    #endif /* FIPS_VERSION3_GE(6,0,0) */
#endif

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)
    wolfssl_linuxkm_pie_redirect_table.GetCA = GetCA;
#ifndef NO_SKID
    wolfssl_linuxkm_pie_redirect_table.GetCAByName = GetCAByName;
#ifdef HAVE_OCSP
    wolfssl_linuxkm_pie_redirect_table.GetCAByKeyHash = GetCAByKeyHash;
#endif /* HAVE_OCSP */
#endif /* NO_SKID */
#ifdef WOLFSSL_AKID_NAME
    wolfssl_linuxkm_pie_redirect_table.GetCAByAKID = GetCAByAKID;
#endif /* WOLFSSL_AKID_NAME */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    wolfssl_linuxkm_pie_redirect_table.wolfSSL_X509_NAME_add_entry_by_NID = wolfSSL_X509_NAME_add_entry_by_NID;
    wolfssl_linuxkm_pie_redirect_table.wolfSSL_X509_NAME_free = wolfSSL_X509_NAME_free;
    wolfssl_linuxkm_pie_redirect_table.wolfSSL_X509_NAME_new_ex = wolfSSL_X509_NAME_new_ex;
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#ifdef HAVE_OCSP
    wolfssl_linuxkm_pie_redirect_table.CheckOcspResponder = CheckOcspResponder;
#endif

#endif /* !WOLFCRYPT_ONLY && !NO_CERTS */

    wolfssl_linuxkm_pie_redirect_table.dump_stack = dump_stack;

    wolfssl_linuxkm_pie_redirect_table.preempt_count = my_preempt_count;
#ifndef _raw_spin_lock_bh
    wolfssl_linuxkm_pie_redirect_table._raw_spin_lock_bh = _raw_spin_lock_bh;
#endif
#ifndef _raw_spin_unlock_bh
    wolfssl_linuxkm_pie_redirect_table._raw_spin_unlock_bh = _raw_spin_unlock_bh;
#endif
/* CONFIG_DEBUG_SPINLOCK, not CONFIG_DEBUG_LOCK_ALLOC, see the matching
 * guard in linuxkm_wc_port.h.  All three sites (field, assignment, #define)
 * must name the same macro or the assignment writes a field that does not
 * exist. */
#ifdef CONFIG_DEBUG_SPINLOCK
    wolfssl_linuxkm_pie_redirect_table.__raw_spin_lock_init = __raw_spin_lock_init;
#endif
    wolfssl_linuxkm_pie_redirect_table._cond_resched = _cond_resched;

#ifndef WOLFSSL_LINUXKM_USE_MUTEXES
    wolfssl_linuxkm_pie_redirect_table.wc_lkm_LockMutex = wc_lkm_LockMutex;
#endif

#ifdef CONFIG_ARM64
#ifndef CONFIG_ARCH_TEGRA
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    wolfssl_linuxkm_pie_redirect_table.alt_cb_patch_nops = alt_cb_patch_nops;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) */
    wolfssl_linuxkm_pie_redirect_table.queued_spin_lock_slowpath = queued_spin_lock_slowpath;
#endif
#endif

    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_can_block = wc_linuxkm_can_block;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_sig_ignore_begin = wc_linuxkm_sig_ignore_begin;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_sig_ignore_end = wc_linuxkm_sig_ignore_end;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_check_for_intr_signals = wc_linuxkm_check_for_intr_signals;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_relax_long_loop = wc_linuxkm_relax_long_loop;
#ifdef LINUXKM_RBGC
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_irq_save = wc_linuxkm_irq_save;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_irq_restore = wc_linuxkm_irq_restore;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_cpu_id = wc_linuxkm_cpu_id;
    wolfssl_linuxkm_pie_redirect_table.wc_linuxkm_mono_ns = wc_linuxkm_mono_ns;
#endif

#ifdef CONFIG_KASAN
    wolfssl_linuxkm_pie_redirect_table.kasan_disable_current = kasan_disable_current;
    wolfssl_linuxkm_pie_redirect_table.kasan_enable_current = kasan_enable_current;
#endif

    /* runtime assert that the table has no null slots after initialization. */
    {
        unsigned long *i;
        static_assert(sizeof(unsigned long) == sizeof(void *),
                      "unexpected pointer size");
        for (i = (unsigned long *)&wolfssl_linuxkm_pie_redirect_table;
             i < (unsigned long *)&wolfssl_linuxkm_pie_redirect_table._last_slot;
             ++i)
            if (*i == 0) {
                pr_err("ERROR: wolfCrypt container redirect table initialization was "
                       "incomplete [%u].\n",
                       (unsigned)(i-(unsigned long *)&wolfssl_linuxkm_pie_redirect_table));
                return -EFAULT;
            }
    }

    return 0;
}

#endif /* WC_SYM_RELOC_TABLES */

#if defined(HAVE_FIPS) && defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE)

#include <wolfssl/wolfcrypt/coding.h>

PRAGMA_GCC_DIAG_PUSH
PRAGMA_GCC("GCC diagnostic ignored \"-Wnested-externs\"")
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-arith\"")
PRAGMA_GCC("GCC diagnostic ignored \"-Wunused-parameter\"")
#include <crypto/hash.h>
PRAGMA_GCC_DIAG_POP

/* failsafe definitions for FIPS <5.3 */
#ifndef FIPS_IN_CORE_DIGEST_SIZE
    #ifndef NO_SHA256
        #define FIPS_IN_CORE_DIGEST_SIZE 32
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA256
        #define FIPS_IN_CORE_KEY_SZ      32
        #define FIPS_IN_CORE_VERIFY_SZ   FIPS_IN_CORE_KEY_SZ
    #elif defined(WOLFSSL_SHA384)
        #define FIPS_IN_CORE_DIGEST_SIZE 48
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA384
        #define FIPS_IN_CORE_KEY_SZ      48
        #define FIPS_IN_CORE_VERIFY_SZ   FIPS_IN_CORE_KEY_SZ
    #else
        #error Unsupported FIPS hash alg.
    #endif
#endif

extern const char coreKey[FIPS_IN_CORE_KEY_SZ*2 + 1];
extern const unsigned int wolfCrypt_FIPS_ro_start[];
extern const unsigned int wolfCrypt_FIPS_ro_end[];

static int linux_fips_hmac_setkey(struct shash_desc *desc, const byte *key, word32 key_len) {
    int ret = crypto_shash_setkey(desc->tfm, key, key_len);
    if (ret) {
        pr_err("ERROR: crypto_shash_setkey failed: err %d\n", ret);
        return BAD_STATE_E;
    }

    ret = crypto_shash_init(desc);
    if (ret) {
        pr_err("ERROR: crypto_shash_init failed: err %d\n", ret);
        return BAD_STATE_E;
    }
    return 0;
}
static int linux_fips_hmac_update(struct shash_desc *desc, const byte *in, word32 in_len) {
    int ret = crypto_shash_update(desc, in, in_len);
    if (ret) {
        pr_err("ERROR: crypto_shash_update failed: err %d\n", ret);
        return BAD_STATE_E;
    }
    else
        return 0;
}
static int linux_fips_hmac_final(struct shash_desc *desc, byte *out, word32 out_sz) {
    int ret;

    (void)out_sz;

    ret = crypto_shash_final(desc, out);
    if (ret) {
        pr_err("ERROR: crypto_shash_final failed: err %d\n", ret);
        return BAD_STATE_E;
    }
    else
        return 0;
}

static int updateFipsHash(void)
{
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    int ret;
    word32 verifyCore_size = XSTRLEN(verifyCore) + 1;
    char *old_verifyCore = XMALLOC(verifyCore_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (old_verifyCore == NULL)
        return MEMORY_E;
    XMEMCPY(old_verifyCore, verifyCore, verifyCore_size);

    wc_static_assert(((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA256) ||
                     ((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA384) ||
                     ((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA512) ||
                     ((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA3_256) ||
                     ((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA3_384) ||
                     ((unsigned)FIPS_IN_CORE_HASH_TYPE == (unsigned)WC_SHA3_512));

    switch ((unsigned)FIPS_IN_CORE_HASH_TYPE) {
    case (unsigned)WC_SHA256:
        tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
        break;
    case (unsigned)WC_SHA384:
        tfm = crypto_alloc_shash("hmac(sha384)", 0, 0);
        break;
    case (unsigned)WC_SHA512:
        tfm = crypto_alloc_shash("hmac(sha512)", 0, 0);
        break;
    case (unsigned)WC_SHA3_256:
        tfm = crypto_alloc_shash("hmac(sha3-256)", 0, 0);
        break;
    case (unsigned)WC_SHA3_384:
        tfm = crypto_alloc_shash("hmac(sha3-384)", 0, 0);
        break;
    case (unsigned)WC_SHA3_512:
        tfm = crypto_alloc_shash("hmac(sha3-512)", 0, 0);
        break;
    }

    if (IS_ERR(tfm)) {
        if (PTR_ERR(tfm) == -ENOMEM) {
            pr_err("ERROR: crypto_alloc_shash failed: out of memory\n");
            ret = MEMORY_E;
        } else if (PTR_ERR(tfm) == -ENOENT) {
            pr_err("ERROR: crypto_alloc_shash failed: target kernel is missing algorithm implementation for hash type %u\n", FIPS_IN_CORE_HASH_TYPE);
            ret = NOT_COMPILED_IN;
        } else {
            pr_err("ERROR: crypto_alloc_shash failed with ret %d\n", (int)PTR_ERR(tfm));
            ret = HASH_TYPE_E;
        }
        tfm = NULL;
        goto out;
    }

    {
        size_t desc_size = crypto_shash_descsize(tfm) + sizeof *desc;
        desc = XMALLOC(desc_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (desc == NULL) {
            pr_err("ERROR: failed allocating desc.\n");
            ret = MEMORY_E;
            goto out;
        }
        XMEMSET(desc, 0, desc_size);
    }

    desc->tfm = tfm;

    ret = wc_fips_generate_hash(
        &seg_map,
        FIPS_IN_CORE_DIGEST_SIZE,
        coreKey,
        desc,
        /* NOLINTBEGIN(clang-diagnostic-cast-function-type-strict) */
        (wc_fips_verifyCore_hmac_setkey_fn)linux_fips_hmac_setkey,
        (wc_fips_verifyCore_hmac_update_fn)linux_fips_hmac_update,
        (wc_fips_verifyCore_hmac_final_fn)linux_fips_hmac_final,
        /* NOLINTEND(clang-diagnostic-cast-function-type-strict) */
        verifyCore,
        &verifyCore_size,
#if defined(DEBUG_LINUXKM_PIE_SUPPORT) && defined(WC_SYM_RELOC_TABLES)
        &reloc_counts
#else
        NULL
#endif
        );

    if (ret < 0)
        goto out;

    if (strcmp(old_verifyCore, verifyCore) == 0) {
#if defined(DEBUG_LINUXKM_PIE_SUPPORT) || defined(WOLFSSL_LINUXKM_VERBOSE_DEBUG)
        pr_info("updateFipsHash: verifyCore already matches [%s]\n", verifyCore);
#else
        pr_info("updateFipsHash: verifyCore already matches.\n");
#endif
    }
    else {
#if defined(DEBUG_LINUXKM_PIE_SUPPORT) || defined(WOLFSSL_LINUXKM_VERBOSE_DEBUG)
        pr_info("updateFipsHash: verifyCore updated [%s].\n", verifyCore);
#else
        pr_info("updateFipsHash: verifyCore updated.\n");
#endif
    }

    ret = 0;

  out:

    if (tfm != NULL)
        crypto_free_shash(tfm);
    XFREE(desc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(old_verifyCore, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* HAVE_FIPS && WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE */

#ifdef CONFIG_HAVE_KPROBES

static WC_MAYBE_UNUSED void *my_kallsyms_lookup_name(const char *name) {
    static typeof(kallsyms_lookup_name) *kallsyms_lookup_name_ptr = NULL;
    static struct kprobe kallsyms_lookup_name_kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    unsigned long a;

    if (! kallsyms_lookup_name_ptr) {
        int ret;

        if (! wc_linuxkm_can_block())
            return NULL;

        kallsyms_lookup_name_kp.addr = NULL;
        if ((ret = register_kprobe(&kallsyms_lookup_name_kp)) != 0) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            pr_err_once("ERROR: register_kprobe(&kallsyms_lookup_name_kp) failed: %d\n", ret);
#endif
            return 0;
        }
        kallsyms_lookup_name_ptr = (typeof(kallsyms_lookup_name_ptr))kallsyms_lookup_name_kp.addr;
        unregister_kprobe(&kallsyms_lookup_name_kp);
        if (! kallsyms_lookup_name_ptr) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            pr_err_once("ERROR: kallsyms_lookup_name_kp.addr is null.\n");
#endif
            return 0;
        }
    }

    a = kallsyms_lookup_name_ptr(name);
    return (void *)a;
}

#endif /* CONFIG_HAVE_KPROBES */

#ifdef HAVE_FIPS

static ssize_t FIPS_rerun_self_test_handler(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    int ret;

    (void)kobj;
    (void)attr;

    /* only recognize "1" and "1\n". */
    if ((count < 1) || (count > 2) ||
        (buf[0] != '1') ||
        ((count == 2) && (buf[1] != '\n')))
    {
        return -EINVAL;
    }

    pr_info("wolfCrypt: rerunning FIPS self-test on command.\n");

    if (WC_SIG_IGNORE_BEGIN() >= 0) {
        ret = wolfCrypt_IntegrityTest_fips();
        (void)WC_SIG_IGNORE_END();
    }
    else {
        pr_err("ERROR: WC_SIG_IGNORE_BEGIN() failed.\n");
        ret = -1;
    }
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_IntegrityTest_fips: error %d\n", ret);
        return -EINVAL;
    }

    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("ERROR: wolfCrypt_GetStatus_fips() failed with code %d: %s\n", ret, wc_GetErrorString(ret));
        if (ret == WC_NO_ERR_TRACE(IN_CORE_FIPS_E))
            return -ELIBBAD;
        else
            return -EINVAL;
    }

    ret = wc_RunAllCast_fips();
    if (ret != 0) {
        pr_err("ERROR: wc_RunAllCast_fips() failed with return value %d\n", ret);
        return -EINVAL;
    }

    pr_info("wolfCrypt FIPS re-self-test succeeded: all algorithms verified and available.\n");

    return count;
}

#ifdef FIPS_OPTEST

typedef struct test_func_args {
    int return_code;
} test_func_args;

static ssize_t FIPS_optest_trig_handler(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, const size_t count)
{
    int ret;
    int argc;
    const char *argv[3];
    /* Textual sysfs error code + NUL, plus headroom.  Fits the v7.0.0 5-char
     * codes (e.g. ML_KEM_PCT_E) that the old [5] rejected. */
    char code_buf[8];
    size_t corrected_count;
    int i;

    (void)kobj;
    (void)attr;

    /* buf may or may not have an LF at end -- tolerate both.  there is no
     * terminating null in either case.
     */
    if (count < 1)
        return -EINVAL;
    if (buf[count-1] == '\n')
        corrected_count = count - 1;
    else
        corrected_count = count;
    if ((corrected_count < 1) || (corrected_count > (sizeof(code_buf) - 1)))
        return -EINVAL;
    XMEMCPY(code_buf, buf, corrected_count);
    code_buf[corrected_count] = 0;

    if (strspn(code_buf, "-0123456789") != corrected_count)
        return -EINVAL;

    argv[0] = "./optest";
    argv[1] = "0";
    argv[2] = code_buf;
    argc = 3;

    printf("OK, testing code %s\n", code_buf);

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
    {
        unsigned long stack_usage;
        stack_usage = wc_linuxkm_stack_current();
        pr_info("STACK INFO: usage at call to linuxkm_op_test_1(): %lu of %lu total\n", stack_usage, THREAD_SIZE);
        wc_linuxkm_stack_hwm_prepare(0xee);
    #endif

    ret = linuxkm_op_test_1(argc, &argv[0]);

    #ifdef WC_LINUXKM_HAVE_STACK_DEBUG
        stack_usage = wc_linuxkm_stack_hwm_measure_rel(0xee);
        pr_info("STACK INFO: rel usage by linuxkm_op_test_1(): %lu\n", stack_usage);
        /* shush up false stack HWM reading by kernel: */
        wc_linuxkm_stack_hwm_prepare(0);
    }
    #endif

    printf("ret of op_test = %d\n", ret);

    /* reload the library in memory and re-init state */
    printf("Reloading the module in memory (equivalent to power "
           "cycle)\n");
    WOLFSSL_ATOMIC_STORE(*conTestFailure_ptr, 0);
    for (i = 0; i < FIPS_CAST_COUNT; ++i)
        fipsCastStatus_put(i, FIPS_CAST_STATE_INIT);
    /* note, must call fipsEntry() here, not wolfCrypt_IntegrityTest_fips(),
     * because wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256) isn't available
     * anymore.
     */
    if (WC_SIG_IGNORE_BEGIN() >= 0) {
        fipsEntry();
        (void)WC_SIG_IGNORE_END();
    }
    else
        pr_err("ERROR: WC_SIG_IGNORE_BEGIN() failed.\n");
    ret = wolfCrypt_GetStatus_fips();
    printf("Status indicator of library reload/powercycle: %d\n",
           ret);
    printf("Module status is: %d\n", wolfCrypt_GetStatus_fips());
    printf("Module mode is: %d\n", wolfCrypt_GetMode_fips());

    return count;
}

#endif /* FIPS_OPTEST */

#endif /* HAVE_FIPS */
