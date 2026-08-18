/* x86_vector_register_glue.c -- glue logic to save and restore vector registers
 * on x86
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

/* included by linuxkm/module_hooks.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#include <linux/printk.h>
#include <linux/ratelimit.h>

#if !defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) || !defined(CONFIG_X86)
    #error x86_vector_register_glue.c included in non-vectorized/non-x86 project.
#endif

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    #define VRG_PR_ERR_X pr_err
    #define VRG_PR_WARN_X pr_warn
#else
    #define VRG_PR_ERR_X pr_err_once
    #define VRG_PR_WARN_X pr_warn_once
#endif

static unsigned int wc_linuxkm_svr_states_n_tracked = 0;

struct wc_thread_svr_count_ent {
    volatile pid_t pid;                 /* sync pivot, __atomic access only. */
    unsigned int fpu_state;             /* plain, owner-private under the nonpreemptibility invariant. */
    volatile unsigned long reserved_at; /* volatile, read live by foreign diagnostics. */
};
struct wc_thread_svr_count_ent *wc_linuxkm_svr_states = NULL;

#define WC_SVR_COUNT_MASK     0x1fffffffU
#define WC_SVR_INHIBITED_FLAG 0x40000000U
#define WC_SVR_BH_HELD_FLAG   0x20000000U

#define WC_SVR_FREE_SLOT_PID 0
#define WC_SVR_IDLE_PID ((pid_t)(-1))
#define WC_SVR_PID_SLOT_ID() (__extension__ (task_pid_nr(current) ? : WC_SVR_IDLE_PID))

/* On targets with 64 bit longs, jiffies starts at INITIAL_JIFFIES and climbs
 * monotonically -- a zero ->reserved_at means that slot has not been reserved
 * since wc_linuxkm_allocate_svr_states().  On 32 bit long targets it
 * wraps periodically, and WC_SVR_SLOT_AGE_MS() is best effort (used only in log
 * messages).
 */
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
    #define WC_SVR_SLOT_AGE_MS(slot) ((slot)->reserved_at ? \
                                      ((long)jiffies - (long)(slot)->reserved_at) * (MSEC_PER_SEC / HZ) : \
                                      -1L)
#else
    #define WC_SVR_SLOT_AGE_MS(slot) ((slot)->reserved_at ? \
                                      (long)jiffies_to_msecs(jiffies - (slot)->reserved_at) : \
                                      -1L)
#endif

WARN_UNUSED_RESULT int wc_linuxkm_allocate_svr_states(void)
{
    if (wc_linuxkm_svr_states != NULL) {
#ifdef HAVE_FIPS
        /* see note below in wc_linuxkm_svr_state_assoc_unlikely(). */
        return 0;
#else
        static int warned_for_repeat_alloc = 0;
        if (! warned_for_repeat_alloc) {
            pr_err("BUG: attempt at repeat allocation"
                   " in wc_linuxkm_allocate_svr_states.\n");
            warned_for_repeat_alloc = 1;
        }
        return BAD_STATE_E;
#endif
    }

    wc_linuxkm_svr_states_n_tracked = nr_cpu_ids;

    wc_linuxkm_svr_states =
        (struct wc_thread_svr_count_ent *)malloc(
            wc_linuxkm_svr_states_n_tracked * sizeof(wc_linuxkm_svr_states[0]));

    if (! wc_linuxkm_svr_states) {
        pr_err("ERROR: allocation of %lu bytes for "
               "wc_linuxkm_svr_states failed.\n",
               nr_cpu_ids * sizeof(wc_linuxkm_svr_states[0]));
        return MEMORY_E;
    }

    XMEMSET(wc_linuxkm_svr_states, 0, wc_linuxkm_svr_states_n_tracked
           * sizeof(wc_linuxkm_svr_states[0]));

    return 0;
}

void wc_linuxkm_free_svr_states(void) {
    struct wc_thread_svr_count_ent *i, *i_endptr;
    pid_t i_pid;
    int seen_errors = 0;

    if (wc_linuxkm_svr_states == NULL)
        return;

    for (i = wc_linuxkm_svr_states,
             i_endptr = &wc_linuxkm_svr_states[wc_linuxkm_svr_states_n_tracked];
         i < i_endptr;
         ++i)
    {
        i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
        if (i_pid == WC_SVR_FREE_SLOT_PID)
            continue;
        if (i->fpu_state != 0) {
            pr_err("ERROR: wc_linuxkm_free_svr_states called"
                   " with nonzero state 0x%x for PID %d, age %ld ms.\n", i->fpu_state, i_pid,
                   WC_SVR_SLOT_AGE_MS(i));
            ++seen_errors;
        }
    }

    if (seen_errors > 0) {
        pr_crit("ERROR: wc_linuxkm_free_svr_states encountered"
               " %d errors -- can't free current wc_linuxkm_svr_states.\n", seen_errors);
        return;
    }

    free(wc_linuxkm_svr_states);
    wc_linuxkm_svr_states = NULL;
}

/* lock-free O(1)-lookup CPU-local storage facility for tracking recursive fpu
 * pushing/popping.
 *
 * caller must have already locked itself on its CPU before entering this, or
 * entering the streamlined inline version of it below.
 */
static struct wc_thread_svr_count_ent *wc_linuxkm_svr_state_assoc_unlikely(int create_p) {
    int my_cpu = raw_smp_processor_id();
    pid_t my_pid = WC_SVR_PID_SLOT_ID(), slot_pid;
    struct wc_thread_svr_count_ent *slot;

    {
        static int _warned_on_null = 0;
        if (wc_linuxkm_svr_states == NULL)
        {
#ifdef HAVE_FIPS
            /* FIPS needs to use SHA256 for the core verify HMAC, before
             * reaching the regular wolfCrypt_Init() logic.  to break the
             * dependency loop on intelasm builds, we allocate here.
             * this is not thread-safe and doesn't need to be.
             */
            int ret = wc_linuxkm_allocate_svr_states();
            if (ret != 0)
#endif
            {
                if (_warned_on_null == 0) {
                    pr_err("BUG: wc_linuxkm_svr_state_assoc called by PID %d"
                           " before wc_linuxkm_allocate_svr_states.\n", my_pid);
                    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                    dump_stack();
                    #endif
                    _warned_on_null = 1;
                }
                return NULL;
            }
        }
    }

    slot = &wc_linuxkm_svr_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (create_p) {
            static int _warned_on_redundant_create_p = 0;
            if (_warned_on_redundant_create_p < 10) {
                pr_err("BUG: wc_linuxkm_svr_state_assoc called with create_p=1 by"
                       " PID %d on CPU %d with CPU slot already reserved by"
                       " said PID (age %ld ms).\n", my_pid, my_cpu, WC_SVR_SLOT_AGE_MS(slot));
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
                ++_warned_on_redundant_create_p;
            }
        }
        return slot;
    }
    if (create_p) {
        if (slot_pid == WC_SVR_FREE_SLOT_PID) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            slot->reserved_at = jiffies;
            return slot;
        } else if (slot_pid == WC_SVR_IDLE_PID) {
            /* A WC_SVR_IDLE_PID reservation on a live system is always a live
             * reservation or a bug -- these reservations originate with softirq
             * handlers on the idle threads, and crashes in those handlers
             * summarily panic the kernel.
             *
             * If an idle-context cycle nonetheless goes unbalanced, there is
             * no way to recover.  The exposure is confined to this library --
             * consumers never invoke save/restore directly -- and balance is
             * an enforced invariant (single-exit discipline, fuzzer
             * coverage); this branch is that invariant's audit, not its
             * substitute.
             *
             * Ultimately, recovery is impossible because WC_SVR_IDLE_PID names a
             * context class, not a task, so nothing analogous to find_get_pid()
             * below could decide whether this record is a stale leftover or a
             * live idle-context bracket.  Recovery couldn't close the hazard
             * anyway -- the next idle-context save on this CPU fast-path would
             * match a stale record as its own live nesting and proceed without
             * kernel_fpu_begin().  A record in this state is proof of an
             * unbalanced idle-context save/restore; report it and fail.
             * Save/restore balance discipline, not runtime recovery, is what
             * keeps this branch unreachable.
             */
            pr_err_ratelimited("BUG: wc_linuxkm_svr_state_assoc_unlikely found WC_SVR_IDLE_PID in the slot for calling CPU %d PID %d (age %ld ms) requesting outermost vector register save -- CPU is acceleration-degraded.\n", my_cpu, my_pid, WC_SVR_SLOT_AGE_MS(slot));
            return NULL;
        } else {
            struct pid *slot_pid_struct;

            /* if the slot is already occupied, that can be benign-ish due to an
             * unwanted migration, or due to a process crashing in kernel mode.
             * it will require fixup either here, or by the thread that owns the
             * slot, which will happen when it releases its lock.
             */
            slot_pid_struct = find_get_pid(slot_pid);
            if (slot_pid_struct == NULL) {
                if (__atomic_compare_exchange_n(&slot->pid, &slot_pid, my_pid, 0 /* weak */, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
                    pr_warn("WARNING: wc_linuxkm_svr_state_assoc_unlikely fixed up orphaned slot on CPU %d owned by dead PID %d (age %ld ms).\n", my_cpu, slot_pid, WC_SVR_SLOT_AGE_MS(slot));
                    slot->reserved_at = jiffies;
                    return slot;
                }
            } else {
                /* drop the refcount bumped by find_get_pid(). */
                put_pid(slot_pid_struct);
            }

            {
                static int _warned_on_mismatched_pid = 0;
                if (_warned_on_mismatched_pid < 10) {
                    pr_warn("WARNING: wc_linuxkm_svr_state_assoc called by pid %d on CPU %d"
                            " but CPU slot already reserved by pid %d (age %ld ms).\n",
                            my_pid, my_cpu, slot_pid, WC_SVR_SLOT_AGE_MS(slot));
                    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                    dump_stack();
                    #endif
                    ++_warned_on_mismatched_pid;
                }
            }

            return NULL;
        }
    } else if (my_pid == WC_SVR_IDLE_PID) {
        /* unique per value, not per task - all swappers share WC_SVR_IDLE_PID, so a
         * scan match may be another CPU's live hold.
         */
        return NULL;
    } else {
        /* check for migration.  this can happen despite our best efforts if any
         * I/O occurred while locked, e.g. kernel messages like "uninitialized
         * urandom read".  since we're locked now, we can safely migrate the
         * entry in wc_linuxkm_svr_states[], freeing up the slot on the previous
         * cpu.
         */
        unsigned int cpu_i;
        for (cpu_i = 0; cpu_i < wc_linuxkm_svr_states_n_tracked; ++cpu_i) {
            if (__atomic_load_n(
                    &wc_linuxkm_svr_states[cpu_i].pid,
                    __ATOMIC_CONSUME)
                == my_pid)
            {
                wc_linuxkm_svr_states[my_cpu] = wc_linuxkm_svr_states[cpu_i];
                __atomic_store_n(&wc_linuxkm_svr_states[cpu_i].fpu_state, 0,
                                 __ATOMIC_RELEASE);
                __atomic_store_n(&wc_linuxkm_svr_states[cpu_i].pid, WC_SVR_FREE_SLOT_PID,
                                 __ATOMIC_RELEASE);
                /* don't clear the .reserved_at member -- it's invalidated by
                 * the .pid assignment, and it might prove useful
                 * forensically. */
                return &wc_linuxkm_svr_states[my_cpu];
            }
        }
        return NULL;
    }
}

static inline struct wc_thread_svr_count_ent *wc_linuxkm_svr_state_assoc(
    int create_p, int assume_fpu_began)
{
    int my_cpu = raw_smp_processor_id(); /* my_cpu is only trustworthy if we're
                                          * already nonpreemptible -- we'll
                                          * determine that soon enough by
                                          * checking if the pid matches or,
                                          * failing that, if create_p.
                                          */
    pid_t my_pid, slot_pid;
    struct wc_thread_svr_count_ent *slot;

    if (unlikely(wc_linuxkm_svr_states == NULL)) {
        if (! assume_fpu_began) {
            /* this was just a quick check for whether we're in a recursive
             * wc_save_vector_registers_x86().  we're not.
             */
            return NULL;
        }
        else
            return wc_linuxkm_svr_state_assoc_unlikely(create_p);
    }

    my_pid = WC_SVR_PID_SLOT_ID();

    slot = &wc_linuxkm_svr_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (unlikely(create_p))
            return wc_linuxkm_svr_state_assoc_unlikely(create_p);
        else
            return slot;
    }
    if (! assume_fpu_began) {
        /* this was just a quick check for whether we're in a recursive
         * wc_save_vector_registers_x86().  we're not.
         *
         * if we're in a softirq context, we'll always wind up here, because
         * processes with entries in wc_linuxkm_svr_states[] always have
         * softirqs inhibited.
         */
        return NULL;
    }
    if (likely(create_p)) {
        if (likely(slot_pid == WC_SVR_FREE_SLOT_PID)) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            slot->reserved_at = jiffies;
            return slot;
        } else {
            return wc_linuxkm_svr_state_assoc_unlikely(create_p);
        }
    } else {
        return wc_linuxkm_svr_state_assoc_unlikely(create_p);
    }
}

static void wc_linuxkm_svr_state_release_unlikely(
    struct wc_thread_svr_count_ent *ent)
{
    if (ent->fpu_state != 0) {
        static int warned_nonzero_fpu_state = 0;
        if (! warned_nonzero_fpu_state) {
            VRG_PR_ERR_X("ERROR: wc_linuxkm_svr_state_release for pid %d on CPU %d"
                         " with nonzero fpu_state 0x%x (age %ld ms).\n", ent->pid,
                         raw_smp_processor_id(), ent->fpu_state, WC_SVR_SLOT_AGE_MS(ent));
            warned_nonzero_fpu_state = 1;
        }
        ent->fpu_state = 0;
    }
    __atomic_store_n(&ent->pid, WC_SVR_FREE_SLOT_PID, __ATOMIC_RELEASE);
}

static inline void wc_linuxkm_svr_state_release(
    struct wc_thread_svr_count_ent *ent)
{
    if (unlikely(ent->fpu_state != 0))
        return wc_linuxkm_svr_state_release_unlikely(ent);
    __atomic_store_n(&ent->pid, WC_SVR_FREE_SLOT_PID, __ATOMIC_RELEASE);
}

/* Note that a volatile is used here deliberately, rather than an atomic, to
 * avoid frivolous overhead.  wc_svr_disallowed_count is intrinsically only
 * precise and reliable when the module is single-threaded (i.e. during module
 * wolfssl_init()).  Incrementing it atomically would gain nothing meaningful
 * but incur the atomic tax.
 */
static volatile unsigned long long int wc_svr_disallowed_count = 0;

void wc_svr_disallowed_count_reset(void) {
    wc_svr_disallowed_count = 0;
}

unsigned long long int wc_svr_disallowed_count_current(void) {
    return wc_svr_disallowed_count;
}

static inline void wc_svr_disallowed_count_increment(void) {
    wc_svr_disallowed_count = wc_svr_disallowed_count + 1;
}

WARN_UNUSED_RESULT int wc_can_save_vector_registers_x86(void)
{
    struct wc_thread_svr_count_ent *pstate;

    /* check for hard interrupt context (unusable current->pid) preemptively.
     * if we're in a softirq context we'll catch that below with
     * a second preempt_count() check.
     */
    if ((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) {
#ifdef DEBUG_VECTOR_REGISTER_ACCESS_HARDIRQ_INFO
        pr_info("HARDIRQ_INFO: wc_can_save_vector_registers_x86() with preempt_count 0x%x, PID %d, CPU %d\n",
                preempt_count(), task_pid_nr(current), raw_smp_processor_id());
        dump_stack();
#endif
        wc_svr_disallowed_count_increment();
        return 0;
    }

    /* Check if we're already saved, per wc_linuxkm_svr_states. */
    pstate = wc_linuxkm_svr_state_assoc(0, 0);

    if ((pstate != NULL) && (pstate->fpu_state != 0U)) {
        if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
            wc_svr_disallowed_count_increment();
            return 0;
        }
        if (unlikely((pstate->fpu_state & WC_SVR_COUNT_MASK)
                     == WC_SVR_COUNT_MASK))
        {
            /* would overflow */
            wc_svr_disallowed_count_increment();
            return 0;
        } else {
            return 1;
        }
    }

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (SAVE_VECTOR_REGISTERS2_fuzzer() != 0) {
        wc_svr_disallowed_count_increment();
        return 0;
    }
#endif

    if ((preempt_count() == 0) || may_use_simd())
        return 1;
    else {
        wc_svr_disallowed_count_increment();
        return 0;
    }
}

WARN_UNUSED_RESULT int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_svr_count_ent *pstate;
    unsigned int new_state_flags = 0;

    /* Check for hard interrupt context (unusable current->pid) preemptively.
     * If we're in a softirq context we'll catch that below with
     * a second look at preempt_count().
     *
     * Note that this is not actually an abnormal condition in any way --
     * e.g. with LINUXKM_DRBG_GET_RANDOM_BYTES, get_random_u32() and the
     * like called from hard IRQ handlers land here, and we return
     * WC_ACCEL_INHIBIT_E for graceful fallback to C.
     */
    if ((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) {
#ifdef DEBUG_VECTOR_REGISTER_ACCESS_HARDIRQ_INFO
        pr_info("HARDIRQ_INFO: wc_save_vector_registers_x86() with preempt_count 0x%x, PID %d, CPU %d\n",
                preempt_count(), task_pid_nr(current), raw_smp_processor_id());
        dump_stack();
#endif
        wc_svr_disallowed_count_increment();
        return WC_ACCEL_INHIBIT_E;
    }

    pstate = wc_linuxkm_svr_state_assoc(0, 0);

    /* allow for nested calls */
    if (pstate && (pstate->fpu_state != 0U)) {
        if (unlikely((pstate->fpu_state & WC_SVR_BH_HELD_FLAG) && (softirq_count() == 0))) {
            VRG_PR_ERR_X("BUG: wc_save_vector_registers_x86(): zero softirq_count in nested call (depth %u, age %ld ms) after local_bh_disable() on CPU %d.\n",
                         (pstate->fpu_state & WC_SVR_COUNT_MASK),
                         WC_SVR_SLOT_AGE_MS(pstate),
                         raw_smp_processor_id());
        }
        if (unlikely(flags & WC_SVR_FLAG_MAYBE_INHIBIT)) {
            VRG_PR_WARN_X("BUG: wc_save_vector_registers_x86() called by pid %d on CPU %d "
                          "with _MAYBE_INHIBIT flag in nested call (depth %u, age %ld ms).\n", task_pid_nr(current),
                          raw_smp_processor_id(),
                          (pstate->fpu_state & WC_SVR_COUNT_MASK),
                          WC_SVR_SLOT_AGE_MS(pstate));
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
            wc_svr_disallowed_count_increment();
            return BAD_STATE_E;
        }
        if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
            /* don't allow recursive inhibit calls when already inhibited --
             * it would add no functionality and require keeping a separate
             * count of inhibit recursions.
             */
            wc_svr_disallowed_count_increment();
            return WC_ACCEL_INHIBIT_E;
        }
        if (unlikely((pstate->fpu_state & WC_SVR_COUNT_MASK)
                     == WC_SVR_COUNT_MASK))
        {
            pr_err("ERROR: wc_save_vector_registers_x86 recursion register overflow for "
                   "pid %d on CPU %d (age %ld ms).\n", pstate->pid, raw_smp_processor_id(),
                   WC_SVR_SLOT_AGE_MS(pstate));
            wc_svr_disallowed_count_increment();
            return BAD_STATE_E;
        }
        if (unlikely(flags & WC_SVR_FLAG_INHIBIT)) {
            ++pstate->fpu_state;
            pstate->fpu_state |= WC_SVR_INHIBITED_FLAG;
            wc_svr_disallowed_count_increment();
            return 0;
        }
        else {
            ++pstate->fpu_state;
            return 0;
        }
        __builtin_unreachable();
    }

#ifndef DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON
    /* EINTR during optest, which is exercised by the kernel test harness, acts
     * like a failed save, which would emit (and indeed be) an ERROR in
     * DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON builds.
     */
    {
        int ret = WC_CHECK_FOR_INTR_SIGNALS();
        if (ret) {
            wc_svr_disallowed_count_increment();
            return ret;
        }
    }
#endif

    WC_RELAX_LONG_LOOP();

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (flags & WC_SVR_FLAG_FUZZ) {
        int ret = SAVE_VECTOR_REGISTERS2_fuzzer();
        if (ret != 0) {
            if (flags & WC_SVR_FLAG_MAYBE_INHIBIT)
                flags |= WC_SVR_FLAG_INHIBIT;
            else {
                wc_svr_disallowed_count_increment();
                return ret;
            }
        }
    }
#endif

    if ((flags & WC_SVR_FLAG_MAYBE_INHIBIT) &&
        ((preempt_count() != 0) && !may_use_simd()))
    {
        wc_svr_disallowed_count_increment();
        return WC_ACCEL_INHIBIT_E; /* not an error here, just a
                                    * short-circuit result.
                                    */
    }

    if (flags & WC_SVR_FLAG_INHIBIT) {
        if ((preempt_count() != 0) && !may_use_simd()) {
            wc_svr_disallowed_count_increment();
            return WC_ACCEL_INHIBIT_E; /* not an error here, just a
                                        * short-circuit result.
                                        */
        }
        /* we need to inhibit migration and softirqs here to assure that we can
         * support recursive calls safely, i.e. without mistaking a softirq
         * context for a recursion.
         *
         * pre-5.11, migrate_disable() either doesn't exist or is a no-op --
         * there, we lean on pinning from the bh offset or irq disablement.
         */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
        migrate_disable();
        #endif

        if (! irqs_disabled()) {
            local_bh_disable();
            new_state_flags |= WC_SVR_BH_HELD_FLAG;

            if (softirq_count() == 0) {
                VRG_PR_ERR_X("BUG: wc_save_vector_registers_x86(): zero softirq_count in outermost call after local_bh_disable() on CPU %d.\n",
                             raw_smp_processor_id());
                local_bh_enable();
                #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
                migrate_enable();
                #endif
                wc_svr_disallowed_count_increment();
                return WC_ACCEL_INHIBIT_E;
            }
        }

        pstate = wc_linuxkm_svr_state_assoc(1, 1);
        if (pstate == NULL) {
            if (new_state_flags & WC_SVR_BH_HELD_FLAG)
                local_bh_enable();
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_enable();
            #endif
            wc_svr_disallowed_count_increment();
            return BAD_STATE_E;
        }

        pstate->fpu_state =
            (WC_SVR_INHIBITED_FLAG | new_state_flags) + 1U;

        wc_svr_disallowed_count_increment();
        return 0;
    }

    if ((preempt_count() == 0) || may_use_simd()) {
        /* fpregs_lock() calls either local_bh_disable() or preempt_disable()
         * depending on CONFIG_PREEMPT_RT -- we call both, explicitly, with the
         * sole exception that local_bh_disable() is necessarily omitted if the
         * caller has irqs_disabled().  This exception is critical: without it,
         * a caller in a critical section get local_bh_enable()d when it calls
         * wc_restore_vector_registers_x86(), reenabling interrupts during its
         * critical section.
         *
         * Note: pre-6.15, kernel_fpu_begin() is preempt_disable()-only -- it
         * never defers softirqs, and on !CONFIG_PREEMPT_COUNT configs it leaves
         * preempt_count() zero, which would break our locking algorithm.  6.15+
         * (mainline commit d02198550423) disables bh in kernel_fpu_begin(),
         * except for irqs-off callers.  We sidestep the variance completely by
         * making the disables ourselves; helpfully, all these calls are
         * recursion-safe.
         */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
        migrate_disable();
        #endif

        if (! irqs_disabled()) {
            local_bh_disable();
            new_state_flags |= WC_SVR_BH_HELD_FLAG;
        }

        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_disable();
        #endif
        kernel_fpu_begin();
        pstate = wc_linuxkm_svr_state_assoc(1, 1);
        if (pstate == NULL) {
            kernel_fpu_end();
            #if IS_ENABLED(CONFIG_PREEMPT_RT)
            preempt_enable();
            #endif
            if (new_state_flags & WC_SVR_BH_HELD_FLAG)
                local_bh_enable();
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_enable();
            #endif
            wc_svr_disallowed_count_increment();
            return BAD_STATE_E;
        }

        pstate->fpu_state = new_state_flags | 1U;

        if ((new_state_flags & WC_SVR_BH_HELD_FLAG) && (softirq_count() == 0)) {
            VRG_PR_ERR_X("BUG: wc_save_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                         raw_smp_processor_id());
        }

        return 0;
    } else {
        if (preempt_count() != 0) {
            VRG_PR_WARN_X("WARNING: wc_save_vector_registers_x86 called with no saved state and nonzero preempt_count 0x%x on CPU %d.\n", preempt_count(), raw_smp_processor_id());
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
        }
        wc_svr_disallowed_count_increment();
        return WC_ACCEL_INHIBIT_E;
    }

    __builtin_unreachable();
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_svr_count_ent *pstate;
    unsigned int cur_fpu_state;

    if ((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) {
        VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called from interrupt handler on CPU %d.\n",
                raw_smp_processor_id());
        return;
    }

    pstate = wc_linuxkm_svr_state_assoc(0, 1);
    if (unlikely(pstate == NULL)) {
        VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
               "with no saved state.\n", task_pid_nr(current),
               raw_smp_processor_id());
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        dump_stack();
        #endif
        return;
    }

    if ((--pstate->fpu_state & WC_SVR_COUNT_MASK) > 0U) {
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
                VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _MAYBE_INHIBIT flag at non-outermost depth %u (age %ld ms).\n", task_pid_nr(current),
                              raw_smp_processor_id(),
                              (pstate->fpu_state & WC_SVR_COUNT_MASK) + 1U,
                              WC_SVR_SLOT_AGE_MS(pstate));
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
        }
        if (flags & WC_SVR_FLAG_INHIBIT) {
            if (pstate->fpu_state & WC_SVR_INHIBITED_FLAG)
                pstate->fpu_state &= ~WC_SVR_INHIBITED_FLAG;
            else {
                VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _INHIBIT flag but saved state isn't _INHIBITED_ (age %ld ms).\n",
                              task_pid_nr(current), raw_smp_processor_id(), WC_SVR_SLOT_AGE_MS(pstate));
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
            }
        }
        return;
    }

    cur_fpu_state = pstate->fpu_state;

    if ((pstate->fpu_state & ~WC_SVR_BH_HELD_FLAG) == 0U) {
        pstate->fpu_state = 0;
        wc_linuxkm_svr_state_release(pstate);
        kernel_fpu_end();
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_enable();
        #endif
        if (cur_fpu_state & WC_SVR_BH_HELD_FLAG) {
            if (softirq_count() == 0) {
                VRG_PR_ERR_X("BUG: wc_restore_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                             raw_smp_processor_id());
            }
            local_bh_enable();
        }
    } else if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
        if (unlikely(! (flags & (WC_SVR_FLAG_INHIBIT | WC_SVR_FLAG_MAYBE_INHIBIT)))) {
            VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                          "without _INHIBIT flag but saved state is _INHIBITED_ (age %ld ms).\n",
                          task_pid_nr(current), raw_smp_processor_id(), WC_SVR_SLOT_AGE_MS(pstate));
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
        }
        pstate->fpu_state = 0U;
        wc_linuxkm_svr_state_release(pstate);
        if (cur_fpu_state & WC_SVR_BH_HELD_FLAG) {
            if (softirq_count() == 0) {
                VRG_PR_ERR_X("BUG: wc_restore_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                             raw_smp_processor_id());
            }
            local_bh_enable();
        }
    }

    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
    migrate_enable();
    #endif

    WC_RELAX_LONG_LOOP();

    return;
}

#endif /* !WC_SKIP_INCLUDED_C_FILES */
