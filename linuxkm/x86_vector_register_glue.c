/* x86_vector_register_glue.c -- glue logic to save and restore vector registers
 * on x86
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#if !defined(WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS) || !defined(CONFIG_X86)
    #error x86_vector_register_glue.c included in non-vectorized/non-x86 project.
#endif

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    #define VRG_PR_ERR_X pr_err
    #define VRG_PR_WARN_X pr_warn
#else
    #define VRG_PR_ERR_X pr_err_once
    #define VRG_PR_WARN_X pr_warn_once
#endif

/* kernel 4.19 -- the most recent LTS before 5.4 -- lacks the necessary safety
 * checks in __kernel_fpu_begin(), and lacks TIF_NEED_FPU_LOAD.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
    #error WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS on x86 requires kernel 5.4.0 or higher.
#endif

static unsigned int wc_linuxkm_fpu_states_n_tracked = 0;

struct wc_thread_fpu_count_ent {
    volatile pid_t pid;
    unsigned int fpu_state;
};
struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_states = NULL;

#define WC_FPU_COUNT_MASK 0x3fffffffU
#define WC_FPU_INHIBITED_FLAG 0x40000000U

WARN_UNUSED_RESULT int allocate_wolfcrypt_linuxkm_fpu_states(void)
{
    if (wc_linuxkm_fpu_states != NULL) {
#ifdef HAVE_FIPS
        /* see note below in wc_linuxkm_fpu_state_assoc_unlikely(). */
        return 0;
#else
        static int warned_for_repeat_alloc = 0;
        if (! warned_for_repeat_alloc) {
            pr_err("BUG: attempt at repeat allocation"
                   " in allocate_wolfcrypt_linuxkm_fpu_states.\n");
            warned_for_repeat_alloc = 1;
        }
        return BAD_STATE_E;
#endif
    }

    wc_linuxkm_fpu_states_n_tracked = nr_cpu_ids;

    wc_linuxkm_fpu_states =
        (struct wc_thread_fpu_count_ent *)malloc(
            wc_linuxkm_fpu_states_n_tracked * sizeof(wc_linuxkm_fpu_states[0]));

    if (! wc_linuxkm_fpu_states) {
        pr_err("ERROR: allocation of %lu bytes for "
               "wc_linuxkm_fpu_states failed.\n",
               nr_cpu_ids * sizeof(struct fpu_state *));
        return MEMORY_E;
    }

    memset(wc_linuxkm_fpu_states, 0, wc_linuxkm_fpu_states_n_tracked
           * sizeof(wc_linuxkm_fpu_states[0]));

    return 0;
}

void free_wolfcrypt_linuxkm_fpu_states(void) {
    struct wc_thread_fpu_count_ent *i, *i_endptr;
    pid_t i_pid;

    if (wc_linuxkm_fpu_states == NULL)
        return;

    for (i = wc_linuxkm_fpu_states,
             i_endptr = &wc_linuxkm_fpu_states[wc_linuxkm_fpu_states_n_tracked];
         i < i_endptr;
         ++i)
    {
        i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
        if (i_pid == 0)
            continue;
        if (i->fpu_state != 0) {
            pr_err("ERROR: free_wolfcrypt_linuxkm_fpu_states called"
                   " with nonzero state 0x%x for PID %d.\n", i->fpu_state, i_pid);
            i->fpu_state = 0;
        }
    }

    free(wc_linuxkm_fpu_states);
    wc_linuxkm_fpu_states = NULL;
}

/* lock-free O(1)-lookup CPU-local storage facility for tracking recursive fpu
 * pushing/popping.
 *
 * caller must have already locked itself on its CPU before entering this, or
 * entering the streamlined inline version of it below.
 */
static struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_state_assoc_unlikely(int create_p) {
    int my_cpu = raw_smp_processor_id();
    pid_t my_pid = task_pid_nr(current), slot_pid;
    struct wc_thread_fpu_count_ent *slot;

    {
        static int _warned_on_null = 0;
        if (wc_linuxkm_fpu_states == NULL)
        {
#ifdef HAVE_FIPS
            /* FIPS needs to use SHA256 for the core verify HMAC, before
             * reaching the regular wolfCrypt_Init() logic.  to break the
             * dependency loop on intelasm builds, we allocate here.
             * this is not thread-safe and doesn't need to be.
             */
            int ret = allocate_wolfcrypt_linuxkm_fpu_states();
            if (ret != 0)
#endif
            {
                if (_warned_on_null == 0) {
                    pr_err("BUG: wc_linuxkm_fpu_state_assoc called by PID %d"
                           " before allocate_wolfcrypt_linuxkm_fpu_states.\n", my_pid);
                    _warned_on_null = 1;
                }
                return NULL;
            }
        }
    }

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (create_p) {
            static int _warned_on_redundant_create_p = 0;
            if (_warned_on_redundant_create_p < 10) {
                pr_err("BUG: wc_linuxkm_fpu_state_assoc called with create_p=1 by"
                       " PID %d on CPU %d with CPU slot already reserved by"
                       " said PID.\n", my_pid, my_cpu);
                ++_warned_on_redundant_create_p;
            }
        }
        return slot;
    }
    if (create_p) {
        if (slot_pid == 0) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            return slot;
        } else {
            /* if the slot is already occupied, that can be benign-ish due to a
             * unwanted migration, or due to a process crashing in kernel mode.
             * it will require fixup either here, or by the thread that owns the
             * slot, which will happen when it releases its lock.
             */
            if (find_get_pid(slot_pid) == NULL) {
                if (__atomic_compare_exchange_n(&slot->pid, &slot_pid, my_pid, 0, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
                    pr_warn("WARNING: wc_linuxkm_fpu_state_assoc_unlikely fixed up orphaned slot on CPU %d owned by dead PID %d.\n", my_cpu, slot_pid);
                    return slot;
                }
            }

            {
                static int _warned_on_mismatched_pid = 0;
                if (_warned_on_mismatched_pid < 10) {
                    pr_warn("WARNING: wc_linuxkm_fpu_state_assoc called by pid %d on CPU %d"
                            " but CPU slot already reserved by pid %d.\n",
                            my_pid, my_cpu, slot_pid);
                    ++_warned_on_mismatched_pid;
                }
            }

            return NULL;
        }
    } else {
        /* check for migration.  this can happen despite our best efforts if any
         * I/O occurred while locked, e.g. kernel messages like "uninitialized
         * urandom read".  since we're locked now, we can safely migrate the
         * entry in wc_linuxkm_fpu_states[], freeing up the slot on the previous
         * cpu.
         */
        unsigned int cpu_i;
        for (cpu_i = 0; cpu_i < wc_linuxkm_fpu_states_n_tracked; ++cpu_i) {
            if (__atomic_load_n(
                    &wc_linuxkm_fpu_states[cpu_i].pid,
                    __ATOMIC_CONSUME)
                == my_pid)
            {
                wc_linuxkm_fpu_states[my_cpu] = wc_linuxkm_fpu_states[cpu_i];
                __atomic_store_n(&wc_linuxkm_fpu_states[cpu_i].fpu_state, 0,
                                 __ATOMIC_RELEASE);
                __atomic_store_n(&wc_linuxkm_fpu_states[cpu_i].pid, 0,
                                 __ATOMIC_RELEASE);
                return &wc_linuxkm_fpu_states[my_cpu];
            }
        }
        return NULL;
    }
}

static inline struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_state_assoc(
    int create_p, int assume_fpu_began)
{
    int my_cpu = raw_smp_processor_id(); /* my_cpu is only trustworthy if we're
                                          * already nonpreemptible -- we'll
                                          * determine that soon enough by
                                          * checking if the pid matches or,
                                          * failing that, if create_p.
                                          */
    pid_t my_pid, slot_pid;
    struct wc_thread_fpu_count_ent *slot;

    if (unlikely(wc_linuxkm_fpu_states == NULL)) {
        if (! assume_fpu_began) {
            /* this was just a quick check for whether we're in a recursive
             * save_vector_registers_x86().  we're not.
             */
            return NULL;
        }
        else
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
    }

    my_pid = task_pid_nr(current);

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (unlikely(create_p))
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
        else
            return slot;
    }
    if (! assume_fpu_began) {
        /* this was just a quick check for whether we're in a recursive
         * save_vector_registers_x86().  we're not.
         *
         * if we're in a softirq context, we'll always wind up here, because
         * processes with entries in wc_linuxkm_fpu_states[] always have
         * softirqs inhibited.
         */
        return NULL;
    }
    if (likely(create_p)) {
        if (likely(slot_pid == 0)) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            return slot;
        } else {
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
        }
    } else {
        return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
    }
}

static void wc_linuxkm_fpu_state_release_unlikely(
    struct wc_thread_fpu_count_ent *ent)
{
    if (ent->fpu_state != 0) {
        static int warned_nonzero_fpu_state = 0;
        if (! warned_nonzero_fpu_state) {
            VRG_PR_ERR_X("ERROR: wc_linuxkm_fpu_state_free for pid %d on CPU %d"
                   " with nonzero fpu_state 0x%x.\n", ent->pid, raw_smp_processor_id(), ent->fpu_state);
            warned_nonzero_fpu_state = 1;
        }
        ent->fpu_state = 0;
    }
    __atomic_store_n(&ent->pid, 0, __ATOMIC_RELEASE);
}

static inline void wc_linuxkm_fpu_state_release(
    struct wc_thread_fpu_count_ent *ent)
{
    if (unlikely(ent->fpu_state != 0))
        return wc_linuxkm_fpu_state_release_unlikely(ent);
    __atomic_store_n(&ent->pid, 0, __ATOMIC_RELEASE);
}

WARN_UNUSED_RESULT int can_save_vector_registers_x86(void)
{
    struct wc_thread_fpu_count_ent *pstate;

    /* check for hard interrupt context (unusable current->pid) preemptively.
     * if we're in a softirq context we'll catch that below with
     * a second preempt_count() check.
     */
    if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) || (task_pid_nr(current) == 0))
        return 0;

    /* Check if we're already saved, per wc_linuxkm_fpu_states. */
    pstate = wc_linuxkm_fpu_state_assoc(0, 0);

    if ((pstate != NULL) && (pstate->fpu_state != 0U)) {
        if (unlikely(pstate->fpu_state & WC_FPU_INHIBITED_FLAG))
            return 0;
        if (unlikely((pstate->fpu_state & WC_FPU_COUNT_MASK)
                     == WC_FPU_COUNT_MASK))
        {
            /* would overflow */
            return 0;
        } else {
            return 1;
        }
    }

    if ((preempt_count() == 0) || may_use_simd())
        return 1;
    else
        return 0;
}

WARN_UNUSED_RESULT int save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_fpu_count_ent *pstate;

    /* check for hard interrupt context (unusable current->pid) preemptively.
     * if we're in a softirq context we'll catch that below with
     * a second look at preempt_count().
     */
    if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) || (task_pid_nr(current) == 0)) {
        VRG_PR_WARN_X("WARNING: save_vector_registers_x86 called with preempt_count 0x%x and pid %d on CPU %d.\n", preempt_count(), task_pid_nr(current), raw_smp_processor_id());
        return WC_ACCEL_INHIBIT_E;
    }

    pstate = wc_linuxkm_fpu_state_assoc(0, 0);

    /* allow for nested calls */
    if (pstate && (pstate->fpu_state != 0U)) {
        if (unlikely(pstate->fpu_state & WC_FPU_INHIBITED_FLAG)) {
            if (flags & WC_SVR_FLAG_INHIBIT) {
                /* allow recursive inhibit calls as long as the whole stack of
                 * them is inhibiting.
                 */
                ++pstate->fpu_state;
                return 0;
            }
            else
                return WC_ACCEL_INHIBIT_E;
        }
        if (unlikely(flags & WC_SVR_FLAG_INHIBIT))
            return BAD_STATE_E;
        if (unlikely((pstate->fpu_state & WC_FPU_COUNT_MASK)
                     == WC_FPU_COUNT_MASK))
        {
            pr_err("ERROR: save_vector_registers_x86 recursion register overflow for "
                   "pid %d on CPU %d.\n", pstate->pid, raw_smp_processor_id());
            return BAD_STATE_E;
        } else {
            ++pstate->fpu_state;
            return 0;
        }
        __builtin_unreachable();
    }

    if (flags & WC_SVR_FLAG_INHIBIT) {
        if ((preempt_count() != 0) && !may_use_simd())
            return WC_ACCEL_INHIBIT_E; /* not an error here, just a
                                        * short-circuit result.
                                        */
        /* we need to inhibit migration and softirqs here to assure that we can
         * support recursive calls safely, i.e. without mistaking a softirq
         * context for a recursion.
         */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
        migrate_disable();
        #endif
        local_bh_disable();

        if (preempt_count() == 0) {
            VRG_PR_ERR_X("BUG: save_vector_registers_x86(): zero preempt_count after local_bh_disable() on CPU %d.\n",
                   raw_smp_processor_id());
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
            migrate_enable();
            #endif
            local_bh_enable();
            return WC_ACCEL_INHIBIT_E;
        }

        pstate = wc_linuxkm_fpu_state_assoc(1, 1);
        if (pstate == NULL) {
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
            migrate_enable();
            #endif
            local_bh_enable();
            return BAD_STATE_E;
        }

        pstate->fpu_state =
            WC_FPU_INHIBITED_FLAG + 1U;

        return 0;
    }

    if ((preempt_count() == 0) || may_use_simd()) {
        /* fpregs_lock() calls either local_bh_disable() or preempt_disable()
         * depending on CONFIG_PREEMPT_RT -- we call both, explicitly.
         *
         * empirically, on some kernels, kernel_fpu_begin() doesn't reliably
         * disable softirqs, indeed doesn't make preempt_count() nonzero, which
         * breaks our locking algorithm.  we sidestep this completely by
         * explicitly disabling softirq's, preemption, and migration.
         * helpfully, the calls to do that are all guaranteed recursion-safe.
         */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
        migrate_disable();
        #endif
        local_bh_disable();
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_disable();
        #endif
        kernel_fpu_begin();
        pstate = wc_linuxkm_fpu_state_assoc(1, 1);
        if (pstate == NULL) {
            kernel_fpu_end();
            #if IS_ENABLED(CONFIG_PREEMPT_RT)
            preempt_enable();
            #endif
            local_bh_enable();
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
            migrate_enable();
            #endif
            return BAD_STATE_E;
        }

        /* set msb to 0 to trigger kernel_fpu_end() at cleanup. */
        pstate->fpu_state = 1U;

        if (preempt_count() == 0) {
            VRG_PR_ERR_X("BUG: save_vector_registers_x86(): zero preempt_count after kernel_fpu_begin() on CPU %d.\n",
                         raw_smp_processor_id());
        }

        return 0;
    } else  {
        VRG_PR_WARN_X("WARNING: save_vector_registers_x86 called with no saved state and nonzero preempt_count 0x%x on CPU %d.\n", preempt_count(), raw_smp_processor_id());
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        dump_stack();
        #endif
        return WC_ACCEL_INHIBIT_E;
    }

    __builtin_unreachable();
}

void restore_vector_registers_x86(void)
{
    struct wc_thread_fpu_count_ent *pstate;

    if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) || (task_pid_nr(current) == 0)) {
        VRG_PR_WARN_X("BUG: restore_vector_registers_x86() called from interrupt handler on CPU %d.\n",
                raw_smp_processor_id());
        return;
    }

    pstate = wc_linuxkm_fpu_state_assoc(0, 1);
    if (unlikely(pstate == NULL)) {
        VRG_PR_WARN_X("BUG: restore_vector_registers_x86() called by pid %d on CPU %d "
               "with no saved state.\n", task_pid_nr(current),
               raw_smp_processor_id());
        return;
    }

    if ((--pstate->fpu_state & WC_FPU_COUNT_MASK) > 0U) {
        return;
    }

    if (pstate->fpu_state == 0U) {
        wc_linuxkm_fpu_state_release(pstate);
        kernel_fpu_end();
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_enable();
        #endif
        local_bh_enable();
    } else if (unlikely(pstate->fpu_state & WC_FPU_INHIBITED_FLAG)) {
        pstate->fpu_state = 0U;
        wc_linuxkm_fpu_state_release(pstate);
        local_bh_enable();
    }

    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_enable();
    #endif

    return;
}
