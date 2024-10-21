/* x86_vector_register_glue.c -- glue logic to save and restore vector registers
 * on x86
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef WOLFSSL_COMMERCIAL_LICENSE

#ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
    #error WOLFSSL_COMMERCIAL_LICENSE requires LINUXKM_FPU_STATES_FOLLOW_THREADS
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wnested-externs"
/* avoid dependence on "alternatives_patched" and "xfd_validate_state()". */
#undef CONFIG_X86_DEBUG_FPU
#include "../kernel/fpu/internal.h"
#include "../kernel/fpu/xstate.h"
#pragma GCC diagnostic pop

static union wc_linuxkm_fpu_savebuf {
    byte buf[1024]; /* must be 64-byte-aligned */
    struct fpstate fpstate;
} *wc_linuxkm_fpu_savebufs = NULL;

#endif /* WOLFSSL_COMMERCIAL_LICENSE */

#define WC_FPU_COUNT_MASK 0x7fffffffU
#define WC_FPU_SAVED_MASK 0x80000000U

WARN_UNUSED_RESULT int allocate_wolfcrypt_linuxkm_fpu_states(void)
{
    if (wc_linuxkm_fpu_states != NULL) {
#ifdef HAVE_FIPS
        /* see note below in wc_linuxkm_fpu_state_assoc_unlikely(). */
        return 0;
#else
        static int warned_for_repeat_alloc = 0;
        if (! warned_for_repeat_alloc) {
            pr_err("attempt at repeat allocation"
                   " in allocate_wolfcrypt_linuxkm_fpu_states\n");
            warned_for_repeat_alloc = 1;
        }
        return BAD_STATE_E;
#endif
    }

#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
    if (nr_cpu_ids >= 16)
        wc_linuxkm_fpu_states_n_tracked = nr_cpu_ids * 2;
    else
        wc_linuxkm_fpu_states_n_tracked = 32;
#else
    wc_linuxkm_fpu_states_n_tracked = nr_cpu_ids;
#endif

    wc_linuxkm_fpu_states =
        (struct wc_thread_fpu_count_ent *)malloc(
            wc_linuxkm_fpu_states_n_tracked * sizeof(wc_linuxkm_fpu_states[0]));

    if (! wc_linuxkm_fpu_states) {
        pr_err("allocation of %lu bytes for "
               "wc_linuxkm_fpu_states failed.\n",
               nr_cpu_ids * sizeof(struct fpu_state *));
        return MEMORY_E;
    }

    memset(wc_linuxkm_fpu_states, 0, wc_linuxkm_fpu_states_n_tracked
           * sizeof(wc_linuxkm_fpu_states[0]));

#ifdef WOLFSSL_COMMERCIAL_LICENSE
    wc_linuxkm_fpu_savebufs = (union wc_linuxkm_fpu_savebuf *)malloc(
        wc_linuxkm_fpu_states_n_tracked * sizeof(*wc_linuxkm_fpu_savebufs));
    if (! wc_linuxkm_fpu_savebufs) {
        pr_err("allocation of %lu bytes for "
               "wc_linuxkm_fpu_savebufs failed.\n",
               WC_LINUXKM_ROUND_UP_P_OF_2(wc_linuxkm_fpu_states_n_tracked)
               * sizeof(*wc_linuxkm_fpu_savebufs));
        free(wc_linuxkm_fpu_states);
        wc_linuxkm_fpu_states = NULL;
        return MEMORY_E;
    }
    if ((uintptr_t)wc_linuxkm_fpu_savebufs
        & (WC_LINUXKM_ROUND_UP_P_OF_2(sizeof(*wc_linuxkm_fpu_savebufs)) - 1))
    {
        pr_err("allocation of %lu bytes for "
               "wc_linuxkm_fpu_savebufs allocated with wrong alignment 0x%lx.\n",
               WC_LINUXKM_ROUND_UP_P_OF_2(wc_linuxkm_fpu_states_n_tracked)
               * sizeof(*wc_linuxkm_fpu_savebufs),
               (uintptr_t)wc_linuxkm_fpu_savebufs);
        free(wc_linuxkm_fpu_savebufs);
        wc_linuxkm_fpu_savebufs = NULL;
        free(wc_linuxkm_fpu_states);
        wc_linuxkm_fpu_states = NULL;
        return MEMORY_E;
    }

#endif

    return 0;
}

void free_wolfcrypt_linuxkm_fpu_states(void) {
    struct wc_thread_fpu_count_ent *i, *i_endptr;
    pid_t i_pid;

    if (wc_linuxkm_fpu_states == NULL) {
        pr_err("free_wolfcrypt_linuxkm_fpu_states called"
               " before allocate_wolfcrypt_linuxkm_fpu_states.\n");
        return;
    }

    for (i = wc_linuxkm_fpu_states,
             i_endptr = &wc_linuxkm_fpu_states[wc_linuxkm_fpu_states_n_tracked];
         i < i_endptr;
         ++i)
    {
        i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
        if (i_pid == 0)
            continue;
        if (i->fpu_state != 0) {
            pr_err("free_wolfcrypt_linuxkm_fpu_states called"
                   " with nonzero state 0x%x for pid %d.\n", i->fpu_state, i_pid);
            i->fpu_state = 0;
        }
    }

#ifdef WOLFSSL_COMMERCIAL_LICENSE
    free(wc_linuxkm_fpu_savebufs);
    wc_linuxkm_fpu_savebufs = NULL;
#endif
    free(wc_linuxkm_fpu_states);
    wc_linuxkm_fpu_states = NULL;
}

#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
/* legacy thread-local storage facility for tracking recursive fpu
 * pushing/popping
 */
static struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_state_assoc(int create_p) {
    struct wc_thread_fpu_count_ent *i, *i_endptr, *i_empty;
    pid_t my_pid = task_pid_nr(current), i_pid;

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
            if ((! create_p) || (allocate_wolfcrypt_linuxkm_fpu_states() != 0))
#endif
            {
                if (_warned_on_null == 0) {
                    pr_err("wc_linuxkm_fpu_state_assoc called by pid %d"
                           " before allocate_wolfcrypt_linuxkm_fpu_states.\n", my_pid);
                    _warned_on_null = 1;
                }
                return NULL;
            }
        }
    }

    i_endptr = &wc_linuxkm_fpu_states[wc_linuxkm_fpu_states_n_tracked];

    for (;;) {
        for (i = wc_linuxkm_fpu_states,
                 i_empty = NULL;
             i < i_endptr;
             ++i)
        {
            i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
            if (i_pid == my_pid)
                return i;
            if ((i_empty == NULL) && (i_pid == 0))
                i_empty = i;
        }
        if ((i_empty == NULL) || (! create_p))
            return NULL;

        i_pid = 0;
        if (__atomic_compare_exchange_n(
                &(i_empty->pid),
                &i_pid,
                my_pid,
                0 /* weak */,
                __ATOMIC_SEQ_CST /* success_memmodel */,
                __ATOMIC_SEQ_CST /* failure_memmodel */))
        {
            return i_empty;
        }
    }
}

#else /* !LINUXKM_FPU_STATES_FOLLOW_THREADS */

/* lock-free O(1)-lookup CPU-local storage facility for tracking recursive fpu
 * pushing/popping.
 *
 * caller must have already called kernel_fpu_begin() or preempt_disable()
 * before entering this or the streamlined inline version of it below.
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
                    pr_err("wc_linuxkm_fpu_state_assoc called by pid %d"
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
                pr_err("wc_linuxkm_fpu_state_assoc called with create_p=1 by"
                       " pid %d on cpu %d with cpu slot already reserved by"
                       " said pid.\n", my_pid, my_cpu);
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
            /* if the slot is already occupied, that can be benign due to a
             * migration, but it will require fixup by the thread that owns the
             * slot, which will happen when it releases its lock, or sooner (see
             * below).
             */
            static int _warned_on_mismatched_pid = 0;
            if (_warned_on_mismatched_pid < 10) {
                pr_warn("wc_linuxkm_fpu_state_assoc called by pid %d on cpu %d"
                       " but cpu slot already reserved by pid %d.\n",
                        my_pid, my_cpu, slot_pid);
                ++_warned_on_mismatched_pid;
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
    int create_p)
{
    int my_cpu = raw_smp_processor_id(); /* my_cpu is only trustworthy if we're
                                          * already nonpreemptible -- we'll
                                          * determine that soon enough by
                                          * checking if the pid matches or,
                                          * failing that, if create_p.
                                          */
    pid_t my_pid = task_pid_nr(current), slot_pid;
    struct wc_thread_fpu_count_ent *slot;

    if (unlikely(wc_linuxkm_fpu_states == NULL))
        return wc_linuxkm_fpu_state_assoc_unlikely(create_p);

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (unlikely(create_p))
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
        else
            return slot;
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

#endif /* !LINUXKM_FPU_STATES_FOLLOW_THREADS */

#ifdef WOLFSSL_COMMERCIAL_LICENSE
static struct fpstate *wc_linuxkm_fpstate_buf_from_fpu_state(
    struct wc_thread_fpu_count_ent *state)
{
    size_t i = (size_t)(state - wc_linuxkm_fpu_states) / sizeof(*state);
    return &wc_linuxkm_fpu_savebufs[i].fpstate;
}
#endif

static void wc_linuxkm_fpu_state_release_unlikely(
    struct wc_thread_fpu_count_ent *ent)
{
    if (ent->fpu_state != 0) {
        static int warned_nonzero_fpu_state = 0;
        if (! warned_nonzero_fpu_state) {
            pr_err("wc_linuxkm_fpu_state_free for pid %d"
                   " with nonzero fpu_state 0x%x.\n", ent->pid, ent->fpu_state);
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
    if (irq_fpu_usable())
        return 1;
    else if (in_nmi() || (hardirq_count() > 0) || (softirq_count() > 0))
        return 0;
    else if (test_thread_flag(TIF_NEED_FPU_LOAD))
        return 1;
    return 0;
}

WARN_UNUSED_RESULT int save_vector_registers_x86(void)
{
#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
    struct wc_thread_fpu_count_ent *pstate = wc_linuxkm_fpu_state_assoc(1);
#else
    struct wc_thread_fpu_count_ent *pstate = wc_linuxkm_fpu_state_assoc(0);
#endif

    /* allow for nested calls */
#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
    if (pstate == NULL)
        return MEMORY_E;
#endif
    if (
#ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
        (pstate != NULL) &&
#endif
        (pstate->fpu_state != 0U))
    {
        if (unlikely((pstate->fpu_state & WC_FPU_COUNT_MASK)
                     == WC_FPU_COUNT_MASK))
        {
            pr_err("save_vector_registers_x86 recursion register overflow for "
                   "pid %d.\n", pstate->pid);
            return BAD_STATE_E;
        } else {
            ++pstate->fpu_state;
            return 0;
        }
    }

    if (irq_fpu_usable()
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0))
        /* work around a kernel bug -- see linux commit 59f5ede3bc0f0.
         * what we really want here is this_cpu_read(in_kernel_fpu), but
         * in_kernel_fpu is an unexported static array.
         */
        && !test_thread_flag(TIF_NEED_FPU_LOAD)
#endif
        )
    {
#ifdef WOLFSSL_COMMERCIAL_LICENSE
        struct fpstate *fpstate = wc_linuxkm_fpstate_buf_from_fpu_state(pstate);
        fpregs_lock();
        fpstate->xfeatures = ~0UL;
        os_xsave(fpstate);
#else /* !WOLFSSL_COMMERCIAL_LICENSE */
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
        /* inhibit migration, which gums up the algorithm in
         * kernel_fpu_{begin,end}().
         */
        migrate_disable();
    #endif
        kernel_fpu_begin();

#ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
        pstate = wc_linuxkm_fpu_state_assoc(1);
        if (pstate == NULL) {
            kernel_fpu_end();
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) && \
        !defined(WOLFSSL_COMMERCIAL_LICENSE)
            migrate_enable();
    #endif
            return BAD_STATE_E;
        }
#endif

#endif /* !WOLFSSL_COMMERCIAL_LICENSE */
        /* set msb to 0 to trigger kernel_fpu_end() at cleanup. */
        pstate->fpu_state = 1U;
    } else if (in_nmi() || (hardirq_count() > 0) || (softirq_count() > 0)) {
        static int warned_fpu_forbidden = 0;
        if (! warned_fpu_forbidden)
            pr_err("save_vector_registers_x86 called from IRQ handler.\n");
#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
        wc_linuxkm_fpu_state_release(pstate);
#endif
        return BAD_STATE_E;
    } else if (!test_thread_flag(TIF_NEED_FPU_LOAD)) {
        static int warned_fpu_forbidden = 0;
        if (! warned_fpu_forbidden)
            pr_err("save_vector_registers_x86 called with !irq_fpu_usable from"
                   " thread without previous FPU save.\n");
#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
        wc_linuxkm_fpu_state_release(pstate);
#endif
        return BAD_STATE_E;
    } else {
        /* assume already safely in_kernel_fpu from caller, but recursively
         * preempt_disable() to be extra-safe.
         */
        preempt_disable();
#if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) && \
    !defined(WOLFSSL_COMMERCIAL_LICENSE)
        migrate_disable();
#endif
#ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
        pstate = wc_linuxkm_fpu_state_assoc(1);
        if (pstate == NULL) {
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) && \
            !defined(WOLFSSL_COMMERCIAL_LICENSE)
            migrate_enable();
        #endif
            preempt_enable();
            return BAD_STATE_E;
        }
#endif
        /* set msb to 1 to inhibit kernel_fpu_end() at cleanup. */
        pstate->fpu_state =
            WC_FPU_SAVED_MASK + 1U;
    }

    return 0;
}

void restore_vector_registers_x86(void)
{
    struct wc_thread_fpu_count_ent *pstate = wc_linuxkm_fpu_state_assoc(0);
    if (unlikely(pstate == NULL)) {
        pr_err("restore_vector_registers_x86 called by pid %d on CPU %d "
               "with no saved state.\n", task_pid_nr(current),
               raw_smp_processor_id());
        return;
    }

    if ((--pstate->fpu_state & WC_FPU_COUNT_MASK) > 0U) {
        return;
    }

    if (pstate->fpu_state == 0U) {
#ifdef WOLFSSL_COMMERCIAL_LICENSE
        struct fpstate *fpstate = wc_linuxkm_fpstate_buf_from_fpu_state(pstate);
        os_xrstor(fpstate, fpstate->xfeatures);
        fpregs_unlock();
#else
    #ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
        wc_linuxkm_fpu_state_release(pstate);
    #endif
        kernel_fpu_end();
#endif
    } else {
        pstate->fpu_state = 0U;
    #ifndef LINUXKM_FPU_STATES_FOLLOW_THREADS
        wc_linuxkm_fpu_state_release(pstate);
    #endif
        preempt_enable();
    }
#if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) && \
    !defined(WOLFSSL_COMMERCIAL_LICENSE)
    migrate_enable();
#endif

#ifdef LINUXKM_FPU_STATES_FOLLOW_THREADS
    wc_linuxkm_fpu_state_release(pstate);
#endif

    return;
}
