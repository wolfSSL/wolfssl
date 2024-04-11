/* linuxkm_memory.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* included by wolfcrypt/src/memory.c */

#ifdef HAVE_KVMALLOC
/* adapted from kvrealloc() draft by Changli Gao, 2010-05-13 */
void *lkm_realloc(void *ptr, size_t newsize) {
    void *nptr;
    size_t oldsize;

    if (unlikely(newsize == 0)) {
        kvfree(ptr);
        return ZERO_SIZE_PTR;
    }

    if (unlikely(ptr == NULL))
        return kvmalloc_node(newsize, GFP_KERNEL, NUMA_NO_NODE);

    if (is_vmalloc_addr(ptr)) {
        /* no way to discern the size of the old allocation,
         * because the kernel doesn't export find_vm_area().  if
         * it did, we could then call get_vm_area_size() on the
         * returned struct vm_struct.
         */
        return NULL;
    } else {
#ifndef __PIE__
        struct page *page;

        page = virt_to_head_page(ptr);
        if (PageSlab(page) || PageCompound(page)) {
            if (newsize < PAGE_SIZE)
#endif /* ! __PIE__ */
                return krealloc(ptr, newsize, GFP_KERNEL);
#ifndef __PIE__
            oldsize = ksize(ptr);
        } else {
            oldsize = page->private;
            if (newsize <= oldsize)
                return ptr;
        }
#endif /* ! __PIE__ */
    }

    nptr = kvmalloc_node(newsize, GFP_KERNEL, NUMA_NO_NODE);
    if (nptr != NULL) {
        memcpy(nptr, ptr, oldsize);
        kvfree(ptr);
    }

    return nptr;
}
#endif /* HAVE_KVMALLOC */

#if defined(WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS) && defined(CONFIG_X86)

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
        static int warned_for_repeat_alloc = 0;
        if (! warned_for_repeat_alloc) {
            pr_err("attempt at repeat allocation"
                   " in allocate_wolfcrypt_linuxkm_fpu_states\n");
            warned_for_repeat_alloc = 1;
        }
        return BAD_STATE_E;
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
            if (_warned_on_null == 0) {
                pr_err("wc_linuxkm_fpu_state_assoc called by pid %d"
                       " before allocate_wolfcrypt_linuxkm_fpu_states.\n", my_pid);
                _warned_on_null = 1;
            }
            return NULL;
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
 * pushing/popping
 */
static struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_state_assoc_unlikely(int create_p) {
    int my_cpu = raw_smp_processor_id();
    pid_t my_pid = task_pid_nr(current), slot_pid;
    struct wc_thread_fpu_count_ent *slot;

    {
        static int _warned_on_null = 0;
        if (wc_linuxkm_fpu_states == NULL)
        {
            if (_warned_on_null == 0) {
                pr_err("wc_linuxkm_fpu_state_assoc called by pid %d"
                       " before allocate_wolfcrypt_linuxkm_fpu_states.\n", my_pid);
                _warned_on_null = 1;
            }
            return NULL;
        }
    }

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid)
        return slot;
    if (create_p) {
        /* caller must have already called kernel_fpu_begin() if create_p. */
        if (slot_pid == 0) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            return slot;
        } else {
            static int _warned_on_mismatched_pid = 0;
            if (_warned_on_mismatched_pid < 10) {
                pr_err("wc_linuxkm_fpu_state_assoc called by pid %d on cpu %d"
                       " but cpu slot already reserved by pid %d.\n", my_pid, my_cpu, slot_pid);
                ++_warned_on_mismatched_pid;
            }
            return NULL;
        }
    } else {
        return NULL;
    }
}

static inline struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_state_assoc(int create_p) {
    int my_cpu = raw_smp_processor_id(); /* my_cpu is only trustworthy if we're
                                          * already nonpreemptible -- we'll
                                          * determine that soon enough by
                                          * checking if the pid matches or,
                                          * failing that, if create_p.
                                          */
    pid_t my_pid = task_pid_nr(current), slot_pid;
    struct wc_thread_fpu_count_ent *slot;

    if (wc_linuxkm_fpu_states == NULL)
        return wc_linuxkm_fpu_state_assoc_unlikely(create_p);

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid)
        return slot;
    if (create_p) {
        /* caller must have already called kernel_fpu_begin() if create_p. */
        if (slot_pid == 0) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELEASE);
            return slot;
        } else {
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
        }
    } else {
        return NULL;
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

static void wc_linuxkm_fpu_state_release_unlikely(struct wc_thread_fpu_count_ent *ent) {
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

static inline void wc_linuxkm_fpu_state_release(struct wc_thread_fpu_count_ent *ent) {
    if (unlikely(ent->fpu_state != 0))
        return wc_linuxkm_fpu_state_release_unlikely(ent);
    __atomic_store_n(&ent->pid, 0, __ATOMIC_RELEASE);
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

    if (irq_fpu_usable()) {
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
    } else {
        /* assume already safely in_kernel_fpu. */
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
#endif /* WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS && CONFIG_X86 */

#if defined(__PIE__) && (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
/* needed in 6.1+ because show_free_areas() static definition in mm.h calls
 * __show_free_areas(), which isn't exported (neither was show_free_areas()).
 */
void my__show_free_areas(
    unsigned int flags,
    nodemask_t *nodemask,
    int max_zone_idx)
{
    (void)flags;
    (void)nodemask;
    (void)max_zone_idx;
    return;
}
#endif

#if defined(__PIE__) && defined(CONFIG_FORTIFY_SOURCE)
/* needed because FORTIFY_SOURCE inline implementations call fortify_panic(). */
void __my_fortify_panic(const char *name) {
    pr_emerg("__my_fortify_panic in %s\n", name);
    BUG();
}
#endif
