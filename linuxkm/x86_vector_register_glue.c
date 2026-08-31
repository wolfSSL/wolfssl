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

#if !defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) || !defined(CONFIG_X86)
    #error x86_vector_register_glue.c included in non-vectorized/non-x86 project.
#endif

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    #define VRG_PR_ERR_X wc_linuxkm_pr_err_ratelimited
    #define VRG_PR_WARN_X wc_linuxkm_pr_warn_ratelimited
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

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
/* separately tracked count of softirq-contention events (contrast with
 * wc_svr_disallowed_count, below). */
static atomic_long_t softirq_SVR_err_count;
static atomic_long_t hardirq_SVR_err_count;
static atomic_long_t NMI_SVR_err_count;
static atomic_long_t other_SVR_err_count;
#endif

#ifdef WC_SVR_USE_NATIVE_REG_BUFS

struct wc_svr_native_ctx_state {
    unsigned int depth;   /* same-context nesting count.  Save only on 0->1,
                           * restore only on 1->0.  Owner-private: only code
                           * executing in this context class on this CPU
                           * reads or writes it, and context classes on one
                           * CPU interleave strictly (run-to-completion), so
                           * no atomics are needed.
                           *
                           * For NMIs, we save the interrupt depth directly,
                           * match the depth on restore (opportunistic error
                           * detection), and return WC_ACCEL_INHIBIT_E on any
                           * nested NMI SVR attempt (no buffer to save to).
                           */
    unsigned int pin_preempt; /* set at init for the softirq entry: on
                               * PREEMPT_RT, serving-softirq is preemptible,
                               * which would break both the frozen-cause
                               * precondition and register ownership, so the
                               * section holds preempt_disable().  On
                               * mainline this is a free nop-nesting.
                               * Hardirq needs no pin.
                               */
    u8 *save_area;        /* this CPU+context's slice of
                           * wc_svr_native_save_mem, 64-byte aligned for
                           * XSAVE. */
};

struct wc_svr_native_cpu_state {
    struct wc_svr_native_ctx_state softirq;
    struct wc_svr_native_ctx_state hardirq;
    struct wc_svr_native_ctx_state nmi;
};

wc_static_assert(sizeof(struct wc_svr_native_cpu_state) %
                 sizeof(struct wc_svr_native_ctx_state) == 0);
#define WC_SVR_NATIVE_CTX_PER_CPU ((sizeof(struct wc_svr_native_cpu_state) / \
                                    sizeof(struct wc_svr_native_ctx_state)))

static void wc_svr_native_init(void);
static int wc_svr_native_check_busy(void);
static void wc_svr_native_free(void);
static inline struct wc_svr_native_cpu_state *wc_svr_native_here(void);
static WARN_UNUSED_RESULT int wc_svr_can_native_save(void);
static WARN_UNUSED_RESULT int wc_svr_native_save(enum wc_svr_flags flags);
static int wc_svr_native_restore(enum wc_svr_flags flags);

static int wc_svr_native_ready = 0;

#endif /* WC_SVR_USE_NATIVE_REG_BUFS */

WARN_UNUSED_RESULT int wc_linuxkm_allocate_svr_states(void)
{
    if (wc_linuxkm_svr_states != NULL) {
#ifdef HAVE_FIPS
        /* see note below in wc_linuxkm_svr_state_assoc_unlikely(). */
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        /* If the first allocation was the FIPS pre-Init lazy path, native
         * init deferred itself out of the atomic context; this task-context
         * repeat call is the retry (no-op once ready).
         */
        /* If the first allocation was the FIPS pre-Init lazy path and
         * native init could not complete there (NMI defer, allocation
         * failure), this repeat call is the retry (no-op once ready).
         */
        wc_svr_native_init();
#endif
        return 0;
#else
        wc_linuxkm_pr_err_ratelimited("BUG: attempt at repeat allocation"
                   " in wc_linuxkm_allocate_svr_states.\n");
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

#ifdef WC_SVR_USE_NATIVE_REG_BUFS
    /* Best-effort: any failure leaves wc_svr_native_ready clear and the
     * module on its long-standing refusal semantics.
     */
    wc_svr_native_init();
#endif

    return 0;
}

void wc_linuxkm_free_svr_states(void) {
    struct wc_thread_svr_count_ent *i, *i_endptr;
    pid_t i_pid;
    int seen_errors = 0;

    if (wc_linuxkm_svr_states == NULL)
        return;

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    pr_info("IRQ INFO: WC_ACCEL_INHIBIT_E totals at module shutdown: %ld softirq, %ld hardirq, %ld NMI, %ld other\n",
            atomic_long_read(&softirq_SVR_err_count),
            atomic_long_read(&hardirq_SVR_err_count),
            atomic_long_read(&NMI_SVR_err_count),
            atomic_long_read(&other_SVR_err_count));
#endif

#ifdef WC_SVR_USE_NATIVE_REG_BUFS
    seen_errors += wc_svr_native_check_busy();
#endif

    for (i = wc_linuxkm_svr_states,
             i_endptr = &wc_linuxkm_svr_states[wc_linuxkm_svr_states_n_tracked];
         i < i_endptr;
         ++i)
    {
        i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
        if (i_pid == WC_SVR_FREE_SLOT_PID)
            continue;
        /* Any occupied slot blocks deallocation.  A slot with fpu_state
         * still zero is a claim in flight (pid published, state not yet
         * stored) -- freeing under it is a use-after-free for the
         * claimant, so it is no safer than a nonzero state. */
        pr_err("ERROR: wc_linuxkm_free_svr_states called"
               " with occupied slot: state 0x%x for PID %d, age %ld ms.\n", i->fpu_state, i_pid,
               WC_SVR_SLOT_AGE_MS(i));
        ++seen_errors;
    }

    if (seen_errors > 0) {
        pr_crit("ERROR: wc_linuxkm_free_svr_states encountered"
               " %d errors -- can't free current wc_linuxkm_svr_states.\n", seen_errors);
        return;
    }

    free(wc_linuxkm_svr_states);
    wc_linuxkm_svr_states = NULL;

#ifdef WC_SVR_USE_NATIVE_REG_BUFS
    wc_svr_native_free();
#endif
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
                wc_linuxkm_pr_err_ratelimited("BUG: wc_linuxkm_svr_state_assoc called by PID %d"
                           " before wc_linuxkm_allocate_svr_states.\n", my_pid);
                return NULL;
            }
        }
    }

    slot = &wc_linuxkm_svr_states[my_cpu];
    slot_pid = __atomic_load_n(&slot->pid, __ATOMIC_CONSUME);
    if (slot_pid == my_pid) {
        if (create_p) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_linuxkm_svr_state_assoc called with create_p=1 by"
                                  " PID %d on CPU %d with CPU slot already reserved by"
                                  " said PID (age %ld ms).\n", my_pid, my_cpu, WC_SVR_SLOT_AGE_MS(slot));
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
            wc_linuxkm_pr_err_ratelimited("BUG: wc_linuxkm_svr_state_assoc_unlikely found WC_SVR_IDLE_PID in the slot for calling CPU %d PID %d (age %ld ms) requesting outermost vector register save -- CPU is acceleration-degraded.\n", my_cpu, my_pid, WC_SVR_SLOT_AGE_MS(slot));
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
                    wc_linuxkm_pr_warn_ratelimited("WARNING: wc_linuxkm_svr_state_assoc_unlikely fixed up orphaned slot on CPU %d owned by dead PID %d (age %ld ms).\n", my_cpu, slot_pid, WC_SVR_SLOT_AGE_MS(slot));
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
                    wc_linuxkm_pr_warn_ratelimited("WARNING: wc_linuxkm_svr_state_assoc called by pid %d on CPU %d"
                            " but CPU slot already reserved by pid %d (age %ld ms).\n",
                            my_pid, my_cpu, slot_pid, WC_SVR_SLOT_AGE_MS(slot));
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
         * cpu -- but only into an empty local slot: overwriting a live
         * association (e.g. two tasks that swapped CPUs, each holding open
         * sections) would orphan the other task's state and unbalance its
         * restore.  if the local slot is occupied -- by a live pid or by
         * WC_SVR_IDLE_PID -- return the entry in place instead: slot
         * locality is an optimization, this same scan finds the entry
         * wherever it lives, and release is by pointer.
         */
        unsigned int cpu_i;
        for (cpu_i = 0; cpu_i < wc_linuxkm_svr_states_n_tracked; ++cpu_i) {
            pid_t expected_free = WC_SVR_FREE_SLOT_PID;
            if (__atomic_load_n(
                    &wc_linuxkm_svr_states[cpu_i].pid,
                    __ATOMIC_CONSUME)
                != my_pid)
            {
                continue;
            }
            if (__atomic_compare_exchange_n(
                    &wc_linuxkm_svr_states[my_cpu].pid, &expected_free,
                    my_pid, 0 /* weak */, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE))
            {
                wc_linuxkm_svr_states[my_cpu].fpu_state =
                    wc_linuxkm_svr_states[cpu_i].fpu_state;
                wc_linuxkm_svr_states[my_cpu].reserved_at =
                    wc_linuxkm_svr_states[cpu_i].reserved_at;
                __atomic_store_n(&wc_linuxkm_svr_states[cpu_i].fpu_state, 0,
                                 __ATOMIC_RELEASE);
                __atomic_store_n(&wc_linuxkm_svr_states[cpu_i].pid, WC_SVR_FREE_SLOT_PID,
                                 __ATOMIC_RELEASE);
                /* don't clear the source .reserved_at member -- it's
                 * invalidated by the .pid assignment, and it might prove
                 * useful forensically. */
                return &wc_linuxkm_svr_states[my_cpu];
            }
            else {
                /* local slot occupied -- serve the entry where it stands. */
                return &wc_linuxkm_svr_states[cpu_i];
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
    struct wc_thread_svr_count_ent *pstate = NULL;
    int cur_preempt_count = preempt_count();
    int ret;

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (SAVE_VECTOR_REGISTERS2_fuzzer() != 0) {
        wc_svr_disallowed_count_increment();
        ret = 0;
        goto out_no_fallback_warning;
    }
#endif

    /* check for hard interrupt context (unusable current->pid) preemptively.
     * if we're in a softirq context we'll catch that below with
     * a second check of cur_preempt_count.
     */
    if (cur_preempt_count & (NMI_MASK | HARDIRQ_MASK)) {
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        ret = wc_svr_can_native_save();
        goto out;
#else /* !WC_SVR_USE_NATIVE_REG_BUFS */
        ret = 0;
        wc_svr_disallowed_count_increment();
    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        atomic_long_inc(&hardirq_SVR_err_count);
    #endif
    #ifdef DEBUG_VECTOR_REGISTER_ACCESS_HARDIRQ_INFO
        wc_linuxkm_pr_info_ratelimited("HARDIRQ_INFO: wc_can_save_vector_registers_x86() with preempt_count 0x%x, PID %d, CPU %d\n",
                preempt_count(), task_pid_nr(current), raw_smp_processor_id());
    #endif
        goto out;
#endif /* !WC_SVR_USE_NATIVE_REG_BUFS */
    }

    /* Check if we're already saved, per wc_linuxkm_svr_states. */
    pstate = wc_linuxkm_svr_state_assoc(0, 0);

    if ((pstate != NULL) && (pstate->fpu_state != 0U)) {
        if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
            wc_svr_disallowed_count_increment();
            ret = 0;
            /* previously inhibited -- either explicit, and therefore properly
             * unwarned at the outset, or implicit / error path, and therefore
             * already warned. */
            goto out_no_fallback_warning;
        }
        if (unlikely((pstate->fpu_state & WC_SVR_COUNT_MASK)
                     == WC_SVR_COUNT_MASK))
        {
            /* would overflow */
            wc_svr_disallowed_count_increment();
            ret = 0;
            goto out;
        } else {
            ret = 1;
            goto out;
        }
    }

    if ((preempt_count() == 0) || may_use_simd())
        return 1;
    else {
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        if (likely(wc_svr_native_ready) && in_serving_softirq()) {
            struct wc_svr_native_ctx_state *nctx =
                &wc_svr_native_here()->softirq;
            if (likely(nctx->depth != ~0U))
                return 1;
        }
#endif
        wc_svr_disallowed_count_increment();
    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        atomic_long_inc(&softirq_SVR_err_count);
    #endif
        ret = 0;
    }

out:
#ifdef WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK
    if (! ret) {
        wc_linuxkm_pr_emerg_ratelimited("ERROR: wc_can_save_vector_registers_x86() returning false on CPU %d, preempt_count 0x%x, pstate->fpu_state 0x%x, code %d.\n",
                             raw_smp_processor_id(), cur_preempt_count, pstate ? pstate->fpu_state : 0, ret);
    }
#endif

out_no_fallback_warning:

    return ret;
}

WARN_UNUSED_RESULT int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_svr_count_ent *pstate = NULL;
    unsigned int new_state_flags = 0;
    int cur_preempt_count = preempt_count();
    int ret;

    /* Check for hard interrupt context (unusable current->pid) preemptively.
     * If we're in a softirq context we'll catch that below with
     * a second look at preempt_count().
     *
     * Note that this is not actually an abnormal condition -- e.g. with
     * LINUXKM_DRBG_GET_RANDOM_BYTES, get_random_u32() and the like called from
     * hard IRQ handlers can land here, and we return success if
     * WC_SVR_USE_NATIVE_REG_BUFS, else WC_ACCEL_INHIBIT_E for graceful fallback
     * to C.
     */
    if ((cur_preempt_count & (NMI_MASK | HARDIRQ_MASK)) != 0) {
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        /* Native service for plain-flavor saves in hardirq.  The in_nmi()
         * disposition must stay ahead of any may_use_simd() call --
         * irq_fpu_usable() carries WARN_ON_ONCE(in_nmi()).  The inhibit flavors
         * and !wc_svr_native_ready keep the long-standing graceful refusal
         * below.
         */
        return wc_svr_native_save(flags);
#endif /* WC_SVR_USE_NATIVE_REG_BUFS */
#ifdef DEBUG_VECTOR_REGISTER_ACCESS_HARDIRQ_INFO
        wc_linuxkm_pr_info_ratelimited("HARDIRQ_INFO: wc_save_vector_registers_x86() with preempt_count 0x%x, PID %d, CPU %d\n",
                cur_preempt_count, task_pid_nr(current), raw_smp_processor_id());
#endif
        wc_svr_disallowed_count_increment();
        ret = WC_ACCEL_INHIBIT_E;
        goto out;
    }

    pstate = wc_linuxkm_svr_state_assoc(0, 0);

    /* allow for nested calls */
    if (pstate && (pstate->fpu_state != 0U)) {
        if (unlikely((pstate->fpu_state & WC_SVR_BH_HELD_FLAG) && (softirq_count() == 0))) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_save_vector_registers_x86(): zero softirq_count in nested call (depth %u, age %ld ms) after local_bh_disable() on CPU %d.\n",
                         (pstate->fpu_state & WC_SVR_COUNT_MASK),
                         WC_SVR_SLOT_AGE_MS(pstate),
                         raw_smp_processor_id());
        }
        if (unlikely(flags & WC_SVR_FLAG_MAYBE_INHIBIT)) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_save_vector_registers_x86() called by pid %d on CPU %d "
                          "with _MAYBE_INHIBIT flag in nested call (depth %u, age %ld ms).\n", task_pid_nr(current),
                          raw_smp_processor_id(),
                          (pstate->fpu_state & WC_SVR_COUNT_MASK),
                          WC_SVR_SLOT_AGE_MS(pstate));
            wc_svr_disallowed_count_increment();
            ret = BAD_STATE_E;
            goto out;
        }
        if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
            /* don't allow recursive inhibit calls when already inhibited --
             * it would add no functionality and require keeping a separate
             * count of inhibit recursions.
             */
            wc_svr_disallowed_count_increment();
            ret = WC_ACCEL_INHIBIT_E;
            /* explicit inhibit request -- bypass WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK */
            goto out_no_fallback_warning;
        }
        if (unlikely((pstate->fpu_state & WC_SVR_COUNT_MASK)
                     == WC_SVR_COUNT_MASK))
        {
            wc_linuxkm_pr_err_ratelimited("ERROR: wc_save_vector_registers_x86 recursion register overflow for "
                   "pid %d on CPU %d (age %ld ms).\n", pstate->pid, raw_smp_processor_id(),
                   WC_SVR_SLOT_AGE_MS(pstate));
            wc_svr_disallowed_count_increment();
            ret = BAD_STATE_E;
            goto out;
        }
        if (unlikely(flags & WC_SVR_FLAG_INHIBIT)) {
            ++pstate->fpu_state;
            pstate->fpu_state |= WC_SVR_INHIBITED_FLAG;
            wc_svr_disallowed_count_increment();
            /* explicit inhibit request requiring subsequent restore -- bypass
             * WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK. */
            ret = 0;
            goto out_no_fallback_warning;
        }
        else {
            ++pstate->fpu_state;
            ret = 0;
            goto out;
        }
        __builtin_unreachable();
    }

#if !defined(DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON) && !defined(WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK)
    /* EINTR during optest, which is exercised by the kernel test harness, acts
     * like a failed save, which would emit (and indeed be) an ERROR in
     * DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON builds.
     */
    {
        ret = WC_CHECK_FOR_INTR_SIGNALS();
        if (ret) {
            wc_svr_disallowed_count_increment();
            goto out;
        }
    }
#endif

    WC_RELAX_LONG_LOOP();

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (flags & WC_SVR_FLAG_FUZZ) {
        ret = SAVE_VECTOR_REGISTERS2_fuzzer();
        if (ret != 0) {
            if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
                flags |= WC_SVR_FLAG_INHIBIT;
                ret = 0;
            }
            else {
                ret = WC_ACCEL_INHIBIT_E;
                wc_svr_disallowed_count_increment();
                /* Test harness setting -- Bypass
                 * WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK. */
                goto out_no_fallback_warning;
            }
        }
    }
#endif

    if ((flags & WC_SVR_FLAG_MAYBE_INHIBIT) &&
        ((cur_preempt_count != 0) && !may_use_simd())
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        && unlikely(! wc_svr_native_ready)
#endif
        )
    {
        wc_svr_disallowed_count_increment();
        ret = WC_ACCEL_INHIBIT_E; /* not an error here, just a short-circuit
                                   * result, but will be loudly warned if
                                   * WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK.
                                   */
        goto out;
    }

    if (flags & WC_SVR_FLAG_INHIBIT) {
        if ((cur_preempt_count != 0) && !may_use_simd()) {
            wc_svr_disallowed_count_increment();
            /* explicit inhibit request, and not an error here -- bypass
             * WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK */
            ret = WC_ACCEL_INHIBIT_E;
            goto out_no_fallback_warning;
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
                wc_linuxkm_pr_err_ratelimited("BUG: wc_save_vector_registers_x86(): zero softirq_count in outermost call after local_bh_disable() on CPU %d.\n",
                             raw_smp_processor_id());
                local_bh_enable();
                #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
                migrate_enable();
                #endif
                wc_svr_disallowed_count_increment();
                ret = WC_ACCEL_INHIBIT_E;
                goto out;
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
            ret = BAD_STATE_E;
            goto out;
        }

        pstate->fpu_state =
            (WC_SVR_INHIBITED_FLAG | new_state_flags) + 1U;

        wc_svr_disallowed_count_increment();
        ret = 0;
        goto out;
    }

    if ((cur_preempt_count == 0) || may_use_simd()) {
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
            ret = BAD_STATE_E;
            goto out;
        }

        pstate->fpu_state = new_state_flags | 1U;

        if ((new_state_flags & WC_SVR_BH_HELD_FLAG) && (softirq_count() == 0)) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_save_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                         raw_smp_processor_id());
        }

        ret = 0;
        goto out;
    } else {
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        /* Native service for softirq contention (canonically: this softirq
         * interrupted a foreign kernel_fpu section, on a pre-6.15 kernel
         * where kernel_fpu_begin() doesn't defer softirqs).  Whatever holds
         * may_use_simd() false is frozen beneath us until we return, so the
         * section is exact and invisible.  The plain flavor and (when
         * native is ready) the _MAYBE_INHIBIT flavor reach this branch --
         * _MAYBE's legacy short-circuit above is bypassed so that native
         * can serve its vector-preferred arm; _INHIBIT still short-circuits
         * above.  The fuzzer has already had its chance, and nested saves
         * inside an open native softirq section land back here
         * (may_use_simd() is still false) and count up.  A nested call inside a *legacy*
         * (kernel_fpu-backed) softirq section never gets here -- it is
         * intercepted by the pid-match quick-check above.
         */
        if (likely(wc_svr_native_ready) && in_serving_softirq())
            return wc_svr_native_save(flags);
#endif /* WC_SVR_USE_NATIVE_REG_BUFS */

    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        atomic_long_inc(&softirq_SVR_err_count);
    #endif

        if (cur_preempt_count != 0) {
            /* this path is normal on pre-6.15 kernels, where kernel_fpu_begin()
             * doesn't local_bh_disable(), but on 6.15+ it's a warnable
             * anomaly. */
            #if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)

            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            wc_linuxkm_pr_info_ratelimited("INFO: !may_use_simd() in wc_save_vector_registers_x86() on CPU %d PID %d (%s) with preempt_count 0x%x.\n", raw_smp_processor_id(), task_pid_nr(current), current->comm, cur_preempt_count);
            #endif /* WOLFSSL_LINUXKM_VERBOSE_DEBUG */

            #else /* >=6.15.0 */

            wc_linuxkm_pr_warn_ratelimited("WARNING: !may_use_simd() in wc_save_vector_registers_x86 called with no saved state on CPU %d PID %d (%s) with preempt_count 0x%x.\n", raw_smp_processor_id(), task_pid_nr(current), current->comm, cur_preempt_count);

            #endif /* >=6.15.0 */
        }
        else {
            wc_linuxkm_pr_warn_ratelimited("WARNING: !may_use_simd() in wc_save_vector_registers_x86 called with no saved state on CPU %d PID %d (%s) with preempt_count 0x%x.\n", raw_smp_processor_id(), task_pid_nr(current), current->comm, cur_preempt_count);
        }

        wc_svr_disallowed_count_increment();
        ret = WC_ACCEL_INHIBIT_E;
    }

out:
#ifdef WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK
    if (ret != 0) {
        wc_linuxkm_pr_emerg_ratelimited("ERROR: wc_save_vector_registers_x86() failing on CPU %d, preempt_count 0x%x, pstate->fpu_state 0x%x, code %d.\n",
                             raw_smp_processor_id(), cur_preempt_count, pstate ? pstate->fpu_state : 0, ret);
    }
#endif

out_no_fallback_warning:

    return ret;
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_svr_count_ent *pstate;
    unsigned int cur_fpu_state;

    if ((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) {
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        (void)wc_svr_native_restore(flags);
        return;
#else
        wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() called from %s handler on CPU %d.\n",
                       in_nmi() ? "NMI" : "hard IRQ", raw_smp_processor_id());
        return;
#endif /* WC_SVR_USE_NATIVE_REG_BUFS */
    }

#ifdef WC_SVR_USE_NATIVE_REG_BUFS
    if (in_serving_softirq()) {
        if (wc_svr_native_restore(flags) == 0)
            return;
        /* fall through to kernel_fpu-backed softirq, opened while
         * may_use_simd() was true.
         */
    }
#endif /* WC_SVR_USE_NATIVE_REG_BUFS */

    pstate = wc_linuxkm_svr_state_assoc(0, 1);
    if (unlikely(pstate == NULL)) {
        wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
               "with no saved state.\n", task_pid_nr(current),
               raw_smp_processor_id());
        return;
    }

    if ((--pstate->fpu_state & WC_SVR_COUNT_MASK) > 0U) {
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _MAYBE_INHIBIT flag at non-outermost depth %u (age %ld ms).\n", task_pid_nr(current),
                              raw_smp_processor_id(),
                              (pstate->fpu_state & WC_SVR_COUNT_MASK) + 1U,
                              WC_SVR_SLOT_AGE_MS(pstate));
        }
        if (flags & WC_SVR_FLAG_INHIBIT) {
            if (pstate->fpu_state & WC_SVR_INHIBITED_FLAG)
                pstate->fpu_state &= ~WC_SVR_INHIBITED_FLAG;
            else {
                wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _INHIBIT flag but saved state isn't _INHIBITED_ (age %ld ms).\n",
                              task_pid_nr(current), raw_smp_processor_id(), WC_SVR_SLOT_AGE_MS(pstate));
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
                wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                             raw_smp_processor_id());
            }
            local_bh_enable();
        }
    } else if (unlikely(pstate->fpu_state & WC_SVR_INHIBITED_FLAG)) {
        if (unlikely(! (flags & (WC_SVR_FLAG_INHIBIT | WC_SVR_FLAG_MAYBE_INHIBIT)))) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                          "without _INHIBIT flag but saved state is _INHIBITED_ (age %ld ms).\n",
                          task_pid_nr(current), raw_smp_processor_id(), WC_SVR_SLOT_AGE_MS(pstate));
        }
        pstate->fpu_state = 0U;
        wc_linuxkm_svr_state_release(pstate);
        if (cur_fpu_state & WC_SVR_BH_HELD_FLAG) {
            if (softirq_count() == 0) {
                wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
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

#ifdef WC_SVR_USE_NATIVE_REG_BUFS

/* Native per-CPU register save buffers for softirq and hardirq contexts.
 *
 * When may_use_simd() is false, kernel_fpu_begin() is unusable, but the
 * vector register file itself is not: an exact save of every register
 * component our kernels can write, followed by our own vector computation,
 * followed by an exact restore, is invisible to the interrupted context and
 * to every kernel bookkeeping mechanism (in_kernel_fpu, TIF_NEED_FPU_LOAD,
 * fpu_fpregs_owner_ctx), all of which track register *contents*, which we
 * restore bit-exactly.  The one obligation is exactness, and the one
 * precondition is that whatever made may_use_simd() false stays true for the
 * duration of our section.  That holds by run-to-completion: the condition's
 * owner is beneath us on this CPU and cannot resume until we return.
 *
 * Two context classes are served, each with a dedicated per-CPU save buffer:
 *
 *   - hardirq: previously refused outright (WC_ACCEL_INHIBIT_E).  Handlers
 *     run with IRQs disabled, so a hardirq section can be interrupted only
 *     by NMI, which is not served (below) and whose kernel handlers do not
 *     touch the FPU.
 *
 *   - softirq when !may_use_simd(): previously refused with a ratelimited
 *     warning.  Reachable when a softirq interrupts a foreign
 *     kernel_fpu section (pre-6.15 kernels, where kernel_fpu_begin() is
 *     preempt_disable()-only and softirqs can run over an open section).
 *     A hardirq arriving over our softirq section lands in the hardirq
 *     buffer; the two never share.
 *
 * NMI context remains refused in this revision: the register mechanism below
 * would serve it (a fourth buffer), but everything reachable under an NMI
 * bracket must additionally be lock-free against the interrupted context,
 * and that audit is module-wide, not glue-local.  Note also that
 * irq_fpu_usable() carries WARN_ON_ONCE(in_nmi()) on current kernels, so the
 * in_nmi() disposition below must stay ahead of any may_use_simd() call.
 *
 * Task context needs no buffer here: its save buffer is the task struct,
 * maintained by kernel_fpu_begin()/end() on the existing paths, which remain
 * in sole charge of task-context sections.
 *
 * Same-context recursion (an outer bracket in a PK algorithm, an inner
 * bracket in a hash it calls) is a pure depth count: the registers are
 * already owned by this context, so only the 0->1 transition saves and only
 * the 1->0 transition restores.  Recursion never consumes a second buffer.
 * As on the existing paths, an inner section does not preserve the outer's
 * register contents -- the standing wolfCrypt discipline that live vector
 * state never spans a C-level call is what makes the count sufficient.
 *
 * The native state is deliberately NOT placed in struct
 * wc_thread_svr_count_ent: these buffers belong to the CPU, while ents
 * belong to pids and are copied between CPU slots by the migration scan in
 * wc_linuxkm_svr_state_assoc_unlikely().  A CPU-owned pointer inside a
 * pid-owned struct would follow the pid to the wrong CPU.
 *
 * Interweave invariants with the existing machinery:
 *
 *   - A pid-keyed (legacy) section always holds softirqs off (or IRQs off)
 *     for its duration, so a softirq can never run over an open legacy
 *     section of the task it interrupted.  Hence the recursion quick-check
 *     in wc_save_vector_registers_x86() and the native depth check below
 *     partition cleanly: a nested call inside a legacy softirq section is
 *     caught by the pid match (in_kernel_fpu makes may_use_simd() false, but
 *     the quick-check runs first); a nested call inside a native softirq
 *     section reaches the native depth check because may_use_simd() is still
 *     false (its cause is frozen beneath us).
 *
 *   - The plain save flavor is served natively in both classes, and the
 *     _MAYBE_INHIBIT flavor ("vector if possible, else say so") is served
 *     natively in softirq -- native IS the vector-possible arm, so its
 *     legacy short-circuit is bypassed when wc_svr_native_ready.  The
 *     _INHIBIT flavor (a no-vector section request) keeps its existing
 *     short-circuit semantics in all contexts (WC_ACCEL_INHIBIT_E,
 *     tolerated by all callers), as does _MAYBE_INHIBIT in hardirq;
 *     native service for those, and for NMI, is left for a later revision.
 */

/* XSAVE requested-feature bitmap: x87 (0), SSE (1), AVX/YMM (2), and the
 * AVX-512 components opmask (5), ZMM_Hi256 (6), Hi16_ZMM (7) -- every
 * component a wolfCrypt vector routine can write, and nothing else.  The
 * effective mask is this ANDed with XCR0, so components the OS hasn't
 * enabled (which the wolfCrypt dispatchers therefore won't use) drop out.
 * Components outside the mask (AMX, PKRU, MPX) are neither saved nor
 * restored nor touched by wolfCrypt code, so they ride through unchanged.
 */
#define WC_SVR_NATIVE_XFEATURE_MASK 0x00e7U

static struct wc_svr_native_cpu_state *wc_svr_native_states = NULL;
static u8 *wc_svr_native_save_mem = NULL;    /* raw allocation */
static unsigned int wc_svr_native_save_size = 0; /* per-buffer, 64-multiple */
static u32 wc_svr_native_mask_lo = 0;
static u32 wc_svr_native_mask_hi = 0;        /* always 0; kept for the asm
                                              * constraints and for clarity
                                              * that EDX:EAX is a 64 bit
                                              * RFBM. */
static int wc_svr_native_use_xsave = 0;
static int wc_svr_native_have_sse = 0; /* CPUID.1:EDX[25], cached at init;
                                        * gates the ldmxcsr in
                                        * wc_svr_native_regs_save(). */

/* wc_svr_native_cpuid_count() is open-coded, like xgetbv below: the kernel's
 * cpuid helpers have been migrating between asm/processor.h, asm/cpuid.h, and
 * asm/cpuid/api.h across our supported kernel span, and this file targets
 * exactly one ISA.  Constraints mirror the kernel's native_cpuid().
 */
static inline void wc_svr_native_cpuid_count(u32 leaf, u32 subleaf,
                                             u32 *a, u32 *b, u32 *c, u32 *d)
{
    __asm__ __volatile__("cpuid"
                         : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
                         : "0" (leaf), "2" (subleaf)
                         : "memory");
}

static inline struct wc_svr_native_cpu_state *wc_svr_native_here(void)
{
    /* Callers are in nmi, hardirq, or serving-softirq (or, for the selftest,
     * preempt-disabled task context), so raw_smp_processor_id() is stable.
     */
    return &wc_svr_native_states[raw_smp_processor_id()];
}

/* Exact save of the masked register components into a 64-byte-aligned area,
 * then normalization of MXCSR to its default, mirroring
 * kernel_fpu_begin_mask()'s KFPU_MXCSR: the interrupted context may have
 * unmasked exception bits set, under which a wolfCrypt SSE/AVX instruction
 * could fault.  The interrupted MXCSR is in the save image and comes back at
 * restore.
 *
 * Plain XSAVE/XRSTOR (never XSAVEOPT/XSAVES/XSAVEC): the modified
 * optimization keys on the last-XRSTOR address, and reusing per-context
 * areas under XSAVEOPT can legally skip stores.  Our XRSTOR to a foreign
 * area merely invalidates the kernel's own tracking address, making the
 * task's next XSAVES a full save -- conservative and correct.  The 64-bit
 * forms are used on x86_64 so the x87 FIP/FDP come back at full width --
 * with the 32-bit forms an exact restore would truncate them, a visible
 * state change for the interrupted context.
 *
 * No vector-register clobber lists: like the rest of this file, this
 * compiles with -mno-sse in force, so the compiler never holds values in
 * vector registers.  "memory" clobbers order the asm against the depth
 * bookkeeping.
 */
static void wc_svr_native_regs_save(u8 *area)
{
    if (wc_svr_native_use_xsave) {
#ifdef CONFIG_X86_64
        __asm__ __volatile__("xsave64 (%0)"
                             : : "r" (area),
                                 "a" (wc_svr_native_mask_lo),
                                 "d" (wc_svr_native_mask_hi)
                             : "memory");
#else
        __asm__ __volatile__("xsave (%0)"
                             : : "r" (area),
                                 "a" (wc_svr_native_mask_lo),
                                 "d" (wc_svr_native_mask_hi)
                             : "memory");
#endif
    }
    else {
#ifdef CONFIG_X86_64
        __asm__ __volatile__("fxsave64 (%0)" : : "r" (area) : "memory");
#else
        __asm__ __volatile__("fxsave (%0)" : : "r" (area) : "memory");
#endif
    }

    if (wc_svr_native_have_sse) {
        static const u32 wc_svr_native_mxcsr_default = 0x1f80;
        __asm__ __volatile__("ldmxcsr %0"
                             : : "m" (wc_svr_native_mxcsr_default));
    }
}

static void wc_svr_native_regs_restore(u8 *area)
{
    if (wc_svr_native_use_xsave) {
#ifdef CONFIG_X86_64
        __asm__ __volatile__("xrstor64 (%0)"
                             : : "r" (area),
                                 "a" (wc_svr_native_mask_lo),
                                 "d" (wc_svr_native_mask_hi)
                             : "memory");
#else
        __asm__ __volatile__("xrstor (%0)"
                             : : "r" (area),
                                 "a" (wc_svr_native_mask_lo),
                                 "d" (wc_svr_native_mask_hi)
                             : "memory");
#endif
    }
    else {
#ifdef CONFIG_X86_64
        __asm__ __volatile__("fxrstor64 (%0)" : : "r" (area) : "memory");
#else
        __asm__ __volatile__("fxrstor (%0)" : : "r" (area) : "memory");
#endif
    }
}

/* Register-file round-trip selftest, run once at init from task context.
 *
 * Loads a known pattern into the registers, saves, destroys the registers,
 * restores, reads the registers back, and compares; then corrupts one byte
 * of the save image (offset 160 = XMM0 byte 0 in the legacy region --
 * deliberately not the XSAVE header, which XRSTOR validates and would #GP
 * on) and proves the corruption is detected.  A negative control converts
 * "the comparison is miswired" from silent to loud.
 *
 * The test brackets itself with its own mechanism -- IRQs off, exact save
 * of the live register file into this CPU's hardirq buffer, pattern
 * round-trip in the softirq buffer, exact restore -- rather than with
 * kernel_fpu_begin()/end().  The kernel bracket was an incidental
 * dependency, and its gating predicate (may_use_simd() ->
 * irq_fpu_usable()) has drifted across kernel versions, spuriously
 * refusing task-context init on some (observed on linux-next, 2026-08).
 * The self-bracket depends only on the ISA, and doubles as a live
 * demonstration of the invisibility property being certified: the
 * interrupted state here is the insmod task's own user registers, restored
 * bit-exactly.  (If XSAVE/XRSTOR themselves misbehaved, the bracket could
 * not contain the damage -- but that contingency is a CPU that doesn't
 * implement its own spec, and the kernel_fpu bracket had the same exposure
 * through its XRSTOR.)
 *
 * Scope: xmm0-15 (and ymm0-15 when AVX is enabled) are exercised.  The
 * AVX-512 components in the mask (opmask, ZMM_Hi256, Hi16_ZMM) ride through
 * XSAVE/XRSTOR on the same terms but are not pattern-tested here.
 */
#ifdef CONFIG_X86_64
    #define WC_SVR_NATIVE_ST_NREG 16
#else
    #define WC_SVR_NATIVE_ST_NREG 8
#endif
#define WC_SVR_NATIVE_ST_MAX_STRIDE 32

static void wc_svr_native_st_load(const u8 *p, int use_avx)
{
    if (use_avx) {
        __asm__ __volatile__(
            "vmovdqu 0x000(%0), %%ymm0\n\t"
            "vmovdqu 0x020(%0), %%ymm1\n\t"
            "vmovdqu 0x040(%0), %%ymm2\n\t"
            "vmovdqu 0x060(%0), %%ymm3\n\t"
            "vmovdqu 0x080(%0), %%ymm4\n\t"
            "vmovdqu 0x0a0(%0), %%ymm5\n\t"
            "vmovdqu 0x0c0(%0), %%ymm6\n\t"
            "vmovdqu 0x0e0(%0), %%ymm7\n\t"
#ifdef CONFIG_X86_64
            "vmovdqu 0x100(%0), %%ymm8\n\t"
            "vmovdqu 0x120(%0), %%ymm9\n\t"
            "vmovdqu 0x140(%0), %%ymm10\n\t"
            "vmovdqu 0x160(%0), %%ymm11\n\t"
            "vmovdqu 0x180(%0), %%ymm12\n\t"
            "vmovdqu 0x1a0(%0), %%ymm13\n\t"
            "vmovdqu 0x1c0(%0), %%ymm14\n\t"
            "vmovdqu 0x1e0(%0), %%ymm15\n\t"
#endif
            : : "r" (p) : "memory");
    }
    else {
        __asm__ __volatile__(
            "movdqu 0x00(%0), %%xmm0\n\t"
            "movdqu 0x10(%0), %%xmm1\n\t"
            "movdqu 0x20(%0), %%xmm2\n\t"
            "movdqu 0x30(%0), %%xmm3\n\t"
            "movdqu 0x40(%0), %%xmm4\n\t"
            "movdqu 0x50(%0), %%xmm5\n\t"
            "movdqu 0x60(%0), %%xmm6\n\t"
            "movdqu 0x70(%0), %%xmm7\n\t"
#ifdef CONFIG_X86_64
            "movdqu 0x80(%0), %%xmm8\n\t"
            "movdqu 0x90(%0), %%xmm9\n\t"
            "movdqu 0xa0(%0), %%xmm10\n\t"
            "movdqu 0xb0(%0), %%xmm11\n\t"
            "movdqu 0xc0(%0), %%xmm12\n\t"
            "movdqu 0xd0(%0), %%xmm13\n\t"
            "movdqu 0xe0(%0), %%xmm14\n\t"
            "movdqu 0xf0(%0), %%xmm15\n\t"
#endif
            : : "r" (p) : "memory");
    }
}

static void wc_svr_native_st_store(u8 *p, int use_avx)
{
    if (use_avx) {
        __asm__ __volatile__(
            "vmovdqu %%ymm0, 0x000(%0)\n\t"
            "vmovdqu %%ymm1, 0x020(%0)\n\t"
            "vmovdqu %%ymm2, 0x040(%0)\n\t"
            "vmovdqu %%ymm3, 0x060(%0)\n\t"
            "vmovdqu %%ymm4, 0x080(%0)\n\t"
            "vmovdqu %%ymm5, 0x0a0(%0)\n\t"
            "vmovdqu %%ymm6, 0x0c0(%0)\n\t"
            "vmovdqu %%ymm7, 0x0e0(%0)\n\t"
#ifdef CONFIG_X86_64
            "vmovdqu %%ymm8, 0x100(%0)\n\t"
            "vmovdqu %%ymm9, 0x120(%0)\n\t"
            "vmovdqu %%ymm10, 0x140(%0)\n\t"
            "vmovdqu %%ymm11, 0x160(%0)\n\t"
            "vmovdqu %%ymm12, 0x180(%0)\n\t"
            "vmovdqu %%ymm13, 0x1a0(%0)\n\t"
            "vmovdqu %%ymm14, 0x1c0(%0)\n\t"
            "vmovdqu %%ymm15, 0x1e0(%0)\n\t"
#endif
            : : "r" (p) : "memory");
    }
    else {
        __asm__ __volatile__(
            "movdqu %%xmm0, 0x00(%0)\n\t"
            "movdqu %%xmm1, 0x10(%0)\n\t"
            "movdqu %%xmm2, 0x20(%0)\n\t"
            "movdqu %%xmm3, 0x30(%0)\n\t"
            "movdqu %%xmm4, 0x40(%0)\n\t"
            "movdqu %%xmm5, 0x50(%0)\n\t"
            "movdqu %%xmm6, 0x60(%0)\n\t"
            "movdqu %%xmm7, 0x70(%0)\n\t"
#ifdef CONFIG_X86_64
            "movdqu %%xmm8, 0x80(%0)\n\t"
            "movdqu %%xmm9, 0x90(%0)\n\t"
            "movdqu %%xmm10, 0xa0(%0)\n\t"
            "movdqu %%xmm11, 0xb0(%0)\n\t"
            "movdqu %%xmm12, 0xc0(%0)\n\t"
            "movdqu %%xmm13, 0xd0(%0)\n\t"
            "movdqu %%xmm14, 0xe0(%0)\n\t"
            "movdqu %%xmm15, 0xf0(%0)\n\t"
#endif
            : : "r" (p) : "memory");
    }
}

static WARN_UNUSED_RESULT int wc_svr_native_selftest(void)
{
    int use_avx = wc_svr_native_use_xsave &&
        ((wc_svr_native_mask_lo & 0x4U) != 0U);
    unsigned int stride = use_avx ? 32U : 16U;
    unsigned int st_len = WC_SVR_NATIVE_ST_NREG * stride;
    u8 *want = NULL, *got = NULL;
    u8 *area, *bracket;
    unsigned long irqflags;
    unsigned int i;
    int ret;

    want = (u8 *)malloc(WC_SVR_NATIVE_ST_NREG * WC_SVR_NATIVE_ST_MAX_STRIDE);
    got = (u8 *)malloc(WC_SVR_NATIVE_ST_NREG * WC_SVR_NATIVE_ST_MAX_STRIDE);
    if ((want == NULL) || (got == NULL)) {
        ret = MEMORY_E;
        goto out;
    }

    for (i = 0; i < st_len; ++i)
        want[i] = (u8)((i * 251U) + 3U);

    /* No context guard here: the self-bracket below needs only an
     * irqs-savable, non-NMI context (wc_svr_native_init() disposes of NMI
     * before calling), and init contexts are legitimately atomic-ish --
     * the FIPS pre-Init lazy path arrives inside the outermost save's own
     * bh-off/kernel_fpu bracket, and wolfCrypt_Init() itself has been
     * observed arriving with irqs disabled and preempt_count 0 (non-FIPS
     * 5.10/5.15, 2026-08).  An
     * earlier in_interrupt() guard here silently disabled the mechanism on
     * exactly those paths.
     */

    local_irq_save(irqflags); /* quiesce the CPU: no migration, no
                               * preemption, no interrupts -- sole register
                               * file ownership for the bracket's duration.
                               * Deliberately unconditional under
                               * already_locked: the enclosing bracket holds
                               * softirqs off, but on pre-6.15 kernels a
                               * foreign hardirq kernel_fpu user is excluded
                               * only when in_kernel_fpu is set, which the
                               * _INHIBIT-flavored lazy path doesn't do --
                               * and mid-selftest our pattern registers
                               * belong to no fpstate, so a foreign save
                               * would leak them into the interrupted task's
                               * user state.  IRQs-off closes that window on
                               * all vintages, and nests harmlessly.
                               */

    bracket = wc_svr_native_here()->hardirq.save_area;
    wc_svr_native_regs_save(bracket);

    /* The softirq buffer of this CPU serves as scratch: no sections are open
     * at init, and XSAVE never writes XCOMP_BV, so the zeroed-header
     * invariant established below survives this use.  Same for the hardirq
     * buffer's service as the bracket area above.
     */
    area = wc_svr_native_here()->softirq.save_area;

    wc_svr_native_st_load(want, use_avx);
    wc_svr_native_regs_save(area);
    XMEMSET(got, 0, st_len);
    wc_svr_native_st_load(got, use_avx);   /* destroy the registers, as
                                            * wolfCrypt would. */
    wc_svr_native_regs_restore(area);
    wc_svr_native_st_store(got, use_avx);  /* what the interrupted context
                                            * would see. */

    ret = (XMEMCMP(want, got, st_len) == 0) ? 0 : -1;

    if (ret == 0) {
        /* Negative control: a corrupted image must be detected. */
        area[160] ^= 0xffU;
        wc_svr_native_st_load(want, use_avx);
        wc_svr_native_regs_save(area);
        area[160] ^= 0xffU;
        XMEMSET(got, 0, st_len);
        wc_svr_native_st_load(got, use_avx);
        wc_svr_native_regs_restore(area);
        wc_svr_native_st_store(got, use_avx);
        ret = (XMEMCMP(want, got, st_len) != 0) ? 0 : -1;
        if (ret != 0)
            pr_err("ERROR: wc_svr_native_selftest: negative control not"
                   " detected.\n");
    }
    else {
        pr_err("ERROR: wc_svr_native_selftest: register file round-trip"
               " mismatch.\n");
    }

    wc_svr_native_regs_restore(bracket);
    local_irq_restore(irqflags);

    if (ret != 0)
        ret = BAD_STATE_E;

out:
    if (want != NULL)
        free(want);
    if (got != NULL)
        free(got);
    return ret;
}

/* Size and allocate the save buffers, prove the mechanism with the selftest,
 * and only then mark it ready.  Any failure leaves wc_svr_native_ready
 * clear, and every native branch below then falls through to the
 * long-standing refusal semantics -- the capability is additive, never
 * load-bearing for correctness.
 *
 * Called from wc_linuxkm_allocate_svr_states() (task context, including the
 * FIPS pre-Init lazy-allocation path).  Idempotent for the FIPS repeat-call
 * pattern.
 */

static size_t wc_svr_native_save_mem_size;

static void wc_svr_native_init(void)
{
    u8 *aligned;
    unsigned int cpu_i;
    int wc_svr_native_have_osxsave, wc_svr_native_have_fxsr;

    if (wc_svr_native_states != NULL)
        return;

    if (in_nmi()) {
        /* Nothing below is possible in NMI; a later allocate call retries.
         * Every other context is serviceable: the selftest brackets itself
         * with irqs off, and the allocations ride the same malloc mapping
         * as the pre-existing lazy-path table allocation.
         */
        return;
    }

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    if (in_interrupt() || irqs_disabled()) {
        /* Not a problem -- just record the context so atypical init
         * environments are visible in the log (FIPS pre-Init lazy path,
         * irqs-off wolfCrypt_Init(), etc).
         */
        wc_linuxkm_pr_info_ratelimited("wc_svr_native_init in atomic context: preempt_count 0x%x,"
                " irqs_disabled %d.\n",
                preempt_count(), irqs_disabled() ? 1 : 0);
    }
#endif

    {
        u32 eax, ebx, ecx, edx;
        wc_svr_native_cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
        wc_svr_native_have_sse = (int)((edx >> 25) & 1U);
        wc_svr_native_have_osxsave = (int)((ecx >> 27) & 1U);
        wc_svr_native_have_fxsr = (int)((edx >> 24) & 1U);
    }

    if (wc_svr_native_have_osxsave) {
        /* CPUID.1:ECX[27] mirrors live CR4.OSXSAVE, so noxsave/clearcpuid
         * boots read 0 here and degrade to the FXSAVE arm, consistently
         * with the wolfCrypt dispatchers (which likewise see no OSXSAVE and
         * select no AVX+ paths).
         */
        u32 eax, ebx, ecx, edx;
        u32 xcr0_lo, xcr0_hi;

        __asm__ __volatile__("xgetbv"
                             : "=a" (xcr0_lo), "=d" (xcr0_hi)
                             : "c" (0));
        wc_svr_native_mask_lo = xcr0_lo & WC_SVR_NATIVE_XFEATURE_MASK;
        wc_svr_native_mask_hi = 0;

        /* CPUID.(EAX=0DH,ECX=0):ECX = maximum standard-format XSAVE area
         * size over all XCR0-enablable components -- an upper bound for our
         * subset mask on any core in the package.
         */
        wc_svr_native_cpuid_count(0x0d, 0, &eax, &ebx, &ecx, &edx);
        wc_svr_native_save_size = (ecx + 63U) & ~63U;
        if (wc_svr_native_save_size < 576U) {
            /* legacy region (512) + XSAVE header (64) is the floor;
             * anything smaller is CPUID nonsense.
             */
            pr_err("ERROR: wc_svr_native_init: implausible XSAVE area size"
                   " %u.\n", wc_svr_native_save_size);
            return;
        }
        wc_svr_native_use_xsave = 1;
    }
    else if (wc_svr_native_have_fxsr) {
        /* No OSXSAVE means no YMM+ state is architecturally enabled, so the
         * wolfCrypt dispatchers won't select AVX+ paths, and FXSAVE's
         * x87+SSE coverage is the complete writable set.
         */
        wc_svr_native_save_size = 512U;
        wc_svr_native_use_xsave = 0;
    }
    else {
        pr_warn("WARNING: wc_svr_native_init: no XSAVE or FXSR -- native"
                " register save buffers disabled.\n");
        return;
    }

    wc_svr_native_states = (struct wc_svr_native_cpu_state *)malloc(
        (size_t)nr_cpu_ids * sizeof(struct wc_svr_native_cpu_state));
    if (wc_svr_native_states == NULL) {
        pr_err("ERROR: allocation of %zu bytes for wc_svr_native_states"
               " failed.\n",
               (size_t)nr_cpu_ids * sizeof(struct wc_svr_native_cpu_state));
        return;
    }
    XMEMSET(wc_svr_native_states, 0,
            (size_t)nr_cpu_ids * sizeof(struct wc_svr_native_cpu_state));

    /* One allocation, three 64-aligned buffers per CPU.  Zero-initialized and
     * never re-zeroed: XSAVE writes XSTATE_BV but never XCOMP_BV, and
     * standard-format XRSTOR requires XCOMP_BV == 0, so the zeroing at birth
     * is the invariant that keeps every later XRSTOR well-formed (SDM vol. 1
     * ch. 13).
     */
    wc_svr_native_save_mem_size =
        (size_t)nr_cpu_ids *
        WC_SVR_NATIVE_CTX_PER_CPU *
        (size_t)wc_svr_native_save_size + 63U;
    wc_svr_native_save_mem = (u8 *)malloc(wc_svr_native_save_mem_size);
    if (wc_svr_native_save_mem == NULL) {
        pr_err("ERROR: allocation of %zu bytes for native register save"
               " buffers failed.\n", wc_svr_native_save_mem_size);
        free(wc_svr_native_states);
        wc_svr_native_states = NULL;
        return;
    }
    XMEMSET(wc_svr_native_save_mem, 0, wc_svr_native_save_mem_size);

    aligned = PTR_ALIGN(wc_svr_native_save_mem, 64);
    /* cast: nr_cpu_ids is plain int on pre-4.15 kernels (treewide
     * unsigned conversion), tripping -Wsign-compare there. */
    for (cpu_i = 0; cpu_i < (unsigned int)nr_cpu_ids; ++cpu_i) {
        struct wc_svr_native_cpu_state *cst = &wc_svr_native_states[cpu_i];
        cst->softirq.save_area =
            aligned + ((size_t)cpu_i * WC_SVR_NATIVE_CTX_PER_CPU *
                       wc_svr_native_save_size);
        cst->softirq.pin_preempt = 1;
        cst->hardirq.save_area =
            cst->softirq.save_area + wc_svr_native_save_size;
        cst->hardirq.pin_preempt = 0;
        cst->nmi.save_area =
            cst->hardirq.save_area + wc_svr_native_save_size;
        cst->nmi.pin_preempt = 0;
    }

    if (wc_svr_native_selftest() != 0) {
        free(wc_svr_native_save_mem);
        wc_svr_native_save_mem = NULL;
        free(wc_svr_native_states);
        wc_svr_native_states = NULL;
        return;
    }

    wc_svr_native_ready = 1;

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    pr_info("wolfCrypt: native register save buffers enabled (%s, %u bytes"
            " x %zu x %u CPUs).\n",
            wc_svr_native_use_xsave ? "xsave" : "fxsave",
            wc_svr_native_save_size, WC_SVR_NATIVE_CTX_PER_CPU, nr_cpu_ids);
#endif
}

/* Returns the number of still-open native sections (0 when teardown is
 * safe), mirroring the occupied-slot scan in wc_linuxkm_free_svr_states().
 */
static int wc_svr_native_check_busy(void)
{
    unsigned int cpu_i;
    int busy = 0;

    if (wc_svr_native_states == NULL)
        return 0;

    for (cpu_i = 0; cpu_i < (unsigned int)nr_cpu_ids; ++cpu_i) {
        if (wc_svr_native_states[cpu_i].softirq.depth != 0) {
            pr_err("ERROR: wc_linuxkm_free_svr_states called with open native"
                   " softirq section on CPU %u (depth %u).\n",
                   cpu_i, wc_svr_native_states[cpu_i].softirq.depth);
            ++busy;
        }
        if (wc_svr_native_states[cpu_i].hardirq.depth != 0) {
            pr_err("ERROR: wc_linuxkm_free_svr_states called with open native"
                   " hardirq section on CPU %u (depth %u).\n",
                   cpu_i, wc_svr_native_states[cpu_i].hardirq.depth);
            ++busy;
        }
        if (wc_svr_native_states[cpu_i].nmi.depth != 0) {
            pr_err("ERROR: wc_linuxkm_free_svr_states called with open native"
                   " NMI section on CPU %u (depth %u).\n",
                   cpu_i, wc_svr_native_states[cpu_i].nmi.depth);
            ++busy;
        }
    }
    return busy;
}

static void wc_svr_native_free(void)
{
    wc_svr_native_ready = 0;
    if (wc_svr_native_save_mem != NULL) {
        ForceZero(wc_svr_native_save_mem, wc_svr_native_save_mem_size);
        free(wc_svr_native_save_mem);
        wc_svr_native_save_mem = NULL;
        wc_svr_native_save_mem_size = 0;
    }
    if (wc_svr_native_states != NULL) {
        free(wc_svr_native_states);
        wc_svr_native_states = NULL;
    }
    wc_svr_native_save_size = 0;
    wc_svr_native_use_xsave = 0;
}

/* Runtime readiness accessor for out-of-file policy decisions -- notably
 * the FIPS<v7 default-bank WC_RNG_BANK_FLAG_NO_VECTOR_OPS pin in
 * lkcapi_sha_glue.c, which must stay in force on any boot where native
 * service didn't come up: without it, refused saves reintroduce the
 * mid-object asm/C fallback switching that the frozen v5/v6 boundaries
 * cannot survive.  Runtime, not compile-time: WC_SVR_USE_NATIVE_REG_BUFS
 * being built in does not imply readiness (hardware without XSAVE/FXSR,
 * allocation failure, selftest failure).
 */
WARN_UNUSED_RESULT int wc_linuxkm_svr_native_is_ready(void)
{
    return wc_svr_native_ready;
}

static WARN_UNUSED_RESULT int wc_svr_can_native_save(void) {
    int cur_preempt_count = preempt_count();
    struct wc_svr_native_ctx_state *ctx;

    if (! wc_svr_native_ready)
        return 0;

    if (cur_preempt_count & NMI_MASK)
        ctx = &wc_svr_native_here()->nmi;
    else if (cur_preempt_count & HARDIRQ_MASK)
        ctx = &wc_svr_native_here()->hardirq;
    else if (in_serving_softirq())
        ctx = &wc_svr_native_here()->softirq;
    else {
        wc_svr_disallowed_count_increment();
        return 0;
    }

    if (ctx->depth > 0U) {
        if (cur_preempt_count & NMI_MASK) {
            wc_svr_disallowed_count_increment();
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            atomic_long_inc(&NMI_SVR_err_count);
        #endif
            return 0;
        }
        else if (unlikely(ctx->depth == ~0U)) {
            wc_svr_disallowed_count_increment();
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            if (cur_preempt_count & HARDIRQ_MASK)
                atomic_long_inc(&hardirq_SVR_err_count);
            else if (cur_preempt_count)
                atomic_long_inc(&softirq_SVR_err_count);
            else
                atomic_long_inc(&other_SVR_err_count);
        #endif
            return 0;
        }
        return 1;
    }
    else
        return 1;
}

/* Open a native section in the given context class: count if one is already
 * open, else save and (for softirq) pin.  Serves only the plain save
 * flavor; callers filter _INHIBIT/_MAYBE_INHIBIT to the existing paths.
 */
static WARN_UNUSED_RESULT int wc_svr_native_save(enum wc_svr_flags flags) {
    int cur_preempt_count = preempt_count();
    struct wc_svr_native_ctx_state *ctx;
    int ret;

    if (! wc_svr_native_ready) {
        ret = WC_ACCEL_INHIBIT_E;
        goto out;
    }

    if (flags & WC_SVR_FLAG_INHIBIT) {
        ret = WC_ACCEL_INHIBIT_E;
        goto out;
    }

    if (cur_preempt_count & NMI_MASK)
        ctx = &wc_svr_native_here()->nmi;
    else if (cur_preempt_count & HARDIRQ_MASK)
        ctx = &wc_svr_native_here()->hardirq;
    else if (in_serving_softirq())
        ctx = &wc_svr_native_here()->softirq;
    else {
        ret = WC_ACCEL_INHIBIT_E;
        wc_svr_disallowed_count_increment();
    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        atomic_long_inc(&other_SVR_err_count);
    #endif
        goto out;
    }

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    /* Mirror the existing paths: injection at outermost depth only. */
    if ((flags & WC_SVR_FLAG_FUZZ) && (ctx->depth == 0U)) {
        int ret = SAVE_VECTOR_REGISTERS2_fuzzer();
        if (ret != 0) {
            wc_svr_disallowed_count_increment();
            /* Bypass WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK. */
            return ret;
        }
    }
#endif

    if (ctx->depth > 0U) {
        if (cur_preempt_count & NMI_MASK) {
            wc_linuxkm_pr_warn_ratelimited("WARNING: wc_svr_native_save() rejected on CPU %d "
                                "at NMI depth %lu after previous save at depth %u.\n",
                                raw_smp_processor_id(),
                                (preempt_count() & NMI_MASK) >> NMI_SHIFT,
                                ctx->depth);
            wc_svr_disallowed_count_increment();
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            atomic_long_inc(&NMI_SVR_err_count);
        #endif
            ret = WC_ACCEL_INHIBIT_E;
            goto out;
        }
        else if (unlikely(ctx->depth == ~0U)) {
            wc_linuxkm_pr_err_ratelimited("ERROR: wc_svr_native_save recursion count overflow on"
                   " CPU %d.\n", raw_smp_processor_id());
            wc_svr_disallowed_count_increment();
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            if (cur_preempt_count & HARDIRQ_MASK)
                atomic_long_inc(&hardirq_SVR_err_count);
            else if (cur_preempt_count)
                atomic_long_inc(&softirq_SVR_err_count);
            else
                atomic_long_inc(&other_SVR_err_count);
        #endif
            ret = WC_ACCEL_INHIBIT_E;
            goto out;
        }
        ++ctx->depth;
        ret = 0;
        goto out;
    }

    if (ctx->pin_preempt)
        preempt_disable();

    wc_svr_native_regs_save(ctx->save_area);
    if (cur_preempt_count & NMI_MASK)
        ctx->depth = (cur_preempt_count & NMI_MASK) >> NMI_SHIFT;
    else
        ctx->depth = 1;
    ret = 0;

out:

#ifdef WC_SVR_PR_EMERG_ON_ACCEL_FALLBACK
    if (ret != 0) {
        wc_linuxkm_pr_emerg_ratelimited("ERROR: wolfCrypt wc_svr_native_save() failing on CPU %d, preempt_count 0x%x, code %d.\n",
                             raw_smp_processor_id(), cur_preempt_count, ret);
    }
#endif

    return ret;
}

static int wc_svr_native_restore(enum wc_svr_flags flags)
{
    int cur_preempt_count = preempt_count();
    struct wc_svr_native_ctx_state *ctx;

    if (! wc_svr_native_ready) {
        wc_linuxkm_pr_err_ratelimited("BUG: wc_svr_native_restore() without wc_svr_native_ready.\n");
        return NOT_READY_E;
    }

    if (cur_preempt_count & NMI_MASK)
        ctx = &wc_svr_native_here()->nmi;
    else if (cur_preempt_count & HARDIRQ_MASK)
        ctx = &wc_svr_native_here()->hardirq;
    else if (in_serving_softirq()) {
        ctx = &wc_svr_native_here()->softirq;
        /* softirq is often saved by regular ol' kernel_fpu_begin(). */
        if (ctx->depth == 0)
            return BAD_INDEX_E; /* overloaded local-use-only error code */
    }
    else {
        /* shouldn't be here -- task context. */
        return BAD_INDEX_E; /* overloaded local-use-only error code */
    }

    if (unlikely(flags & WC_SVR_FLAG_INHIBIT)) {
        /* Native sections are opened by the plain and _MAYBE_INHIBIT
         * flavors (the latter when native service preempts the legacy
         * short-circuit), so _MAYBE-paired restores are legitimate here;
         * only an _INHIBIT-flavored restore against an open native section
         * is a caller pairing bug -- _INHIBIT never opens one.
         */
        wc_linuxkm_pr_err_ratelimited("BUG: wc_svr_native_restore() with inhibit"
                      " flags 0x%x on open native section (CPU %d,"
                      " depth %u, preempt_count 0x%x).\n",
                      (unsigned int)flags, raw_smp_processor_id(),
                      ctx->depth, preempt_count());
    }

    if (ctx->depth == 0) {
        wc_linuxkm_pr_err_ratelimited("BUG: wc_svr_native_restore() with no saved state on CPU %d, preempt_count 0x%x.\n",
                           raw_smp_processor_id(), preempt_count());
        return BAD_INDEX_E;
    }

    if (in_nmi()) {
        if (((preempt_count() & NMI_MASK) >> NMI_SHIFT) != ctx->depth) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_svr_native_restore() NMI depth "
                               "mismatch on CPU %d, current depth %lu, "
                               "expected depth %u.\n",
                               raw_smp_processor_id(),
                               (preempt_count() & NMI_MASK) >> NMI_SHIFT,
                               ctx->depth);
            return BAD_INDEX_E;
        }
    }
    else if (ctx->depth > 1U) {
        --ctx->depth;
        return 0;
    }

    wc_svr_native_regs_restore(ctx->save_area);
    ctx->depth = 0;

    if (ctx->pin_preempt)
        preempt_enable();

    return 0;
}

#endif /* WC_SVR_USE_NATIVE_REG_BUFS */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
