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

#if !defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) || \
    !(defined(CONFIG_X86) || defined(CONFIG_ARM) || defined(CONFIG_ARM64))
    #error vector register glue included in non-vectorized or unsupported-arch project.
#endif

/* Arch-neutral per-CPU tracker; only the SIMD claim/release differs: x86
 * kernel_fpu_*, ARM/ARM64 kernel_neon_*.  wc_*_x86 names kept on all arches. */
#if defined(CONFIG_X86)
    #define WC_LINUXKM_FPU_BEGIN() kernel_fpu_begin()
    #define WC_LINUXKM_FPU_END()   kernel_fpu_end()
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
    #include <asm/neon.h>
    #define WC_LINUXKM_FPU_BEGIN() kernel_neon_begin()
    #define WC_LINUXKM_FPU_END()   kernel_neon_end()
#endif

/* Non-FIPS and the in-development FIPS flavors (dev, dev-no-post) take this
 * branch, which keeps the ownership arbitration below.  Each argument for it
 * is left intact, with a rendered judgement appended so the two can be
 * weighed against each other.  FIPS Ready is certifiable, so it takes the
 * #else with v5, v6 and v7. */
#if defined(WC_FIPS_UNCERTIFIED_BUILD) || \
    !(defined(HAVE_FIPS) || defined(WOLFSSL_FIPS_READY))

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
    #define VRG_PR_ERR_X pr_err
    #define VRG_PR_WARN_X pr_warn
#else
    #define VRG_PR_ERR_X pr_err_once
    #define VRG_PR_WARN_X pr_warn_once
#endif

static unsigned int wc_linuxkm_fpu_states_n_tracked = 0;

struct wc_thread_fpu_count_ent {
    /* in_use, not pid, is the "slot occupied" sentinel.  The idle task
     * ("swapper/N", one per CPU) has pid 0, and softirqs, notably timer
     * callbacks, run on it routinely.  Using pid==0 to mean "free" leaves
     * the idle task unrepresentable in this table.
     */
    volatile int in_use;
    volatile pid_t pid;
    /* Second half of the slot key.  pid alone is not an owner identity here:
     * every CPU's idle task is pid 0, and a softirq borrows the pid of
     * whatever task it interrupted, so "same pid" can mean two unrelated
     * execution contexts.
     *
     * MEASURED 2026-08-11 (matrix/scripts/combos/oe3-k2/...-svr-slot-probe,
     * results under matrix/results/64-bit-x86_64-intel-kernel-svr-slot-probe/):
     * driving per-CPU SHA-256 for 120 s, three slots were in_use with pid 0 at
     * the same instant, 231 duplicate-pid observations.  The earlier probe that
     * showed max_in_use=1 drove the DRBG, whose single shared WC_RNG serialises
     * every caller, it measured the DRBG's own exclusion, not this table.
     *
     * ctx distinguishes softirq-handler context from task context.  It is
     * stable across a save/restore bracket: in_serving_softirq() tests
     * SOFTIRQ_OFFSET (one unit, set by __do_softirq), while our own
     * local_bh_disable() adds SOFTIRQ_DISABLE_OFFSET (two units) and leaves
     * that bit alone.  So a section cannot change its own answer, and a
     * softirq cannot start inside a bracket that has bh disabled. */

    /* I feel this is an OVERSTEP because: the kernel exposes no ownership
     * query for the vector registers, so pid and ctx are an owner identity
     * this module invented.  Inside a section fpregs_lock() pins the CPU, so
     * per-CPU alone is already exact. */
    volatile int ctx;
    unsigned int fpu_state;
    /* jiffies at the moment this slot was claimed.  Used only to bound a leak:
     * see the stale-slot reclaim in wc_linuxkm_fpu_state_assoc_unlikely(). */
    unsigned long claimed_at;
};

/* How long a slot may be held before a claimant on the same CPU may take it.
 * Used only by the reclaim arms, which FIPS builds compile out, see below.
 *
 * THE FIVE SECONDS ARE NOT DERIVED FROM A MEASUREMENT.  This comment used to
 * argue that a bracket is "milliseconds at worst" because the longest crypto
 * operation is an SLH-DSA or ML-DSA sign.  Nobody timed one under a bracket,
 * here or anywhere else in this tree, so treat the figure as arbitrary until
 * someone does.  Compared with time_after() so the jiffies wrap is handled; a
 * bare comparison is wrong roughly every 49 days at HZ=1000. */

/* I feel this is an OVERSTEP because: the kernel sets no bound on how long a
 * critical section may be held, so any timeout here is our policy applied to
 * another context's section, not a rule we can cite. */
#define WC_FPU_SLOT_STALE_JIFFIES (5 * HZ)

/* OWNERSHIP ARBITRATION IS OFF IN FIPS BUILDS.
 *
 * The reclaim arms below let this module decide that another task's slot is
 * stale and take it.  Nothing in the kernel's documented interface supports
 * that: Documentation/core-api/floating-point.rst assigns the caller exactly
 * one job, "if the caller expects to nest critical sections, it must implement
 * its own reference counting", and exposes no way to ask who currently owns
 * the vector registers.  kernel_fpu_available() reports platform capability,
 * not ownership.  A reclaim also revokes nothing, only kernel_fpu_end() can,
 * so it changes this table while the kernel's own state is untouched.
 *
 * REMINDER, DO NOT DROP: this is disabled, not resolved.  Restore it, or
 * delete it for good, once there is testing that shows either that the reclaim
 * is unnecessary or that removing it causes no strange behaviour.  Rationale,
 * measurements and the open arm32 gap are in
 * linuxkm/SVR-FALLBACK-ANALYSIS.md 13.4.  Define
 * WC_LINUXKM_SVR_SLOT_RECLAIM to build the old behaviour back in.
 */

/* I agree this is an OVERSTEP, and note it is disabled rather than removed:
 * claimed_at is still stored on every claim while nothing in a FIPS build
 * reads it. */
#if defined(HAVE_FIPS) && !defined(WC_LINUXKM_SVR_SLOT_RECLAIM)
    #define WC_LINUXKM_SVR_NO_SLOT_RECLAIM
#endif
struct wc_thread_fpu_count_ent *wc_linuxkm_fpu_states = NULL;

/* Count of softirq brackets THIS module has open on this CPU.
 *
 * The error path in wc_restore_vector_registers_x86() has to decide whether it
 * is holding a bracket it must release.  softirq_count() cannot answer that:
 * it is nonzero for ANY bh-disable, and spin_lock_bh(), which is what
 * wc_LockMutex() now takes, contributes SOFTIRQ_LOCK_OFFSET to the same
 * field (spinlock_api_smp.h).  Releasing on that test can therefore drop the
 * softirq exclusion belonging to a mutex the caller still holds.
 *
 * Incremented only where this module actually took a bracket and returned
 * success, and decremented only where it releases one, so a nonzero value
 * means at least one bracket on this CPU is ours.  The whole bracket runs
 * bh-disabled and migration-disabled, so the CPU cannot change underneath it.
 *
 * SCOPE, stated plainly: this proves the bracket is OURS, not that it belongs
 * to THIS call.  The nested-success path in wc_save_vector_registers_x86()
 * returns 0 without taking a bracket, so a nested caller whose slot has since
 * vanished still reaches the error path with a nonzero count that belongs to
 * its outer frame.  Closing that needs the slot lookup not to miss; it is not
 * something a counter can decide.
 *
 * THAT SCOPE LIMIT HAS A CONSEQUENCE THIS COUNTER MUST SURVIVE.  When the
 * error path does consume an outer frame's bracket, the outer frame's own
 * restore decrements the same increment a second time and the count goes
 * NEGATIVE.  Every read below therefore tests "> 0", never "!= 0": a negative
 * count must read as "no bracket held", because the alternative is that
 * wc_lkm_LockMutex() refuses on this CPU forever, and since that refusal
 * became fatal, forever means every wolfSSL_Mutex, which includes
 * LockDrbgState(), which means wc_InitRng() fails for the life of the module.
 * A miscounted bracket must not be able to take the DRBG down.  The decrement
 * sites are guarded so the count cannot be driven below zero in the first
 * place; the "> 0" tests are the second line, for a path that is added later
 * and forgets. */

/* I feel this is an OVERSTEP because: it is a second count of the sections
 * fpu_state already counts.  Two counters of one thing can disagree, and
 * each unwind path consults only one of them. */
static DEFINE_PER_CPU(int, wc_svr_bracket_depth);

/* Nonzero when this CPU is inside one of this module's vector-register
 * brackets.  Exposed so the lock primitives can refuse to run there: between
 * SAVE_VECTOR_REGISTERS() and RESTORE_VECTOR_REGISTERS() the module is in a
 * truly atomic region on EVERY configuration, because kernel_fpu_begin_mask()
 * calls preempt_disable() unconditionally (arch/x86/kernel/fpu/core.c) and
 * this module adds local_bh_disable() and, on PREEMPT_RT, its own
 * preempt_disable().
 *
 * Reading a per-CPU value without pinning is safe for this use: inside a
 * bracket preemption and migration are both disabled, so a nonzero answer is
 * exact.  Outside one, the worst case is reading another CPU's zero, which is
 * the same answer. */

/* I feel this citation is now STALE because: it holds through 6.14, but 6.15
 * changed the opening to fpregs_lock() only if !irqs_disabled(), which is
 * local_bh_disable() on !RT.  Checked against v6.12, v6.15 and v6.17
 * sources. */
static int wc_linuxkm_in_svr_bracket(void)
{
    return this_cpu_read(wc_svr_bracket_depth) > 0;
}

/* Release one bracket level, and REFUSE to go below zero.
 *
 * Every decrement in this file goes through here.  A decrement with nothing to
 * release means the count no longer describes reality, the known way in is
 * the scope limit above, where the slot-miss path consumes an outer frame's
 * bracket and that frame then releases the same one again.  Letting the count
 * go negative would make wc_linuxkm_in_svr_bracket() true on this CPU for the
 * life of the module even under a "> 0" test, because nothing ever resets it.
 * Since wc_lkm_LockMutex() refuses fatally inside a bracket, that is a
 * permanent loss of every wolfSSL_Mutex on that CPU, DRBG included.
 *
 * Clamped rather than silently floored, and reported once: an imbalance here is
 * a real defect, and the count going wrong has to stay visible even though it
 * is no longer allowed to be fatal. */

/* I feel this is an OVERSTEP because: the clamp guards the counter, not the
 * unwind.  It returns void, so two of its three callers run
 * local_bh_enable() regardless and the imbalance still lands. */
static void wc_linuxkm_svr_bracket_dec(void)
{
    if (unlikely(this_cpu_read(wc_svr_bracket_depth) <= 0)) {
        VRG_PR_ERR_X("BUG: wc_restore_vector_registers_x86(): bracket depth "
                     "already %d on CPU %d; not decrementing.\n",
                     this_cpu_read(wc_svr_bracket_depth),
                     raw_smp_processor_id());
        return;
    }
    this_cpu_dec(wc_svr_bracket_depth);
}

#define WC_FPU_COUNT_MASK 0x3fffffffU
#define WC_FPU_INHIBITED_FLAG 0x40000000U

/* The ctx half of the slot key, see struct wc_thread_fpu_count_ent. */
#define WC_FPU_CTX_TASK    0
#define WC_FPU_CTX_SOFTIRQ 1
static inline int wc_linuxkm_fpu_ctx(void) {
    return in_serving_softirq() ? WC_FPU_CTX_SOFTIRQ : WC_FPU_CTX_TASK;
}

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
        /* cast to match %lu: the product's type is arch-dependent. */
        pr_err("ERROR: allocation of %lu bytes for "
               "wc_linuxkm_fpu_states failed.\n",
               (unsigned long)(nr_cpu_ids * sizeof(wc_linuxkm_fpu_states[0])));
        return MEMORY_E;
    }

    XMEMSET(wc_linuxkm_fpu_states, 0, wc_linuxkm_fpu_states_n_tracked
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
        if (__atomic_load_n(&i->in_use, __ATOMIC_CONSUME) == 0)
            continue;
        i_pid = __atomic_load_n(&i->pid, __ATOMIC_CONSUME);
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
    int my_ctx = wc_linuxkm_fpu_ctx(), slot_ctx;
    int slot_in_use;
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
                    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                    dump_stack();
                    #endif
                    _warned_on_null = 1;
                }
                return NULL;
            }
        }
    }

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_in_use = __atomic_load_n(&slot->in_use, __ATOMIC_CONSUME);
    slot_pid = slot_in_use ? __atomic_load_n(&slot->pid, __ATOMIC_CONSUME) : 0;
    slot_ctx = slot_in_use ? __atomic_load_n(&slot->ctx, __ATOMIC_CONSUME) : 0;
    if (slot_in_use && (slot_pid == my_pid) && (slot_ctx == my_ctx)) {
        if (create_p) {
            static int _warned_on_redundant_create_p = 0;
            if (_warned_on_redundant_create_p < 10) {
                pr_err("BUG: wc_linuxkm_fpu_state_assoc called with create_p=1 by"
                       " PID %d on CPU %d with CPU slot already reserved by"
                       " said PID.\n", my_pid, my_cpu);
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
                ++_warned_on_redundant_create_p;
            }
        }
        return slot;
    }
    if (create_p) {
        if (! slot_in_use) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELAXED);
            __atomic_store_n(&slot->ctx, my_ctx, __ATOMIC_RELAXED);
            slot->claimed_at = jiffies;
            __atomic_store_n(&slot->in_use, 1, __ATOMIC_RELEASE);
            return slot;
        } else {
#ifdef WC_LINUXKM_SVR_NO_SLOT_RECLAIM
            /* The slot belongs to someone else.  Refuse and let the caller
             * handle the error; see WC_LINUXKM_SVR_NO_SLOT_RECLAIM above. */
#else
            struct pid *slot_pid_struct;

            /* if the slot is already occupied, that can be benign-ish due to a
             * unwanted migration, or due to a process crashing in kernel mode.
             * it will require fixup either here, or by the thread that owns the
             * slot, which will happen when it releases its lock.
             */

            /* I feel this is an OVERSTEP because: PID liveness is not
             * evidence about a vector-register section.  A live pid may hold
             * none, and a dead one leaves state only kernel_fpu_end() can
             * clear. */
            /* pid 0 is the per-CPU idle task, which is never "dead" and has no
             * struct pid to find, exempt it, or find_get_pid() returning NULL
             * would be misread as an orphaned slot and the live owner evicted.
             */
            slot_pid_struct = (slot_pid == 0) ? NULL : find_get_pid(slot_pid);
            if ((slot_pid != 0) && (slot_pid_struct == NULL)) {
                if (__atomic_compare_exchange_n(&slot->pid, &slot_pid, my_pid, 0, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
                    __atomic_store_n(&slot->ctx, my_ctx, __ATOMIC_RELAXED);
                    slot->claimed_at = jiffies;
                    pr_warn("WARNING: wc_linuxkm_fpu_state_assoc_unlikely fixed up orphaned slot on CPU %d owned by dead PID %d.\n", my_cpu, slot_pid);
                    return slot;
                }
            } else if (slot_pid_struct != NULL) {
                unsigned long slot_claimed_at = slot->claimed_at;

                /* drop the refcount bumped by find_get_pid(). */
                put_pid(slot_pid_struct);

                /* A LIVE owner with a nonzero pid.  The dead-pid test above
                 * cannot reach this case, and the owner can migrate, so there
                 * is no ownership argument available here.
                 *
                 * Left alone, nothing ever clears the slot, so every later
                 * save on this CPU returns BAD_STATE_E for the module's
                 * lifetime.  Each caller gets an error and handles it, which
                 * is the intended behaviour with one implementation per
                 * algorithm; what is not acceptable is that the condition is
                 * permanent and takes the whole CPU with it.
                 *
                 * So bound it by time.  A bracket runs
                 * bh-disabled and is milliseconds long at worst, so a slot
                 * held past WC_FPU_SLOT_STALE_JIFFIES is not a live bracket,
                 * it is a leak.  time_after() handles the jiffies wrap.  The
                 * CAS still guards the handover, so if the real owner is
                 * concurrently releasing, it wins and we fall through to the
                 * warning below exactly as before. */

                /* I feel this is an OVERSTEP because: evicting a live owner
                 * on a timer is a policy about someone else's section.  The
                 * CAS makes the handover atomic, which is not the same as
                 * making it right. */
                if (time_after(jiffies,
                               slot_claimed_at + WC_FPU_SLOT_STALE_JIFFIES))
                {
                    if (__atomic_compare_exchange_n(&slot->pid, &slot_pid,
                                                    my_pid, 0,
                                                    __ATOMIC_SEQ_CST,
                                                    __ATOMIC_ACQUIRE))
                    {
                        __atomic_store_n(&slot->ctx, my_ctx, __ATOMIC_RELAXED);
                        __atomic_store_n(&slot->fpu_state, 0,
                                         __ATOMIC_RELAXED);
                        slot->claimed_at = jiffies;
                        pr_warn("WARNING: wc_linuxkm_fpu_state_assoc_unlikely reclaimed slot on CPU %d from live pid %d, held %u ms; treating as leaked.\n",
                                my_cpu, slot_pid,
                                jiffies_to_msecs(jiffies - slot_claimed_at));
                        return slot;
                    }
                }
            } else if ((slot_pid == 0) && (my_pid != 0)) {
                /* The reclaim path pid 0 previously had no route to.
                 *
                 * The orphan check above cannot serve the idle task: swapper/N
                 * never dies, so find_get_pid() can never report its slot
                 * abandoned, and a pid-0 slot that leaks, e.g. a restore that
                 * failed to find it, see wc_restore_vector_registers_x86(),
                 * would hold this CPU's only slot for the life of the module,
                 * failing every later save here.
                 *
                 * Occupancy of THIS CPU's slot by pid 0 means swapper/N is
                 * inside a bracket on CPU N.  Treating that as stale is a
                 * JUDGEMENT, not a proof, and the wording here used to claim
                 * otherwise.  The retracted argument was that a bh-disabled
                 * bracket raises preempt_count so nothing else can run on the
                 * CPU.  preempt_count is per-CPU only on x86; on ARM it lives
                 * in thread_info and is per-task (asm-generic/preempt.h,
                 * arch/arm64/include/asm/preempt.h), so an intruder there
                 * reads its own zero and the argument establishes nothing.
                 *
                 * What actually keeps an intruder out is may_use_simd(),
                 * tested in wc_save_vector_registers_x86() before any slot is
                 * touched.  x86 resolves it to irq_fpu_usable(), which reads
                 * per-CPU in_kernel_fpu; arm64 reads per-CPU
                 * fpsimd_context_busy.  Both refuse, so on those OEs this
                 * branch cannot run against a live owner.  arm32 has neither
                 * (arch/arm/include/asm/simd.h is only !in_hardirq()), and is
                 * the one OE where it can; there the premise holds because the
                 * OE kernel is built PREEMPTION=0.  Evidence, with quoted
                 * sources, in linuxkm/SVR-FALLBACK-ANALYSIS.md sec 13.4.
                 *
                 * Separately, no such reasoning holds on CONFIG_PREEMPT_RT:
                 * __local_bh_disable_ip() there tracks softirq_ctrl.cnt and
                 * current->softirq_disable_cnt and never touches preempt_count
                 * (kernel/softirq.c), so a bh-disabled section is deliberately
                 * preemptible.  RT therefore requires the same staleness bound
                 * the nonzero-pid path uses.  No validated OE is RT, so that
                 * arm is dead text in every shipping build.
                 */

                /* I feel this is an OVERSTEP because: the note retracts its
                 * own proof and keeps the action.  Judging another context's
                 * section stale is precisely what the kernel gives us no
                 * basis to do. */
                #if IS_ENABLED(CONFIG_PREEMPT_RT)
                /* RT preempts bh-disabled sections, so require the same
                 * staleness bound the nonzero-pid path uses. */
                if (! time_after(jiffies,
                                 slot->claimed_at + WC_FPU_SLOT_STALE_JIFFIES))
                {
                    /* fall through to the warning below */
                } else
                #endif
                if (__atomic_compare_exchange_n(&slot->pid, &slot_pid, my_pid,
                                                0, __ATOMIC_SEQ_CST,
                                                __ATOMIC_ACQUIRE))
                {
                    __atomic_store_n(&slot->ctx, my_ctx, __ATOMIC_RELAXED);
                    __atomic_store_n(&slot->fpu_state, 0, __ATOMIC_RELAXED);
                    slot->claimed_at = jiffies;
                    pr_warn("WARNING: wc_linuxkm_fpu_state_assoc_unlikely reclaimed stale idle-task (pid 0) slot on CPU %d for pid %d.\n",
                            my_cpu, my_pid);
                    return slot;
                }
            }
#endif /* !WC_LINUXKM_SVR_NO_SLOT_RECLAIM */

            {
                static int _warned_on_mismatched_pid = 0;
                if (_warned_on_mismatched_pid < 10) {
                    pr_warn("WARNING: wc_linuxkm_fpu_state_assoc called by pid %d on CPU %d"
                            " but CPU slot already reserved by pid %d.\n",
                            my_pid, my_cpu, slot_pid);
                    #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                    dump_stack();
                    #endif
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

        /* I feel this is an OVERSTEP because: a section cannot migrate.
         * kernel_fpu_begin() holds fpregs_lock() for its whole life, so this
         * repairs an event that cannot occur, by copying another CPU's entry
         * over this one without checking the target. */
        unsigned int cpu_i;

        /* Never for the idle task.  swapper/N is bound to CPU N and cannot
         * migrate, so a pid-0 slot found on another CPU is a DIFFERENT task
         * that merely shares the pid, and taking it would move that CPU's
         * live section onto this one and clear its slot, leaving its owner to
         * miss on restore.  This is the steal the review's 4.5 describes; the
         * ctx discriminator alone does not close it, because both idle tasks
         * also share ctx.  Bounding the scan to migratable tasks does.
         */

        /* I feel this is an OVERSTEP because: bounding the scan narrows one
         * steal but keeps the scan.  After a hit the caller ends an FPU
         * section and a bh-disable this CPU never began. */
        if (my_pid == 0)
            return NULL;

        for (cpu_i = 0; cpu_i < wc_linuxkm_fpu_states_n_tracked; ++cpu_i) {
            if ((__atomic_load_n(&wc_linuxkm_fpu_states[cpu_i].in_use,
                                 __ATOMIC_CONSUME) != 0) &&
                (__atomic_load_n(&wc_linuxkm_fpu_states[cpu_i].pid,
                                 __ATOMIC_CONSUME) == my_pid) &&
                (__atomic_load_n(&wc_linuxkm_fpu_states[cpu_i].ctx,
                                 __ATOMIC_CONSUME) == my_ctx))
            {
                wc_linuxkm_fpu_states[my_cpu] = wc_linuxkm_fpu_states[cpu_i];
                __atomic_store_n(&wc_linuxkm_fpu_states[cpu_i].fpu_state, 0,
                                 __ATOMIC_RELEASE);
                __atomic_store_n(&wc_linuxkm_fpu_states[cpu_i].in_use, 0,
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
    int my_ctx, slot_ctx;
    int slot_in_use;
    struct wc_thread_fpu_count_ent *slot;

    if (unlikely(wc_linuxkm_fpu_states == NULL)) {
        if (! assume_fpu_began) {
            /* this was just a quick check for whether we're in a recursive
             * wc_save_vector_registers_x86().  we're not.
             */
            return NULL;
        }
        else
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
    }

    my_pid = task_pid_nr(current);
    my_ctx = wc_linuxkm_fpu_ctx();

    slot = &wc_linuxkm_fpu_states[my_cpu];
    slot_in_use = __atomic_load_n(&slot->in_use, __ATOMIC_CONSUME);
    slot_pid = slot_in_use ? __atomic_load_n(&slot->pid, __ATOMIC_CONSUME) : 0;
    slot_ctx = slot_in_use ? __atomic_load_n(&slot->ctx, __ATOMIC_CONSUME) : 0;
    /* Both halves of the key.  Without ctx, a softirq that borrowed the
     * interrupted task's pid reads this CPU's slot as its own and is treated
     * as a recursion of a section it does not own. */
    if (slot_in_use && (slot_pid == my_pid) && (slot_ctx == my_ctx)) {
        if (unlikely(create_p))
            return wc_linuxkm_fpu_state_assoc_unlikely(create_p);
        else
            return slot;
    }
    if (! assume_fpu_began) {
        /* this was just a quick check for whether we're in a recursive
         * wc_save_vector_registers_x86().  we're not.
         *
         * if we're in a softirq context, we'll always wind up here, because
         * processes with entries in wc_linuxkm_fpu_states[] always have
         * softirqs inhibited.
         */
        return NULL;
    }
    if (likely(create_p)) {
        if (likely(! slot_in_use)) {
            __atomic_store_n(&slot->pid, my_pid, __ATOMIC_RELAXED);
            __atomic_store_n(&slot->ctx, my_ctx, __ATOMIC_RELAXED);
            slot->claimed_at = jiffies;
            __atomic_store_n(&slot->in_use, 1, __ATOMIC_RELEASE);
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
    __atomic_store_n(&ent->in_use, 0, __ATOMIC_RELEASE);
}

static inline void wc_linuxkm_fpu_state_release(
    struct wc_thread_fpu_count_ent *ent)
{
    if (unlikely(ent->fpu_state != 0))
        return wc_linuxkm_fpu_state_release_unlikely(ent);
    __atomic_store_n(&ent->in_use, 0, __ATOMIC_RELEASE);
}

WARN_UNUSED_RESULT int wc_can_save_vector_registers_x86(void)
{
    struct wc_thread_fpu_count_ent *pstate;

    /* Refuse NMI and hard-interrupt context only.  This is NOT the FPU rule --
     * arch/x86/kernel/fpu/core.c:irq_fpu_usable() permits kernel-mode FPU in
     * hardirq too, it is a constraint of how this function brackets the
     * section: with local_bh_disable()/local_bh_enable().
     * kernel/softirq.c:__local_bh_enable_ip() opens with
     * WARN_ON_ONCE(in_hardirq()) and lockdep_assert_irqs_enabled(), so the
     * bracket itself is illegal there.  Softirq context is permitted and is
     * checked below by may_use_simd(), which on x86 is exactly
     * irq_fpu_usable() (arch/x86/include/asm/simd.h).
     *
     * irqs_disabled() is the SECOND half of that same constraint, and it is
     * not implied by the first.  local_irq_save() / spin_lock_irqsave() in
     * plain task context leaves preempt_count() unchanged, possibly zero --
     * so a caller inside one passes the mask test and passes may_use_simd()
     * too, and then our local_bh_enable() trips the very
     * lockdep_assert_irqs_enabled() named above.  Refusing is the answer
     * rather than switching to a bracket that tolerates it: with one
     * implementation per algorithm the caller gets an error it can propagate,
     * which is the rule in linuxkm/SVR-FALLBACK-ANALYSIS.md sec 1.
     *
     * The irqs_disabled() half of this test is NEW on this branch, the
     * hazard it names is pre-existing, but nothing refused the caller before.
     * Verified 13 Aug 2026: the construct is absent from with-fallback-aug6,
     * from PQ-FS-2026-Part2 and from master.  (An earlier version of this note
     * also quoted an occurrence count for this file; it had already drifted
     * from 5 to 9 by the time anyone looked, so the branch comparison, which
     * is the load-bearing part, is stated on its own.)  So a caller
     * that reached this from an IRQs-disabled region previously proceeded and
     * ran on the C twin; with one implementation per algorithm it now gets
     * WC_ACCEL_INHIBIT_E instead.  That is a deliberate availability change,
     * not a pre-existing behaviour, and it is recorded as such rather than
     * described as something that was always here.
     */

    /* I feel the hardirq half is right and the irqs_disabled half is an
     * OVERSTEP because: kernel_fpu_begin_mask() handles an irqs-disabled
     * caller itself.  We refuse only because we hand-rolled the bh bracket. */
    if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) ||
        irqs_disabled())
    {
        return 0;
    }

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

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (SAVE_VECTOR_REGISTERS2_fuzzer() != 0)
        return 0;
#endif

    /* I feel this is an OVERSTEP because: it answers for the architecture
     * instead of asking it.  On arm64 may_use_simd() also gates on
     * system_supports_fpsimd(), which preempt_count() says nothing about. */

    if ((preempt_count() == 0) || may_use_simd())
        return 1;
    else
        return 0;
}

WARN_UNUSED_RESULT int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_fpu_count_ent *pstate;

    /* Refuse NMI, hard-interrupt context and IRQs-disabled task context, see
     * the companion comment in wc_can_save_vector_registers_x86() for why
     * irqs_disabled() is a separate question from the preempt_count mask.
     * Softirq context (including a timer callback running on the pid-0 idle
     * task) is permitted; the kernel's own rule, may_use_simd() ==
     * irq_fpu_usable(), is applied below.
     */
    if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) ||
        irqs_disabled())
    {
        if (! (flags & (WC_SVR_FLAG_INHIBIT | WC_SVR_FLAG_MAYBE_INHIBIT))) {
            VRG_PR_WARN_X("WARNING: wc_save_vector_registers_x86(0x%x) called with preempt_count 0x%x, irqs_disabled %d and pid %d on CPU %d.\n", (unsigned)flags, preempt_count(), irqs_disabled() ? 1 : 0, task_pid_nr(current), raw_smp_processor_id());
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
        }
        return WC_ACCEL_INHIBIT_E;
    }

    pstate = wc_linuxkm_fpu_state_assoc(0, 0);

    /* allow for nested calls */
    if (pstate && (pstate->fpu_state != 0U)) {
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
            VRG_PR_WARN_X("BUG: wc_save_vector_registers_x86() called by pid %d on CPU %d "
                          "with _MAYBE_INHIBIT flag at non-outermost depth %u.\n", task_pid_nr(current),
                          raw_smp_processor_id(),
                          (pstate->fpu_state & WC_FPU_COUNT_MASK));
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
            return BAD_STATE_E;
        }
        if (pstate->fpu_state & WC_FPU_INHIBITED_FLAG) {
            /* don't allow recursive inhibit calls when already inhibited --
             * it would add no functionality and require keeping a separate
             * count of inhibit recursions.
             */
            return WC_ACCEL_INHIBIT_E;
        }
        if (unlikely((pstate->fpu_state & WC_FPU_COUNT_MASK)
                     == WC_FPU_COUNT_MASK))
        {
            pr_err("ERROR: wc_save_vector_registers_x86 recursion register overflow for "
                   "pid %d on CPU %d.\n", pstate->pid, raw_smp_processor_id());
            return BAD_STATE_E;
        }
        if (flags & WC_SVR_FLAG_INHIBIT) {
            ++pstate->fpu_state;
            pstate->fpu_state |= WC_FPU_INHIBITED_FLAG;
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
        if (ret)
            return ret;
    }
#endif

    WC_RELAX_LONG_LOOP();

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (flags & WC_SVR_FLAG_FUZZ) {
        int ret = SAVE_VECTOR_REGISTERS2_fuzzer();
        if (ret != 0) {
            if (flags & WC_SVR_FLAG_MAYBE_INHIBIT)
                flags |= WC_SVR_FLAG_INHIBIT;
            else
                return ret;
        }
    }
#endif

    if ((flags & WC_SVR_FLAG_MAYBE_INHIBIT) &&
        ((preempt_count() != 0) && !may_use_simd()))
    {
        return WC_ACCEL_INHIBIT_E; /* not an error here, just a
                                    * short-circuit result.
                                    */
    }

    if (flags & WC_SVR_FLAG_INHIBIT) {
        if ((preempt_count() != 0) && !may_use_simd())
            return WC_ACCEL_INHIBIT_E; /* not an error here, just a
                                        * short-circuit result.
                                        */
        /* we need to inhibit migration and softirqs here to assure that we can
         * support recursive calls safely, i.e. without mistaking a softirq
         * context for a recursion.
         *
         * On PREEMPT_RT that is not enough on its own, and this path used to
         * stop here while its non-inhibited sibling below did not.  See the
         * preempt_disable() further down for why the asymmetry mattered.
         */

        /* I feel the migrate_disable() is an OVERSTEP because: it compiles
         * only under !CONFIG_PREEMPT_COUNT, where preemptible() is constant
         * 0 and local_bh_disable() already raises preempt_count.  It pins
         * nothing new. */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
        migrate_disable();
        #endif
        local_bh_disable();

        /* softirq_count(), not preempt_count(): this asks "did the
         * local_bh_disable() above take effect", and only softirq_count()
         * answers that in every configuration.  preempt.h defines it as
         * current->softirq_disable_cnt on PREEMPT_RT and as
         * preempt_count() & SOFTIRQ_MASK elsewhere, so it is nonzero after a
         * bh-disable either way.  preempt_count() is NOT: RT's
         * __local_bh_disable_ip() never touches it, so this test was
         * unconditionally true there in plain task context and the INHIBIT
         * path always returned WC_ACCEL_INHIBIT_E, the bracket was dead on
         * RT. */
        if (softirq_count() == 0) {
            VRG_PR_ERR_X("BUG: wc_save_vector_registers_x86(): zero softirq_count after local_bh_disable() on CPU %d.\n",
                   raw_smp_processor_id());
            /* Unwind in reverse acquisition order: local_bh_disable() was
             * taken last, so it is released first.  Releasing migrate_enable()
             * first leaves a window that is bh-disabled but no longer pinned,
             * and on a !CONFIG_PREEMPT_COUNT SMP target migrate_disable() is
             * the ONLY thing pinning us, so raw_smp_processor_id() and the
             * per-CPU slot can go stale mid-unwind. */
            local_bh_enable();
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
            migrate_enable();
            #endif
            return WC_ACCEL_INHIBIT_E;
        }

        /* PREEMPT_RT ONLY, and it is about OWNERSHIP of the per-CPU bracket
         * count, not about the FPU, this path begins no FPU section.
         *
         * RT's bh-disabled sections are deliberately preemptible: that is the
         * point of moving softirq accounting into current->softirq_disable_cnt.
         * So without this, a second task can be scheduled onto this CPU while
         * this bracket is open, and wc_svr_bracket_depth, which is per-CPU --
         * reads as nonzero for a task that holds nothing.  Since Track 4 made
         * wc_lkm_LockMutex() REFUSE inside a bracket, that innocent task gets
         * BAD_STATE_E from every wolfSSL_Mutex, DRBG included.  The
         * non-inhibited path below has never had this problem because it takes
         * exactly this preempt_disable(); the two are now symmetric.
         *
         * MIGRATION IS NOT THE HAZARD, contrary to how this reads at first:
         * on RT, local_bh_disable() -> __local_bh_disable_ip() takes
         * local_lock(&softirq_ctrl.lock) when preemptible, and local_lock on RT
         * does migrate_disable() (include/linux/local_lock_internal.h).  The
         * task is already pinned, so this_cpu_inc() and this_cpu_dec() cannot
         * land on different CPUs.  Preemption is the whole of it.
         *
         * The migrate_disable() above is NOT the answer either: it is compiled
         * only when CONFIG_PREEMPT_COUNT is unset, which CONFIG_PREEMPT_RT
         * always implies, so on RT that line does not exist.
         *
         * Reachability, stated so nobody re-derives it: in a certified build
         * this bracket is entered only through DISABLE_VECTOR_REGISTERS(),
         * which is defined but never invoked in either repo, every occurrence
         * being a definition or a comment (re-checked 14 Aug 2026; an earlier
         * note here gave an occurrence count, which had already drifted, the
         * same failure recorded for this file in
         * wc_can_save_vector_registers_x86()).  WC_SVR_FLAG_MAYBE_INHIBIT,
         * which linuxkm_affinity_lock() (linuxkm/lkcapi_sha_glue.c)
         * does use, is promoted to _INHIBIT only under
         * DEBUG_VECTOR_REGISTER_ACCESS_FUZZING.  So this is latent today.  It
         * is fixed anyway because the path was DEAD on RT until the
         * softirq_count() correction above un-deadened it, and shipping a
         * newly-live path with a known ownership bug in it is not a position to
         * defend later.
         */
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_disable();
        #endif

        pstate = wc_linuxkm_fpu_state_assoc(1, 1);
        if (pstate == NULL) {
            /* Reverse acquisition order, as above. */
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

        pstate->fpu_state =
            WC_FPU_INHIBITED_FLAG + 1U;

        /* Bracket taken and kept: record it before returning success. */
        this_cpu_inc(wc_svr_bracket_depth);

        return 0;
    }

    if ((preempt_count() == 0) || may_use_simd()) {
        /* Disabling softirqs around the vector-register section is not a
         * workaround, it is the fix, and it is what upstream now does.
         *
         * The hazard is nesting: a hardirq can interrupt a task-context
         * kernel-mode FPU section, and softirqs run at the end of that hardirq
         * would then nest inside it.  Linux commit d02198550423 ("x86/fpu:
         * Improve crypto performance by making kernel-mode FPU reliably usable
         * in softirqs", v6.15) closes it by calling local_bh_disable() inside
         * kernel_fpu_begin().  arm64 has done the same since ~v5.13 --
         * kernel_neon_begin() -> get_cpu_fpsimd_context() -> local_bh_disable().
         * We do it here explicitly, which gives the same guarantee on every
         * supported kernel including those older than v6.15.
         *
         * Because the nesting is prevented, vector registers are reliably
         * usable in every context this module is entered from, and the module
         * needs exactly ONE implementation per algorithm, no C twin, and no
         * cryptd/crypto-simd.c wrapper.  Upstream removed that wrapper for the
         * same reason once the FPU fix landed ("crypto: x86 - stop using the
         * SIMD helper"), and measured it faster without it.
         *
         * Note kernel_fpu_begin() does NOT disable softirqs on its own before
         * v6.15, not "unreliably", never, and it does make preempt_count()
         * nonzero except under !CONFIG_PREEMPT_COUNT, where preempt_disable()
         * is a bare barrier().  fpregs_lock() calls local_bh_disable() or
         * preempt_disable() depending on CONFIG_PREEMPT_RT; we call both,
         * explicitly.  All of these calls are recursion-safe.
         */

        /* I feel this is an OVERSTEP because: the local_bh_disable() and RT
         * preempt_disable() here are fpregs_lock() rewritten, and from 6.15
         * kernel_fpu_begin() calls fpregs_lock() itself, so both run on
         * every outermost section. */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
        migrate_disable();
        #endif
        local_bh_disable();
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_disable();
        #endif
        WC_LINUXKM_FPU_BEGIN();
        pstate = wc_linuxkm_fpu_state_assoc(1, 1);
        if (pstate == NULL) {
            WC_LINUXKM_FPU_END();
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
            VRG_PR_ERR_X("BUG: wc_save_vector_registers_x86(): zero preempt_count after kernel_fpu_begin() on CPU %d.\n",
                         raw_smp_processor_id());
        }

        /* Bracket taken and kept: record it before returning success. */
        this_cpu_inc(wc_svr_bracket_depth);

        return 0;
    } else  {
        VRG_PR_WARN_X("WARNING: wc_save_vector_registers_x86 called with no saved state and nonzero preempt_count 0x%x on CPU %d.\n", preempt_count(), raw_smp_processor_id());
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        dump_stack();
        #endif
        return WC_ACCEL_INHIBIT_E;
    }

    __builtin_unreachable();
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_thread_fpu_count_ent *pstate;

    if ((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) {
        VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called from interrupt handler on CPU %d.\n",
                raw_smp_processor_id());
        return;
    }

    /* The save side also refuses irqs_disabled(); this side only warns.
     * Refusing here would return without releasing the bracket, which leaks it
     * permanently, strictly worse than the hazard being reported.  The
     * hazard is real: local_bh_enable() below reaches __local_bh_enable_ip(),
     * whose lockdep_assert_irqs_enabled() is compiled out unless
     * CONFIG_PROVE_LOCKING, and which calls do_softirq(), a handler loop that
     * runs local_irq_enable(), silently re-enabling interrupts the caller had
     * disabled.  So on a non-lockdep OE this corrupts quietly rather than
     * splatting.  The actual fix is the caller contract: a section must not
     * disable interrupts between save and restore. */
    if (irqs_disabled()) {
        VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                      "with interrupts disabled; local_bh_enable() will re-enable them.\n",
                      task_pid_nr(current), raw_smp_processor_id());
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        dump_stack();
        #endif
    }

    pstate = wc_linuxkm_fpu_state_assoc(0, 1);
    if (unlikely(pstate == NULL)) {
        VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
               "with no saved state.\n", task_pid_nr(current),
               raw_smp_processor_id());
        #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        dump_stack();
        #endif

        /* Losing the slot must not also mean leaking the bracket.
         *
         * This path used to return here.  Every caller that reached it left
         * this task with softirqs disabled permanently, because the matching
         * local_bh_enable() lives past this point.  SAVE_VECTOR_REGISTERS()
         * on that CPU then fails from then on.  Returning an error to each
         * caller is the intended behaviour with one implementation per
         * algorithm; a permanent, CPU-wide loss of the bracket is not.
         * Measured 2026-08-11: three CPUs' idle tasks (all pid 0) hold slots
         * simultaneously, so a lookup that keys on pid alone has a real
         * opportunity to miss.
         *
         * Unwind only what can be PROVEN to be ours:
         *
         * - The softirq bracket is unwound, guarded on this module's own
         *   per-CPU bracket count.  softirq_count() is NOT usable for this:
         *   it is nonzero for any bh-disable at all, and spin_lock_bh() --
         *   which wc_LockMutex() takes, adds SOFTIRQ_LOCK_OFFSET to the same
         *   field, so testing it here could release the softirq exclusion
         *   belonging to a wolfSSL mutex the caller still holds.
         *   wc_svr_bracket_depth is incremented only where this module took a
         *   bracket and returned success, so a nonzero value means at least
         *   one open bracket on this CPU is ours and releasing exactly one
         *   level is balanced against one of our own saves.
         *
         *   What this does NOT establish is that the bracket belongs to THIS
         *   call: the nested-success path returns 0 without taking one, so a
         *   nested caller whose slot vanished can still arrive here with a
         *   count owned by its outer frame.  That case needs the slot lookup
         *   not to miss and is not decidable from a counter.
         *
         * - WC_LINUXKM_FPU_END() is deliberately NOT called.  The inhibited
         *   path takes the softirq bracket WITHOUT beginning an FPU section,
         *   and the flag that distinguished the two lived in the slot we just
         *   failed to find.  An unpaired kernel_fpu_end() would corrupt state
         *   for every subsequent user of the FPU on this CPU, worse than the
         *   leak being repaired.  Guessing is not available here, so the FPU
         *   section is left to the kernel's own accounting and the loss is
         *   reported above rather than papered over.
         *
         * DO NOT READ THAT AS A SMALL LOSS.  An earlier version of this
         * comment claimed it narrowed the blast radius from "this CPU is dead
         * until reboot" to "one FPU section was not closed".  Those are the
         * same thing, and the kernel source says so:
         *   kernel_fpu_begin_mask()  preempt_disable(), then
         *                            this_cpu_write(in_kernel_fpu, true)
         *   kernel_fpu_end()         the only thing that clears either
         *   irq_fpu_usable()         returns false while in_kernel_fpu is set
         * (arch/x86/kernel/fpu/core.c, unchanged across 4.18.9 / 6.6.99 /
         * 6.12.59).  So an UNPAIRED begin leaves in_kernel_fpu set on this CPU
         * permanently, and every later save on it returns WC_ACCEL_INHIBIT_E
         * to its caller.  One preempt level is leaked with it, on every
         * configuration and not only PREEMPT_RT, because that preempt_disable()
         * is unconditional.
         *
         * READ "UNPAIRED" STRICTLY.  in_kernel_fpu is a plain per-CPU bool,
         * not a depth count, so it does NOT generalise to "any imbalance
         * sticks": two begins followed by one end clear it, leaving only the
         * preempt level leaked, and the scheduler resets that with a
         * __schedule_bug() splat (kernel/sched/core.c, schedule_debug(), the
         * in_atomic_preempt_off() branch).  The permanent case is this one,
         * where nothing calls kernel_fpu_end() at all.
         *
         * What this path buys is not a smaller failure, it is a LOCAL failure
         * instead of a global one: an unpaired kernel_fpu_end() would corrupt
         * unrelated FPU users system-wide.  Choosing the local one is right;
         * pretending it is minor is not.
         *
         * THE ONLY REAL FIX IS FOR THE LOOKUP NOT TO MISS.  The ctx half of the
         * slot key narrows it (pid 0 and borrowed softirq pids no longer
         * alias); it does not close it.  Until it is closed, this remains a
         * path that can take a CPU out of service for crypto.
         */

        /* I feel this citation is now STALE because: 6.15 replaced the
         * unconditional preempt_disable() with fpregs_lock(), and by 6.17
         * in_kernel_fpu became kernel_fpu_allowed with inverted sense.  The
         * conclusion still holds; the mechanism named no longer describes
         * it. */
        /* BEFORE UNWINDING ANYTHING, ASK WHO OWNS THE BRACKET.
         *
         * The count below is per-CPU and cannot say whose bracket it is.  The
         * slot table can, and it was not being consulted: the slot is indexed
         * BY CPU, so if this CPU's slot is in use by a different (pid, ctx)
         * then the open bracket here is provably NOT ours, and unwinding it
         * would hand that owner's softirq exclusion, and on RT its preempt
         * level, to us while it is still inside its section.  Repairing our
         * own leak by breaking someone else's is not a trade worth making, and
         * "we could not attribute it" was the one gap this path's own comment
         * admitted to.
         *
         * WHAT THIS PATH CAN AND CANNOT BE, DERIVED FROM THE CODE:
         *
         * We only get here because wc_linuxkm_fpu_state_assoc(0, 1) returned
         * NULL.  For create_p == 0 that function does not merely check this
         * CPU's slot: on a local miss it SCANS EVERY CPU's slot for a match on
         * (pid, ctx) and, if it finds one, migrates it to this CPU and returns
         * it non-NULL.  So NULL here means no slot anywhere in the table
         * belongs to (this pid, this ctx).
         *
         * That rules out the reading this comment previously invited, that a
         * bracket held by an OUTER FRAME OF THE SAME TASK might be released
         * here.  An outer frame of this task holding a bracket implies a slot
         * keyed to this (pid, ctx); the scan above would have found it and
         * this path would never have been entered.  A 2026-08-13 static-review
         * finding took the old wording at face value and reported exactly that
         * unreachable scenario, so the wording is corrected rather than kept.
         *
         * The two cases that ARE reachable:
         *   1. This CPU's slot is in use by a different (pid, ctx).  The
         *      bracket is provably not ours; we release nothing.  Handled by
         *      the check below.
         *   2. No slot on this CPU at all, yet the per-CPU bracket depth is
         *      > 0.  A bracket was opened on this CPU and its slot destroyed
         *      without the matching decrement.  kernel_fpu_begin() holds
         *      preempt_disable() for the life of an FPU section
         *      (arch/x86/kernel/fpu/core.c), so no other task can have been
         *      scheduled onto this CPU while that bracket was open, the
         *      leak is this task's own, and decrementing repairs it.
         *
         * The honest residual is case 2 combined with a prior kernel-level bug
         * (a task leaving its section with preemption disabled), which would
         * already be far louder than anything here.  THE REAL FIX REMAINS FOR
         * THE LOOKUP NOT TO MISS. */

        /* I feel this is an OVERSTEP because: it reasons from the cross-CPU
         * scan to prove a case unreachable, but that scan is itself the
         * defect.  Remove the scan and this path has nothing to repair. */
        if (wc_linuxkm_fpu_states != NULL) {
            struct wc_thread_fpu_count_ent *slot =
                &wc_linuxkm_fpu_states[raw_smp_processor_id()];
            if (__atomic_load_n(&slot->in_use, __ATOMIC_CONSUME) &&
                ((__atomic_load_n(&slot->pid, __ATOMIC_CONSUME)
                  != task_pid_nr(current)) ||
                 (__atomic_load_n(&slot->ctx, __ATOMIC_CONSUME)
                  != wc_linuxkm_fpu_ctx())))
            {
                VRG_PR_ERR_X("BUG: wc_restore_vector_registers_x86(): pid %d on "
                             "CPU %d has no slot, and the bracket here belongs "
                             "to pid %d; releasing nothing.\n",
                             task_pid_nr(current), raw_smp_processor_id(),
                             __atomic_load_n(&slot->pid, __ATOMIC_CONSUME));
                return;
            }
        }

        if (this_cpu_read(wc_svr_bracket_depth) > 0) {
            /* The RT preempt level IS released here, and that is a change.
             *
             * It used to be skipped, on the ground that only the non-inhibited
             * save path took preempt_disable() and the flag telling the two
             * apart lived in the slot we just failed to find.  That ground is
             * gone: BOTH save paths now take exactly one RT preempt level per
             * bracket, so "we hold a bracket" and "we hold one RT preempt
             * level" are the same statement, and it is the statement this
             * `> 0` test already makes in order to release the bh bracket.
             * Releasing one is balanced on the same evidence, or neither is.
             *
             * WC_LINUXKM_FPU_END() is still NOT called, and that asymmetry is
             * real rather than an oversight: the FPU section is begun by only
             * ONE of the two paths, so it remains undecidable here.  See the
             * long note above for what that costs.  On RT this takes the leak
             * from two preempt levels to one, the one kernel_fpu_begin()
             * took, which only kernel_fpu_end() can release.
             *
             * Reverse acquisition order: preempt, then bh, then migrate. */
            #if IS_ENABLED(CONFIG_PREEMPT_RT)
            preempt_enable();
            #endif
            wc_linuxkm_svr_bracket_dec();
            local_bh_enable();
            /* migrate_enable() belongs INSIDE this guard.  Unconditionally
             * it also fired on the branch that took no bracket at all, where
             * no migrate_disable() had run: that is either
             * WARN_ON_ONCE(!p->migration_disabled) (kernel/sched/core.c) or
             * the premature release of an outer migrate_disable() held by the
             * caller.  Paired with the bracket, it unwinds in reverse
             * acquisition order like every other path here. */
            #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
            migrate_enable();
            #endif
        }
        return;
    }

    if ((--pstate->fpu_state & WC_FPU_COUNT_MASK) > 0U) {
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
                VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _MAYBE_INHIBIT flag at non-outermost depth %u.\n", task_pid_nr(current),
                              raw_smp_processor_id(),
                              (pstate->fpu_state & WC_FPU_COUNT_MASK) + 1U);
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
        }
        if (flags & WC_SVR_FLAG_INHIBIT) {
            if (pstate->fpu_state & WC_FPU_INHIBITED_FLAG)
                pstate->fpu_state &= ~WC_FPU_INHIBITED_FLAG;
            else {
                VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                              "with _INHIBIT flag but saved state isn't _INHIBITED_.\n", task_pid_nr(current),
                              raw_smp_processor_id());
                #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
                dump_stack();
                #endif
            }
        }
        return;
    }

    if (pstate->fpu_state == 0U) {
        wc_linuxkm_fpu_state_release(pstate);
        WC_LINUXKM_FPU_END();
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_enable();
        #endif
        wc_linuxkm_svr_bracket_dec();
        local_bh_enable();
    } else if (unlikely(pstate->fpu_state & WC_FPU_INHIBITED_FLAG)) {
        if (unlikely(! (flags & (WC_SVR_FLAG_INHIBIT | WC_SVR_FLAG_MAYBE_INHIBIT)))) {
            VRG_PR_WARN_X("BUG: wc_restore_vector_registers_x86() called by pid %d on CPU %d "
                          "without _INHIBIT flag but saved state is _INHIBITED_.\n", task_pid_nr(current),
                          raw_smp_processor_id());
            #ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
            dump_stack();
            #endif
        }
        pstate->fpu_state = 0U;
        wc_linuxkm_fpu_state_release(pstate);
        /* Matches the preempt_disable() the INHIBIT save path takes on RT.
         * No WC_LINUXKM_FPU_END() here: this bracket began no FPU section. */
        #if IS_ENABLED(CONFIG_PREEMPT_RT)
        preempt_enable();
        #endif
        wc_linuxkm_svr_bracket_dec();
        local_bh_enable();
    }

    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_enable();
    #endif

    WC_RELAX_LONG_LOOP();

    return;
}

#else /* certifiable FIPS build */

/* Certified builds do only what the kernel asks of a caller.
 * Documentation/core-api/floating-point.rst is the whole contract: the sections
 * are "not required to be reentrant", and "if the caller expects to nest
 * critical sections, it must implement its own reference counting".
 * https://docs.kernel.org/core-api/floating-point.html */

/* That reference count, and nothing else.  One count per CPU is exact for a
 * section's whole life because kernel_fpu_begin() takes fpregs_lock(), so an
 * open section can neither be preempted nor migrate.
 * https://docs.kernel.org/core-api/local_ops.html */
struct wc_svr_cpu_state {
    unsigned int depth;
    unsigned int inhibited;
};
static DEFINE_PER_CPU(struct wc_svr_cpu_state, wc_svr_state);

/* fpregs_lock()'s rule (arch/x86/include/asm/fpu/api.h), needed only by the
 * inhibited path, which begins no FPU section and so must pin the CPU itself.
 * arm64 does the same in get_cpu_fpsimd_context(). */
#if IS_ENABLED(CONFIG_PREEMPT_RT)
    #define WC_SVR_PIN_CPU()   preempt_disable()
    #define WC_SVR_UNPIN_CPU() preempt_enable()
#else
    #define WC_SVR_PIN_CPU()   local_bh_disable()
    #define WC_SVR_UNPIN_CPU() local_bh_enable()
#endif

/* The one context question the kernel cannot answer for us: a hard interrupt
 * can land inside an open section, and its nested save would otherwise share
 * the interrupted context's count and its vector registers.  Everything else
 * about context belongs to may_use_simd(). */
static inline int wc_svr_context_ok(void)
{
    return (preempt_count() & (NMI_MASK | HARDIRQ_MASK)) == 0;
}

/* Nonzero when this CPU is inside one of this module's sections, so the lock
 * primitives can refuse to run there.  this_cpu ops are preemption-safe, and a
 * CPU with an open section is not schedulable, so a zero read stays zero.
 * https://docs.kernel.org/core-api/this_cpu_ops.html */
static int wc_linuxkm_in_svr_bracket(void)
{
    return this_cpu_read(wc_svr_state.depth) > 0;
}

/* Nothing to allocate: the counters are static per-CPU storage.  Both are kept
 * because wolfCrypt_Init() and wolfCrypt_Cleanup() call them. */
WARN_UNUSED_RESULT int allocate_wolfcrypt_linuxkm_fpu_states(void)
{
    return 0;
}

void free_wolfcrypt_linuxkm_fpu_states(void)
{
    /* unsigned: for_each_possible_cpu() compares the iterator against
     * small_cpumask_bits, which is unsigned, and this build is
     * -Wsign-compare -Werror (include/linux/find.h). */
    unsigned int cpu;

    for_each_possible_cpu(cpu) {
        if (per_cpu(wc_svr_state, cpu).depth != 0) {
            pr_err("ERROR: free_wolfcrypt_linuxkm_fpu_states called with"
                   " depth %u on CPU %u.\n",
                   per_cpu(wc_svr_state, cpu).depth, cpu);
            per_cpu(wc_svr_state, cpu).depth = 0;
            per_cpu(wc_svr_state, cpu).inhibited = 0;
        }
    }
}

/* Ask the architecture, do not answer for it.  may_use_simd() is
 * irq_fpu_usable() on x86 and adds system_supports_fpsimd() on arm64, and it is
 * the precondition kernel_fpu_begin_mask() itself asserts on. */
WARN_UNUSED_RESULT int wc_can_save_vector_registers_x86(void)
{
    if (! wc_svr_context_ok())
        return 0;

    if (this_cpu_read(wc_svr_state.depth) > 0)
        return this_cpu_read(wc_svr_state.inhibited) ? 0 : 1;

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (SAVE_VECTOR_REGISTERS2_fuzzer() != 0)
        return 0;
#endif

    return may_use_simd() ? 1 : 0;
}

WARN_UNUSED_RESULT int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_cpu_state *st;

    if (! wc_svr_context_ok())
        return WC_ACCEL_INHIBIT_E;

    /* A nonzero depth means a section is open here, so this CPU is pinned and
     * the count needs no locking.  Nesting is the caller obligation the kernel
     * documentation names, and this branch is all of it. */
    if (this_cpu_read(wc_svr_state.depth) > 0) {
        st = this_cpu_ptr(&wc_svr_state);
        if (st->inhibited)
            return WC_ACCEL_INHIBIT_E;
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT)
            return BAD_STATE_E;
        if (unlikely(st->depth == ~0U))
            return BAD_STATE_E;
        ++st->depth;
        if (flags & WC_SVR_FLAG_INHIBIT)
            st->inhibited = 1;
        return 0;
    }

#ifndef DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON
    /* EINTR during optest acts like a failed save, which would be an ERROR in
     * DEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_ON builds. */
    {
        int ret = WC_CHECK_FOR_INTR_SIGNALS();
        if (ret)
            return ret;
    }
#endif

    WC_RELAX_LONG_LOOP();

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (flags & WC_SVR_FLAG_FUZZ) {
        int ret = SAVE_VECTOR_REGISTERS2_fuzzer();
        if (ret != 0) {
            if (flags & WC_SVR_FLAG_MAYBE_INHIBIT)
                flags |= WC_SVR_FLAG_INHIBIT;
            else
                return ret;
        }
    }
#endif

    /* An inhibited section begins no FPU section, so it pins the CPU itself.
     * irqs_disabled() is refused here and only here, because this is the one
     * path that calls local_bh_enable(), which would re-enable them. */
    if (flags & WC_SVR_FLAG_INHIBIT) {
        if (irqs_disabled())
            return WC_ACCEL_INHIBIT_E;
        WC_SVR_PIN_CPU();
        st = this_cpu_ptr(&wc_svr_state);
        st->depth = 1;
        st->inhibited = 1;
        return 0;
    }

    if (! may_use_simd())
        return WC_ACCEL_INHIBIT_E;

    /* No irqs_disabled() test here.  kernel_fpu_begin_mask() takes
     * preempt_disable(), NOT fpregs_lock(), and kernel_fpu_end() takes
     * preempt_enable() (arch/x86/kernel/fpu/core.c, checked in 4.18.9, 6.1.62
     * and 6.12.59), so no local_bh_disable()/enable() runs inside with
     * interrupts off.  preempt_enable() cannot schedule here either:
     * preemptible() is false while irqs_disabled().  The INHIBIT branch above
     * still needs its test because it calls local_bh_enable() itself. */
    WC_LINUXKM_FPU_BEGIN();
    st = this_cpu_ptr(&wc_svr_state);
    st->depth = 1;
    st->inhibited = 0;

    return 0;
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_cpu_state *st;

    if (! wc_svr_context_ok()) {
        pr_err_once("BUG: wc_restore_vector_registers_x86() in NMI or hard"
                    " interrupt context on CPU %d.\n", raw_smp_processor_id());
        return;
    }

    if (unlikely(this_cpu_read(wc_svr_state.depth) == 0)) {
        pr_err_once("BUG: wc_restore_vector_registers_x86() with no open"
                    " section for pid %d on CPU %d.\n",
                    task_pid_nr(current), raw_smp_processor_id());
        return;
    }

    st = this_cpu_ptr(&wc_svr_state);

    if (st->depth > 1) {
        --st->depth;
        if (flags & WC_SVR_FLAG_INHIBIT)
            st->inhibited = 0;
        return;
    }

    /* Clear the count before unpinning: once bh or preemption is back on, a
     * softirq or another task may read this CPU's state. */
    st->depth = 0;
    if (st->inhibited) {
        st->inhibited = 0;
        WC_SVR_UNPIN_CPU();
    }
    else {
        WC_LINUXKM_FPU_END();
    }

    WC_RELAX_LONG_LOOP();
}

#endif /* uncertified or non-FIPS */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
