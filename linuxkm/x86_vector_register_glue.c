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
    #include <linux/version.h>

#if defined(CONFIG_ARM64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0))
    /* Linux 6.19 changed the arm64 contract: the CALLER supplies the buffer that
     * holds the interrupted kernel-mode FPSIMD state.  Verified by reading the
     * header in each tree, not inferred from a release note:
     *   linux-6.18.45  void kernel_neon_begin(void);
     *   linux-6.19.14  void kernel_neon_begin(struct user_fpsimd_state *);
     *   linux-7.0.14, linux-7.1.9  same as 6.19.
     * This gate said 7.0.0 until 2026-08-21, so arm64 6.19.x through 6.x
     * failed to compile: the call passed no argument to a function that
     * requires one.
     *   arch/arm64/include/asm/neon.h
     *     void kernel_neon_begin(struct user_fpsimd_state *);
     *     void kernel_neon_end(struct user_fpsimd_state *);
     *   arch/arm64/kernel/fpsimd.c
     *     begin(): in task context records it as
     *              current->thread.kernel_fpsimd_state so a CONTEXT SWITCH can
     *              preserve the section, and WARNs if that field was not NULL;
     *              nested in softirq it does fpsimd_save_state(state).
     *     end():   nested in softirq does fpsimd_load_state(state); otherwise
     *              WARN_ON(current->thread.kernel_fpsimd_state != state).
     *
     * So the buffer must live for the WHOLE section and be EXCLUSIVE to it.
     * One per CPU per context is exclusive for softirq and hardirq, neither of
     * which can migrate.  Task context is the hard case: kernel_neon_begin()
     * releases the fpsimd context before returning, so the task stays
     * preemptible and could be switched out and resumed on another CPU while a
     * second task reuses this CPU's slot.  Pinning the CPU for the life of the
     * section makes the slot exclusive, and is exactly what kernel_fpu_begin()
     * already does on x86 -- so this makes the two architectures agree rather
     * than introducing a new rule.  Nothing inside a section may sleep
     * (wc_linuxkm_can_block() refuses while a bracket is open), so pinning
     * costs no correctness.
     *
     * Pre-7.0 arm64 and all arm32 keep the no-argument form: only arm64
     * changed. */
    struct wc_lkm_neon_slots {
        struct user_fpsimd_state s[3];  /* task, softirq, hardirq */
    };
    static DEFINE_PER_CPU(struct wc_lkm_neon_slots, wc_lkm_neon_slots);

    static inline struct user_fpsimd_state *wc_lkm_neon_slot(void)
    {
        unsigned int i;
        if (preempt_count() & (NMI_MASK | HARDIRQ_MASK))
            i = 2;
        else if (in_serving_softirq())
            i = 1;
        else
            i = 0;
        /* raw_: the CPU is held for the whole life of the section, so this
         * resolves to the same slot at begin and at end -- by the
         * preempt_disable() in FPU_BEGIN where CONFIG_PREEMPT_COUNT is set,
         * and by the migrate_disable() next to it where it is not.  With only
         * the preempt_disable(), 22,358 of 60,087 measured sections resolved a
         * DIFFERENT slot at end(); see below. */
        return &raw_cpu_ptr(&wc_lkm_neon_slots)->s[i];
    }

    /* preempt_disable() is the pin only where CONFIG_PREEMPT_COUNT is set.
     * Without it, include/linux/preempt.h:284 defines it as barrier() and
     * preemptible() as the constant 0 at :293 (linux-6.19.14), so the slot
     * above is NOT exclusive and the kernel's own
     *   WARN_ON((preemptible() || in_serving_softirq()) && !state);
     * at arch/arm64/kernel/fpsimd.c:1824 cannot see it either.  arm64 reaches
     * that configuration on a stock tree: it selects HAVE_PREEMPT_DYNAMIC_KEY,
     * not _CALL (arch/arm64/Kconfig:245), so PREEMPT_DYNAMIC is not default y
     * (kernel/Kconfig.preempt:131) and a CONFIG_PREEMPT_NONE build leaves
     * PREEMPT_COUNT unset.
     *
     * It matters here more than anywhere else in this file, because from 6.19
     * the buffer IS the kernel's save area for the interrupted section:
     *   linux-6.19.14 arch/arm64/kernel/fpsimd.c kernel_neon_begin()
     *     :1860  WARN_ON(current->thread.kernel_fpsimd_state != NULL);
     *     :1861  current->thread.kernel_fpsimd_state = state;
     *     :1862  set_thread_flag(TIF_KERNEL_FPSTATE);
     *     :1869  put_cpu_fpsimd_context();   <- the bh-disable taken at :1828
     *                                           ends HERE, not at the end of
     *                                           the NEON section
     *   linux-6.19.14 arch/arm64/kernel/fpsimd.c kernel_neon_end()
     *     :1902  WARN_ON(current->thread.kernel_fpsimd_state != state);
     * So the kernel records OUR per-CPU buffer against the TASK and demands
     * the same pointer back.  A task that migrates mid-section resolves
     * wc_lkm_neon_slot() on the new CPU, hands kernel_neon_end() a different
     * pointer, and leaves the origin CPU's slot claimable while its section is
     * still live.
     *
     * The pin has to live for the whole section, which is why it is here and
     * not left to WC_SVR_DECIDE_PIN(): that one is released immediately after
     * WC_LINUXKM_FPU_BEGIN() returns, on the ground that FPU_BEGIN holds the
     * CPU -- true only where preempt_disable() is a pin.
     *
     * MEASURED, on linux-6.19.14 arm64 CONFIG_PREEMPT_NONE (PREEMPT_COUNT
     * unset), SMP=4, 16 threads, this exact begin/end shape, a schedule point
     * inside the section, everything else identical between arms:
     *   without the pin  60,087 sections, 60,087 unpinned, 22,358 changed CPU,
     *                    22,358 wrong pointer at end(), 17,210 landing on a
     *                    slot with another live section, and 22,358 kernel
     *                    WARNs at fpsimd.c:1902 -- the kernel's own oracle,
     *                    agreeing exactly with our count
     *   with the pin     79,414 sections, 0 unpinned, 0 moved, 0 wrong
     *                    pointer, 0 slot collisions, 0 kernel WARNs
     * Detector controls: forcing the comparison once yields cpumoved=1 in the
     * pinned build, and the same source on a CONFIG_PREEMPT kernel reports
     * zero yields and zero moves without the pin, because there
     * preempt_disable() already is one.
     *
     * migrate_disable() is what keeps the CPU fixed where preempt_disable()
     * cannot; see WC_SVR_DECIDE_PIN() below for why it, and not
     * get_cpu()/local_bh_disable(), is the primitive that works, and for the
     * 5.11 floor (through 5.10 migrate_disable() is literally
     * preempt_disable()).  Task context only: a softirq or hardirq cannot
     * migrate, and the context test is stable across one begin/end pair
     * because an interrupt that arrives inside it runs to completion first. */
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
        #define WC_LKM_NEON_TASK_CTX()                              \
            ((! (preempt_count() & (NMI_MASK | HARDIRQ_MASK))) &&   \
             (! in_serving_softirq()))
        #define WC_LKM_NEON_PIN()                                   \
            do { if (WC_LKM_NEON_TASK_CTX()) migrate_disable(); } while (0)
        #define WC_LKM_NEON_UNPIN()                                 \
            do { if (WC_LKM_NEON_TASK_CTX()) migrate_enable(); } while (0)
    #else
        #define WC_LKM_NEON_PIN()   WC_DO_NOTHING
        #define WC_LKM_NEON_UNPIN() WC_DO_NOTHING
    #endif
    #define WC_LINUXKM_FPU_BEGIN()                                  \
        do {                                                        \
            WC_LKM_NEON_PIN();                                      \
            preempt_disable();                                      \
            kernel_neon_begin(wc_lkm_neon_slot());                  \
        } while (0)
    #define WC_LINUXKM_FPU_END()                                    \
        do {                                                        \
            kernel_neon_end(wc_lkm_neon_slot());                    \
            preempt_enable();                                       \
            WC_LKM_NEON_UNPIN();                                    \
        } while (0)
#else
    #define WC_LINUXKM_FPU_BEGIN() kernel_neon_begin()
    #define WC_LINUXKM_FPU_END()   kernel_neon_end()
#endif

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
                 * -- arch/arm/include/asm/simd.h is only !in_hardirq(), and
                 * before 6.3 there is no such file at all, so the asm-generic
                 * !in_interrupt() applies; neither form reads a per-CPU busy
                 * flag -- and is the one OE where it can; the premise holds
                 * there because the OE kernel is built PREEMPTION=0.
                 * Evidence, with quoted
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

        /* RENDERED: not an overstep from 5.11 on, but the 5.7 floor was, and
         * it is raised here.
         *
         * The judgement this replaces read "preemptible() is constant 0 and
         * local_bh_disable() already raises preempt_count, so it pins nothing
         * new".  Both premises are true -- preemptible() is literally 0 under
         * !CONFIG_PREEMPT_COUNT (include/linux/preempt.h:293 in
         * linux-6.19.14), and __local_bh_disable_ip() is preempt_count_add()
         * then barrier() (include/linux/bottom_half.h:11-14, same text in
         * 5.7.19, 5.11.22, 6.6.152 and 6.19.14) -- and the conclusion does not
         * follow.  A raised preempt_count blocks only INVOLUNTARY preemption,
         * which this configuration does not have; a VOLUNTARY schedule still
         * runs, and the task can come back on a different CPU, where the
         * per-CPU slot claimed below is somebody else's.  migrate_disable() is
         * the one primitive whose effect does not route through PREEMPT_MASK:
         * it sets current->migration_disabled, which migrate_disable_switch()
         * reads from __schedule() (linux-5.11.22/kernel/sched/core.c:1728) and
         * is_migration_disabled() reads on the wakeup path
         * (linux-5.11.22/kernel/sched/sched.h:1101), neither of them gated on
         * CONFIG_PREEMPT_COUNT.
         *
         * FLOOR 5.11, NOT 5.7.  Through 5.10 migrate_disable() IS
         * preempt_disable(), read verbatim:
         *   linux-5.7.19/include/linux/preempt.h:335-338
         *   linux-5.10.265/include/linux/preempt.h:336-339
         *     static __always_inline void migrate_disable(void)
         *     { preempt_disable(); }
         * so under this guard's own !CONFIG_PREEMPT_COUNT it was barrier() and
         * compensated for nothing.  Confirmed by compiling this exact guard
         * against every tree's own headers and .config: 0 emitted calls on
         * 5.6.19 through 5.10.265, exactly 1 from 5.11.22, against a
         * schedule() control that emitted 1 on all of them.  See
         * WC_SVR_DECIDE_PIN() below for the same argument in the certifiable
         * half. */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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

        /* RENDERED, on the local_bh_disable() and RT preempt_disable() below:
         * they are fpregs_lock() rewritten, and from 6.15 kernel_fpu_begin()
         * does call fpregs_lock() itself -- but only when interrupts are on:
         *   linux-6.14.11 arch/x86/kernel/fpu/core.c:423   preempt_disable();
         *   linux-6.15.11 arch/x86/kernel/fpu/core.c:430   if (!irqs_disabled())
         *                                                          fpregs_lock();
         * so on 6.15+ they are redundant on the outermost section and are
         * still the only bh-disable below 6.15.  That is an argument about
         * those two calls, not about the pin.
         *
         * RENDERED, on migrate_disable(): kept, floor raised 5.7 -> 5.11.  The
         * reasoning and the citations are on the sibling site in the INHIBIT
         * path above; nothing here differs. */
        #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
            (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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
                (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
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

/* WHY THE COUNT IS PER CONTEXT AND NOT PER CPU.
 *
 * kernel_fpu_begin() takes fpregs_lock(), which disables softirqs, only from
 * 6.15 (d02198550423).  On every earlier kernel it takes a plain
 * preempt_disable():
 *
 *   6.14.11 arch/x86/kernel/fpu/core.c kernel_fpu_begin_mask() -> preempt_disable()
 *   6.15.11 arch/x86/kernel/fpu/core.c kernel_fpu_begin_mask() -> fpregs_lock()
 *
 * preempt_disable() adds to PREEMPT_MASK, and irq_exit() gates softirq
 * processing on in_interrupt(), which reads NMI_MASK|HARDIRQ_MASK|SOFTIRQ_MASK
 * and not PREEMPT_MASK (include/linux/preempt.h).  So on a pre-6.15 kernel a
 * softirq runs on top of an open section, and a hard interrupt can do so on
 * any kernel.
 *
 * A single per-CPU count cannot describe that.  An interrupting context would
 * read the interrupted context's nonzero count, conclude a section is already
 * open, and use the vector registers the interrupted context is holding data
 * in.  One count per context per CPU is exact: task, softirq and hardirq nest
 * in that order and never interleave, and a context that owns a section cannot
 * be preempted or migrate out of it. */
enum {
    WC_SVR_CTX_TASK    = 0,
    WC_SVR_CTX_SOFTIRQ = 1,
    WC_SVR_CTX_HARDIRQ = 2,
    WC_SVR_NCTX        = 3
};

struct wc_svr_ctx_state {
    unsigned int depth;
    unsigned int inhibited;
    unsigned int nested;
    /* Nonzero when the save that opened this section took a migrate_disable()
     * as well as the preempt_disable(), so the restore releases exactly what
     * the save took.  Only the nested-save path outlives the save function, so
     * only it needs the flag recorded here; every other path carries it in a
     * local.  See WC_SVR_DECIDE_PIN(). */
    unsigned int migrate_pinned;
};
struct wc_svr_cpu_state {
    struct wc_svr_ctx_state c[WC_SVR_NCTX];
};
static DEFINE_PER_CPU(struct wc_svr_cpu_state, wc_svr_state);

/* raw_cpu_ptr(), not this_cpu_ptr(): the speculative reads below happen before
 * the CPU is pinned, and this_cpu_ptr() has a CONFIG_DEBUG_PREEMPT check that
 * would fire on every one of them.  What makes the read sound is the same thing
 * that makes it sound in the kernel's own this_cpu_ops guidance: a nonzero
 * depth can only be read on a CPU whose section holds it there, so a zero read
 * stays zero and a nonzero read is ours.
 * Taking the pointer also avoids this_cpu_read() with a RUNTIME index, which on
 * x86 becomes a %gs-relative memory operand with a register base. */
static inline struct wc_svr_ctx_state *wc_svr_here(int ctx)
{
    return &raw_cpu_ptr(&wc_svr_state)->c[ctx];
}

/* in_serving_softirq() tests SOFTIRQ_OFFSET, one unit, set by __do_softirq().
 * WC_SVR_PIN_CPU()'s local_bh_disable() adds SOFTIRQ_DISABLE_OFFSET, two units,
 * and leaves that bit alone (include/linux/preempt.h), so a bracket cannot
 * change its own answer between save and restore. */
static inline int wc_svr_ctx(void)
{
    if (preempt_count() & (NMI_MASK | HARDIRQ_MASK))
        return WC_SVR_CTX_HARDIRQ;
    if (in_serving_softirq())
        return WC_SVR_CTX_SOFTIRQ;
    return WC_SVR_CTX_TASK;
}

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

/* WHETHER kernel_fpu_begin()/kernel_neon_begin() MAY BE CALLED, which on arm32
 * is not what may_use_simd() answers on every supported kernel.
 *
 * arch/arm/include/asm/simd.h, read out of the trees rather than quoted from a
 * comment:
 *   <= 6.2   no such file; the asm-generic fallback is !in_interrupt()
 *   6.3      IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !in_hardirq()
 *            (measured: 6.3.13, 6.4.16 and 6.5.13 all carry this file and are
 *            indistinguishable from 6.6.99 -- an earlier revision of this
 *            comment said 6.6, which was wrong by three releases)
 *   6.16 ..  the same, plus && !irqs_disabled()
 *
 * So before 6.16 a task- or softirq-context caller with interrupts DISABLED is
 * told yes.  Acting on that opens a kernel_neon section, and the matching
 * kernel_neon_end() calls local_bh_enable(); __local_bh_enable_ip() opens with
 * lockdep_assert_irqs_enabled() (kernel/softirq.c:386 in linux-6.6.99) and,
 * under CONFIG_TRACE_IRQFLAGS, ends with an unconditional local_irq_enable()
 * (:411) -- which re-enables interrupts inside the CALLER's interrupts-off
 * region.  Measured on emulated armv7 6.6.99, in this module's own frame:
 *   WARNING: at kernel/softirq.c:386 __local_bh_enable_ip
 *     __local_bh_enable_ip from wc_restore_vector_registers_x86 [libwolfssl]
 *   WARNING: at kernel/locking/irqflag-debug.c:10
 *     raw_local_irq_restore() called with IRQs enabled
 *
 * ARM ONLY, and deliberately.  x86's irq_fpu_usable() and arm64's
 * may_use_simd() already give the right answer with interrupts off, and
 * narrowing them here would refuse sections those architectures can serve.
 *
 * Refusing here does not refuse the caller: control falls through to the
 * nested save, which is the path that already serves this context on 6.16+.
 * Measured there, lockdep-clean: 11,583 nested saves in softirq-with-IRQs-off
 * and 3,958,560 in task-with-IRQs-off on 6.16.12 with zero reports. */
#ifdef CONFIG_ARM
    #define WC_SVR_MAY_USE_SIMD() (may_use_simd() && (! irqs_disabled()))
#else
    #define WC_SVR_MAY_USE_SIMD() may_use_simd()
#endif

/* ---- diagnostic counters, off in every shipped build ----------------------
 *
 * "Declines went to zero" is a statement about what the module did NOT do, and
 * on its own it is consistent with the save never running: with the requests
 * having been served some other way, or with the probe never landing where it
 * was supposed to.  These count the two events directly, per context -- a
 * section opened by saving the interrupted context's registers, and a section
 * refused because there was no save area to open one with -- so a run can show
 * the mechanism ran rather than infer it from an absence.
 *
 * They are deliberately built OUTSIDE the WC_SVR_HAVE_NESTED_SAVE gate, so that
 * a WC_LINUXKM_NO_NESTED_VECTOR_SAVE control build reports the same two numbers
 * from the same source and the pair can be compared.
 *
 * Per-CPU and non-atomic: a counter is only ever incremented on its own CPU
 * with that CPU pinned, so nothing else is writing the same word.  The read
 * side sums across CPUs and does not need to be exact. */
#ifdef WC_LINUXKM_SVR_COUNT_NESTED

struct wc_svr_nested_counts {
    unsigned long saves[WC_SVR_NCTX];
    unsigned long refused[WC_SVR_NCTX];
};
static DEFINE_PER_CPU(struct wc_svr_nested_counts, wc_svr_nested_counts);

#define WC_SVR_COUNT_SAVE(ctx)                                                \
    (++raw_cpu_ptr(&wc_svr_nested_counts)->saves[ctx])
#define WC_SVR_COUNT_REFUSE(ctx)                                              \
    (++raw_cpu_ptr(&wc_svr_nested_counts)->refused[ctx])

static int wc_svr_nested_counts_fmt(char *buffer, int refused)
{
    unsigned long t[WC_SVR_NCTX];
    unsigned int cpu;
    int i;

    for (i = 0; i < WC_SVR_NCTX; ++i)
        t[i] = 0;
    for_each_possible_cpu(cpu) {
        const struct wc_svr_nested_counts *c =
            &per_cpu(wc_svr_nested_counts, cpu);
        for (i = 0; i < WC_SVR_NCTX; ++i)
            t[i] += refused ? c->refused[i] : c->saves[i];
    }
    return scnprintf(buffer, PAGE_SIZE, "task=%lu softirq=%lu hardirq=%lu\n",
                     t[WC_SVR_CTX_TASK], t[WC_SVR_CTX_SOFTIRQ],
                     t[WC_SVR_CTX_HARDIRQ]);
}

static int wc_svr_nested_saves_get(char *buffer,
                                   const struct kernel_param *kp)
{
    (void)kp;
    return wc_svr_nested_counts_fmt(buffer, 0);
}

static int wc_svr_nested_refused_get(char *buffer,
                                     const struct kernel_param *kp)
{
    (void)kp;
    return wc_svr_nested_counts_fmt(buffer, 1);
}

static const struct kernel_param_ops wc_svr_nested_saves_ops = {
    .get = wc_svr_nested_saves_get
};
static const struct kernel_param_ops wc_svr_nested_refused_ops = {
    .get = wc_svr_nested_refused_get
};
module_param_cb(svr_nested_saves, &wc_svr_nested_saves_ops, NULL, 0444);
module_param_cb(svr_nested_refused, &wc_svr_nested_refused_ops, NULL, 0444);

#else /* !WC_LINUXKM_SVR_COUNT_NESTED */

#define WC_SVR_COUNT_SAVE(ctx)   WC_DO_NOTHING
#define WC_SVR_COUNT_REFUSE(ctx) WC_DO_NOTHING

#endif /* WC_LINUXKM_SVR_COUNT_NESTED */

/* ---- taking the registers when the kernel says they are in use ------------
 *
 * may_use_simd() reports whether kernel_fpu_begin() may be called, and on x86
 * that is irq_fpu_usable(): false when this CPU is inside a kernel-mode FPU
 * section, and, in a hard interrupt, when softirqs are disabled.  The reason it
 * is false is always the same one: the vector registers hold live state and
 * kernel_fpu_begin() has nowhere to put it.  kernel_fpu_begin() saves the
 * interrupted TASK's user registers, into current->thread.fpu; it has no place
 * for a kernel section's.
 *
 * That is a missing save area, not a property of the hardware.  Bring one and
 * the constraint is gone: XSAVE the live state into per-CPU, per-context
 * storage, use the registers, XRSTOR it back.  The interrupted context resumes
 * with its registers byte for byte, which is the entire promise
 * kernel_fpu_begin() made it.
 *
 * This is NOT a second implementation and NOT a fallback.  The same wolfCrypt
 * code runs on the same vector registers either way; only the place the
 * previous occupant's bytes are parked differs.  There is one implementation of
 * every algorithm in this module, and it is the one that runs here.
 *
 * ONLY EVER WHEN may_use_simd() IS FALSE, and that restriction is load-bearing.
 * While it is false, no other context on this CPU can start a kernel_fpu
 * section on top of us, because irq_fpu_usable() is false for them too, for the
 * same reason.  When it is true we call kernel_fpu_begin() and the kernel's own
 * in_kernel_fpu flag keeps everyone else out.  Either way exactly one context
 * on this CPU owns the registers.
 *
 * NMI is excluded, here as before.  irq_fpu_usable() WARNs on NMI on every
 * kernel in range and the DRBG's NMI path is not this module's to change.
 *
 * 6.15 and later reach this path far less often -- kernel_fpu_begin() disables
 * softirqs there, so a softirq cannot land inside a section at all -- but the
 * mechanism is not version-gated, because the hardirq case is not fixed by
 * that commit on any kernel. */
#if defined(CONFIG_X86) && !defined(WC_LINUXKM_NO_NESTED_VECTOR_SAVE)
    #define WC_SVR_HAVE_NESTED_SAVE
    #define WC_SVR_NESTED_X86
#elif defined(CONFIG_ARM64) && !defined(WC_LINUXKM_NO_NESTED_VECTOR_SAVE)
    /* Same mechanism, same justification, different register file.
     *
     * arm64 refuses SIMD in hardirq, with IRQs disabled, in NMI, and while
     * another kernel_neon section is open (arch/arm64/include/asm/simd.h) --
     * and it refuses for the same reason x86 does: fpsimd_save() has nowhere
     * to put the interrupted state.  That is a missing save area, not a
     * property of the architecture, and "ARM cannot service a hardirq" is
     * therefore a statement about today's code, not about ARM.
     *
     * THE ONE CONSTRAINT THAT DECIDES CORRECTNESS: writing V0-V31
     * architecturally ZEROES bits [VL-1:128] of Z0-Z31.  So saving and
     * restoring only the V registers is exact on a part with no SVE, and
     * DESTRUCTIVE on a part where SVE state is live.  The save therefore
     * covers the file the part actually has: V0-V31 with FPSR/FPCR without
     * SVE, and Z0-Z31 with P0-P15, FFR and FPSR/FPCR with it.  SME is refused
     * outright -- see wc_svr_nested_init(). */
    #define WC_SVR_HAVE_NESTED_SAVE
    #define WC_SVR_NESTED_ARM64
#elif defined(CONFIG_ARM) && !defined(WC_LINUXKM_NO_NESTED_VECTOR_SAVE)
    /* Same mechanism again, on the register file AArch32 actually has.
     *
     * EVERY LINE NUMBER IN THE arm32 CODE BELOW WAS READ OUT OF ONE OF TWO
     * TREES, and both are named wherever they disagree: linux-6.6.99 and
     * linux-6.16.12.  linux-7.1.9 agrees with linux-6.16.12 on every one of
     * them, so it is not cited separately.  Checking a citation against the
     * wrong tree gives a false miss.
     *
     * WHY arm32 REFUSES, read out of the kernel rather than assumed.
     * may_use_simd() is not one expression across the supported range:
     *
     *   <= 6.2   there is no arch/arm/include/asm/simd.h, so the asm-generic
     *            fallback applies -- include/asm-generic/simd.h,
     *            `return !in_interrupt()`, which counts the SOFTIRQ mask, so
     *            softirq is refused as well as hardirq.
     *   6.3      arch/arm/include/asm/simd.h appears (NOT 6.6 -- measured
     *            across 6.3.13 / 6.4.16 / 6.5.13):
     *            `IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !in_hardirq()`.
     *   6.16 .. 7.1
     *            the same, plus `&& !irqs_disabled()`.
     *
     * Every one of those is false in hard interrupt context on every version,
     * which is why 148,358 of 148,358 hardirq requests were declined on
     * emulated armv7 before this existed.  And every one of them is false for
     * the SAME reason x86's and arm64's are: kernel_neon_begin() saves the
     * interrupted TASK's VFP state, into thread->vfpstate
     * (arch/arm/vfp/vfpmodule.c:839-840 in 6.6.99, :890-891 in 6.16.12 and
     * 7.1.9), and has nowhere to put a kernel section's.  A save area of our
     * own removes the constraint; it does not weaken it.
     *
     * ONLY EVER WHEN may_use_simd() IS FALSE, and on arm32 that is what makes
     * the register file exclusively ours.  in_hardirq() means no other context
     * can run on this CPU until we return -- Linux does not nest hard IRQs, and
     * arm32 has no NMI -- and irqs_disabled() in task or softirq context means
     * the same with preemption disabled on top.  A concurrent kernel_neon
     * section is impossible for the same reason it is on x86: may_use_simd() is
     * false for anyone who would open one, and BUG_ON(in_hardirq()) inside
     * kernel_neon_begin() (:829, :879) makes the attempt fatal rather than
     * quiet.
     *
     * WHICH ALSO SETTLES THE CPU.  The per-CPU save area is only sound if the
     * CPU cannot change between the decision and the restore.  On arm32 the
     * context that reaches this path settles that on its own, without relying
     * on preempt_disable(): a hard interrupt handler cannot migrate, a softirq
     * cannot migrate, and irqs_disabled() in task context cannot be preempted.
     * That matters because CONFIG_PREEMPT_COUNT is not universal -- on a
     * PREEMPT_NONE build without it, preempt_disable() is a compiler barrier
     * and pins nothing.  Here there is nothing left for it to pin.
     *
     * THE CONSTRAINT THAT DECIDES CORRECTNESS HERE is not a register-file
     * width, as it is on arm64; it is FPEXC.EN.  arm32 gates all access to the
     * VFP/NEON register file and to FPSCR on that bit, kernel_neon_end() clears
     * it on the way out (:852, :903), and a VFP instruction issued with it
     * clear takes an undefined-instruction exception.  So the save enables the
     * unit first, exactly as kernel_neon_begin() does, and puts FPEXC back
     * byte for byte on the way out.  See wc_svr_a32_state_save(). */
    #define WC_SVR_HAVE_NESTED_SAVE
    #define WC_SVR_NESTED_ARM32
#endif

#ifdef WC_SVR_HAVE_NESTED_SAVE

#include <asm/cpufeature.h>
#ifdef WC_SVR_NESTED_X86
#include <asm/processor.h>
#endif

#ifdef WC_SVR_NESTED_ARM64

#include <asm/sysreg.h>

/* THE FPSIMD REGISTER FILE: 32 x 128-bit V registers, then FPSR and FPCR.
 * That is the whole vector state on a part with no SVE. */
#define WC_SVR_A64_VREG_BYTES   512
#define WC_SVR_A64_AREA_BYTES   576   /* 512 + FPSR/FPCR, rounded to 64 */

/* THE SVE REGISTER FILE.
 *
 * Writing V0-V31 architecturally ZEROES bits [VL-1:128] of Z0-Z31 (Arm ARM DDI
 * 0487, "Effect of using AArch64 SIMD&FP instructions on SVE registers"), so on
 * a part where SVE state can be live, saving and restoring only V0-V31 hands
 * the interrupted context back a truncated register file.  Saving Z0-Z31,
 * P0-P15 and FFR covers the whole file at any vector length, and restoring Z
 * restores V with it, because V_n IS Z_n[127:0].
 *
 * The layout and the instruction encodings below are the kernel's own, so a
 * reader can check every constant against a file that ships with the kernel:
 * arch/arm64/include/asm/fpsimdmacros.h -- macros sve_save and sve_load, built
 * from _sve_str_v, _sve_ldr_v, _sve_str_p, _sve_ldr_p, _sve_rdffr, _sve_wrffr,
 * _sve_pfalse and _sve_rdvl.  There the base register is a macro argument; here
 * it is fixed at x9 so every encoding is a constant.
 *
 *   area + 0             Z0..Z31,  VL bytes each     -> 32 * VL
 *   area + 32*VL         P0..P15,  VL/8 bytes each   ->  2 * VL
 *   area + 34*VL         FFR,      VL/8 bytes
 *   area + META_OFF      FPSR (u32), FPCR (u32), VL (u32)
 *
 * META_OFF is a constant past the end of the register region at the LARGEST
 * vector length, so the restore can read back the length the save used without
 * already knowing it.
 *
 * The MUL VL addressing modes scale by the CURRENT vector length, so the base
 * pointer is derived from RDVL at save time and the vector length is recorded
 * in the area; the restore addresses the area with the length that was actually
 * saved rather than re-reading it.  Save and restore both run inside one
 * pinned, preemption-disabled section, so ZCR_EL1.LEN cannot move between them.
 *
 * SIZING.  ZCR_EL1.LEN is four bits -- ZCR_ELx_LEN_MASK is GENMASK(3, 0) in
 * arch/arm64/include/generated/asm/sysreg-defs.h -- so VQ <= 16 and VL <= 256
 * bytes.  The area is allocated for that architectural bound.  It is not
 * allocated from a probed maximum, because probing the maximum means writing
 * ZCR_EL1, and a write to ZCR_EL1 makes Z, P and FFR UNPREDICTABLE; a length
 * outside the bound is refused at save time instead of overrunning the area. */
#define WC_SVR_A64_SVE_VQ_MAX    16u
#define WC_SVR_A64_SVE_VL_MAX    (WC_SVR_A64_SVE_VQ_MAX * 16u)
#define WC_SVR_A64_SVE_REG_BYTES(vl) \
    ((34u * (unsigned int)(vl)) + ((unsigned int)(vl) / 8u))
#define WC_SVR_A64_SVE_META_OFF \
    ((WC_SVR_A64_SVE_REG_BYTES(WC_SVR_A64_SVE_VL_MAX) + 15u) & ~15u)
#define WC_SVR_A64_SVE_AREA_BYTES \
    ((WC_SVR_A64_SVE_META_OFF + 16u + 63u) & ~63u)

/* CPACR_EL1.FPEN and .ZEN gate FP and SVE at EL1.  The kernel does not promise
 * either is enabled when this code runs, and it enables them the same way
 * around its own EL1 SVE accesses -- cpacr_save_enable_kernel_sve() and
 * cpacr_restore(), arch/arm64/include/asm/fpsimd.h.  Those are recent helpers,
 * so the two register writes are open-coded here and the bit names are taken
 * from the kernel when it defines them. */
#ifndef CPACR_EL1_ZEN_EL1EN
    #define CPACR_EL1_ZEN_EL1EN  (1UL << 16)
#endif
#ifndef CPACR_EL1_FPEN_EL1EN
    #define CPACR_EL1_FPEN_EL1EN (1UL << 20)
#endif
#define WC_SVR_A64_CPACR_SVE (CPACR_EL1_FPEN_EL1EN | CPACR_EL1_ZEN_EL1EN)

/* system_supports_sme() does not exist before the kernel grew SME support, and
 * on a kernel built without it there is no SME state for anyone to have live. */
#ifdef CONFIG_ARM64_SME
    #define wc_svr_a64_sme_present() system_supports_sme()
#else
    #define wc_svr_a64_sme_present() 0
#endif

static inline unsigned long wc_svr_a64_sve_enable(void)
{
    unsigned long old = read_sysreg(cpacr_el1);
    if ((old & WC_SVR_A64_CPACR_SVE) != WC_SVR_A64_CPACR_SVE) {
        write_sysreg(old | WC_SVR_A64_CPACR_SVE, cpacr_el1);
        isb();
    }
    return old;
}

static inline void wc_svr_a64_sve_disable(unsigned long old)
{
    if ((old & WC_SVR_A64_CPACR_SVE) != WC_SVR_A64_CPACR_SVE) {
        write_sysreg(old, cpacr_el1);
        isb();
    }
}

/* Encodings, base register x9.  Every constant here is the corresponding macro
 * body from arch/arm64/include/asm/fpsimdmacros.h with nxbase = 9.  The
 * assembler evaluates the arithmetic, including the two's-complement masking of
 * the negative MUL VL offsets, exactly as the kernel's macros do. */
#define WC_SVE_STR_Z(n) ".inst (0xe5804000|(" #n ")|(9<<5)"                    \
    "|((((" #n ")-34)&7)<<10)|((((" #n ")-34)&0x1f8)<<13))\n\t"
#define WC_SVE_LDR_Z(n) ".inst (0x85804000|(" #n ")|(9<<5)"                    \
    "|((((" #n ")-34)&7)<<10)|((((" #n ")-34)&0x1f8)<<13))\n\t"
#define WC_SVE_STR_P(n) ".inst (0xe5800000|(" #n ")|(9<<5)"                    \
    "|((((" #n ")-16)&7)<<10)|((((" #n ")-16)&0x1f8)<<13))\n\t"
#define WC_SVE_LDR_P(n) ".inst (0x85800000|(" #n ")|(9<<5)"                    \
    "|((((" #n ")-16)&7)<<10)|((((" #n ")-16)&0x1f8)<<13))\n\t"
#define WC_SVE_PFALSE(n) ".inst (0x2518e400|(" #n "))\n\t"
/* STR/LDR P0, [x9] -- offset 0 is the FFR slot. */
#define WC_SVE_STR_P_FFR ".inst (0xe5800000|(9<<5))\n\t"
#define WC_SVE_LDR_P_FFR ".inst (0x85800000|(9<<5))\n\t"
#define WC_SVE_RDFFR_P0  ".inst 0x2519f000\n\t"
#define WC_SVE_WRFFR_P0  ".inst 0x25289000\n\t"

#define WC_SVE_Z_SEQ(M)                                                        \
    M(0)  M(1)  M(2)  M(3)  M(4)  M(5)  M(6)  M(7)                             \
    M(8)  M(9)  M(10) M(11) M(12) M(13) M(14) M(15)                            \
    M(16) M(17) M(18) M(19) M(20) M(21) M(22) M(23)                            \
    M(24) M(25) M(26) M(27) M(28) M(29) M(30) M(31)
#define WC_SVE_P_SEQ(M)                                                        \
    M(0)  M(1)  M(2)  M(3)  M(4)  M(5)  M(6)  M(7)                             \
    M(8)  M(9)  M(10) M(11) M(12) M(13) M(14) M(15)

static unsigned int wc_svr_save_size;
static int          wc_svr_nested_ready;
static u8         **wc_svr_save_area;
static u8         **wc_svr_save_alloc;
/* Fixed at init from system_supports_sve(), which is a boot-time-final
 * capability.  It selects which register FILE is saved, not which of two
 * implementations of one thing runs: a part without SVE has no Z, P or FFR and
 * would take an undefined-instruction exception on the encodings above. */
static int          wc_svr_a64_sve;

static inline unsigned int wc_svr_a64_rdvl(void)
{
    unsigned long vl;
    /* RDVL X9, #1 */
    asm volatile(".inst (0x04bf5000 | 9 | (1 << 5))\n\t"
                 "mov %0, x9\n\t"
                 : "=r"(vl) : : "x9");
    return (unsigned int)vl;
}

static inline int wc_svr_a64_vl_ok(unsigned int vl)
{
    return (vl >= 16u) && (vl <= WC_SVR_A64_SVE_VL_MAX) && ((vl & 15u) == 0u);
}

static inline void wc_svr_a64_fpsimd_save(u8 *area)
{
    u64 fpsr, fpcr;
    u8 *p = area;
    asm volatile(
        "st1 {v0.16b-v3.16b},   [%0], #64\n\t"
        "st1 {v4.16b-v7.16b},   [%0], #64\n\t"
        "st1 {v8.16b-v11.16b},  [%0], #64\n\t"
        "st1 {v12.16b-v15.16b}, [%0], #64\n\t"
        "st1 {v16.16b-v19.16b}, [%0], #64\n\t"
        "st1 {v20.16b-v23.16b}, [%0], #64\n\t"
        "st1 {v24.16b-v27.16b}, [%0], #64\n\t"
        "st1 {v28.16b-v31.16b}, [%0], #64\n\t"
        : "+r"(p) : : "memory");
    asm volatile("mrs %0, fpsr" : "=r"(fpsr));
    asm volatile("mrs %0, fpcr" : "=r"(fpcr));
    *(u64 *)(area + WC_SVR_A64_VREG_BYTES)     = fpsr;
    *(u64 *)(area + WC_SVR_A64_VREG_BYTES + 8) = fpcr;
}

static inline void wc_svr_a64_fpsimd_restore(const u8 *area)
{
    u64 fpsr = *(const u64 *)(area + WC_SVR_A64_VREG_BYTES);
    u64 fpcr = *(const u64 *)(area + WC_SVR_A64_VREG_BYTES + 8);
    const u8 *p = area;
    asm volatile(
        "ld1 {v0.16b-v3.16b},   [%0], #64\n\t"
        "ld1 {v4.16b-v7.16b},   [%0], #64\n\t"
        "ld1 {v8.16b-v11.16b},  [%0], #64\n\t"
        "ld1 {v12.16b-v15.16b}, [%0], #64\n\t"
        "ld1 {v16.16b-v19.16b}, [%0], #64\n\t"
        "ld1 {v20.16b-v23.16b}, [%0], #64\n\t"
        "ld1 {v24.16b-v27.16b}, [%0], #64\n\t"
        "ld1 {v28.16b-v31.16b}, [%0], #64\n\t"
        : "+r"(p) : : "memory");
    asm volatile("msr fpsr, %0" : : "r"(fpsr));
    asm volatile("msr fpcr, %0" : : "r"(fpcr));
}

/* Returns 0 with the whole SVE file in the area, or -1 having written nothing
 * and touched no register, so the caller can refuse the section. */
static int wc_svr_a64_sve_save(u8 *area)
{
    unsigned long cpacr;
    unsigned int vl, off;
    u64 fpsr, fpcr;
    u8 *pffr;

    cpacr = wc_svr_a64_sve_enable();
    vl = wc_svr_a64_rdvl();
    if (! wc_svr_a64_vl_ok(vl)) {
        wc_svr_a64_sve_disable(cpacr);
        return -1;
    }
    pffr = area + (34u * vl);
    asm volatile("mov x9, %0\n\t"
                 WC_SVE_Z_SEQ(WC_SVE_STR_Z)
                 WC_SVE_P_SEQ(WC_SVE_STR_P)
                 /* FFR has no store of its own: read it into P0, store P0
                  * into the FFR slot at offset 0, then reload P0 from P0's own
                  * slot at offset -16.  This is sve_save() in
                  * fpsimdmacros.h. */
                 WC_SVE_RDFFR_P0
                 WC_SVE_STR_P_FFR
                 WC_SVE_LDR_P(0)
                 : : "r"(pffr) : "x9", "memory");
    asm volatile("mrs %0, fpsr" : "=r"(fpsr));
    asm volatile("mrs %0, fpcr" : "=r"(fpcr));
    off = WC_SVR_A64_SVE_META_OFF;
    *(u32 *)(area + off)     = (u32)fpsr;
    *(u32 *)(area + off + 4) = (u32)fpcr;
    *(u32 *)(area + off + 8) = vl;
    wc_svr_a64_sve_disable(cpacr);
    return 0;
}

static void wc_svr_a64_sve_restore(const u8 *area)
{
    unsigned long cpacr;
    unsigned int vl, off;
    u64 fpsr, fpcr;
    const u8 *pffr;

    /* The length the save actually used, not a fresh RDVL: this must address
     * the area the way it was written.  A save that returned 0 wrote it, and
     * only a save that returned 0 opens a section to restore. */
    off = WC_SVR_A64_SVE_META_OFF;
    vl  = *(const u32 *)(area + off + 8);
    if (! wc_svr_a64_vl_ok(vl)) {
        /* Unreachable: the section was opened by a save that returned 0, and
         * that save wrote this field.  Say so rather than return quietly --
         * these are the interrupted context's registers, and leaving them
         * wrong without a word is the one outcome worse than failing. */
        pr_err_once("BUG: wc_restore_vector_registers_x86() found no vector"
                    " length in the save area on CPU %d; the interrupted"
                    " context's SVE registers are NOT being restored.\n",
                    raw_smp_processor_id());
        return;
    }
    fpsr = *(const u32 *)(area + off);
    fpcr = *(const u32 *)(area + off + 4);
    pffr = area + (34u * vl);

    cpacr = wc_svr_a64_sve_enable();
    asm volatile("mov x9, %0\n\t"
                 WC_SVE_Z_SEQ(WC_SVE_LDR_Z)
                 /* FFR through P0, then P0..P15 over the top of it. */
                 WC_SVE_LDR_P_FFR
                 WC_SVE_WRFFR_P0
                 WC_SVE_P_SEQ(WC_SVE_LDR_P)
                 : : "r"(pffr) : "x9", "memory");
    asm volatile("msr fpsr, %0" : : "r"(fpsr));
    asm volatile("msr fpcr, %0" : : "r"(fpcr));
    wc_svr_a64_sve_disable(cpacr);
}

static inline int wc_svr_regs_save(u8 *area)
{
    if (wc_svr_a64_sve)
        return wc_svr_a64_sve_save(area);
    wc_svr_a64_fpsimd_save(area);
    return 0;
}

static inline void wc_svr_regs_restore(const u8 *area)
{
    if (wc_svr_a64_sve) {
        wc_svr_a64_sve_restore(area);
        return;
    }
    wc_svr_a64_fpsimd_restore(area);
}

/* kernel_neon_begin() leaves FPCR/FPSR as the interrupted context had them, so
 * unlike x86 there is no control register to normalise here. */
static inline void wc_svr_load_default_mxcsr(void) { }

static inline u8 *wc_svr_area(int ctx)
{
    return wc_svr_save_area[raw_smp_processor_id()] +
           ((size_t)ctx * wc_svr_save_size);
}

#elif defined(WC_SVR_NESTED_ARM32)

#include <asm/vfp.h>
#include <asm/hwcap.h>

/* THE AArch32 VFP/NEON REGISTER FILE, and the whole of it: d0-d15, then
 * d16-d31 on a part that has them, then FPSCR, then FPEXC, and -- only while
 * FPEXC.EX is set -- FPINST and FPINST2.  That is precisely the set
 * vfp_save_state() writes and vfp_load_state() reads
 * (arch/arm/vfp/vfphw.S:31-67, the same lines in both trees), which is the
 * kernel's own
 * answer to "what is the VFP state of a context".
 *
 *   area + 0     d0-d15    128 B
 *   area + 128   d16-d31   128 B, present only where the part has them
 *   area + 256   FPSCR     u32
 *   area + 260   FPEXC     u32
 *   area + 264   FPINST    u32   (meaningful only while FPEXC.EX)
 *   area + 268   FPINST2   u32   (meaningful only while FPEXC.EX && FPEXC.FP2V)
 *
 * The d16-d31 region keeps its slot on a 16-register part rather than being
 * packed away, so one set of offsets describes both.  VFPFSTMIA does the same
 * -- `addeq \base, \base, #32*4`, step over the unused space
 * (arch/arm/include/asm/vfpmacros.h:70 and :76 in 6.6.99, :59 and :65 in
 * 6.16.12).
 *
 * D16 vs D32 IS A CORRECTNESS QUESTION, not an optimisation: `vstmia rN,
 * {d16-d31}` on a VFPv3-D16 or VFPv4-D16 part is an undefined instruction.  It
 * is settled once at init from MVFR0 -- see wc_svr_a32_probe_d32(). */
#define WC_SVR_A32_D0_15_OFF     0u
#define WC_SVR_A32_D16_31_OFF    128u
#define WC_SVR_A32_FPSCR_OFF     256u
#define WC_SVR_A32_FPEXC_OFF     260u
#define WC_SVR_A32_FPINST_OFF    264u
#define WC_SVR_A32_FPINST2_OFF   268u
#define WC_SVR_A32_AREA_BYTES    320u   /* 272, rounded up to 64 */

/* THE VFP SYSTEM REGISTERS, addressed as coprocessor 10 registers.  Two
 * encodings exist for the same instructions, and the kernel used to carry both:
 * fmrx()/fmxr() had a `vmrs`/`vmsr` form and an `mrc`/`mcr p10, 7` form, chosen
 * by CONFIG_AS_VFP_VMRS_FPINST, which probes whether the assembler knows the
 * register name FPINST (arch/arm/vfp/vfpinstr.h:85-97 in 6.6.99, with the CRn
 * numbers from arch/arm/include/asm/vfp.h:13-19).  6.16.12 has dropped the
 * coprocessor fallback, and the CRn defines with it, so what is written below
 * is the 6.6.99 encoding and not a quotation from every tree.
 *
 * It is used anyway, on both, and deliberately: it is the same instruction, it
 * assembles in ARM and in Thumb-2 with no .fpu directive, and it does not
 * depend on a kernel CONFIG that an out-of-tree module cannot see.
 *
 * FPSID, FPEXC, MVFR0 and MVFR1 are readable and writable at PL1 with FPEXC.EN
 * CLEAR; only the register file and FPSCR are gated by EN.  The kernel depends
 * on that in two places a reader can check: kernel_neon_begin() reads and then
 * writes FPEXC as its first act, before anything has enabled the unit
 * (arch/arm/vfp/vfpmodule.c:832-833 in 6.6.99, :883-884 in 6.16.12 and 7.1.9),
 * and vfp_init() reads FPSID and MVFR0 having enabled only CPACR -- vfp_enable()
 * touches the coprocessor access register and nothing else (:419-430). */
#define WC_SVR_A32_SYSREG_RD(name, crn)                                        \
    static inline u32 wc_svr_a32_rd_##name(void)                               \
    {                                                                          \
        u32 v;                                                                 \
        asm volatile("mrc p10, 7, %0, " #crn ", cr0, 0" : "=r"(v) : : "cc");   \
        return v;                                                              \
    }
#define WC_SVR_A32_SYSREG_WR(name, crn)                                        \
    static inline void wc_svr_a32_wr_##name(u32 v)                             \
    {                                                                          \
        asm volatile("mcr p10, 7, %0, " #crn ", cr0, 0" : : "r"(v) : "cc");    \
    }
WC_SVR_A32_SYSREG_RD(fpscr,   cr1)
WC_SVR_A32_SYSREG_WR(fpscr,   cr1)
WC_SVR_A32_SYSREG_RD(mvfr0,   cr7)
WC_SVR_A32_SYSREG_RD(fpexc,   cr8)
WC_SVR_A32_SYSREG_WR(fpexc,   cr8)
WC_SVR_A32_SYSREG_RD(fpinst,  cr9)
WC_SVR_A32_SYSREG_WR(fpinst,  cr9)
WC_SVR_A32_SYSREG_RD(fpinst2, cr10)
WC_SVR_A32_SYSREG_WR(fpinst2, cr10)

static unsigned int wc_svr_save_size;
static int          wc_svr_nested_ready;
static u8         **wc_svr_save_area;
static u8         **wc_svr_save_alloc;
/* Fixed at init from MVFR0, which is hardware and does not change.  It selects
 * how much of ONE register file is copied, not which of two implementations of
 * anything runs. */
static int          wc_svr_a32_d32;

/* .fpu in inline asm, which is how the kernel itself reaches VFP from C
 * (arch/arm/vfp/vfpinstr.h:69 and :76 in 6.6.99, :67 and :74 in 6.16.12) and
 * how this module's own AArch32 assembly
 * already declares itself (wolfcrypt/src/port/arm/armv8-32-*.S, `.fpu neon` and
 * `.fpu crypto-neon-fp-armv8`).  The non-writeback form of VSTMIA/VLDMIA is
 * used so the base register is a plain input and nothing has to be told the
 * pointer moved. */
static inline void wc_svr_a32_dregs_save(u8 *area, int d32)
{
    asm volatile(".fpu vfpv2\n\t"
                 "vstmia %0, {d0-d15}\n\t"
                 : : "r"(area + WC_SVR_A32_D0_15_OFF) : "memory");
    if (d32)
        asm volatile(".fpu vfpv3\n\t"
                     "vstmia %0, {d16-d31}\n\t"
                     : : "r"(area + WC_SVR_A32_D16_31_OFF) : "memory");
}

static inline void wc_svr_a32_dregs_restore(const u8 *area, int d32)
{
    asm volatile(".fpu vfpv2\n\t"
                 "vldmia %0, {d0-d15}\n\t"
                 : : "r"(area + WC_SVR_A32_D0_15_OFF) : "memory");
    if (d32)
        asm volatile(".fpu vfpv3\n\t"
                     "vldmia %0, {d16-d31}\n\t"
                     : : "r"(area + WC_SVR_A32_D16_31_OFF) : "memory");
}

/* int, to match the arm64 save, which can decline at a vector length it cannot
 * fit.  Nothing here can fail -- every register touched exists on every part
 * that reaches this code, and how many double registers there are was settled at
 * init -- so this always returns 0. */
static inline int wc_svr_a32_state_save(u8 *area, int d32)
{
    u32 fpexc = wc_svr_a32_rd_fpexc();
    u32 fpinst = 0, fpinst2 = 0;

    /* ENABLE THE UNIT FIRST.  FPEXC.EN gates every access to the register file
     * and to FPSCR, and kernel_neon_end() leaves it CLEAR
     * (arch/arm/vfp/vfpmodule.c:852 in 6.6.99, :903 in 6.16.12 and 7.1.9), so a
     * hard interrupt arriving in ordinary kernel code will usually find it
     * clear.  A VFP instruction issued then takes an undefined-instruction
     * exception -- in hardirq context, not somewhere to discover that.  These
     * are the same two instructions in the same order that kernel_neon_begin()
     * opens with (:832-833, :883-884).  Nothing here relies on the kernel
     * having enabled it for us. */
    wc_svr_a32_wr_fpexc(fpexc | FPEXC_EN);

    /* A VFP SUBARCHITECTURE EXCEPTION PENDING IN THE INTERRUPTED CONTEXT.
     * FPEXC.EX means a bounced instruction is waiting in FPINST, and issuing a
     * further VFP instruction on top of that is the one thing in this function
     * that could take an exception.  FPINST and FPINST2 are read ONLY under
     * that flag, which is the guard vfp_save_state() uses for the same access
     * (arch/arm/vfp/vfphw.S:58-63, the same lines in both trees); outside it the
     * access is UNPREDICTABLE, so
     * it is not made.  The pending state is then cleared for the duration --
     * the same bits VFP_bounce() clears before it touches the unit
     * (vfpmodule.c:343 in 6.6.99, :371 in 6.16.12) -- and the SAVED FPEXC still
     * carries it, so the
     * interrupted context gets it back untouched.
     *
     * On VFPv3 and later without a VFP subarchitecture, which is every part
     * this module's armv7 build can run on, FPEXC.EX reads as zero and this
     * branch is never taken.  It costs one test not to have assumed that. */
    if (fpexc & FPEXC_EX) {
        fpinst = wc_svr_a32_rd_fpinst();
        if (fpexc & FPEXC_FP2V)
            fpinst2 = wc_svr_a32_rd_fpinst2();
        wc_svr_a32_wr_fpexc((fpexc | FPEXC_EN) &
                            ~(u32)(FPEXC_EX | FPEXC_DEX | FPEXC_FP2V |
                                   FPEXC_VV | FPEXC_TRAP_MASK));
    }

    wc_svr_a32_dregs_save(area, d32);
    *(u32 *)(area + WC_SVR_A32_FPSCR_OFF)   = wc_svr_a32_rd_fpscr();
    *(u32 *)(area + WC_SVR_A32_FPEXC_OFF)   = fpexc;
    *(u32 *)(area + WC_SVR_A32_FPINST_OFF)  = fpinst;
    *(u32 *)(area + WC_SVR_A32_FPINST2_OFF) = fpinst2;
    return 0;
}

static inline void wc_svr_a32_state_restore(const u8 *area, int d32)
{
    u32 fpscr   = *(const u32 *)(area + WC_SVR_A32_FPSCR_OFF);
    u32 fpexc   = *(const u32 *)(area + WC_SVR_A32_FPEXC_OFF);
    u32 fpinst  = *(const u32 *)(area + WC_SVR_A32_FPINST_OFF);
    u32 fpinst2 = *(const u32 *)(area + WC_SVR_A32_FPINST2_OFF);

    /* The unit is still enabled -- the save enabled it and this section has held
     * this CPU ever since -- but write it rather than rely on it, and keep the
     * exception bits clear until the register file is back in place.
     *
     * ORDER, and it is vfp_load_state()'s order (arch/arm/vfp/vfphw.S:31-49, the
     * same lines in both trees):
     * the register file first, "while FPEXC is in a safe state"; then FPINST
     * and FPINST2, under FPEXC.EX, for the same reason the save read them;
     * then FPSCR.  FPEXC goes back LAST, because writing it is what can clear
     * EN and end access to everything above it. */
    wc_svr_a32_wr_fpexc((fpexc | FPEXC_EN) &
                        ~(u32)(FPEXC_EX | FPEXC_DEX | FPEXC_FP2V |
                               FPEXC_VV | FPEXC_TRAP_MASK));
    wc_svr_a32_dregs_restore(area, d32);
    if (fpexc & FPEXC_EX) {
        wc_svr_a32_wr_fpinst(fpinst);
        if (fpexc & FPEXC_FP2V)
            wc_svr_a32_wr_fpinst2(fpinst2);
    }
    wc_svr_a32_wr_fpscr(fpscr);
    wc_svr_a32_wr_fpexc(fpexc);
}

static inline int wc_svr_regs_save(u8 *area)
{
    return wc_svr_a32_state_save(area, wc_svr_a32_d32);
}

static inline void wc_svr_regs_restore(const u8 *area)
{
    wc_svr_a32_state_restore(area, wc_svr_a32_d32);
}

/* kernel_neon_begin() leaves FPSCR exactly as the interrupted context had it --
 * it saves the word and writes nothing back (arch/arm/vfp/vfphw.S:57 and :65,
 * the same lines in both trees) --
 * so a section opened by saving must do the same.  Normalising it here would be
 * the one respect in which the two ways of opening a section differed, which is
 * the thing this file exists to avoid. */
static inline void wc_svr_load_default_mxcsr(void) { }

static inline u8 *wc_svr_area(int ctx)
{
    return wc_svr_save_area[raw_smp_processor_id()] +
           ((size_t)ctx * wc_svr_save_size);
}

/* HOW MANY DOUBLE REGISTERS.  MVFR0.A_SIMD == 2 means 32 x 64-bit registers,
 * 1 means 16 (VFPv3-D16 and VFPv4-D16), 0 means no Advanced SIMD.  That is the
 * comparison the kernel's own VFPFSTMIA and VFPFLDMIA make on ARMv7 and later
 * -- `cmp \tmp, #2`, arch/arm/include/asm/vfpmacros.h:49 and :74 in 6.6.99,
 * :38 and :63 in 6.16.12.
 *
 * elf_hwcap's HWCAP_VFPD32 is the same fact computed once at boot from the same
 * field (vfp_init(), arch/arm/vfp/vfpmodule.c:932-936 in 6.6.99, :983-987 in
 * 6.16.12), but only inside
 * `if (IS_ENABLED(CONFIG_VFPv3))`, so on a kernel built without CONFIG_VFPv3 it
 * reads 0 on a part that has 32.  MVFR0 is the hardware, so MVFR0 decides; the
 * hwcap is read as well and a disagreement is reported rather than quietly
 * resolved, because it means the kernel is managing less of the file than
 * exists. */
static int wc_svr_a32_probe_d32(void)
{
    u32 fpexc, mvfr0;
    int by_mvfr0, by_hwcap = (elf_hwcap & HWCAP_VFPD32) ? 1 : 0;

    /* MVFR0 is not gated by FPEXC.EN (see the accessor block above), but enable
     * the unit around the read anyway: it costs two register writes once, at
     * init, and it removes the reader's need to take that on trust.
     *
     * preempt_disable() explicitly rather than on the strength of the caller
     * already having done it: FPEXC is per-CPU hardware, and leaving a task
     * scheduled out with the unit enabled behind the kernel's back would defeat
     * the lazy-restore bookkeeping.  No VFP instruction is issued between the
     * two writes, so nothing observes the enabled state.
     *
     * The COPROCESSOR access this needs is not in question: the kernel gives
     * every CPU full cp10/cp11 access as it comes online -- vfp_enable() from
     * vfp_starting_cpu() at CPUHP_AP_ARM_VFP_STARTING
     * (arch/arm/vfp/vfpmodule.c:419-430, :639-643 and :983-985 in 6.6.99;
     * :453-464, :670-674 and :1034-1036 in 6.16.12) -- and vfp_dying_cpu()
     * (:633-637 in 6.6.99, :664-668 in 6.16.12) does not take it away. */
    preempt_disable();
    fpexc = wc_svr_a32_rd_fpexc();
    wc_svr_a32_wr_fpexc(fpexc | FPEXC_EN);
    mvfr0 = wc_svr_a32_rd_mvfr0();
    wc_svr_a32_wr_fpexc(fpexc);
    preempt_enable();

    by_mvfr0 = ((mvfr0 & MVFR0_A_SIMD_MASK) == 2u) ? 1 : 0;
    if (by_mvfr0 != by_hwcap)
        pr_info("wolfCrypt: MVFR0 %#x reports %s double registers and"
                " elf_hwcap reports %s; MVFR0 decides.\n",
                mvfr0, by_mvfr0 ? "32" : "16", by_hwcap ? "32" : "16");
    return by_mvfr0;
}

#else /* WC_SVR_NESTED_X86 */

/* x87, SSE, AVX, AVX-512 opmask, ZMM_Hi256 and Hi16_ZMM: every component a
 * wolfCrypt vector routine can write, and nothing else.  AMX is deliberately
 * absent, which is also what keeps XFD out of this: a component that is never
 * requested can never fault on being requested. */
#define WC_SVR_XFEATURE_MASK 0x00e7ULL

/* Byte-encoded so this does not depend on the assembler being built with
 * -mxsave, exactly as arch/x86/include/asm/fpu/xstate.h does it.  modrm 0x27 is
 * XSAVE (%rdi), 0x2f is XRSTOR (%rdi); the REX.W prefix selects the 64-bit
 * forms.  0f 01 d0 is XGETBV. */
#ifdef CONFIG_X86_64
    #define WC_SVR_REX "0x48, "
    #define WC_SVR_FXSAVE  "fxsave64 (%0)"
    #define WC_SVR_FXRSTOR "fxrstor64 (%0)"
#else
    #define WC_SVR_REX ""
    #define WC_SVR_FXSAVE  "fxsave (%0)"
    #define WC_SVR_FXRSTOR "fxrstor (%0)"
#endif
#define WC_SVR_XSAVE_INSN  ".byte " WC_SVR_REX "0x0f,0xae,0x27"
#define WC_SVR_XRSTOR_INSN ".byte " WC_SVR_REX "0x0f,0xae,0x2f"

static u8         **wc_svr_save_area;      /* [nr_cpu_ids][WC_SVR_NCTX][sz] */
static u8         **wc_svr_save_alloc;     /* the unaligned allocations */
static unsigned int wc_svr_save_size;      /* per context, 64-byte multiple */
static u64          wc_svr_save_mask;
static int          wc_svr_use_xsave;
static int          wc_svr_nested_ready;

static inline u64 wc_svr_xgetbv0(void)
{
    u32 lo, hi;
    asm volatile(".byte 0x0f,0x01,0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((u64)hi << 32) | (u64)lo;
}

/* int, not void, to match the arm64 save, which can decline -- see the SVE
 * block above.  Nothing here can fail, so this always returns 0. */
static inline int wc_svr_regs_save(u8 *area)
{
    if (wc_svr_use_xsave) {
        u32 lo = (u32)wc_svr_save_mask, hi = (u32)(wc_svr_save_mask >> 32);
        asm volatile(WC_SVR_XSAVE_INSN
                     : : "D"(area), "a"(lo), "d"(hi) : "memory");
    }
    else {
        asm volatile(WC_SVR_FXSAVE : : "r"(area) : "memory");
    }
    return 0;
}

static inline void wc_svr_regs_restore(const u8 *area)
{
    if (wc_svr_use_xsave) {
        u32 lo = (u32)wc_svr_save_mask, hi = (u32)(wc_svr_save_mask >> 32);
        asm volatile(WC_SVR_XRSTOR_INSN
                     : : "D"(area), "a"(lo), "d"(hi) : "memory");
    }
    else {
        asm volatile(WC_SVR_FXRSTOR : : "r"(area) : "memory");
    }
}

/* kernel_fpu_begin() puts a known MXCSR under the section it opens
 * (kfpu_mask & KFPU_MXCSR, arch/x86/kernel/fpu/core.c).  A section opened by
 * saving inherits whatever the interrupted context left, so give it the same
 * starting point.  MXCSR_DEFAULT, arch/x86/include/asm/fpu/types.h. */
static inline void wc_svr_load_default_mxcsr(void)
{
    static const u32 wc_svr_mxcsr_default = 0x1f80U;
    if (boot_cpu_has(X86_FEATURE_XMM))
        asm volatile("ldmxcsr %0" : : "m"(wc_svr_mxcsr_default));
}

static inline u8 *wc_svr_area(int ctx)
{
    return wc_svr_save_area[raw_smp_processor_id()] + ((size_t)ctx * wc_svr_save_size);
}

#endif /* WC_SVR_NESTED_X86 */

/* Fill / read the vector file for the self-test.  On x86 this reaches
 * %ymm0-%ymm15, or %xmm0-%xmm15 without AVX -- the widest set that assembles
 * without an AVX-512 assembler.  x87 and MXCSR are covered by the save area but
 * not written here; neither are the AVX-512-only components the mask names
 * (opmask, ZMM_Hi256, Hi16_ZMM), which is stated in full at the call site in
 * wc_svr_nested_init().
 *
 * -mno-sse is in force for kernel code, so the compiler emits no vector
 * instructions of its own between the store and the compare; only an
 * interrupting context could, and this runs with preemption disabled. */
#ifdef WC_SVR_NESTED_ARM64
    #define WC_SVR_ST_NREG 32
    #define WC_SVR_ST_STRIDE 16
static int __maybe_unused wc_svr_st_avx;  /* unused on arm64; kept so the shared code compiles */
static inline void wc_svr_st_load(const u8 *b)
{
    const u8 *p = b;
    asm volatile(
        "ld1 {v0.16b-v3.16b},   [%0], #64\n\t"
        "ld1 {v4.16b-v7.16b},   [%0], #64\n\t"
        "ld1 {v8.16b-v11.16b},  [%0], #64\n\t"
        "ld1 {v12.16b-v15.16b}, [%0], #64\n\t"
        "ld1 {v16.16b-v19.16b}, [%0], #64\n\t"
        "ld1 {v20.16b-v23.16b}, [%0], #64\n\t"
        "ld1 {v24.16b-v27.16b}, [%0], #64\n\t"
        "ld1 {v28.16b-v31.16b}, [%0], #64\n\t"
        : "+r"(p) : : "memory");
}
static inline void wc_svr_st_store(u8 *b)
{
    u8 *p = b;
    asm volatile(
        "st1 {v0.16b-v3.16b},   [%0], #64\n\t"
        "st1 {v4.16b-v7.16b},   [%0], #64\n\t"
        "st1 {v8.16b-v11.16b},  [%0], #64\n\t"
        "st1 {v12.16b-v15.16b}, [%0], #64\n\t"
        "st1 {v16.16b-v19.16b}, [%0], #64\n\t"
        "st1 {v20.16b-v23.16b}, [%0], #64\n\t"
        "st1 {v24.16b-v27.16b}, [%0], #64\n\t"
        "st1 {v28.16b-v31.16b}, [%0], #64\n\t"
        : "+r"(p) : : "memory");
}
#elif defined(WC_SVR_NESTED_ARM32)
/* d0-d31, or d0-d15 on a 16-register part; the count is only known at run time,
 * so the arm32 self-test below carries its own bound and this pair is the
 * whole-file mover, nothing more.  The pattern therefore reaches EVERY register
 * the save covers, which is not true of the x86 pattern -- see the note in
 * wc_svr_nested_init(). */
    #define WC_SVR_ST_NREG 32
    #define WC_SVR_ST_STRIDE 8
static inline void wc_svr_st_load(const u8 *b)
{
    wc_svr_a32_dregs_restore(b, wc_svr_a32_d32);
}
static inline void wc_svr_st_store(u8 *b)
{
    wc_svr_a32_dregs_save(b, wc_svr_a32_d32);
}
#elif defined(CONFIG_X86_64)
    #define WC_SVR_ST_NREG 16
    #define WC_SVR_ST_STRIDE 32
    #define WC_SVR_ST_SEQ(M) \
        M(0)  M(1)  M(2)  M(3)  M(4)  M(5)  M(6)  M(7) \
        M(8)  M(9)  M(10) M(11) M(12) M(13) M(14) M(15)
#else
    #define WC_SVR_ST_NREG 8
    #define WC_SVR_ST_STRIDE 32
    #define WC_SVR_ST_SEQ(M) M(0) M(1) M(2) M(3) M(4) M(5) M(6) M(7)
#endif
#if !defined(WC_SVR_NESTED_ARM64) && !defined(WC_SVR_NESTED_ARM32)
#define WC_SVR_ST_LOADY(n)  "vmovdqu " #n "*32(%0), %%ymm" #n "\n\t"
#define WC_SVR_ST_STORY(n)  "vmovdqu %%ymm" #n ", " #n "*32(%0)\n\t"
#define WC_SVR_ST_LOADX(n)  "movdqu "  #n "*32(%0), %%xmm" #n "\n\t"
#define WC_SVR_ST_STORX(n)  "movdqu %%xmm" #n ", "  #n "*32(%0)\n\t"

static int wc_svr_st_avx;

static inline void wc_svr_st_load(const u8 *b)
{
    if (wc_svr_st_avx)
        asm volatile(WC_SVR_ST_SEQ(WC_SVR_ST_LOADY) : : "r"(b) : "memory");
    else
        asm volatile(WC_SVR_ST_SEQ(WC_SVR_ST_LOADX) : : "r"(b) : "memory");
}

static inline void wc_svr_st_store(u8 *b)
{
    if (wc_svr_st_avx)
        asm volatile(WC_SVR_ST_SEQ(WC_SVR_ST_STORY) : : "r"(b) : "memory");
    else
        asm volatile(WC_SVR_ST_SEQ(WC_SVR_ST_STORX) : : "r"(b) : "memory");
}
#endif /* !WC_SVR_NESTED_ARM64 */

#ifdef WC_SVR_NESTED_ARM64

/* Clobber P0-P15 and FFR the way nothing in wolfCrypt does, so the self-test
 * can tell a restored predicate from one that was never disturbed. */
static inline void wc_svr_a64_sve_clobber_pffr(void)
{
    unsigned long cpacr = wc_svr_a64_sve_enable();
    asm volatile(WC_SVE_P_SEQ(WC_SVE_PFALSE)
                 WC_SVE_WRFFR_P0
                 : : : "memory");
    wc_svr_a64_sve_disable(cpacr);
}

/* Build the pattern with the SVE routines, exercise the pair under test, read
 * the result back with the SVE routines.  Two things stop that from being the
 * instrument vouching for itself:
 *
 *  - the clobber in the middle is what a wolfCrypt routine actually does, V
 *    register writes, which the architecture defines as ZEROING bits
 *    [VL-1:128] of every Z register; plus an explicit P/FFR clobber.  If the
 *    save did not cover a byte, that byte comes back zeroed or false, not
 *    merely inconsistent.
 *
 *  - the low 128 bits are checked a SECOND time through the FPSIMD store,
 *    which addresses V_n by REGISTER NUMBER rather than by memory offset.  A
 *    save and restore that agreed with each other on a wrong Z offset would
 *    pass the byte compare and fail this one.
 *
 * WC_LINUXKM_SVR_SELFTEST_FPSIMD_ONLY_CONTROL swaps the pair under test for the
 * FPSIMD-only save, which is the code this SVE path replaced.  A build with it
 * defined MUST fail; that is what shows the wider save is load-bearing and not
 * decoration. */
#ifdef WC_LINUXKM_SVR_SELFTEST_FPSIMD_ONLY_CONTROL
    #define WC_SVR_A64_ST_SAVE(a)    (wc_svr_a64_fpsimd_save(a), 0)
    #define WC_SVR_A64_ST_RESTORE(a) wc_svr_a64_fpsimd_restore(a)
#else
    #define WC_SVR_A64_ST_SAVE(a)    wc_svr_a64_sve_save(a)
    #define WC_SVR_A64_ST_RESTORE(a) wc_svr_a64_sve_restore(a)
#endif

static int wc_svr_a64_sve_selftest(void)
{
    u8 *pat = NULL, *sav = NULL, *got = NULL, *vec = NULL;
    unsigned long cpacr;
    unsigned int vl, regs, i;
    u64 fpsr, fpcr;
    int ret = 0, saved = 0;

    cpacr = wc_svr_a64_sve_enable();
    vl = wc_svr_a64_rdvl();
    wc_svr_a64_sve_disable(cpacr);
    if (! wc_svr_a64_vl_ok(vl)) {
        pr_err("wolfCrypt: SVE vector length %u B is outside the range this"
               " save area covers.\n", vl);
        return -EIO;
    }
    regs = WC_SVR_A64_SVE_REG_BYTES(vl);

    pat = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    sav = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    got = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    vec = (u8 *)kzalloc(WC_SVR_A64_VREG_BYTES, GFP_ATOMIC);
    if ((pat == NULL) || (sav == NULL) || (got == NULL) || (vec == NULL)) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < regs; i++)
        pat[i] = (u8)((i * 31u) ^ 0x5au);
    /* FFR is not a free-form predicate.  WRFFR with a value that is not "the
     * low N element bits set, the rest clear" is CONSTRAINED UNPREDICTABLE
     * (Arm ARM DDI 0487, WRFFR), and real silicon does not round-trip one --
     * measured: an arbitrary pattern here fails on a Neoverse-N3 and passes
     * under QEMU, which is the wrong way round for a self-test.  Give the FFR
     * slot a legal value; every other slot takes the arbitrary pattern. */
    memset(pat + (34u * vl), 0xffu, (vl / 8u) / 2u);
    memset(pat + (34u * vl) + ((vl / 8u) / 2u), 0x00u,
           (vl / 8u) - ((vl / 8u) / 2u));
    /* FPCR is a control register: an arbitrary bit pattern would change the
     * rounding mode or unmask an exception for the context this pretends to
     * be, so the pattern carries what is live right now. */
    asm volatile("mrs %0, fpsr" : "=r"(fpsr));
    asm volatile("mrs %0, fpcr" : "=r"(fpcr));
    *(u32 *)(pat + WC_SVR_A64_SVE_META_OFF)     = (u32)fpsr;
    *(u32 *)(pat + WC_SVR_A64_SVE_META_OFF + 4) = (u32)fpcr;
    *(u32 *)(pat + WC_SVR_A64_SVE_META_OFF + 8) = vl;
    for (i = 0; i < WC_SVR_A64_VREG_BYTES; i++)
        vec[i] = 0xc3u;

    if (! may_use_simd()) {
        pr_warn("wolfCrypt: vector registers unavailable at init; "
                "save/restore self-test skipped.\n");
        ret = -EAGAIN;
        goto out;
    }

    preempt_disable();
    WC_LINUXKM_FPU_BEGIN();

    wc_svr_a64_sve_restore(pat);        /* the interrupted context's state */
    saved = WC_SVR_A64_ST_SAVE(sav);    /* what a nested caller would do */
#ifdef WC_LINUXKM_SVR_SELFTEST_NEGATIVE_CONTROL
    /* Diagnostic only.  A self-test that has never been seen to fail has not
     * been shown capable of failing.  One byte in each region the save is
     * responsible for; a build with this defined that still reports OK is the
     * finding. */
    if (saved == 0) {
        sav[0] ^= 0xffu;                        /* Z0, low 128 bits */
        if (vl > 16u)
            sav[16] ^= 0xffu;                   /* Z0, above bit 127 */
        sav[32u * vl] ^= 0xffu;                 /* P0 */
        sav[34u * vl] ^= 0xffu;                 /* FFR */
    }
#endif
    wc_svr_st_load(vec);                /* V writes: Z truncated above 127 */
    wc_svr_a64_sve_clobber_pffr();
    if (saved == 0)
        WC_SVR_A64_ST_RESTORE(sav);     /* hand them back */
    wc_svr_a64_sve_save(got);           /* what the interrupted context sees */
    wc_svr_st_store(vec);               /* V by register number, not offset */

    WC_LINUXKM_FPU_END();
    preempt_enable();

    if (saved != 0) {
        pr_err("wolfCrypt: SVE vector register save declined at VL %u B.\n",
               vl);
        ret = -EIO;
        goto out;
    }

    for (i = 0; i < 32u; i++) {
        if (memcmp(got + (i * vl), pat + (i * vl), vl) != 0) {
            pr_err("wolfCrypt: Z%u did not survive save/restore at VL %u B.\n",
                   i, vl);
            ret = -EIO;
            goto out;
        }
    }
    for (i = 0; i < 16u; i++) {
        if (memcmp(got + (32u * vl) + (i * (vl / 8u)),
                   pat + (32u * vl) + (i * (vl / 8u)), vl / 8u) != 0) {
            pr_err("wolfCrypt: P%u did not survive save/restore.\n", i);
            ret = -EIO;
            goto out;
        }
    }
    if (memcmp(got + (34u * vl), pat + (34u * vl), vl / 8u) != 0) {
        pr_err("wolfCrypt: FFR did not survive save/restore.\n");
        ret = -EIO;
        goto out;
    }
    for (i = 0; i < 32u; i++) {
        if (memcmp(vec + (i * 16u), pat + (i * vl), 16u) != 0) {
            pr_err("wolfCrypt: V%u (Z%u[127:0]) read back by register number"
                   " does not match the saved state.\n", i, i);
            ret = -EIO;
            goto out;
        }
    }

out:
    kfree(pat);
    kfree(sav);
    kfree(got);
    kfree(vec);
    return ret;
}

#endif /* WC_SVR_NESTED_ARM64 */

#ifdef WC_SVR_NESTED_ARM32

/* WC_LINUXKM_SVR_SELFTEST_D16_ONLY_CONTROL swaps the pair under test for one
 * that covers only d0-d15 -- which is what a save written for a VFPv3-D16 part,
 * or one that simply forgot the upper half, would do.  On a part with 32 double
 * registers a build with this defined MUST fail, and that is what shows the
 * d16-d31 half is load-bearing rather than decoration.  On a 16-register part
 * the control is identical to the real thing and proves nothing; init says so
 * rather than letting it read as a pass. */
#ifdef WC_LINUXKM_SVR_SELFTEST_D16_ONLY_CONTROL
    #define WC_SVR_A32_ST_SAVE(a)    wc_svr_a32_state_save(a, 0)
    #define WC_SVR_A32_ST_RESTORE(a) wc_svr_a32_state_restore(a, 0)
#else
    #define WC_SVR_A32_ST_SAVE(a)    wc_svr_a32_state_save(a, wc_svr_a32_d32)
    #define WC_SVR_A32_ST_RESTORE(a) wc_svr_a32_state_restore(a, wc_svr_a32_d32)
#endif

/* Which of the two acquire forms the self-test used, so the "OK" line names it
 * rather than leaving the reader to work it out. */
static int wc_svr_a32_st_nested_acquire;

static int wc_svr_a32_selftest(void)
{
    u8 *pat = NULL, *sav = NULL, *got = NULL, *vec = NULL, *outer = NULL;
    unsigned int nregs = wc_svr_a32_d32 ? 32u : 16u;
    unsigned int nbytes = nregs * 8u;
    unsigned int i;
    u32 live_fpscr, pat_fpscr, got_fpscr;
    int ret = 0, saved = 0, used_neon;

    pat   = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    sav   = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    got   = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    vec   = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    outer = (u8 *)kzalloc(wc_svr_save_size, GFP_ATOMIC);
    if ((pat == NULL) || (sav == NULL) || (got == NULL) || (vec == NULL) ||
        (outer == NULL)) {
        ret = -ENOMEM;
        goto out;
    }
    for (i = 0; i < nbytes; i++)
        pat[i] = (u8)((i * 7u) ^ 0xa5u);
    for (i = 0; i < nbytes; i++)
        vec[i] = 0xc3u;

    /* OWN THE REGISTERS THE WAY THE MECHANISM ITSELF OWNS THEM.
     *
     * The x86 and arm64 self-tests open a kernel_fpu / kernel_neon section and
     * skip themselves if they cannot, because at their init may_use_simd() is
     * true.  On arm32 that does not hold: up to 6.2 may_use_simd() is the
     * asm-generic !in_interrupt(), which counts the SOFTIRQ MASK, and
     * wolfCrypt_Init() can reach here with softirqs disabled.  Skipping then
     * disables the nested save on precisely the kernels whose refusals it
     * exists to remove -- measured, on emulated armv7 6.1.183: "vector
     * registers unavailable at init; save/restore self-test skipped".
     *
     * So acquire them the way wc_save_vector_registers_x86() acquires them:
     * kernel_neon_begin() when the kernel says that is allowed, and otherwise
     * by saving the interrupted context's file into an area of our own.  The
     * second form uses the mechanism under test to hold the registers, so say
     * plainly what that does and does not prove: it does NOT independently
     * establish that the outer save works, but the PAIR under test still has to
     * round-trip a pattern through a full clobber of every register, and the
     * two negative controls below still have to FAIL.  A broken save fails the
     * comparison either way.
     *
     * kernel_neon_begin() BUGs on in_hardirq(); module init is task context, so
     * the first branch is the one taken from 6.3 onwards -- 6.3 is where
     * arch/arm/include/asm/simd.h appears and stops counting the SOFTIRQ mask.
     * Read out of the trees: the file is absent in 6.2.16 and present in
     * 6.3.13, 6.4.16, 6.5.13 and 6.6.152. */
    used_neon = may_use_simd() ? 1 : 0;
    wc_svr_a32_st_nested_acquire = used_neon ? 0 : 1;
    preempt_disable();
    if (used_neon) {
        WC_LINUXKM_FPU_BEGIN();
    }
    else if (wc_svr_a32_state_save(outer, wc_svr_a32_d32) != 0) {
        preempt_enable();
        pr_err("wolfCrypt: could not take the vector registers at init.\n");
        ret = -EIO;
        goto out;
    }

    /* FPSCR IS A CONTROL REGISTER AS WELL AS A STATUS ONE.  An arbitrary bit
     * pattern would change the rounding mode, the flush-to-zero setting or the
     * short-vector LEN/STRIDE fields for the context this is pretending to be.
     * The pattern therefore flips only the six CUMULATIVE EXCEPTION flags,
     * which are status and carry no behaviour.  That still makes the FPSCR half
     * of the round trip real: the clobber below writes the live value back, so
     * a save that dropped FPSCR would come back with the wrong word. */
    live_fpscr = wc_svr_a32_rd_fpscr();
    pat_fpscr  = live_fpscr ^ (u32)(FPSCR_IOC | FPSCR_DZC | FPSCR_OFC |
                                    FPSCR_UFC | FPSCR_IXC | FPSCR_IDC);

    wc_svr_st_load(pat);              /* the "interrupted context's" file */
    wc_svr_a32_wr_fpscr(pat_fpscr);
    saved = WC_SVR_A32_ST_SAVE(sav);  /* what a nested caller would do */
#ifdef WC_LINUXKM_SVR_SELFTEST_NEGATIVE_CONTROL
    /* Diagnostic only.  A self-test that has never been seen to fail has not
     * been shown capable of failing -- it is the instrument vouching for
     * itself.  One byte in each region the save is responsible for; a build
     * with this defined that still reports OK is the finding. */
    if (saved == 0) {
        sav[WC_SVR_A32_D0_15_OFF] ^= 0xffu;                  /* d0  */
        if (wc_svr_a32_d32)
            sav[WC_SVR_A32_D16_31_OFF] ^= 0xffu;             /* d16 */
        *(u32 *)(sav + WC_SVR_A32_FPSCR_OFF) ^= FPSCR_IXC;   /* FPSCR */
    }
#endif
    wc_svr_st_load(vec);              /* destroy them, as wolfCrypt would */
    wc_svr_a32_wr_fpscr(live_fpscr);
    if (saved == 0)
        WC_SVR_A32_ST_RESTORE(sav);   /* hand them back */
    wc_svr_st_store(got);             /* what the interrupted context sees */
    got_fpscr = wc_svr_a32_rd_fpscr();

    if (used_neon)
        WC_LINUXKM_FPU_END();
    else
        wc_svr_a32_state_restore(outer, wc_svr_a32_d32);
    preempt_enable();

    if (saved != 0) {
        pr_err("wolfCrypt: VFP register save declined at init.\n");
        ret = -EIO;
        goto out;
    }
    for (i = 0; i < nregs; i++) {
        if (memcmp(got + (i * 8u), pat + (i * 8u), 8u) != 0) {
            pr_err("wolfCrypt: d%u did not survive save/restore.\n", i);
            ret = -EIO;
            goto out;
        }
    }
    if (got_fpscr != pat_fpscr) {
        pr_err("wolfCrypt: FPSCR did not survive save/restore"
               " (wanted %#x, got %#x).\n", pat_fpscr, got_fpscr);
        ret = -EIO;
        goto out;
    }

out:
    kfree(pat);
    kfree(sav);
    kfree(got);
    kfree(vec);
    kfree(outer);
    return ret;
}

static int wc_svr_selftest(void)
{
    return wc_svr_a32_selftest();
}

#else /* !WC_SVR_NESTED_ARM32 */

/* Returns 0 on an exact round trip, negative otherwise. */
static int wc_svr_selftest(void)
{
    u8 *want = NULL, *got = NULL, *area;
    size_t step, i;
    int ret = 0;

#ifdef WC_SVR_NESTED_ARM64
    if (wc_svr_a64_sve)
        return wc_svr_a64_sve_selftest();
    /* Every V register is written in full, so the whole slot is compared. */
    step = WC_SVR_ST_STRIDE;
#else
    if (! wc_svr_use_xsave && ! boot_cpu_has(X86_FEATURE_FXSR))
        return -EOPNOTSUPP;

    wc_svr_st_avx = boot_cpu_has(X86_FEATURE_AVX) ? 1 : 0;
    /* The SSE path writes 16 of every 32 bytes, so only that much is compared;
     * comparing the untouched half would report a clobber that never happened. */
    step = wc_svr_st_avx ? 32 : 16;
#endif

    /* Same locked, preempt-disabled context as the allocations above. */
    want = kmalloc(WC_SVR_ST_NREG * WC_SVR_ST_STRIDE, GFP_ATOMIC);
    got  = kmalloc(WC_SVR_ST_NREG * WC_SVR_ST_STRIDE, GFP_ATOMIC);
    if ((want == NULL) || (got == NULL)) {
        ret = -ENOMEM;
        goto out;
    }
    for (i = 0; i < (size_t)(WC_SVR_ST_NREG * WC_SVR_ST_STRIDE); i++)
        want[i] = (u8)((i * 7u) ^ 0xa5u);

    /* kernel_fpu_begin() BUGs on !may_use_simd(), so check rather than assume.
     * At module init this is task context with no section open, so it should
     * always be true; if it somehow is not, skip the test rather than take the
     * machine down proving a point. */
    if (! may_use_simd()) {
        pr_warn("wolfCrypt: vector registers unavailable at init; "
                "save/restore self-test skipped.\n");
        ret = -EAGAIN;
        goto out;
    }

    /* Run it exactly the way a nested section runs: pinned, from task context,
     * with the module's own save area. */
    preempt_disable();
    area = wc_svr_area(WC_SVR_CTX_TASK);

    WC_LINUXKM_FPU_BEGIN();      /* own the registers legitimately for the test */
    wc_svr_st_load(want);        /* the "interrupted context's" data */
    ret = wc_svr_regs_save(area);  /* what a nested caller would do */
#ifdef WC_LINUXKM_SVR_SELFTEST_NEGATIVE_CONTROL
    /* Diagnostic only.  A self-test that has never been seen to fail has not
     * been shown capable of failing -- it is the instrument vouching for
     * itself.  This corrupts the saved state so the round trip MUST be
     * detected as broken; a build with this defined that still reports OK is
     * the finding. */
    area[0] ^= 0xffu;
    area[160] ^= 0xffu;
#endif
    memset(got, 0, WC_SVR_ST_NREG * WC_SVR_ST_STRIDE);
    wc_svr_st_load(got);         /* destroy them, as wolfCrypt would */
    if (ret == 0)
        wc_svr_regs_restore(area);   /* hand them back */
    wc_svr_st_store(got);        /* what the interrupted context would see */
    WC_LINUXKM_FPU_END();

    preempt_enable();

    if (ret != 0) {
        pr_err("wolfCrypt: vector register save declined at init.\n");
        ret = -EIO;
        goto out;
    }

    for (i = 0; i < WC_SVR_ST_NREG; i++) {
        if (memcmp(got + (i * WC_SVR_ST_STRIDE), want + (i * WC_SVR_ST_STRIDE), step) != 0) {
            pr_err("wolfCrypt: vector register %zu did not survive "
                   "save/restore.\n", i);
            ret = -EIO;
            break;
        }
    }

out:
    kfree(want);
    kfree(got);
    return ret;
}

#endif /* !WC_SVR_NESTED_ARM32 */

static void wc_svr_nested_free(void)
{
    unsigned int cpu;

    wc_svr_nested_ready = 0;
    if (wc_svr_save_alloc) {
        for (cpu = 0; cpu < (unsigned int)nr_cpu_ids; ++cpu)
            kfree(wc_svr_save_alloc[cpu]);
        kfree(wc_svr_save_alloc);
        wc_svr_save_alloc = NULL;
    }
    kfree(wc_svr_save_area);
    wc_svr_save_area = NULL;
}

static int wc_svr_nested_init(void)
{
    unsigned int cpu;
#ifdef WC_SVR_NESTED_ARM64
    /* WHICH REGISTER FILE.  Writing V0-V31 zeroes bits [VL-1:128] of Z0-Z31,
     * so on an SVE part the save has to cover Z0-Z31, P0-P15 and FFR; on a part
     * without SVE those registers do not exist and V0-V31 with FPSR/FPCR is the
     * whole file. */
    if (! system_supports_fpsimd()) {
        pr_info("wolfCrypt: no FPSIMD; nested vector save unavailable.\n");
        return 0;
    }
    if (wc_svr_a64_sme_present()) {
        /* THE REMAINING REFUSAL, stated narrowly.  SME adds ZA and ZT0, and a
         * streaming-mode context has a second vector length and may not
         * implement FFR at all, so the save below would not cover the state
         * that is live.  Refuse rather than restore a subset: on an SME part
         * this leaves the module declining exactly as it did before. */
        pr_info("wolfCrypt: SME is implemented; the nested vector save does not"
                " cover ZA, ZT0 or streaming mode, so sections in hardirq and"
                " IRQs-off contexts continue to be refused.\n");
        return 0;
    }
    if (system_supports_sve()) {
        wc_svr_a64_sve = 1;
        wc_svr_save_size = WC_SVR_A64_SVE_AREA_BYTES;
    }
    else {
        wc_svr_a64_sve = 0;
        wc_svr_save_size = WC_SVR_A64_AREA_BYTES;
    }
#elif defined(WC_SVR_NESTED_ARM32)
    /* CONFIG_KERNEL_MODE_NEON has to be set for kernel_neon_begin() to exist at
     * all, and this file calls it unconditionally on arm32, so a build without
     * it does not link -- there is nothing to test for here.  What does have to
     * be established at run time is that there is a VFP unit, and how much of
     * one.  elf_hwcap's HWCAP_VFP is set by vfp_init() only after it has read
     * FPSID through an undef hook and found a unit that answers
     * (arch/arm/vfp/vfpmodule.c:895-997 in 6.6.99, :946-1048 in 6.16.12), so it
     * is the kernel's own finding
     * rather than a guess from the CPU model. */
    if (! (elf_hwcap & HWCAP_VFP)) {
        pr_info("wolfCrypt: no VFP unit; nested vector save unavailable, and"
                " sections in hardirq and IRQs-off contexts continue to be"
                " refused.\n");
        return 0;
    }
    wc_svr_a32_d32 = wc_svr_a32_probe_d32();
    wc_svr_save_size = WC_SVR_A32_AREA_BYTES;
#else
    u32 eax, ebx, ecx, edx;
#endif

#ifdef WC_SVR_NESTED_X86
    /* X86_FEATURE_XSAVE is cleared by the kernel when it will not use XSAVE
     * (setup_clear_cpu_cap on "noxsave"), and OSXSAVE reports CR4.OSXSAVE,
     * without which XGETBV faults.  Require both before executing either. */
    if (boot_cpu_has(X86_FEATURE_XSAVE) && boot_cpu_has(X86_FEATURE_OSXSAVE)) {
        cpuid_count(0x0d, 0, &eax, &ebx, &ecx, &edx);
        wc_svr_save_mask = wc_svr_xgetbv0() & WC_SVR_XFEATURE_MASK;
        /* ECX is the largest standard-format area for everything XCR0 can
         * enable, so it bounds any subset of it. */
        wc_svr_save_size = ecx;
        wc_svr_use_xsave = 1;
        if ((wc_svr_save_mask == 0) || (wc_svr_save_size < 576))
            return 0;
    }
    else if (boot_cpu_has(X86_FEATURE_FXSR)) {
        /* No XSAVE means no AVX on any x86 part, so x87 and SSE, which is all
         * FXSAVE covers, is also all wolfCrypt can be using. */
        wc_svr_save_mask = 0;
        wc_svr_save_size = 512;
        wc_svr_use_xsave = 0;
    }
    else {
        return 0;
    }

    wc_svr_save_size = (wc_svr_save_size + 63U) & ~63U;
#endif /* WC_SVR_NESTED_X86 */

    /* GFP_ATOMIC, not GFP_KERNEL.  allocate_wolfcrypt_linuxkm_fpu_states() is
     * called from wolfCrypt_Init() while wc_lkm_LockMutex() holds
     * inits_count_mutex with preemption disabled, so a sleeping allocation here
     * is "BUG: sleeping function called from invalid context" -- caught by
     * CONFIG_DEBUG_ATOMIC_SLEEP, in the test arm only, because without nested
     * save this function allocates nothing at all.
     * Failure is already handled: the caller disables nested save and the
     * module goes on refusing sections, which is the pre-existing behaviour. */
    wc_svr_save_area  = (u8 **)kcalloc(nr_cpu_ids, sizeof(u8 *), GFP_ATOMIC);
    wc_svr_save_alloc = (u8 **)kcalloc(nr_cpu_ids, sizeof(u8 *), GFP_ATOMIC);
    if ((wc_svr_save_area == NULL) || (wc_svr_save_alloc == NULL)) {
        wc_svr_nested_free();
        return -ENOMEM;
    }

    for (cpu = 0; cpu < (unsigned int)nr_cpu_ids; ++cpu) {
        /* Zeroed, and never zeroed again: XSAVE writes XSTATE_BV but not
         * XCOMP_BV, and XCOMP_BV must stay 0 for the area to be read back as
         * standard format (SDM Vol. 1, 13.4.2). */
        size_t need = (size_t)wc_svr_save_size * WC_SVR_NCTX;
        u8 *p = (u8 *)kzalloc(need + 64, GFP_ATOMIC);
        if (p == NULL) {
            wc_svr_nested_free();
            return -ENOMEM;
        }
        wc_svr_save_alloc[cpu] = p;
        wc_svr_save_area[cpu] = (u8 *)(((uintptr_t)p + 63U) & ~(uintptr_t)63U);
    }

    wc_svr_nested_ready = 1;

    /* POWER-ON SELF-TEST OF THE SAVE/RESTORE ITSELF.
     *
     * The mask, the area size and the XSAVE/XRSTOR pair are all derived from
     * CPUID and XCR0 at run time, so they differ per CPU model -- and the one
     * model that matters most, AVX-512, cannot be executed by any VM on the
     * development host (Arrow Lake has no AVX-512, and Intel SDE runs
     * userspace, not kernels).  A test rig would prove one machine.  This
     * proves the machine it is actually running on, including the customer's.
     *
     * Write a known pattern into the vector registers wc_svr_st_load() can
     * address, save it, destroy the registers, restore, and compare.
     *
     * WHAT THE x86 PATTERN DOES NOT COVER.  wc_svr_st_load()/_store() reach
     * %ymm0-%ymm15 (or %xmm0-%xmm15 without AVX).  WC_SVR_XFEATURE_MASK also
     * names opmask, ZMM_Hi256 and Hi16_ZMM -- bits 5, 6 and 7 of 0x00e7 -- and
     * nothing here writes those, so on an AVX-512 part they are still in their
     * init state when XSAVE runs.  XSAVE then writes XSTATE_BV[i] = 0 for them
     * and XRSTOR re-initialises rather than reloads them (SDM Vol. 1, 13.7 and
     * 13.8), so the round trip is correct but is not exercised.  A pass proves
     * the mask value, the area size, the 64-byte alignment and the
     * standard-format round trip on this machine; it does not prove the three
     * AVX-512-only components.
     *
     * WHAT NO ARCHITECTURE'S PATTERN PROVES.  This runs in task context inside
     * a legitimate kernel_fpu_begin().  It says nothing about saving when
     * may_use_simd() is false, from a softirq or a hardirq on top of a live
     * section -- which is the case the nested save relies on.  That argument is
     * reasoning, not measurement, and the "self-test OK" line below is not
     * evidence for it.
     *
     * If the round trip is not exact, nested save is disabled and the module
     * goes on refusing -- the behaviour it had before this mechanism existed,
     * which is safe.
     */
    if (wc_svr_selftest() != 0) {
        pr_err("wolfCrypt: vector-register save/restore self-test FAILED; "
               "nested save disabled, sections will be refused as before.\n");
        wc_svr_nested_ready = 0;
        return 0;
    }
#ifdef WC_SVR_NESTED_ARM64
    if (wc_svr_a64_sve) {
        unsigned long cpacr = wc_svr_a64_sve_enable();
        unsigned int vl = wc_svr_a64_rdvl();
        wc_svr_a64_sve_disable(cpacr);
        pr_info("wolfCrypt: vector-register save/restore self-test OK "
                "(SVE Z0-Z31 + P0-P15 + FFR + FPSR/FPCR, VL %u B, "
                "%u B/context).\n", vl, wc_svr_save_size);
    }
    else {
        pr_info("wolfCrypt: vector-register save/restore self-test OK "
                "(FPSIMD V0-V31 + FPSR/FPCR, %u B/context).\n",
                wc_svr_save_size);
    }
#elif defined(WC_SVR_NESTED_ARM32)
    /* Unlike the x86 line below, this one covers the whole save: the pattern
     * reaches every double register the area holds, and FPSCR is compared as
     * well.  FPEXC, FPINST and FPINST2 are saved and restored but are not
     * exercised by the pattern -- FPEXC is the register the section itself has
     * to modify to run at all, and FPINST/FPINST2 are meaningful only under
     * FPEXC.EX, which does not occur on a VFPv3-or-later part. */
    pr_info("wolfCrypt: vector-register save/restore self-test OK "
            "(VFP d0-d%d + FPSCR + FPEXC, %u B/context, registers held by %s).\n",
            wc_svr_a32_d32 ? 31 : 15, wc_svr_save_size,
            wc_svr_a32_st_nested_acquire ? "the nested save itself"
                                         : "kernel_neon_begin()");
#ifdef WC_LINUXKM_SVR_SELFTEST_D16_ONLY_CONTROL
    if (! wc_svr_a32_d32)
        pr_warn("wolfCrypt: the d16-only self-test control is VACUOUS on this"
                " part -- it has 16 double registers, so the control and the"
                " real save cover the same file.  This pass is not evidence"
                " that d16-d31 are covered.\n");
#endif
#else
    /* Name the pattern's reach, so the log line cannot be read as covering
     * the AVX-512-only components in the mask. */
    pr_info("wolfCrypt: vector-register save/restore self-test OK "
            "(mask 0x%llx, %u B/context, pattern in %s0-15).\n",
            (unsigned long long)wc_svr_save_mask, wc_svr_save_size,
            wc_svr_st_avx ? "ymm" : "xmm");
#endif

    return 0;
}

#else /* !WC_SVR_HAVE_NESTED_SAVE */

#define wc_svr_nested_ready 0
static int wc_svr_nested_init(void) { return 0; }
static void wc_svr_nested_free(void) { }

#endif /* WC_SVR_HAVE_NESTED_SAVE */

/* The nested-save path decides and claims in two steps, and both halves are
 * per-CPU, so the CPU has to stay put across them.  kernel_fpu_begin() pins for
 * the same reason.  Without nested save compiled in, nothing between the test
 * and the claim is per-CPU and this stays out of the way -- notably on ARM,
 * where kernel_neon_begin() does its own pinning.
 *
 * WHY preempt_disable() IS NOT ENOUGH ON ITS OWN.
 *
 * It is the pin on any kernel built with CONFIG_PREEMPT_COUNT.  Without that
 * symbol -- PREEMPT_NONE, or PREEMPT_VOLUNTARY with no PREEMPT_DYNAMIC, which
 * is what x86_64 defconfig produced through 5.15 -- include/linux/preempt.h
 * defines it as barrier(), and preemptible() as constant 0:
 *
 *   linux-6.1.62  include/linux/preempt.h:274  #define preempt_disable() barrier()
 *   linux-6.12.59 include/linux/preempt.h:286  #define preempt_disable() barrier()
 *
 * It increments nothing there, so it pins nothing, and because preemptible()
 * is a constant nothing warns.  Only the PREEMPT_MASK half of preempt_count()
 * goes blind: preempt_count_add() sits OUTSIDE the CONFIG_PREEMPT_COUNT guard
 * (linux-5.15.216/include/linux/preempt.h:199, guard opens at :210), so
 * local_bh_disable() still raises SOFTIRQ_DISABLE_OFFSET and the hardirq and
 * softirq masks stay exact.
 *
 * THIS IS A CONFIG, NOT A KERNEL VERSION.  kernel/Kconfig.preempt makes
 * PREEMPT_COUNT a bare bool that only PREEMPTION selects; PREEMPT_VOLUNTARY
 * does not select it, and x86_64 defconfig produced exactly that combination
 * through 5.15, gaining PREEMPT_DYNAMIC -> PREEMPTION -> PREEMPT_COUNT only at
 * 5.16.  Older enterprise and embedded kernels ship it routinely.  On x86_64
 * 7.1 the combination is no longer reachable -- PREEMPT_NONE gained
 * "depends on ARCH_NO_PREEMPT" and PREEMPT_VOLUNTARY gained "depends on
 * !ARCH_HAS_PREEMPT_LAZY", and x86 has the latter and not the former
 * (linux-7.1.9/kernel/Kconfig.preempt) -- but PREEMPT_COUNT is still a bare
 * bool, so architectures without ARCH_HAS_PREEMPT_LAZY can still produce it.
 *
 * The same blindness in wc_linuxkm_can_block() let a cond_resched() sleep
 * inside an open section, migrate the task, and strand kernel_fpu_begin()'s
 * section on the origin CPU (module_hooks.c).  That was fixed by testing the
 * open section directly.  This site is the other half: the pin itself has to
 * be a pin.
 *
 * WHY migrate_disable() IS THE RIGHT ANSWER HERE, AND NOT JUST THE ANSWER THE
 * UNCERTIFIED HALF OF THIS FILE ALREADY USES.
 *
 * What this region needs is that it does not change CPU.  It does not need to
 * be non-preemptible: nothing between the test and the claim sleeps, and a
 * task that is merely scheduled out and back in on the SAME CPU observes the
 * same per-CPU slot it tested.  migrate_disable() delivers exactly that
 * property, and it is the only primitive whose effect does not route through
 * PREEMPT_MASK: it sets current->migration_disabled, which
 * migrate_disable_switch() and select_task_rq() consult directly
 * (kernel/sched/core.c), so a voluntary schedule inside the region resumes on
 * the CPU it left.  get_cpu()/put_cpu() and local_bh_disable() are both
 * preempt_count arithmetic and are just as blind; local_irq_save() would pin
 * but cannot be held for the life of a crypto section, and does not compile
 * in-boundary on arm64 before 6.6.
 *
 * VERSION FLOOR IS 5.11, NOT 5.7.  Through 5.10 migrate_disable() is
 * literally preempt_disable() -- read verbatim from
 * linux-5.7.19/include/linux/preempt.h:335 and
 * linux-5.10.265/include/linux/preempt.h:336,
 *   static __always_inline void migrate_disable(void) { preempt_disable(); }
 * so on a !CONFIG_PREEMPT_COUNT build it is barrier() and compensates for
 * nothing.  The per-task migration_disabled machinery, and
 * EXPORT_SYMBOL_GPL(migrate_disable), arrive in 5.11
 * (linux-5.11.22/kernel/sched/core.c:1756).  The uncertified half of this file
 * carries the same 5.11 floor at its SEVEN sites -- counted, not recalled; an
 * earlier revision of this paragraph said eight, which is the drift this file
 * warns about elsewhere -- raised there from 5.7 for exactly this reason.  5.6
 * and earlier have no migrate_disable() at all.  On
 * !CONFIG_PREEMPT_COUNT kernels below 5.11 there is no primitive that pins
 * this region short of disabling interrupts, and this code does not pretend
 * otherwise.
 *
 * TASK CONTEXT ONLY.  Only task context can change CPU; a softirq or hardirq
 * runs to completion on the CPU it interrupted.  wc_svr_ctx() tells them apart
 * with NMI_MASK/HARDIRQ_MASK and in_serving_softirq(), and those masks ARE
 * maintained without CONFIG_PREEMPT_COUNT -- only the PREEMPT_MASK half of
 * preempt_count() goes blind.  Restricting the call to task context is
 * therefore sufficient, and it also keeps migrate_enable()'s
 * __set_cpus_allowed_ptr() arm, which takes rq locks, unreachable from
 * interrupt context.
 *
 * !SMP compiles nothing: include/linux/preempt.h defines migrate_disable() as
 * an empty inline there, correctly, because there is nowhere to migrate to. */
#ifdef WC_SVR_HAVE_NESTED_SAVE
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
        #define WC_SVR_MIGRATE_PIN_NEEDED 1
        #define WC_SVR_DECIDE_PIN(flag_)                                \
            do {                                                        \
                if (! (preempt_count() & (NMI_MASK | HARDIRQ_MASK)) &&  \
                    ! in_serving_softirq())                             \
                {                                                       \
                    migrate_disable();                                  \
                    (flag_) = 1;                                        \
                }                                                       \
                preempt_disable();                                      \
            } while (0)
        /* Reverse acquisition order: the preempt_disable() was taken last so
         * it is released first.  Releasing migrate_enable() first would leave
         * a window that still believes it is pinned but is not. */
        #define WC_SVR_DECIDE_UNPIN(flag_)                              \
            do {                                                        \
                preempt_enable();                                       \
                if (flag_)                                              \
                    migrate_enable();                                   \
            } while (0)
    #else
        #define WC_SVR_DECIDE_PIN(flag_)                                \
            do { (void)(flag_); preempt_disable(); } while (0)
        #define WC_SVR_DECIDE_UNPIN(flag_)                              \
            do { (void)(flag_); preempt_enable(); } while (0)
    #endif
#else
    #define WC_SVR_DECIDE_PIN(flag_)   (void)(flag_)
    #define WC_SVR_DECIDE_UNPIN(flag_) (void)(flag_)
#endif


/* Nonzero when this CPU is inside one of this module's sections, so the lock
 * primitives can refuse to run there.  this_cpu ops are preemption-safe, and a
 * CPU with an open section is not schedulable, so a zero read stays zero.
 * https://docs.kernel.org/core-api/this_cpu_ops.html */
static int wc_linuxkm_in_svr_bracket(void)
{
    const struct wc_svr_cpu_state *st = raw_cpu_ptr(&wc_svr_state);

    return (st->c[WC_SVR_CTX_TASK].depth |
            st->c[WC_SVR_CTX_SOFTIRQ].depth |
            st->c[WC_SVR_CTX_HARDIRQ].depth) > 0;
}

/* The counters are static per-CPU storage; the save areas are not.  Both are
 * kept because wolfCrypt_Init() and wolfCrypt_Cleanup() call them. */
WARN_UNUSED_RESULT int allocate_wolfcrypt_linuxkm_fpu_states(void)
{
    return wc_svr_nested_init();
}

void free_wolfcrypt_linuxkm_fpu_states(void)
{
    /* unsigned: for_each_possible_cpu() compares the iterator against
     * small_cpumask_bits, which is unsigned, and this build is
     * -Wsign-compare -Werror (include/linux/find.h). */
    unsigned int cpu;
    int ctx;

    for_each_possible_cpu(cpu) {
        for (ctx = 0; ctx < WC_SVR_NCTX; ++ctx) {
            struct wc_svr_ctx_state *st = &per_cpu(wc_svr_state, cpu).c[ctx];
            if (st->depth != 0) {
                pr_err("ERROR: free_wolfcrypt_linuxkm_fpu_states called with"
                       " depth %u in context %d on CPU %u.\n",
                       st->depth, ctx, cpu);
                st->depth = 0;
                st->inhibited = 0;
                st->nested = 0;
                st->migrate_pinned = 0;
            }
        }
    }

    wc_svr_nested_free();
}

/* Ask the architecture, do not answer for it.  may_use_simd() is
 * irq_fpu_usable() on x86 and adds system_supports_fpsimd() on arm64, and it is
 * the precondition kernel_fpu_begin_mask() itself asserts on.  A false answer
 * is not the end of it here: with a save area of our own, "in use" is a state
 * this module can take over and hand back. */
WARN_UNUSED_RESULT int wc_can_save_vector_registers_x86(void)
{
    const struct wc_svr_ctx_state *st;
    int ctx;

    if (in_nmi())
        return 0;

    ctx = wc_svr_ctx();
    st = wc_svr_here(ctx);
    if (st->depth > 0)
        return st->inhibited ? 0 : 1;

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    if (SAVE_VECTOR_REGISTERS2_fuzzer() != 0)
        return 0;
#endif

    if (may_use_simd())
        return 1;

    return wc_svr_nested_ready ? 1 : 0;
}

WARN_UNUSED_RESULT int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_ctx_state *st;
    int ctx;
    /* Set by WC_SVR_DECIDE_PIN() when it took a migrate_disable(); read by
     * every WC_SVR_DECIDE_UNPIN() below, and copied into the slot on the one
     * path whose pin outlives this function. */
    int migrate_pinned = 0;

    if (in_nmi())
        return WC_ACCEL_INHIBIT_E;

    ctx = wc_svr_ctx();

    /* A nonzero depth means a section is open in THIS context on this CPU, so
     * the CPU is pinned and the count needs no locking.  Nesting is the caller
     * obligation the kernel documentation names, and this branch is all of
     * it. */
    st = wc_svr_here(ctx);
    if (st->depth > 0) {
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
        st = &this_cpu_ptr(&wc_svr_state)->c[ctx];   /* pinned now */
        st->depth = 1;
        st->inhibited = 1;
        st->nested = 0;
        st->migrate_pinned = 0;
        return 0;
    }

    /* Pin before asking, because the answer and the storage are both per-CPU
     * and a task-context caller is otherwise free to migrate between the two.
     * Nothing below sleeps. */
    WC_SVR_DECIDE_PIN(migrate_pinned);

    /* raw while only DECIDE_PIN holds the CPU -- it is a no-op in builds
     * without nested save, and this_cpu_ptr() would then be a
     * CONFIG_DEBUG_PREEMPT splat in plain task context. */
    if (unlikely(wc_svr_here(ctx)->depth != 0)) {
        /* Only reachable by migrating onto a CPU whose same-context slot is
         * open, which cannot happen while that section holds that CPU.  Refuse
         * rather than share a register file on the strength of a count. */
        WC_SVR_DECIDE_UNPIN(migrate_pinned);
        return BAD_STATE_E;
    }

    if (WC_SVR_MAY_USE_SIMD()) {
        WC_LINUXKM_FPU_BEGIN();
        st = &this_cpu_ptr(&wc_svr_state)->c[ctx];  /* pinned by FPU_BEGIN */
        st->depth = 1;
        st->inhibited = 0;
        st->nested = 0;
        st->migrate_pinned = 0;
        /* FPU_BEGIN holds the CPU only where CONFIG_PREEMPT_COUNT is set: on
         * x86 it is kernel_fpu_begin()'s preempt_disable()
         * (linux-6.14.11 arch/x86/kernel/fpu/core.c:423, and fpregs_lock()
         * from linux-6.15.11:430), and without PREEMPT_COUNT both are
         * barrier() (include/linux/preempt.h:284).  What actually keeps this
         * section on one CPU there is that nothing in it schedules:
         * wc_linuxkm_can_block() refuses while st->depth is nonzero, so
         * WC_RELAX_LONG_LOOP() cannot cond_resched() inside it.  The pin is
         * released here because it is the DECIDE_PIN region that ends, not
         * because FPU_BEGIN replaced it.
         *
         * arm64 from 6.19 is the one case where that is not enough, because
         * the section owns a per-CPU buffer the kernel matches by pointer at
         * kernel_neon_end(); WC_LINUXKM_FPU_BEGIN() takes its own pin there
         * and holds it across the whole section.  See WC_LKM_NEON_PIN(). */
        WC_SVR_DECIDE_UNPIN(migrate_pinned);
        return 0;
    }

#ifdef WC_SVR_HAVE_NESTED_SAVE
    if (wc_svr_nested_ready) {
        /* The arm64 SVE save declines a vector length it cannot fit; a decline
         * here has touched no register and written nothing, so the section is
         * refused exactly as it would have been without nested save. */
        if (wc_svr_regs_save(wc_svr_area(ctx)) != 0) {
            WC_SVR_COUNT_REFUSE(ctx);
            WC_SVR_DECIDE_UNPIN(migrate_pinned);
            return WC_ACCEL_INHIBIT_E;
        }
        wc_svr_load_default_mxcsr();
        WC_SVR_COUNT_SAVE(ctx);
        st = &this_cpu_ptr(&wc_svr_state)->c[ctx];  /* pinned by DECIDE_PIN */
        st->depth = 1;
        st->inhibited = 0;
        st->nested = 1;
        st->migrate_pinned = (unsigned int)migrate_pinned;
        /* The pin IS this section's pin, and is released by the restore. */
        return 0;
    }
#endif

    WC_SVR_COUNT_REFUSE(ctx);
    WC_SVR_DECIDE_UNPIN(migrate_pinned);
    return WC_ACCEL_INHIBIT_E;
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_ctx_state *st;
    int ctx;

    if (in_nmi()) {
        pr_err_once("BUG: wc_restore_vector_registers_x86() in NMI context on"
                    " CPU %d.\n", raw_smp_processor_id());
        return;
    }

    ctx = wc_svr_ctx();

    /* Every path that opened a section left this CPU pinned -- FPU_BEGIN,
     * PIN_CPU or the nested save's preempt_disable() -- so once depth is known
     * nonzero this is the same CPU that opened it.  Until then nothing pins it,
     * which is why the read is raw. */
    st = wc_svr_here(ctx);

    if (unlikely(st->depth == 0)) {
        pr_err_once("BUG: wc_restore_vector_registers_x86() with no open"
                    " section in context %d for pid %d on CPU %d.\n",
                    ctx, task_pid_nr(current), raw_smp_processor_id());
        return;
    }

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
#ifdef WC_SVR_HAVE_NESTED_SAVE
    else if (st->nested) {
        int migrate_pinned = (int)st->migrate_pinned;
        st->nested = 0;
        st->migrate_pinned = 0;
        /* Hand the interrupted context its registers back before letting
         * anything else run on this CPU. */
        wc_svr_regs_restore(wc_svr_area(ctx));
        WC_SVR_DECIDE_UNPIN(migrate_pinned);
    }
#endif
    else {
        WC_LINUXKM_FPU_END();
    }

    WC_RELAX_LONG_LOOP();
}

#endif /* uncertified or non-FIPS */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
