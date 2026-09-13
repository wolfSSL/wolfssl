/* arm64_vector_register_glue.c: glue logic to claim and release the FPSIMD
 * and NEON registers on arm64
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

#if !defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) || !defined(CONFIG_ARM64)
    #error arm64 vector register glue included in non-vectorized or non-arm64 project.
#endif

#ifndef CONFIG_KERNEL_MODE_NEON
    /* Without this option the kernel exports no kernel_neon_begin() and
     * may_use_simd() is always false (linux-6.6.99 fpsimd.c:1904, simd.h:46). */
    #error wolfSSL linuxkm on arm64 requires CONFIG_KERNEL_MODE_NEON.
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
    /* Written against the void kernel_neon_begin() of linux-6.6.99.  6.19
     * changes that signature and has not been read here. */
    #error arm64 vector register glue does not yet support kernel_neon_begin() with a state buffer (6.19+).
#endif

#ifdef DEBUG_VECTOR_REGISTER_ACCESS_FUZZING
    #error DEBUG_VECTOR_REGISTER_ACCESS_FUZZING is not implemented by the arm64 vector register glue.
#endif

/* kernel_neon_begin() BUGs unless may_use_simd(), then takes this CPU's FPSIMD
 * context with bottom halves off (linux-6.6.99 fpsimd.c:1904 and :239,
 * simd.h:26).  One record per CPU per context counts claim and inhibit depth. */

struct wc_svr_arm64_ctx_state {
    unsigned int depth;      /* open claims in this context on this CPU */
    unsigned int inhibit_at; /* depth of the open inhibit claim, 0 when none */
    unsigned int neon_held;  /* 1 between kernel_neon_begin() and _end() */
    unsigned int bh_held;    /* 1 while a pin-only section holds local_bh_disable() */
};

struct wc_svr_arm64_cpu_state {
    struct wc_svr_arm64_ctx_state ctx[2]; /* [0] task, [1] softirq */
};

static DEFINE_PER_CPU(struct wc_svr_arm64_cpu_state, wc_svr_arm64_state);
static atomic64_t wc_svr_disallowed_count = ATOMIC64_INIT(0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    #define wc_svr_arm64_in_hardirq() in_irq()
#else
    #define wc_svr_arm64_in_hardirq() in_hardirq()
#endif

/* Keep softirqs off a section that holds no registers, as the x86 glue does.
 * With interrupts already off, nothing can arrive anyway. */
static inline void wc_svr_arm64_pin_bh(struct wc_svr_arm64_ctx_state *st)
{
    if (! irqs_disabled()) {
        local_bh_disable();
        st->bh_held = 1;
    }
}

/* The record for this context on this CPU.  Every caller has the CPU held,
 * by preempt_disable() here or by the open claim's bottom-half disable. */
static inline struct wc_svr_arm64_ctx_state *wc_svr_arm64_here(void)
{
    return &this_cpu_ptr(&wc_svr_arm64_state)->ctx[in_serving_softirq() ? 1 : 0];
}

/* The records are static.  These entry points exist because wc_port.c and
 * the redirect table expect them. */
__must_check int wc_linuxkm_allocate_svr_states(void)
{
    return 0;
}

void wc_linuxkm_free_svr_states(void)
{
}

void wc_svr_disallowed_count_reset(void)
{
    atomic64_set(&wc_svr_disallowed_count, 0);
}

__must_check unsigned long long int wc_svr_disallowed_count_current(void)
{
    return (unsigned long long int)atomic64_read(&wc_svr_disallowed_count);
}

/* Nonzero when a claim made now would succeed. */
__must_check int wc_can_save_vector_registers_x86(void)
{
    struct wc_svr_arm64_ctx_state *st;
    int ret;

    if (in_nmi() || wc_svr_arm64_in_hardirq())
        return 0;

    preempt_disable();
    st = wc_svr_arm64_here();
    if (st->depth > 0)
        ret = (st->inhibit_at == 0);
    else
        ret = may_use_simd() ? 1 : 0;
    preempt_enable();

    return ret;
}

__must_check int wc_save_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_arm64_ctx_state *st;

    if (in_nmi() || wc_svr_arm64_in_hardirq()) {
        /* may_use_simd() is false here, and any open record belongs to the
         * context this interrupt landed on. */
        atomic64_inc(&wc_svr_disallowed_count);
        return WC_ACCEL_INHIBIT_E;
    }

    preempt_disable();
    st = wc_svr_arm64_here();

    if (st->depth > 0) {
        /* Nested in this context's own section, which already holds the
         * CPU, so the preempt_disable() above is balanced, not carried. */
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
            /* Pin-only claims are outermost only, as in the x86 glue. */
            preempt_enable();
            atomic64_inc(&wc_svr_disallowed_count);
            return BAD_STATE_E;
        }
        if (st->inhibit_at != 0) {
            preempt_enable();
            atomic64_inc(&wc_svr_disallowed_count);
            return WC_ACCEL_INHIBIT_E;
        }
        ++st->depth;
        if (flags & WC_SVR_FLAG_INHIBIT)
            st->inhibit_at = st->depth;
        preempt_enable();
        return 0;
    }

    /* Outermost claim.  The bottom-half disable below is what holds the CPU,
     * taken by kernel_neon_begin() or wc_svr_arm64_pin_bh(). */
    if (flags & WC_SVR_FLAG_INHIBIT) {
        wc_svr_arm64_pin_bh(st);
        st->depth = 1;
        st->inhibit_at = 1;
        /* Counted as the x86 glue counts it: a span in which claims are
         * refused, opened on request. */
        atomic64_inc(&wc_svr_disallowed_count);
        return 0;
    }

    if (! may_use_simd()) {
        if (flags & WC_SVR_FLAG_MAYBE_INHIBIT) {
            /* Held without the registers: nested claims are refused. */
            wc_svr_arm64_pin_bh(st);
            st->depth = 1;
            st->inhibit_at = 1;
            atomic64_inc(&wc_svr_disallowed_count);
            return 0;
        }
        preempt_enable();
        atomic64_inc(&wc_svr_disallowed_count);
        return WC_ACCEL_INHIBIT_E;
    }

    kernel_neon_begin();
    st->depth = 1;
    st->neon_held = 1;
    return 0;
}

void wc_restore_vector_registers_x86(enum wc_svr_flags flags)
{
    struct wc_svr_arm64_ctx_state *st;

    if (in_nmi() || wc_svr_arm64_in_hardirq()) {
        wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() "
            "called from %s on CPU %d, where no claim can be open.\n",
            in_nmi() ? "NMI" : "hardirq", raw_smp_processor_id());
        return;
    }

    preempt_disable();
    st = wc_svr_arm64_here();
    if (st->depth == 0) {
        preempt_enable();
        wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() "
            "with no open claim on CPU %d.\n", raw_smp_processor_id());
        return;
    }
    /* The open claim already holds the CPU; balance the disable above. */
    preempt_enable();

    if (st->inhibit_at == st->depth) {
        if (! (flags & (WC_SVR_FLAG_INHIBIT | WC_SVR_FLAG_MAYBE_INHIBIT))) {
            wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() "
                "closing an inhibit claim without an inhibit flag on CPU %d.\n",
                raw_smp_processor_id());
        }
        st->inhibit_at = 0;
    }
    else if (flags & WC_SVR_FLAG_INHIBIT) {
        wc_linuxkm_pr_err_ratelimited("BUG: wc_restore_vector_registers_x86() "
            "with the inhibit flag but no matching inhibit claim on CPU %d.\n",
            raw_smp_processor_id());
    }

    if (--st->depth == 0) {
        if (st->neon_held) {
            st->neon_held = 0;
            kernel_neon_end();
        }
        if (st->bh_held) {
            st->bh_held = 0;
            local_bh_enable();
        }
        preempt_enable();
    }
}

#endif /* !WC_SKIP_INCLUDED_C_FILES */
