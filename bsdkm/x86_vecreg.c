/* x86_vecreg.c -- logic to save and restore vector registers
 *                 on amd64 in FreeBSD kernel.
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

/* included by bsdkm/wolfkmod.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#include <sys/proc.h>
#include <sys/smp.h>
#include <machine/fpu.h>
#include <machine/pcb.h>

struct wolfkmod_fpu_state_t {
    volatile lwpid_t td_tid;
    volatile u_int   nest;
};

typedef struct wolfkmod_fpu_state_t wolfkmod_fpu_state_t;

/* fpu_states array tracks thread id and nesting level of save/restore
 * and push/pop vector registers macro calls. It is indexed by raw cpu id,
 * and only accessed after the thread calls fpu_kern_enter(), and before
 * calling fpu_kern_leave(), and only indexed by the thread's PCPU_GET(cpuid).
 *
 * after calling fpu_kern_enter():
 *   - kernel fpu is enabled
 *   - migration is disabled
 *   - soft preempts are disabled
 * Hard irq are still possible , but hard irq are forbidden from using FPU
 * in FreeBSD kernel.
 * */
static wolfkmod_fpu_state_t * fpu_states = NULL;

/* check for active td_tid with atomic before proceeding.
 * technically not necessary because fpu_kern_enter() gives thread pinning
 * to cpu, but just to be safe...
 * */
#define wolfkmod_fpu_get_tid()                                               \
            atomic_load_acq_int(&fpu_states[PCPU_GET(cpuid)].td_tid)

int wolfkmod_vecreg_init(void)
{
    if (mp_ncpus <= 0) {
        printf("error: wolfkmod_vecreg_init: mp_ncpus = %d\n", mp_ncpus);
        return (EINVAL);
    }

    fpu_states = malloc(mp_ncpus * sizeof(wolfkmod_fpu_state_t),
                        M_WOLFSSL, M_WAITOK | M_ZERO);
    if (fpu_states == NULL) {
        printf("error: wolfkmod_vecreg_init: malloc(%lu) failed\n",
               mp_ncpus * sizeof(wolfkmod_fpu_state_t));
        return (ENOMEM);
    }

    return (0);
}

void wolfkmod_vecreg_exit(void)
{
    int i = 0;

    if (fpu_states == NULL) {
        return;
    }

    for (i = 0; i < mp_ncpus; ++i) {
        #if defined(WOLFSSL_BSDKM_FPU_DEBUG)
        printf("info: wolfkmod_vecreg_exit: fpu_states[%d] = %d, %d\n",
               i, fpu_states[i].nest, fpu_states[i].td_tid);
        #endif /* WOLFSSL_BSDKM_FPU_DEBUG */

        if (fpu_states[i].nest != 0 || fpu_states[i].td_tid != 0) {
            /* Check for orphaned fpu state. There's nothing we can do
             * but log the event and zero the nesting level. */
            printf("error: wolfkmod_vecreg_exit: fpu_states[%d] = %d, %d\n",
                   i, fpu_states[i].nest, fpu_states[i].td_tid);
            fpu_states[i].nest = 0;
        }
    }

    free(fpu_states, M_WOLFSSL);
    fpu_states = NULL;

    return;
}

/* fpu_kern_enter() and fpu_kern_leave() wrapper defines.
 * Build with WOLFSSL_BSDKM_FPU_DEBUG to see verbose FPU logging.
 */
#if defined(WOLFSSL_BSDKM_FPU_DEBUG)
    #define wolfkmod_print_curthread(what)                                   \
        printf("%s: cpuid = %d, curthread: td_tid = %d, pid = %d (%s), "     \
               "td_critnest = %d, kernfpu = %02x\n",                         \
               (what), PCPU_GET(cpuid), curthread->td_tid,                   \
               curthread->td_proc ? curthread->td_proc->p_pid : -1,          \
               curthread->td_proc ? curthread->td_proc->p_comm : "noproc",   \
               curthread->td_critnest,                                       \
               curthread->td_pcb->pcb_flags & PCB_KERNFPU);

    #define wolfkmod_fpu_kern_enter()                                        \
        wolfkmod_print_curthread("fpu_kern_enter");                          \
        fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);

    #define wolfkmod_fpu_kern_leave()                                        \
        wolfkmod_print_curthread("fpu_kern_leave");                          \
        fpu_kern_leave(curthread, NULL);
#else
    #define wolfkmod_fpu_kern_enter()                                        \
        fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX);

    #define wolfkmod_fpu_kern_leave()                                        \
        fpu_kern_leave(curthread, NULL);
#endif /* WOLFSSL_BSDKM_FPU_DEBUG */

int wolfkmod_vecreg_save(int flags_unused)
{
    (void)flags_unused;

    #if defined(WOLFSSL_BSDKM_FPU_DEBUG)
    wolfkmod_print_curthread("wolfkmod_vecreg_save");
    #endif

    if (is_fpu_kern_thread(0)) {
        /* kernel fpu threads are special, do nothing. They own a
         * persistent, dedicated fpu context. */
        #if defined(WOLFSSL_BSDKM_FPU_DEBUG)
        printf("info: wolfkmod_vecreg_save: is fpu kern thread\n");
        #endif
        return (0);
    }

    if (curthread->td_pcb->pcb_flags & PCB_KERNFPU) {
        /* kern fpu is active for this thread. check td_tid and
         * increment nesting level. */
        lwpid_t td_tid = wolfkmod_fpu_get_tid();
        if (td_tid != curthread->td_tid) {
            printf("error: wolfkmod_vecreg_save: got tid = %d, expected %d\n",
                   td_tid, curthread->td_tid);
            return (EINVAL);
        }
        fpu_states[PCPU_GET(cpuid)].nest++;
    }
    else {
        /* kern fpu not active for this thread, call fpu_kern_enter().
         * after calling fpu_kern_enter():
         *   - kernel fpu is enabled
         *   - migration is disabled
         *   - soft preempts are disabled */
        lwpid_t td_tid = 0;
        wolfkmod_fpu_kern_enter();
        td_tid = wolfkmod_fpu_get_tid();

        if (fpu_states[PCPU_GET(cpuid)].nest != 0 || td_tid != 0) {
            printf("error: wolfkmod_fpu_kern_enter() with nest: %d, %d\n",
                   fpu_states[PCPU_GET(cpuid)].nest, td_tid);
            return (EINVAL);
        }

        /* increment nest and save td_tid. */
        fpu_states[PCPU_GET(cpuid)].nest++;
        fpu_states[PCPU_GET(cpuid)].td_tid = curthread->td_tid;
    }

    return (0);
}

void wolfkmod_vecreg_restore(void)
{
    #if defined(WOLFSSL_BSDKM_FPU_DEBUG)
    wolfkmod_print_curthread("wolfkmod_vecreg_restore");
    #endif

    if (is_fpu_kern_thread(0)) {
        /* kernel fpu threads are special, do nothing. They own a
         * persistent, dedicated fpu context. */
        #if defined(WOLFSSL_BSDKM_FPU_DEBUG)
        printf("info: wolfkmod_vecreg_restore: is fpu kern thread\n");
        #endif
        return;
    }

    if (curthread->td_pcb->pcb_flags & PCB_KERNFPU) {
        /* kern fpu is active for this thread. check tid and nesting level. */
        lwpid_t td_tid = wolfkmod_fpu_get_tid();
        if (td_tid != curthread->td_tid) {
            printf("error: wolfkmod_vecreg_restore: got tid = %d, "
                   "expected %d\n", td_tid, curthread->td_tid);
            return;
        }

        /* decrement the nesting level. */
        if (fpu_states[PCPU_GET(cpuid)].nest > 0) {
            fpu_states[PCPU_GET(cpuid)].nest--;
        }

        /* if last level, zero the thread id then call fpu_kern_leave */
        if (fpu_states[PCPU_GET(cpuid)].nest == 0) {
            fpu_states[PCPU_GET(cpuid)].td_tid = 0;
            wolfkmod_fpu_kern_leave();
        }
    }

    return;
}

#endif /* !WC_SKIP_INCLUDED_C_FILES */
