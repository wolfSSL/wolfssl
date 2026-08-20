/* test_sp_cortexm_crafted_whitebox.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/*
 * MC/DC white-box supplement for the Cortex-M SP backend
 * (wolfcrypt/src/sp_cortexm.c) -- crafted-input half.
 *
 * This is the fourth consumer of tests/unit-mcdc/test_sp_crafted_common.h,
 * alongside sp_x86_64.c / sp_c64.c / sp_c32.c and the three qemu-user ARM
 * lanes. All seven are implementations of ONE public API, so one body drives
 * them; see that header for the full vector list and for the arguments behind
 * the SP exclusion families A-G.
 *
 * It runs on the bare-metal m33mu lane through the lane white-box mechanism
 * added in this pass (lib/lanes.sh forwards "lane_whitebox" for kind m33mu
 * too; lanes/m33mu/entry.sh + harness/build-fw.sh WB_SRC mode relink the
 * firmware with sp_cortexm.c's object replaced by this TU and main() routed
 * here). Before that, sp_cortexm.c's only driver was the UNinstrumented
 * lane_extra_source constructor in test_sp_cortexm_whitebox.c, which can call
 * the file's external-linkage entry points but cannot supply an operand no
 * public caller ever passes.
 *
 * WHAT IT CLOSES (sp_cortexm.c), both from the shared header's vectors:
 *   42093:1  `for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--)` in
 *            sp_ecc_sign_256() -- the `i > 0` operand's FALSE row. A zero
 *            private scalar with an all-zero hash makes s = (e + r*d)/k == 0
 *            on EVERY attempt, so no attempt is accepted and the loop runs all
 *            SP_ECC_MAX_SIG_GEN times instead of leaving on `err`. r is
 *            non-zero and the iteration count is fixed, so nothing here
 *            depends on the RNG.
 *   42989:0  and
 *   42989:1  `if ((err == MP_OKAY) && sp_256_iszero_8(p2->z))` in
 *            sp_256_calc_vfy_point_8(). BOTH operands have to be driven in
 *            THIS one binary, which is why the TU turns
 *            WOLFSSL_SP_SMALL_STACK on below rather than leaving the `err`
 *            operand to the sibling fault white-box. For `A && B`, condition
 *            A's independence pair needs the decision's TRUE outcome, i.e.
 *            A = T *with* B = T -- and B is only ever true on the pZ == 0
 *            vector, which the fault driver does not have. So:
 *              :1  a verify whose public point has pZ == 0. The point is then
 *                  the Jacobian point at infinity and every step of the ladder
 *                  keeps z == 0, so B goes true.
 *              :0  the shared header's allocation sweep over the same entry
 *                  point (WB_SPC_EDGE_SIGNVERIFY, "no-op unless the variant
 *                  sets WOLFSSL_SP_SMALL_STACK"): with the macro on, index 5
 *                  lets sp_ecc_verify_256's own two SP_ALLOC_VARs and
 *                  sp_256_ecc_mulmod_base_8()'s two succeed and fails
 *                  sp_256_ecc_mulmod_8()'s first, so `err` is MEMORY_E by the
 *                  time the guard is evaluated.
 * All of them are paired inside this binary by the ordinary sign/verify calls
 * the same header makes just before them.
 *
 * NOT driven here: the `a == m` modular-inverse vector (verify with
 * s == the curve order). test_sp_crafted_common.h already gates it off for
 * every assembly backend, WOLFSSL_SP_ARM_CORTEX_M_ASM included --
 * sp_256_mod_inv_8() is hand-written Thumb assembly whose halving loop does
 * not terminate on that input.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Before ANY wolfSSL header, so sp_cortexm.c's own
 *     #ifdef WOLFSSL_SP_SMALL_STACK ... SP_ALLOC_VAR = XMALLOC + err
 * arm of the SP_DECL_VAR/SP_ALLOC_VAR macro pair is the one compiled into this
 * translation unit -- otherwise the SP temporaries are plain stack arrays,
 * `err` is MP_OKAY from entry to exit and the shared header's allocation
 * sweeps are inert. Sound for the same reasons spelled out in
 * test_sp_arm_fault_common.h: the lane's white-box link contains exactly ONE
 * copy of sp_cortexm.c -- this one -- so there is no ODR/ABI split with the
 * rest of the firmware, no header or struct layout reacts to the macro, and it
 * adds no decision to the file (SP_ALLOC_VAR/SP_FREE_VAR expand to
 * single-condition ifs, which carry no MC/DC record), so the file's total
 * stays 79 and the union with the other rows stays key-compatible. */
#ifndef WOLFSSL_SP_SMALL_STACK
    #define WOLFSSL_SP_SMALL_STACK
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/sp_cortexm.c>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

/* Pulls in mcdc_fault_alloc.h and the ecc/dh/random headers it needs itself,
 * and defines wb_spc_all(). */
#include "test_sp_crafted_common.h"

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("sp_cortexm.c crafted-input white-box supplement\n");
#if defined(WOLFSSL_SP_ARM_CORTEX_M_ASM)
    wb_spc_all();
    printf("done\n");
#else
    printf("  WOLFSSL_SP_ARM_CORTEX_M_ASM not defined; nothing to exercise\n");
#endif
    /* Always 0: a nonzero exit discards this white-box row's coverage. */
    return 0;
}
