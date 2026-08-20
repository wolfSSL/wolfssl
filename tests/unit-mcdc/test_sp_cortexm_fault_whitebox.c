/* test_sp_cortexm_fault_whitebox.c
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
 * (wolfcrypt/src/sp_cortexm.c) -- heap-fault half.
 *
 * Sibling of test_sp_arm64_fault_whitebox.c / _arm32_ / _armthumb_ and shares
 * their body (tests/unit-mcdc/test_sp_arm_fault_common.h); see that header for
 * why the `err == MP_OKAY` operand of this file's success chains is otherwise
 * dead by construction, why this TU (not a new lane variant) turns
 * WOLFSSL_SP_SMALL_STACK on, and what the allocation sweep does.
 *
 * WHY THIS FILE EXISTS ONLY NOW
 * ----------------------------
 * sp_cortexm.c is measured on the bare-metal m33mu lane, and until this pass
 * that lane had no white-box mechanism at all: lib/lanes.sh forwarded a
 * variant's "lane_whitebox" rows to kind `qemu-user` only, because those lanes
 * can relink against libwolfssl.a with the involved object trimmed. m33mu is a
 * single static firmware link with no archive, so the only driver it could
 * carry was tests/unit-mcdc/test_sp_cortexm_whitebox.c riding along as a
 * lane_extra_source -- an UNinstrumented TU that can call sp_cortexm.c's
 * external-linkage entry points but cannot change how the file itself is
 * compiled. Nothing it did could make an SP temporary allocation exist, let
 * alone fail.
 *
 * The lane now supports white-boxes properly: harness/build-fw.sh has a
 * WB_SRC mode that relinks the firmware from the base build's object manifest
 * with sp_cortexm.c's object replaced by THIS TU (compiled with clang MC/DC),
 * and main() routed here. That is what makes WOLFSSL_SP_SMALL_STACK -- defined
 * below, before the #include -- take effect: this TU holds the one and only
 * compiled copy of sp_cortexm.c in the image, so there is no ODR/ABI split
 * with the rest of the firmware (the macro only changes function-local
 * storage inside the file; no header and no struct layout reacts to it).
 *
 * WHAT IT CLOSES (all in sp_cortexm.c, all the `err == MP_OKAY` operand):
 *   39304:0 39307:0 39310:0   sp_ecc_mulmod_add_256(), three consecutive
 *   40819:0 40822:0 40825:0   sp_ecc_mulmod_base_add_256(), three consecutive
 *       `if ((err == MP_OKAY) && (!inMont))`. inMont is passed 0 so the second
 *       operand stays true and the sweep is what moves err.
 *   42989:0                   `if ((err == MP_OKAY) && sp_256_iszero_8(p2->z))`
 *       in sp_256_calc_vfy_point_8(); err arrives non-MP_OKAY when the
 *       sp_256_ecc_mulmod_8() immediately above it fails its SP allocation.
 * The ordinary (accepting) arrival of each of those guards is produced by the
 * same driver's unarmed preparation calls, in this same binary.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Before ANY wolfSSL header, so sp_cortexm.c's own
 *     #ifdef WOLFSSL_SP_SMALL_STACK ... SP_ALLOC_VAR = XMALLOC + err
 * arm of the SP_DECL_VAR/SP_ALLOC_VAR macro pair is the one compiled into this
 * translation unit. No header reacts to this macro, so it changes nothing but
 * function-local storage inside the file under test. */
#ifndef WOLFSSL_SP_SMALL_STACK
    #define WOLFSSL_SP_SMALL_STACK
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/sp_cortexm.c>

#define SP_ARM_FAULT_LABEL "sp_cortexm.c"
#include "test_sp_arm_fault_common.h"
