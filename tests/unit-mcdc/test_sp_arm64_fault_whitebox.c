/* test_sp_arm64_fault_whitebox.c
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

/*
 * Heap-fault MC/DC supplement for wolfcrypt/src/sp_arm64.c, run inside this
 * module's own emulator lane.
 *
 * Drives the `err == MP_OKAY` operand of the file's success chains by failing
 * an SP temporary allocation. See tests/unit-mcdc/test_sp_arm_fault_common.h
 * for why that operand is otherwise dead by construction, why this TU (not a
 * new lane variant) turns WOLFSSL_SP_SMALL_STACK on, and what the sweep does.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Before ANY wolfSSL header, so sp_arm64.c's own
 *     #ifdef WOLFSSL_SP_SMALL_STACK ... SP_ALLOC_VAR = XMALLOC + err
 * arm of the SP_DECL_VAR/SP_ALLOC_VAR macro pair is the one compiled into this
 * translation unit. No header reacts to this macro, so it changes nothing but
 * function-local storage inside the file under test. */
#ifndef WOLFSSL_SP_SMALL_STACK
    #define WOLFSSL_SP_SMALL_STACK
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/sp_arm64.c>

#define SP_ARM_FAULT_LABEL "sp_arm64.c"
#include "test_sp_arm_fault_common.h"
