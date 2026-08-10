/* test_sp_c64_fault_whitebox.c
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
 * Heap-fault MC/DC supplement for wolfcrypt/src/sp_c64.c.
 *
 * Drives the `err == MP_OKAY` operand of the file's success chains by failing
 * an SP temporary allocation. See tests/unit-mcdc/test_sp_fault_common.h for
 * why that operand is otherwise dead, and what the sweep does.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/sp_c64.c>

/* After the .c: only the test key material is wanted here, and the
 * module config does not ask for the buffers itself. */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

#define SP_FAULT_LABEL "sp_c64.c"
#include "test_sp_fault_common.h"
