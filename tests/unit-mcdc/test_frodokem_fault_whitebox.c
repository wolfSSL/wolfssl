/* test_frodokem_fault_whitebox.c
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
 * MC/DC fault-injection white-box for wolfcrypt/src/wc_frodokem.c.
 *
 * #includes wc_frodokem.c directly so llvm-cov instruments this file's copy
 * (reaching its file-statics), then #includes the shared driver body which
 * installs the heap-fault injector and sweeps the fail-index across
 * make/encap/decap for every compiled parameter set -- driving the FALSE
 * (ret != 0) halves of wc_frodokem.c's allocation success chains. See
 * test_frodokem_fault_common.h for the full rationale.
 */

#include <wolfcrypt/src/wc_frodokem.c>

#include "test_frodokem_fault_common.h"
