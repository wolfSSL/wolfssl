/* test_frodokem_mat_fault_whitebox.c
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
 * MC/DC fault-injection white-box for wolfcrypt/src/wc_frodokem_mat.c.
 *
 * #includes wc_frodokem_mat.c directly so llvm-cov instruments this file's copy
 * (reaching its file-static matrix / noise / mul-add helpers), then #includes
 * the shared driver body. The public FrodoKEM API (wc_frodokem.c) is still
 * provided by the trimmed archive, so make/encap/decap reach these mat routines
 * end to end.
 *
 * NOTE: wc_frodokem_mat.c's 13 (ret == 0) && step residuals become ret != 0
 * only when a SHAKE or AES-ECB primitive returns an error, and on x86/x86_64
 * neither of those primitives allocates from the heap (sha3.c has zero XMALLOC;
 * AES-ECB over the aligned scratch takes a non-allocating path). The heap-fault
 * mock therefore closes NONE of the 13 here -- they need a primitive-return
 * fault mock instead. This driver still runs the mat file end to end (baseline
 * coverage) and is kept so the campaign has a documented, reproducible negative
 * result. See test_frodokem_fault_common.h for the full rationale.
 */

#include <wolfcrypt/src/wc_frodokem_mat.c>

#include "test_frodokem_fault_common.h"
