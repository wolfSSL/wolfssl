/* repro.c
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

/* Reproduces the GCC build failure for CMSIS-RTOS v1/v2 without
 * WOLFSSL_MDK_ARM: types.h fell through to its generic threading branch,
 * which defines WOLFSSL_THREAD as the MSVC-only __stdcall. The bug is
 * preprocessor/type-level so it triggers with GCC on any host. */
#include "user_settings.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/wc_port.h"

static THREAD_RETURN WOLFSSL_THREAD ReproThread(void* arg)
{
    (void)arg;
    return (THREAD_RETURN)0;
}

int main(void)
{
    THREAD_CB cb = ReproThread;
    return (cb != NULL) ? 0 : 1;
}
