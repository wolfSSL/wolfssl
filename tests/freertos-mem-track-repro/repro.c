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

/* Reproduces the memLock / pthread.h compile failure reported by the
 * FreeRTOS/Xtensa customer in wolfSSL 5.9.1. The bug is preprocessor-only
 * so it triggers on any host once __linux__/__MACH__/__ZEPHYR__ are
 * suppressed via -U flags. WOLFSSL_USER_SETTINGS is supplied by run.sh. */
#include "user_settings.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/mem_track.h"

int main(void) { return 0; }
