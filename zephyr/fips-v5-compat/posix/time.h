/* time.h
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

/* Shim for the FIPS v5 random.c, which includes <posix/time.h> from
 * before Zephyr moved its headers under zephyr/. The module needs Zephyr 3.7
 * or later; 4.3 then dropped zephyr/posix/time.h for the libc header. */
#ifndef WOLFSSL_ZEPHYR_COMPAT_POSIX_TIME_H
#define WOLFSSL_ZEPHYR_COMPAT_POSIX_TIME_H

#include <zephyr/version.h>

#if KERNEL_VERSION_NUMBER >= 0x40300
    #include <time.h>
#else
    #include <zephyr/posix/time.h>
#endif

#endif /* WOLFSSL_ZEPHYR_COMPAT_POSIX_TIME_H */
