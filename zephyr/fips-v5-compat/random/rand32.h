/* rand32.h
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

/* Shim for the FIPS v5 random.c, which includes <random/rand32.h> from
 * before Zephyr moved its headers under zephyr/ and renamed rand32.h. */
#ifndef WOLFSSL_ZEPHYR_COMPAT_RAND32_H
#define WOLFSSL_ZEPHYR_COMPAT_RAND32_H

#if __has_include(<zephyr/random/random.h>)
    /* Zephyr 3.5 and later */
    #include <zephyr/random/random.h>
#elif __has_include(<zephyr/random/rand32.h>)
    /* Zephyr 3.1 to 3.4 */
    #include <zephyr/random/rand32.h>
#else
    /* Before 3.1 the original header is still the right one */
    #include_next <random/rand32.h>
#endif

#endif /* WOLFSSL_ZEPHYR_COMPAT_RAND32_H */
