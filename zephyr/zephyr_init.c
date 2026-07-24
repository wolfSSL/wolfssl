/* zephyr_init.c
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

/* The wolfSSL Zephyr module needs no boot-time SYS_INIT hook. wolfCrypt's
 * Hash-DRBG is seeded on demand by wc_GenerateSeed() -- which on Zephyr draws
 * from the hardware entropy driver when one is present (see
 * wolfcrypt/src/random.c) -- and wolfCrypt_Init()/wolfSSL_Init() run lazily
 * from the first library call. This translation unit is kept (it is referenced
 * by the module CMakeLists) as the place for any future module init. */
