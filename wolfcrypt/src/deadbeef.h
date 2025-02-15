/* deadbeef.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_DEADBEEF_H
#define WOLF_CRYPT_DEADBEEF_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_DEADBEEF_RNG

/* Initialize the RNG with deadbeef pattern */
WOLFSSL_LOCAL int wc_InitDeadbeefRng(WC_RNG* rng);

/* Fill buffer with repeating 0xdeadbeef pattern */
WOLFSSL_LOCAL int wc_DeadbeefRng_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);

/* Free RNG resources */
WOLFSSL_LOCAL int wc_FreeDeadbeefRng(WC_RNG* rng);

#endif /* WOLFSSL_DEADBEEF_RNG */
#endif /* WOLF_CRYPT_DEADBEEF_H */
