/* deadbeef.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_DEADBEEF_RNG

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Initialize the RNG with deadbeef pattern */
int wc_InitDeadbeefRng(WC_RNG* rng)
{
    if (rng == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_HASHDRBG
    rng->drbg = NULL;
    rng->status = DRBG_OK;
#endif
    return 0;
}

/* Fill buffer with repeating 0xdeadbeef pattern */
int wc_DeadbeefRng_GenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    word32 i;
    const byte pattern[] = {0xde, 0xad, 0xbe, 0xef};
    
    if (rng == NULL || output == NULL)
        return BAD_FUNC_ARG;

    if (sz == 0)
        return 0;

    /* Fill buffer with repeating 0xdeadbeef pattern */
    for (i = 0; i < sz; i++) {
        output[i] = pattern[i % 4];
    }

    return 0;
}

/* Free RNG resources */
int wc_FreeDeadbeefRng(WC_RNG* rng)
{
    if (rng == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_HASHDRBG
    rng->status = DRBG_NOT_INIT;
#endif
    return 0;
}

#endif /* WOLFSSL_DEADBEEF_RNG */
