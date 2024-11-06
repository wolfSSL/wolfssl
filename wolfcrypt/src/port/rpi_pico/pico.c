/* pico.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
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




#include <inttypes.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_RPIPICO)
#include "pico/rand.h"


/* On RP2040 this uses an optimized PRNG, on RP2350 this uses a hardware TRNG.
 * There is a 128bit function, but internally this is just 2x 64bit calls.
 * Likewise the 32bit call is just a truncated 64bit call, so just stick with
 * the 64bit calls.
 */

int wc_pico_rng_gen_block(unsigned char *output, unsigned int sz)
{
    uint32_t i = 0;

    while (i < sz)
    {
        uint64_t rnd = get_rand_64();
        if (i + 8 < sz)
        {
            XMEMCPY(output + i, &rnd, 8);
            i += 8;
        } else {
            XMEMCPY(output + i, &rnd, sz - i);
            i = sz;
        }
    }

    return 0;
}
#endif
