/* wolfmath.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


/* common functions for either math library */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set USE_FAST_MATH there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef USE_FAST_MATH
    #include <wolfssl/wolfcrypt/tfm.h>
#else
    #include <wolfssl/wolfcrypt/integer.h>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if defined(USE_FAST_MATH) || !defined(NO_BIG_INT)

int get_digit_count(mp_int* a)
{
    if (a == NULL)
        return 0;

    return a->used;
}

mp_digit get_digit(mp_int* a, int n)
{
    if (a == NULL)
        return 0;

    return (n >= a->used || n < 0) ? 0 : a->dp[n];
}

int get_rand_digit(WC_RNG* rng, mp_digit* d)
{
    return wc_RNG_GenerateBlock(rng, (byte*)d, sizeof(mp_digit));
}

int mp_rand(mp_int* a, int digits, WC_RNG* rng)
{
    int ret;
    mp_digit d;

    if (rng == NULL)
        return MISSING_RNG_E;

    if (a == NULL)
        return BAD_FUNC_ARG;

    mp_zero(a);
    if (digits <= 0) {
        return MP_OKAY;
    }

    /* first place a random non-zero digit */
    do {
        ret = get_rand_digit(rng, &d);
        if (ret != 0) {
            return ret;
        }
    } while (d == 0);

    if ((ret = mp_add_d(a, d, a)) != MP_OKAY) {
        return ret;
    }

    while (--digits > 0) {
        if ((ret = mp_lshd(a, 1)) != MP_OKAY) {
            return ret;
        }
        if ((ret = get_rand_digit(rng, &d)) != 0) {
            return ret;
        }
        if ((ret = mp_add_d(a, d, a)) != MP_OKAY) {
            return ret;
        }
    }

    return ret;
}

#endif
