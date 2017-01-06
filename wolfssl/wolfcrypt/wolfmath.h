/* wolfmath.h
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

#ifndef __WOLFMATH_H__
#define __WOLFMATH_H__


/* common math functions */
WOLFSSL_LOCAL int get_digit_count(mp_int* a);
WOLFSSL_LOCAL mp_digit get_digit(mp_int* a, int n);
WOLFSSL_LOCAL int get_rand_digit(WC_RNG* rng, mp_digit* d);
WOLFSSL_LOCAL int mp_rand(mp_int* a, int digits, WC_RNG* rng);


#endif /* __WOLFMATH_H__ */
