/* ecc25519_fe.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

 /* Based On Daniel J Bernstein's curve25519 Public Domain ref10 work. */

#ifndef WOLF_CRYPT_ECC25519_FE_H
#define WOLF_CRYPT_ECC25519_FE_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_ECC25519

#include <stdint.h>

typedef int32_t fe[10];

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

void fe_frombytes(fe,const unsigned char *);
void fe_tobytes(unsigned char *,fe);

void fe_copy(fe,fe);
void fe_0(fe);
void fe_1(fe);
void fe_cswap(fe,fe,unsigned int);

void fe_add(fe,fe,fe);
void fe_sub(fe,fe,fe);
void fe_mul(fe,fe,fe);
void fe_sq(fe,fe);
void fe_mul121666(fe,fe);
void fe_invert(fe,fe);


#endif /* HAVE_ECC25519 */
#endif /* include guard */

