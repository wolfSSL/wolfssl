/* fe_operations.h
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

 /* Based On Daniel J Bernstein's curve25519 and ed25519 Public Domain ref10
    work. */

#ifndef WOLF_CRYPT_FE_OPERATIONS_H
#define WOLF_CRYPT_FE_OPERATIONS_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(HAVE_CURVE25519) || defined(HAVE_ED25519)

#include <stdint.h>

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

typedef int32_t fe[10];

WOLFSSL_LOCAL void fe_0(fe);
WOLFSSL_LOCAL void fe_1(fe);
WOLFSSL_LOCAL void fe_add(fe, const fe, const fe);
WOLFSSL_LOCAL void fe_tobytes(unsigned char *, const fe);
WOLFSSL_LOCAL void fe_sub(fe, const fe, const fe);
WOLFSSL_LOCAL void fe_invert(fe, const fe);
WOLFSSL_LOCAL void fe_sq(fe, const fe);
WOLFSSL_LOCAL void fe_sq2(fe,const fe);
WOLFSSL_LOCAL void fe_frombytes(fe,const unsigned char *);
WOLFSSL_LOCAL void fe_mul(fe,const fe,const fe);
WOLFSSL_LOCAL void fe_copy(fe, const fe);
WOLFSSL_LOCAL void fe_cswap(fe,fe,unsigned int);
WOLFSSL_LOCAL void fe_mul121666(fe,fe);
WOLFSSL_LOCAL int fe_isnonzero(const fe);
WOLFSSL_LOCAL int fe_isnegative(const fe);
WOLFSSL_LOCAL void fe_cmov(fe,const fe,unsigned int);
WOLFSSL_LOCAL void fe_neg(fe,const fe);
WOLFSSL_LOCAL void fe_pow22523(fe,const fe);
WOLFSSL_LOCAL uint64_t load_3(const unsigned char *in);
WOLFSSL_LOCAL uint64_t load_4(const unsigned char *in);

#endif /* HAVE_CURVE25519 or HAVE_ED25519 */
#endif /* WOLF_CRYPT_FE_OPERATIONS_H */

