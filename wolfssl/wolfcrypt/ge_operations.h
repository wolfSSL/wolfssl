/* ge_operations.h
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


 /* Based On Daniel J Bernstein's ed25519 Public Domain ref10 work. */

#ifndef WOLF_CRYPT_GE_OPERATIONS_H
#define WOLF_CRYPT_GE_OPERATIONS_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_ED25519

#include <wolfssl/wolfcrypt/fe_operations.h>

/*
ge means group element.

Here the group is the set of pairs (x,y) of field elements (see fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.

Representations:
  ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  ge_precomp (Duif): (y+x,y-x,2dxy)
*/

#ifdef ED25519_SMALL
  ALIGN16 typedef byte     ge[F25519_SIZE];
#elif defined(CURVED25519_ASM_64BIT)
  ALIGN16 typedef sword64  ge[4];
#elif defined(CURVED25519_ASM_32BIT)
  ALIGN16 typedef sword32  ge[8];
#elif defined(CURVED25519_128BIT)
  ALIGN16 typedef sword64  ge[5];
#else
  ALIGN16 typedef sword32  ge[10];
#endif

typedef struct {
  ge X;
  ge Y;
  ge Z;
} ge_p2;

typedef struct {
  ge X;
  ge Y;
  ge Z;
  ge T;
} ge_p3;

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_LOCAL int  ge_compress_key(byte* out, const byte* xIn, const byte* yIn,
                                                                word32 keySz);
WOLFSSL_LOCAL int  ge_frombytes_negate_vartime(ge_p3 *h,const unsigned char *s);

WOLFSSL_LOCAL int  ge_double_scalarmult_vartime(ge_p2 *r, const unsigned char *a,
                                 const ge_p3 *A, const unsigned char *b);
WOLFSSL_LOCAL void ge_scalarmult_base(ge_p3 *h,const unsigned char *a);
WOLFSSL_LOCAL void sc_reduce(byte* s);
WOLFSSL_LOCAL void sc_muladd(byte* s, const byte* a, const byte* b,
                             const byte* c);
WOLFSSL_LOCAL void ge_tobytes(unsigned char *s,const ge_p2 *h);
#ifndef GE_P3_TOBYTES_IMPL
#define ge_p3_tobytes(s, h) ge_tobytes((s), (const ge_p2 *)(h))
#else
WOLFSSL_LOCAL void ge_p3_tobytes(unsigned char *s,const ge_p3 *h);
#endif


#ifndef ED25519_SMALL
typedef struct {
  ge X;
  ge Y;
  ge Z;
  ge T;
} ge_p1p1;

typedef struct {
  ge yplusx;
  ge yminusx;
  ge xy2d;
} ge_precomp;

typedef struct {
  ge YplusX;
  ge YminusX;
  ge Z;
  ge T2d;
} ge_cached;

#ifdef CURVED25519_ASM
void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p);
#define ge_p3_dbl(r, p)     ge_p2_dbl((ge_p1p1 *)(r), (ge_p2 *)(p))
void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q);
void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
#endif
#endif /* !ED25519_SMALL */

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_ED25519 */

#endif /* WOLF_CRYPT_GE_OPERATIONS_H */
