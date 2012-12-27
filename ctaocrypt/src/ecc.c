/* ecc.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <cyassl/ctaocrypt/settings.h>

#ifdef HAVE_ECC

#include <cyassl/ctaocrypt/ecc.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/error.h>


/* map

   ptmul -> mulmod

*/

#define ECC112
#define ECC128
#define ECC160
#define ECC192
#define ECC224
#define ECC256
#define ECC384
#define ECC521



/* This holds the key settings.  ***MUST*** be organized by size from
   smallest to largest. */

const ecc_set_type ecc_sets[] = {
#ifdef ECC112
{
        14,
        "SECP112R1",
        "DB7C2ABF62E35E668076BEAD208B",
        "659EF8BA043916EEDE8911702B22",
        "DB7C2ABF62E35E7628DFAC6561C5",
        "09487239995A5EE76B55F9C2F098",
        "A89CE5AF8724C0A23E0E0FF77500"
},
#endif
#ifdef ECC128
{
        16,
        "SECP128R1",
        "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF",
        "E87579C11079F43DD824993C2CEE5ED3",
        "FFFFFFFE0000000075A30D1B9038A115",
        "161FF7528B899B2D0C28607CA52C5B86",
        "CF5AC8395BAFEB13C02DA292DDED7A83",
},
#endif
#ifdef ECC160
{
        20,
        "SECP160R1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
        "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45",
        "0100000000000000000001F4C8F927AED3CA752257",
        "4A96B5688EF573284664698968C38BB913CBFC82",
        "23A628553168947D59DCC912042351377AC5FB32",
},
#endif
#ifdef ECC192
{
        24,
        "ECC-192",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
        "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
},
#endif
#ifdef ECC224
{
        28,
        "ECC-224",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
},
#endif
#ifdef ECC256
{
        32,
        "ECC-256",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
},
#endif
#ifdef ECC384
{
        48,
        "ECC-384",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
},
#endif
#ifdef ECC521
{
        66,
        "ECC-521",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
},
#endif
{
   0,
   NULL, NULL, NULL, NULL, NULL, NULL
}
};


ecc_point* ecc_new_point(void);
void ecc_del_point(ecc_point* p);
int  ecc_map(ecc_point*, mp_int*, mp_digit*);
int  ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                              mp_int* modulus, mp_digit* mp);
int  ecc_projective_dbl_point(ecc_point* P, ecc_point* R, mp_int* modulus,
                              mp_digit* mp);


/* helper for either lib */
static int get_digit_count(mp_int* a)
{
    if (a == NULL)
        return 0;

    return a->used;
}

/* helper for either lib */
static unsigned long get_digit(mp_int* a, int n)
{
    if (a == NULL)
        return 0;

    return (n >= a->used || n < 0) ? 0 : a->dp[n];
}


/**
   Add two ECC points
   P        The point to add
   Q        The point to add
   R        [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                             mp_int* modulus, mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   mp_int x;
   mp_int y;
   mp_int z;
   int    err;

   if (P == NULL || Q == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != MP_OKAY) {
      return err;
   }
   
   /* should we dbl instead? */
   err = mp_sub(modulus, &Q->y, &t1);

   if (err == MP_OKAY) {
       if ( (mp_cmp(&P->x, &Q->x) == MP_EQ) && 
            (get_digit_count(&Q->z) && mp_cmp(&P->z, &Q->z) == MP_EQ) &&
            (mp_cmp(&P->y, &Q->y) == MP_EQ || mp_cmp(&P->y, &t1) == MP_EQ)) {
                mp_clear(&t1);
                mp_clear(&t2);
                mp_clear(&x);
                mp_clear(&y);
                mp_clear(&z);

                return ecc_projective_dbl_point(P, R, modulus, mp);
       }
   }

   if (err == MP_OKAY)
       err = mp_copy(&P->x, &x);
   if (err == MP_OKAY)
       err = mp_copy(&P->y, &y);
   if (err == MP_OKAY)
       err = mp_copy(&P->z, &z);

   /* if Z is one then these are no-operations */
   if (err == MP_OKAY) {
       if (get_digit_count(&Q->z)) {
           /* T1 = Z' * Z' */
           err = mp_sqr(&Q->z, &t1);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&t1, modulus, *mp);

           /* X = X * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&t1, &x, &x);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&x, modulus, *mp);

           /* T1 = Z' * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&Q->z, &t1, &t1);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&t1, modulus, *mp);

           /* Y = Y * T1 */
           if (err == MP_OKAY)
               err = mp_mul(&t1, &y, &y);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&y, modulus, *mp);
       }
   }

   /* T1 = Z*Z */
   if (err == MP_OKAY)
       err = mp_sqr(&z, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* T2 = X' * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&Q->x, &t1, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = Z * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&z, &t1, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* T1 = Y' * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&Q->y, &t1, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* Y = Y - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&y, &t1, &y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&y, 0) == MP_LT)
           err = mp_add(&y, modulus, &y);
   }
   /* T1 = 2T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &t1, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T1 = Y + T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &y, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* X = X - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&x, &t2, &x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&x, 0) == MP_LT)
           err = mp_add(&x, modulus, &x);
   }
   /* T2 = 2T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &t2, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp(&t2, modulus) != MP_LT)
           err = mp_sub(&t2, modulus, &t2);
   }
   /* T2 = X + T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp(&t2, modulus) != MP_LT)
           err = mp_sub(&t2, modulus, &t2);
   }

   if (err == MP_OKAY) {
       if (get_digit_count(&Q->z)) {
           /* Z = Z * Z' */
           err = mp_mul(&z, &Q->z, &z);
           if (err == MP_OKAY)
               err = mp_montgomery_reduce(&z, modulus, *mp);
       }
   }

   /* Z = Z * X */
   if (err == MP_OKAY)
       err = mp_mul(&z, &x, &z);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&z, modulus, *mp);

   /* T1 = T1 * X  */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &x, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* X = X * X */
   if (err == MP_OKAY)
       err = mp_sqr(&x, &x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&x, modulus, *mp);
   
   /* T2 = T2 * x */
   if (err == MP_OKAY)
       err = mp_mul(&t2, &x, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = T1 * X  */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &x, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);
 
   /* X = Y*Y */
   if (err == MP_OKAY)
       err = mp_sqr(&y, &x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&x, modulus, *mp);

   /* X = X - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&x, &t2, &x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&x, 0) == MP_LT)
           err = mp_add(&x, modulus, &x);
   }
   /* T2 = T2 - X */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   } 
   /* T2 = T2 - X */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &x, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   }
   /* T2 = T2 * Y */
   if (err == MP_OKAY)
       err = mp_mul(&t2, &y, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* Y = T2 - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&t2, &t1, &y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&y, 0) == MP_LT)
           err = mp_add(&y, modulus, &y);
   }
   /* Y = Y/2 */
   if (err == MP_OKAY) {
       if (mp_isodd(&y))
           err = mp_add(&y, modulus, &y);
   }
   if (err == MP_OKAY)
       err = mp_div_2(&y, &y);

   if (err == MP_OKAY)
       err = mp_copy(&x, &R->x);
   if (err == MP_OKAY)
       err = mp_copy(&y, &R->y);
   if (err == MP_OKAY)
       err = mp_copy(&z, &R->z);

   /* clean up */
   mp_clear(&t1);
   mp_clear(&t2);
   mp_clear(&x);
   mp_clear(&y);
   mp_clear(&z);

   return err;
}


/**
   Double an ECC point
   P   The point to double
   R   [out] The destination of the double
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
   return   MP_OKAY on success
*/
int ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mp_int* modulus,
                             mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   int    err;

   if (P == NULL || R == NULL || modulus == NULL || mp == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL)) != MP_OKAY) {
      return err;
   }

   if (P != R) {
      err = mp_copy(&P->x, &R->x);
      if (err == MP_OKAY)
          err = mp_copy(&P->y, &R->y);
      if (err == MP_OKAY)
          err = mp_copy(&P->z, &R->z);
   }

   /* t1 = Z * Z */
   if (err == MP_OKAY)
       err = mp_sqr(&R->z, &t1);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t1, modulus, *mp);

   /* Z = Y * Z */
   if (err == MP_OKAY)
       err = mp_mul(&R->z, &R->y, &R->z);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->z, modulus, *mp);

   /* Z = 2Z */
   if (err == MP_OKAY)
       err = mp_add(&R->z, &R->z, &R->z);
   if (err == MP_OKAY) {
       if (mp_cmp(&R->z, modulus) != MP_LT)
           err = mp_sub(&R->z, modulus, &R->z);
   }

   /* T2 = X - T1 */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &t1, &t2);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&t2, 0) == MP_LT)
           err = mp_add(&t2, modulus, &t2);
   }
   /* T1 = X + T1 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &R->x, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T2 = T1 * T2 */
   if (err == MP_OKAY)
       err = mp_mul(&t1, &t2, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T1 = 2T2 */
   if (err == MP_OKAY)
       err = mp_add(&t2, &t2, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* T1 = T1 + T2 */
   if (err == MP_OKAY)
       err = mp_add(&t1, &t2, &t1);
   if (err == MP_OKAY) {
       if (mp_cmp(&t1, modulus) != MP_LT)
           err = mp_sub(&t1, modulus, &t1);
   }
   /* Y = 2Y */
   if (err == MP_OKAY)
       err = mp_add(&R->y, &R->y, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp(&R->y, modulus) != MP_LT)
           err = mp_sub(&R->y, modulus, &R->y);
   }
   /* Y = Y * Y */
   if (err == MP_OKAY)
       err = mp_sqr(&R->y, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);
   
   /* T2 = Y * Y */
   if (err == MP_OKAY)
       err = mp_sqr(&R->y, &t2);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&t2, modulus, *mp);

   /* T2 = T2/2 */
   if (err == MP_OKAY) {
       if (mp_isodd(&t2))
           err = mp_add(&t2, modulus, &t2);
   }
   if (err == MP_OKAY)
       err = mp_div_2(&t2, &t2);
   
   /* Y = Y * X */
   if (err == MP_OKAY)
       err = mp_mul(&R->y, &R->x, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);

   /* X  = T1 * T1 */
   if (err == MP_OKAY)
       err = mp_sqr(&t1, &R->x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->x, modulus, *mp);

   /* X = X - Y */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &R->y, &R->x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->x, 0) == MP_LT)
           err = mp_add(&R->x, modulus, &R->x);
   }
   /* X = X - Y */
   if (err == MP_OKAY)
       err = mp_sub(&R->x, &R->y, &R->x);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->x, 0) == MP_LT)
           err = mp_add(&R->x, modulus, &R->x);
   }
   /* Y = Y - X */     
   if (err == MP_OKAY)
       err = mp_sub(&R->y, &R->x, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->y, 0) == MP_LT)
           err = mp_add(&R->y, modulus, &R->y);
   }
   /* Y = Y * T1 */
   if (err == MP_OKAY)
       err = mp_mul(&R->y, &t1, &R->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&R->y, modulus, *mp);

   /* Y = Y - T2 */
   if (err == MP_OKAY)
       err = mp_sub(&R->y, &t2, &R->y);
   if (err == MP_OKAY) {
       if (mp_cmp_d(&R->y, 0) == MP_LT)
           err = mp_add(&R->y, modulus, &R->y);
   }

   /* clean up */ 
   mp_clear(&t1);
   mp_clear(&t2);

   return err;
}


/**
  Map a projective jacbobian point back to affine space
  P        [in/out] The point to map
  modulus  The modulus of the field the ECC curve is in
  mp       The "b" value from montgomery_setup()
  return   MP_OKAY on success
*/
int ecc_map(ecc_point* P, mp_int* modulus, mp_digit* mp)
{
   mp_int t1;
   mp_int t2;
   int    err;

   if (P == NULL || mp == NULL || modulus == NULL)
       return ECC_BAD_ARG_E;

   if ((err = mp_init_multi(&t1, &t2, NULL, NULL, NULL, NULL)) != MP_OKAY) {
      return MEMORY_E;
   }

   /* first map z back to normal */
   err = mp_montgomery_reduce(&P->z, modulus, *mp);

   /* get 1/z */
   if (err == MP_OKAY)
       err = mp_invmod(&P->z, modulus, &t1);
 
   /* get 1/z^2 and 1/z^3 */
   if (err == MP_OKAY)
       err = mp_sqr(&t1, &t2);
   if (err == MP_OKAY)
       err = mp_mod(&t2, modulus, &t2);
   if (err == MP_OKAY)
       err = mp_mul(&t1, &t2, &t1);
   if (err == MP_OKAY)
       err = mp_mod(&t1, modulus, &t1);

   /* multiply against x/y */
   if (err == MP_OKAY)
       err = mp_mul(&P->x, &t2, &P->x);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&P->x, modulus, *mp);
   if (err == MP_OKAY)
       err = mp_mul(&P->y, &t1, &P->y);
   if (err == MP_OKAY)
       err = mp_montgomery_reduce(&P->y, modulus, *mp);
   
   if (err == MP_OKAY)
       mp_set(&P->z, 1);

   /* clean up */
   mp_clear(&t1);
   mp_clear(&t2);

   return err;
}


#ifndef ECC_TIMING_RESISTANT

/* size of sliding window, don't change this! */
#define WINSIZE 4

/**
   Perform a point multiplication 
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
static int ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* modulus,
                      int map)
{
   ecc_point *tG, *M[8];
   int           i, j, err;
   mp_int        mu;
   mp_digit      mp;
   unsigned long buf;
   int           first, bitbuf, bitcpy, bitcnt, mode, digidx;

   if (k == NULL || G == NULL || R == NULL || modulus == NULL)
       return ECC_BAD_ARG_E;

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_init(&mu)) != MP_OKAY) {
      return err;
   }
   if ((err = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
      mp_clear(&mu);
      return err;
   }
  
  /* alloc ram for window temps */
  for (i = 0; i < 8; i++) {
      M[i] = ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ecc_del_point(M[j]);
         }
         mp_clear(&mu);
         return MEMORY_E;
      }
  }

   /* make a copy of G incase R==G */
   tG = ecc_new_point();
   if (tG == NULL)
       err = MEMORY_E;

   /* tG = G  and convert to montgomery */
   if (err == MP_OKAY) {
       if (mp_cmp_d(&mu, 1) == MP_EQ) {
           err = mp_copy(&G->x, &tG->x);
           if (err == MP_OKAY)
               err = mp_copy(&G->y, &tG->y);
           if (err == MP_OKAY)
               err = mp_copy(&G->z, &tG->z);
       } else {
           err = mp_mulmod(&G->x, &mu, modulus, &tG->x);
           if (err == MP_OKAY)
               err = mp_mulmod(&G->y, &mu, modulus, &tG->y);
           if (err == MP_OKAY)
               err = mp_mulmod(&G->z, &mu, modulus, &tG->z);
       }
   }
   mp_clear(&mu);
   
   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(tG, M[0], modulus, &mp);
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(M[0], M[0], modulus, &mp);
   if (err == MP_OKAY)
       err = ecc_projective_dbl_point(M[0], M[0], modulus, &mp);

   /* now find (8+k)G for k=1..7 */
   if (err == MP_OKAY)
       for (j = 9; j < 16; j++) {
           err = ecc_projective_add_point(M[j-9], tG, M[j-8], modulus, &mp);
           if (err != MP_OKAY) break;
       }

   /* setup sliding window */
   if (err == MP_OKAY) {
       mode   = 0;
       bitcnt = 1;
       buf    = 0;
       digidx = get_digit_count(k) - 1;
       bitcpy = bitbuf = 0;
       first  = 1;

       /* perform ops */
       for (;;) {
           /* grab next digit as required */
           if (--bitcnt == 0) {
               if (digidx == -1) {
                   break;
               }
               buf    = get_digit(k, digidx);
               bitcnt = (int) DIGIT_BIT; 
               --digidx;
           }

           /* grab the next msb from the ltiplicand */
           i = (int)(buf >> (DIGIT_BIT - 1)) & 1;
           buf <<= 1;

           /* skip leading zero bits */
           if (mode == 0 && i == 0)
               continue;

           /* if the bit is zero and mode == 1 then we double */
           if (mode == 1 && i == 0) {
               err = ecc_projective_dbl_point(R, R, modulus, &mp);
               if (err != MP_OKAY) break;
               continue;
           }

           /* else we add it to the window */
           bitbuf |= (i << (WINSIZE - ++bitcpy));
           mode = 2;

           if (bitcpy == WINSIZE) {
               /* if this is the first window we do a simple copy */
               if (first == 1) {
                   /* R = kG [k = first window] */
                   err = mp_copy(&M[bitbuf-8]->x, &R->x);
                   if (err != MP_OKAY) break;

                   err = mp_copy(&M[bitbuf-8]->y, &R->y);
                   if (err != MP_OKAY) break;

                   err = mp_copy(&M[bitbuf-8]->z, &R->z);
                   first = 0;
               } else {
                   /* normal window */
                   /* ok window is filled so double as required and add  */
                   /* double first */
                   for (j = 0; j < WINSIZE; j++) {
                       err = ecc_projective_dbl_point(R, R, modulus, &mp);
                       if (err != MP_OKAY) break;
                   }
                   if (err != MP_OKAY) break;  /* out of first for(;;) */

                   /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranted */
                   err = ecc_projective_add_point(R,M[bitbuf-8],R,modulus,&mp);
               }
               if (err != MP_OKAY) break;
               /* empty window and reset */
               bitcpy = bitbuf = 0;
               mode = 1;
           }
       }
   }

   /* if bits remain then double/add */
   if (err == MP_OKAY) {
       if (mode == 2 && bitcpy > 0) {
           /* double then add */
           for (j = 0; j < bitcpy; j++) {
               /* only double if we have had at least one add first */
               if (first == 0) {
                   err = ecc_projective_dbl_point(R, R, modulus, &mp);
                   if (err != MP_OKAY) break;
               }

               bitbuf <<= 1;
               if ((bitbuf & (1 << WINSIZE)) != 0) {
                   if (first == 1) {
                       /* first add, so copy */
                       err = mp_copy(&tG->x, &R->x);
                       if (err != MP_OKAY) break;

                       err = mp_copy(&tG->y, &R->y);
                       if (err != MP_OKAY) break;

                       err = mp_copy(&tG->z, &R->z);
                       if (err != MP_OKAY) break;
                       first = 0;
                   } else {
                       /* then add */
                       err = ecc_projective_add_point(R, tG, R, modulus, &mp);
                       if (err != MP_OKAY) break;
                   }
               }
           }
       }
   }

   /* map R back from projective space */
   if (err == MP_OKAY && map)
       err = ecc_map(R, modulus, &mp);

   mp_clear(&mu);
   ecc_del_point(tG);
   for (i = 0; i < 8; i++) {
       ecc_del_point(M[i]);
   }
   return err;
}

#undef WINSIZE
#endif /* ECC_TIMING_RESISTANT */


/**
   Allocate a new ECC point
   return A newly allocated point or NULL on error 
*/
ecc_point* ecc_new_point(void)
{
   ecc_point* p;
   p = (ecc_point*)XMALLOC(sizeof(ecc_point), 0, DYNAMIC_TYPE_BIGINT);
   if (p == NULL) {
      return NULL;
   }
   XMEMSET(p, 0, sizeof(ecc_point));
   if (mp_init_multi(&p->x, &p->y, &p->z, NULL, NULL, NULL) != MP_OKAY) {
      XFREE(p, 0, DYNAMIC_TYPE_BIGINT);
      return NULL;
   }
   return p;
}

/** Free an ECC point from memory
  p   The point to free
*/
void ecc_del_point(ecc_point* p)
{
   /* prevents free'ing null arguments */
   if (p != NULL) {
      mp_clear(&p->x);
      mp_clear(&p->y);
      mp_clear(&p->z);
      XFREE(p, 0, DYNAMIC_TYPE_BIGINT);
   }
}


/** Returns whether an ECC idx is valid or not
  n      The idx number to check
  return 1 if valid, 0 if not
*/  
static int ecc_is_valid_idx(int n)
{
   int x;

   for (x = 0; ecc_sets[x].size != 0; x++)
       ;
   /* -1 is a valid index --- indicating that the domain params
      were supplied by the user */
   if ((n >= -1) && (n < x)) {
      return 1;
   }
   return 0;
}


/**
  Create an ECC shared secret between two keys
  private_key      The private ECC key
  public_key       The public key
  out              [out] Destination of the shared secret
                   Conforms to EC-DH from ANSI X9.63
  outlen           [in/out] The max size and resulting size of the shared secret
  return           MP_OKAY if successful
*/
int ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen)
{
   word32         x = 0;
   ecc_point*     result;
   mp_int         prime;
   int            err;

   if (private_key == NULL || public_key == NULL || out == NULL ||
                                                    outlen == NULL)
       return BAD_FUNC_ARG;

   /* type valid? */
   if (private_key->type != ECC_PRIVATEKEY) {
      return ECC_BAD_ARG_E;
   }

   if (ecc_is_valid_idx(private_key->idx) == 0 ||
       ecc_is_valid_idx(public_key->idx)  == 0)
      return ECC_BAD_ARG_E;

   if (XSTRNCMP(private_key->dp->name, public_key->dp->name, ECC_MAXNAME) != 0)
      return ECC_BAD_ARG_E;

   /* make new point */
   result = ecc_new_point();
   if (result == NULL) {
      return MEMORY_E;
   }

   if ((err = mp_init(&prime)) != MP_OKAY) {
      ecc_del_point(result);
      return err;
   }

   err = mp_read_radix(&prime, (char *)private_key->dp->prime, 16);

   if (err == MP_OKAY)
       err = ecc_mulmod(&private_key->k, &public_key->pubkey, result, &prime,1);

   if (err == MP_OKAY) {
       x = mp_unsigned_bin_size(&prime);
       if (*outlen < x)
          err = BUFFER_E;
   }

   if (err == MP_OKAY) {
       XMEMSET(out, 0, x);
       err = mp_to_unsigned_bin(&result->x,out + (x -
                                            mp_unsigned_bin_size(&result->x)));
       *outlen = x;
   }

   mp_clear(&prime);
   ecc_del_point(result);

   return err;
}


int ecc_make_key_ex(RNG* rng, ecc_key* key, const ecc_set_type* dp);

/**
  Make a new ECC key 
  rng          An active RNG state
  keysize      The keysize for the new key (in octets from 20 to 65 bytes)
  key          [out] Destination of the newly created key
  return       MP_OKAY if successful,
                       upon error all allocated memory will be freed
*/
int ecc_make_key(RNG* rng, int keysize, ecc_key* key)
{
   int x, err;

   /* find key size */
   for (x = 0; (keysize > ecc_sets[x].size) && (ecc_sets[x].size != 0); x++)
       ;
   keysize = ecc_sets[x].size;

   if (keysize > ECC_MAXSIZE || ecc_sets[x].size == 0) {
      return BAD_FUNC_ARG;
   }
   err = ecc_make_key_ex(rng, key, &ecc_sets[x]);
   key->idx = x;

   return err;
}

int ecc_make_key_ex(RNG* rng, ecc_key* key, const ecc_set_type* dp)
{
   int            err;
   ecc_point*     base;
   mp_int         prime;
   mp_int         order;
   byte           buf[ECC_MAXSIZE];
   int            keysize;

   if (key == NULL || rng == NULL || dp == NULL)
       return ECC_BAD_ARG_E;

   key->idx = -1;
   key->dp  = dp;
   keysize  = dp->size;

   /* allocate ram */
   base = NULL;

   /* make up random string */
   RNG_GenerateBlock(rng, buf, keysize);
   buf[0] |= 0x0c;

   /* setup the key variables */
   if ((err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z,
                            &key->k, &prime, &order)) != MP_OKAY)
       return MEMORY_E;

   base = ecc_new_point();
   if (base == NULL)
      err = MEMORY_E;

   /* read in the specs for this key */
   if (err == MP_OKAY) 
       err = mp_read_radix(&prime,   (char *)key->dp->prime, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&order,   (char *)key->dp->order, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&base->x, (char *)key->dp->Gx, 16);
   if (err == MP_OKAY) 
       err = mp_read_radix(&base->y, (char *)key->dp->Gy, 16);
   
   if (err == MP_OKAY) 
       mp_set(&base->z, 1);
   if (err == MP_OKAY) 
       err = mp_read_unsigned_bin(&key->k, (byte*)buf, keysize);

   /* the key should be smaller than the order of base point */
   if (err == MP_OKAY) { 
       if (mp_cmp(&key->k, &order) != MP_LT)
           err = mp_mod(&key->k, &order, &key->k);
   }
   /* make the public key */
   if (err == MP_OKAY)
       err = ecc_mulmod(&key->k, base, &key->pubkey, &prime, 1);
   if (err == MP_OKAY)
       key->type = ECC_PRIVATEKEY;

   if (err != MP_OKAY) {
       /* clean up */
       mp_clear(&key->pubkey.x);
       mp_clear(&key->pubkey.y);
       mp_clear(&key->pubkey.z);
       mp_clear(&key->k);
   }
   ecc_del_point(base);
   mp_clear(&prime);
   mp_clear(&order);
#ifdef ECC_CLEAN_STACK
   XMEMSET(buff, 0, ECC_MAXSIZE);
#endif
   return err;
}


/* Setup dynamic pointers is using normal math for proper freeing */
void ecc_init(ecc_key* key)
{
    (void)key;
#ifndef USE_FAST_MATH
    key->pubkey.x.dp = NULL;
    key->pubkey.y.dp = NULL;
    key->pubkey.z.dp = NULL;

    key->k.dp = NULL;
#endif
}


/**
  Sign a message digest
  in        The message digest to sign
  inlen     The length of the digest
  out       [out] The destination for the signature
  outlen    [in/out] The max size and resulting size of the signature
  key       A private ECC key
  return    MP_OKAY if successful
*/
int ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen, 
                  RNG* rng, ecc_key* key)
{
   mp_int        r;
   mp_int        s;
   mp_int        e;
   mp_int        p;
   int           err;

   if (in == NULL || out == NULL || outlen == NULL || key == NULL || rng ==NULL)
       return ECC_BAD_ARG_E;

   /* is this a private key? */
   if (key->type != ECC_PRIVATEKEY) {
      return ECC_BAD_ARG_E;
   }
   
   /* is the IDX valid ?  */
   if (ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   /* get the hash and load it as a bignum into 'e' */
   /* init the bignums */
   if ((err = mp_init_multi(&r, &s, &p, &e, NULL, NULL)) != MP_OKAY) { 
      return err;
   }
   err = mp_read_radix(&p, (char *)key->dp->order, 16);

   if (err == MP_OKAY) {
       int truncLen = (int)inlen;
       if (truncLen > ecc_size(key))
           truncLen = ecc_size(key);
       err = mp_read_unsigned_bin(&e, (byte*)in, truncLen);
   }

   /* make up a key and export the public copy */
   if (err == MP_OKAY) {
       ecc_key pubkey;
       ecc_init(&pubkey);
       for (;;) {
           err = ecc_make_key_ex(rng, &pubkey, key->dp);
           if (err != MP_OKAY) break;

           /* find r = x1 mod n */
           err = mp_mod(&pubkey.pubkey.x, &p, &r);
           if (err != MP_OKAY) break;

           if (mp_iszero(&r) == MP_YES)
               ecc_free(&pubkey);
           else { 
               /* find s = (e + xr)/k */
               err = mp_invmod(&pubkey.k, &p, &pubkey.k);
               if (err != MP_OKAY) break;

               err = mp_mulmod(&key->k, &r, &p, &s);   /* s = xr */
               if (err != MP_OKAY) break;
           
               err = mp_add(&e, &s, &s);               /* s = e +  xr */
               if (err != MP_OKAY) break;

               err = mp_mod(&s, &p, &s);               /* s = e +  xr */
               if (err != MP_OKAY) break;

               err = mp_mulmod(&s, &pubkey.k, &p, &s); /* s = (e + xr)/k */
               if (err != MP_OKAY) break;

               ecc_free(&pubkey);
               if (mp_iszero(&s) == MP_NO)
                   break;
            }
       }
       ecc_free(&pubkey);
   }

   /* store as SEQUENCE { r, s -- integer } */
   if (err == MP_OKAY)
       err = StoreECC_DSA_Sig(out, outlen, &r, &s);

   mp_clear(&r);
   mp_clear(&s);
   mp_clear(&p);
   mp_clear(&e);

   return err;
}


/**
  Free an ECC key from memory
  key   The key you wish to free
*/
void ecc_free(ecc_key* key)
{
   if (key == NULL)
       return;

   mp_clear(&key->pubkey.x);
   mp_clear(&key->pubkey.y);
   mp_clear(&key->pubkey.z);
   mp_clear(&key->k);
}


/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
   Verify an ECC signature
   sig         The signature to verify
   siglen      The length of the signature (octets)
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   stat        Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const byte* sig, word32 siglen, byte* hash, word32 hashlen, 
                    int* stat, ecc_key* key)
{
   ecc_point    *mG, *mQ;
   mp_int        r;
   mp_int        s;
   mp_int        v;
   mp_int        w;
   mp_int        u1;
   mp_int        u2;
   mp_int        e;
   mp_int        p;
   mp_int        m;
   mp_digit      mp;
   int           err;

   if (sig == NULL || hash == NULL || stat == NULL || key == NULL)
       return ECC_BAD_ARG_E; 

   /* default to invalid signature */
   *stat = 0;

   /* is the IDX valid ?  */
   if (ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   /* allocate ints */
   if ((err = mp_init_multi(&v, &w, &u1, &u2, &p, &e)) != MP_OKAY) {
      return MEMORY_E;
   }

   if ((err = mp_init(&m)) != MP_OKAY) {
      mp_clear(&v);
      mp_clear(&w);
      mp_clear(&u1);
      mp_clear(&u2);
      mp_clear(&p);
      mp_clear(&e);
      return MEMORY_E;
   }

   /* allocate points */
   mG = ecc_new_point();
   mQ = ecc_new_point();
   if (mQ  == NULL || mG == NULL)
      err = MEMORY_E;

   /* Note, DecodeECC_DSA_Sig() calls mp_init() on r and s.
    * If either of those don't allocate correctly, none of
    * the rest of this function will execute, and everything
    * gets cleaned up at the end. */
   XMEMSET(&r, 0, sizeof(r));
   XMEMSET(&s, 0, sizeof(s));
   if (err == MP_OKAY) 
       err = DecodeECC_DSA_Sig(sig, siglen, &r, &s);

   /* get the order */
   if (err == MP_OKAY)
       err = mp_read_radix(&p, (char *)key->dp->order, 16);

   /* get the modulus */
   if (err == MP_OKAY)
       err = mp_read_radix(&m, (char *)key->dp->prime, 16);

   /* check for zero */
   if (err == MP_OKAY) {
       if (mp_iszero(&r) || mp_iszero(&s) || mp_cmp(&r, &p) != MP_LT ||
                                             mp_cmp(&s, &p) != MP_LT)
           err = MP_ZERO_E; 
   }
   /* read hash */
   if (err == MP_OKAY) {
       int truncLen = (int)hashlen;
       if (truncLen > ecc_size(key))
           truncLen = ecc_size(key);
       err = mp_read_unsigned_bin(&e, (byte*)hash, truncLen);
   }

   /*  w  = s^-1 mod n */
   if (err == MP_OKAY)
       err = mp_invmod(&s, &p, &w);

   /* u1 = ew */
   if (err == MP_OKAY)
       err = mp_mulmod(&e, &w, &p, &u1);

   /* u2 = rw */
   if (err == MP_OKAY)
       err = mp_mulmod(&r, &w, &p, &u2);

   /* find mG and mQ */
   if (err == MP_OKAY)
       err = mp_read_radix(&mG->x, (char *)key->dp->Gx, 16);

   if (err == MP_OKAY)
       err = mp_read_radix(&mG->y, (char *)key->dp->Gy, 16);
   if (err == MP_OKAY)
       mp_set(&mG->z, 1);

   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.x, &mQ->x);
   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.y, &mQ->y);
   if (err == MP_OKAY)
       err = mp_copy(&key->pubkey.z, &mQ->z);

#ifndef ECC_SHAMIR
       /* compute u1*mG + u2*mQ = mG */
       if (err == MP_OKAY)
           err = ecc_mulmod(&u1, mG, mG, &m, 0);
       if (err == MP_OKAY)
           err = ecc_mulmod(&u2, mQ, mQ, &m, 0);
  
       /* find the montgomery mp */
       if (err == MP_OKAY)
           err = mp_montgomery_setup(&m, &mp);

       /* add them */
       if (err == MP_OKAY)
           err = ecc_projective_add_point(mQ, mG, mG, &m, &mp);
   
       /* reduce */
       if (err == MP_OKAY)
           err = ecc_map(mG, &m, &mp);
#else
       /* use Shamir's trick to compute u1*mG + u2*mQ using half the doubles */
       if (err == MP_OKAY)
           err = ecc_mul2add(mG, &u1, mQ, &u2, mG, &m);
#endif /* ECC_SHAMIR */ 

   /* v = X_x1 mod n */
   if (err == MP_OKAY)
       err = mp_mod(&mG->x, &p, &v);

   /* does v == r */
   if (err == MP_OKAY) {
       if (mp_cmp(&v, &r) == MP_EQ)
           *stat = 1;
   }

   ecc_del_point(mG);
   ecc_del_point(mQ);

   mp_clear(&r);
   mp_clear(&s);
   mp_clear(&v);
   mp_clear(&w);
   mp_clear(&u1);
   mp_clear(&u2);
   mp_clear(&p);
   mp_clear(&e);
   mp_clear(&m);

   return err;
}


/* export public ECC key in ANSI X9.63 format */
int ecc_export_x963(ecc_key* key, byte* out, word32* outLen)
{
   byte   buf[ECC_BUFSIZE];
   word32 numlen;

   if (key == NULL || out == NULL || outLen == NULL)
       return ECC_BAD_ARG_E;

   if (ecc_is_valid_idx(key->idx) == 0) {
      return ECC_BAD_ARG_E;
   }
   numlen = key->dp->size;

   if (*outLen < (1 + 2*numlen)) {
      *outLen = 1 + 2*numlen;
      return BUFFER_E;
   }

   /* store byte 0x04 */
   out[0] = 0x04;

   /* pad and store x */
   XMEMSET(buf, 0, sizeof(buf));
   mp_to_unsigned_bin(&key->pubkey.x,
                      buf + (numlen - mp_unsigned_bin_size(&key->pubkey.x)));
   XMEMCPY(out+1, buf, numlen);

   /* pad and store y */
   XMEMSET(buf, 0, sizeof(buf));
   mp_to_unsigned_bin(&key->pubkey.y,
                      buf + (numlen - mp_unsigned_bin_size(&key->pubkey.y)));
   XMEMCPY(out+1+numlen, buf, numlen);

   *outLen = 1 + 2*numlen;

   return 0;
}


/* import public ECC key in ANSI X9.63 format */
int ecc_import_x963(const byte* in, word32 inLen, ecc_key* key)
{
   int x, err;

   
   if (in == NULL || key == NULL)
       return ECC_BAD_ARG_E;

   /* must be odd */
   if ((inLen & 1) == 0) {
      return ECC_BAD_ARG_E;
   }

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                     NULL, NULL) != MP_OKAY) {
      return MEMORY_E;
   }
   err = MP_OKAY;

   /* check for 4, 6 or 7 */
   if (in[0] != 4 && in[0] != 6 && in[0] != 7) {
      err = ASN_PARSE_E;
   }

   /* read data */
   if (err == MP_OKAY) 
       err = mp_read_unsigned_bin(&key->pubkey.x, (byte*)in+1, (inLen-1)>>1);

   if (err == MP_OKAY) 
       err = mp_read_unsigned_bin(&key->pubkey.y, (byte*)in+1+((inLen-1)>>1),
                                  (inLen-1)>>1);
   
   if (err == MP_OKAY) 
       mp_set(&key->pubkey.z, 1);

   if (err == MP_OKAY) {
     /* determine the idx */
      for (x = 0; ecc_sets[x].size != 0; x++) {
         if ((unsigned)ecc_sets[x].size >= ((inLen-1)>>1)) {
            break;
         }
      }
      if (ecc_sets[x].size == 0) {
         err = ASN_PARSE_E;
      } else {
          /* set the idx */
          key->idx  = x;
          key->dp = &ecc_sets[x];
          key->type = ECC_PUBLICKEY;
      }
   }

   if (err != MP_OKAY) {
       mp_clear(&key->pubkey.x);
       mp_clear(&key->pubkey.y);
       mp_clear(&key->pubkey.z);
       mp_clear(&key->k);
   }

   return err;
}


/* ecc private key import, public key in ANSI X9.63 format, private raw */
int ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
                           word32 pubSz, ecc_key* key)
{
    int ret = ecc_import_x963(pub, pubSz, key);
    if (ret != 0)
        return ret;

    key->type = ECC_PRIVATEKEY;

    return mp_read_unsigned_bin(&key->k, priv, privSz);
}


/* key size in octets */
int ecc_size(ecc_key* key)
{
    if (key == NULL) return 0;

    return key->dp->size;
}


/* signature size in octets */
int ecc_sig_size(ecc_key* key)
{
    int sz = ecc_size(key);
    if (sz < 0)
        return sz;

    return sz * 2 + SIG_HEADER_SZ;
}

#endif /* HAVE_ECC */
