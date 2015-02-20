/* ecc25519.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_ECC25519

#include <wolfssl/wolfcrypt/ecc25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #include <wolfcrypt/src/misc.c>
#endif

#define MONTGOMERY_X_LE 65

const ecc25519_set_type ecc25519_sets[] = {
{
        32,
        "CURVE25519",
}
};


/* internal function */
static int curve25519(unsigned char* q, unsigned char* n, unsigned char* p)
{
  unsigned char e[32];
  unsigned int i;
  fe x1;
  fe x2;
  fe z2;
  fe x3;
  fe z3;
  fe tmp0;
  fe tmp1;
  int pos;
  unsigned int swap;
  unsigned int b;

  for (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  fe_frombytes(x1,p);
  fe_1(x2);
  fe_0(z2);
  fe_copy(x3,x1);
  fe_1(z3);

  swap = 0;
  for (pos = 254;pos >= 0;--pos) {
    b = e[pos / 8] >> (pos & 7);
    b &= 1;
    swap ^= b;
    fe_cswap(x2,x3,swap);
    fe_cswap(z2,z3,swap);
    swap = b;
#include <wolfssl/wolfcrypt/ecc25519_montgomery.h>
  }
  fe_cswap(x2,x3,swap);
  fe_cswap(z2,z3,swap);

  fe_invert(z2,z2);
  fe_mul(x2,x2,z2);
  fe_tobytes(q,x2);

  return 0;
}


int wc_ecc25519_make_key(RNG* rng, int keysize, ecc25519_key* key)
{
  unsigned char basepoint[ECC25519_KEYSIZE] = {9};
  unsigned char n[ECC25519_KEYSIZE];
  unsigned char p[ECC25519_KEYSIZE];
  int  i;
  int err;

  if (key == NULL || rng == NULL)
      return ECC_BAD_ARG_E;

  /* currently only a key size of 32 bytes is used */
  if (keysize != ECC25519_KEYSIZE)
      return ECC_BAD_ARG_E;

  /* get random number from RNG */
  err = wc_RNG_GenerateBlock(rng, n, keysize);
  if (err != 0)
      return err;

  for (i = 0; i < keysize; ++i) key->k.point[i] = n[i];
  key->k.point[ 0] &= 248;
  key->k.point[31] &= 127;
  key->k.point[31] |= 64;

  /*compute public key*/
  err = curve25519(p, key->k.point, basepoint);

  /* store keys in big endian format */
  for (i = 0; i < keysize; ++i) n[i] = key->k.point[i];
  for (i = 0; i < keysize; ++i) {
      key->p.point[keysize - i - 1] = p[i];
      key->k.point[keysize - i - 1] = n[i];
  }

  ForceZero(n, keysize);

  return err;
}


int wc_ecc25519_shared_secret(ecc25519_key* private_key, ecc25519_key* public_key,
        byte* out, word32* outlen)
{
    unsigned char k[ECC25519_KEYSIZE];
    unsigned char p[ECC25519_KEYSIZE];
    int err = 0;
    int i;

    /* sanity check */
    if (private_key == NULL || public_key == NULL || out == NULL ||
            outlen == NULL)
        return BAD_FUNC_ARG;

    if (private_key->k.point == NULL || public_key->p.point == NULL)
        return BAD_FUNC_ARG;

    /* avoid implementation fingerprinting */
    if (public_key->p.point[0] > 0x7F)
        return ECC_BAD_ARG_E;

    if (*outlen < ECC25519_KEYSIZE)
        return BUFFER_E;

    XMEMSET(p,   0, sizeof(p));
    XMEMSET(k,   0, sizeof(k));
    XMEMSET(out, 0, ECC25519_KEYSIZE);

    for (i = 0; i < ECC25519_KEYSIZE; ++i) {
        p[i] = public_key->p.point [ECC25519_KEYSIZE - i - 1];
        k[i] = private_key->k.point[ECC25519_KEYSIZE - i - 1];
    }

    err     = curve25519(out , k, p);
    *outlen = ECC25519_KEYSIZE;

    ForceZero(p, sizeof(p));
    ForceZero(k, sizeof(k));

    return err;
}



/* curve25519 uses a serialized string for key representation */
int wc_ecc25519_export_public(ecc25519_key* key, byte* out, word32* outLen)
{
    word32 keySz;
    byte   offset;

    if (key == NULL || out == NULL)
        return BAD_FUNC_ARG;

    /* check size of outgoing key */
    keySz  = wc_ecc25519_size(key);
    offset = 2;

    /* copy in public key and leave room for length and type byte */
    XMEMCPY(out + offset, key->p.point, keySz);
    *outLen = keySz + offset;

    /* length and type */
    out[0] = *outLen;
    out[1] = key->f;

    return 0;
}

/* import curve25519 public key
   return 0 on success */
int wc_ecc25519_import_public(const byte* in, word32 inLen, ecc25519_key* key)
{
    word32 keySz;
    byte   offset;

    /* sanity check */
    if (key == NULL || in == NULL)
        return ECC_BAD_ARG_E;

    /* check size of incoming keys */
    keySz  = wc_ecc25519_size(key);
    offset = 2;

    /* check that it is correct size plus length and type */
    if ((inLen != keySz + offset) || (in[1] != MONTGOMERY_X_LE))
        return ECC_BAD_ARG_E;

    XMEMCPY(key->p.point, in + offset, inLen);

    key->dp = &ecc25519_sets[0];

    return 0;
}


/* export curve25519 private key only raw, outLen is in/out size
   return 0 on success */
int wc_ecc25519_export_private_raw(ecc25519_key* key, byte* out, word32* outLen)
{
    word32 keySz;

    /* sanity check */
    if (key == NULL || out == NULL || outLen == NULL)
        return ECC_BAD_ARG_E;

    keySz = wc_ecc25519_size(key);

    if (*outLen < keySz) {
        *outLen = keySz;
        return BUFFER_E;
    }
    *outLen = keySz;
    XMEMSET(out, 0, *outLen);
    XMEMCPY(out, key->k.point, *outLen);

    return 0;
}


/* curve25519 private key import,public key in serialized format, private raw */
int wc_ecc25519_import_private_raw(const byte* priv, word32 privSz,
                               const byte* pub, word32 pubSz, ecc25519_key* key)
{
    int ret = 0;
    word32 keySz;

    /* sanity check */
    if (key == NULL || priv == NULL || pub ==NULL)
        return ECC_BAD_ARG_E;

    /* check size of incoming keys */
    keySz = wc_ecc25519_size(key);
    if (privSz != keySz || pubSz != keySz)
       return ECC_BAD_ARG_E;

    XMEMCPY(key->k.point, priv, privSz);
    XMEMCPY(key->p.point, pub, pubSz);

    return ret;
}


int wc_ecc25519_init(ecc25519_key* key)
{
    word32 keySz;

    if (key == NULL)
       return ECC_BAD_ARG_E;

    /* currently the format for curve25519 */
    key->f  = MONTGOMERY_X_LE;
    key->dp = &ecc25519_sets[0];
    keySz   = key->dp->size;

    XMEMSET(key->k.point, 0, keySz);
    XMEMSET(key->p.point, 0, keySz);

    return 0;
}


/**
  Clean the memory of a key
*/
void wc_ecc25519_free(ecc25519_key* key)
{
   if (key == NULL)
       return;

   key->dp = NULL;
   ForceZero(key->p.point, sizeof(key->p.point));
   ForceZero(key->k.point, sizeof(key->k.point));
}


/* key size */
int wc_ecc25519_size(ecc25519_key* key)
{
    if (key == NULL) return 0;

    return key->dp->size;
}

#endif /*HAVE_ECC25519*/

