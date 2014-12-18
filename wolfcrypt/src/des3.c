/* des3.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifndef NO_DES3

#ifdef HAVE_FIPS
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS
#endif

#include <wolfssl/wolfcrypt/des3.h>
#include <cyassl/ctaocrypt/error-crypt.h>
#include <cyassl/ctaocrypt/logging.h>

#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif


#ifdef HAVE_CAVIUM
    static int wc_Des3_CaviumSetKey(Des3* des3, const byte* key, const byte* iv);
    static int wc_Des3_CaviumCbcEncrypt(Des3* des3, byte* out, const byte* in,
                                      word32 length);
    static int wc_Des3_CaviumCbcDecrypt(Des3* des3, byte* out, const byte* in,
                                      word32 length);
#endif



int wc_Des_SetKey(Des* des, const byte* key, const byte* iv, int dir)
{
    return Des_SetKey(des, key, iv, dir);
}


int wc_Des3_SetKey(Des3* des, const byte* key, const byte* iv, int dir)
{
    return Des3_SetKey(des, key, iv, dir);
}


int wc_Des_CbcEncrypt(Des* des, byte* out, const byte* in, word32 sz)
{
    return Des_CbcEncrypt(des, out, in, sz);
}


int wc_Des_CbcDecrypt(Des* des, byte* out, const byte* in, word32 sz)
{
    return Des_CbcDecrypt(des, out, in, sz);
}


int wc_Des3_CbcEncrypt(Des3* des, byte* out, const byte* in, word32 sz)
{
    return Des3_CbcEncrypt(des, out, in, sz);
}


int wc_Des3_CbcDecrypt(Des3* des, byte* out, const byte* in, word32 sz)
{
    return Des3_CbcDecrypt(des, out, in, sz);
}


#ifdef CYASSL_DES_ECB

/* One block, compatibility only */
int wc_Des_EcbEncrypt(Des* des, byte* out, const byte* in, word32 sz)
{
    return Des_EcbEncrypt(des, out, in, sz);
}

#endif /* CYASSL_DES_ECB */


void wc_Des_SetIV(Des* des, const byte* iv)
{
    Des_SetIV(des, iv);
}


int wc_Des_CbcDecryptWithKey(byte* out, const byte* in, word32 sz,
                                                const byte* key, const byte* iv)
{
    return Des_CbcDecryptWithKey(out, in, sz, key, iv);
}


int wc_Des3_SetIV(Des3* des, const byte* iv)
{
    return Des3_SetIV(des, iv);
}


int wc_Des3_CbcDecryptWithKey(byte* out, const byte* in, word32 sz,
                                                const byte* key, const byte* iv)
{
    return Des3_CbcDecryptWithKey(out, in, sz, key, iv);
}


#ifdef HAVE_CAVIUM

/* Initiliaze Des3 for use with Nitrox device */
int wc_Des3_InitCavium(Des3* des3, int devId)
{
    return Des3_InitCavium(des3, devId);
}


/* Free Des3 from use with Nitrox device */
void wc_Des3_FreeCavium(Des3* des3)
{
    Des3_FreeCavium(des3);
}


#endif /* HAVE_CAVIUM */

#endif /* NO_DES3 */
