/* hmac.h
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

#ifndef NO_HMAC

#ifdef __cplusplus
    extern "C" {
#endif


/* does init */
int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 keySz)
{
    return HmacSetKey(hmac, type, key, keySz);
}


int wc_HmacUpdate(Hmac* hmac, const byte* in, word32 sz)
{
    return HmacUpdate(hmac, in, sz);
}


int wc_HmacFinal(Hmac* hmac, byte* out)
{
    return HmacFinal(hmac, out);
}


#ifdef HAVE_CAVIUM
    int  wc_HmacInitCavium(Hmac* hmac, int i)
    {
        return HmacInitCavium(hmac, i);
    }


    void wc_HmacFreeCavium(Hmac* hmac)
    {
        HmacFreeCavium(hmac);
    }
#endif

int wc_wolfSSL_GetHmacMaxSize(void)
{
    return CyaSSL_GetHmacMaxSize(void);
}

#ifdef HAVE_HKDF

int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz)
{
    return HKDF(type, inKey, inKeySz, salt, saltSz, info, infoSz, out, outSz);
}


#endif /* HAVE_HKDF */


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
int wc_HmacSetKey_fips(Hmac* hmac, int type, const byte* key,
                                   word32 keySz)
{
    return HmacSetKey_fips(hmac, type, key, keySz);
}

int wc_HmacUpdate_fips(Hmac* hmac, const byte* in , word32 sz)
{
    return HmacUpdate_fips(hmac, in, sz);
}


int wc_HmacFinal_fips(Hmac* hmac, byte* out)
{
    return HmacFinal_fips(hmac, out);
}
#ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define HmacSetKey HmacSetKey_fips
        #define HmacUpdate HmacUpdate_fips
        #define HmacFinal  HmacFinal_fips
    #endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_FIPS */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_HMAC */

