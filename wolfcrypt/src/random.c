/* random.c
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

/* on HPUX 11 you may need to install /dev/random see
   http://h20293.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=KRNG11I

*/

#ifdef HAVE_FIPS
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS
#endif

#include <wolfssl/wolfcrypt/random.h>
#include <cyassl/ctaocrypt/error-crypt.h>

#ifdef __cplusplus
    extern "C" {
#endif



int wc_GenerateSeed(OS_Seed* os, byte* seed, word32 sz)
{
    return GenerateSeed(os, seed, sz);
}

#ifdef HAVE_CAVIUM
    int  wc_InitRngCavium(RNG* rng, int i)
    {
        return InitRngCavium(rng, i);
    }
#endif


int  wc_InitRng(RNG* rng)
{
    return InitRng(rng);
}


int  wc_RNG_GenerateBlock(RNG* rng, byte* b, word32 sz)
{
    return RNG_GenerateBlock(rng, b, sz);
}


int  wc_RNG_GenerateByte(RNG* rng, byte* b)
{
    return RNG_GenerateByte(rng, b);
}

#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    int wc_FreeRng(RNG* rng)
    {
        return FreeRng(rng);
    }


    int wc_RNG_HealthTest(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz)
    {
        return RNG_HealthTest(reseed, entropyA, entropyASz,
                              entropyB, entropyBSz, output, outputSz);
    }
#endif /* HAVE_HASHDRBG || NO_RC4 */


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    int wc_InitRng_fips(RNG* rng)
    {
        return InitRng_fips(rng);
    }


    int wc_FreeRng_fips(RNG* rng)
    {
        return FreeRng_fips(rng);
    }


    int wc_RNG_GenerateBlock_fips(RNG* rng, byte* buf, word32 bufSz)
    {
        return RNG_GenerateBlock_fips(rng, buf, bufSz);
    }

    int wc_RNG_HealthTest_fips(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz)
    {
        return RNG_HealthTest_fips(reseed, entropyA, entropyASz,
                                   entropyB, entropyBSz, output, outputSz);
    }
    #ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define InitRng              InitRng_fips
        #define FreeRng              FreeRng_fips
        #define RNG_GenerateBlock    RNG_GenerateBlock_fips
        #define RNG_HealthTest       RNG_HealthTest_fips
    #endif /* FIPS_NO_WRAPPERS */
#endif /* HAVE_FIPS */


#ifdef __cplusplus
    } /* extern "C" */
#endif

