/* random.h
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


#ifndef WOLF_CRYPT_RANDOM_H
#define WOLF_CRYPT_RANDOM_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    #ifdef NO_SHA256
        #error "Hash DRBG requires SHA-256."
    #endif /* NO_SHA256 */

    #include <cyassl/ctaocrypt/sha256.h>
#else /* HAVE_HASHDRBG || NO_RC4 */
    #include <cyassl/ctaocrypt/arc4.h>
#endif /* HAVE_HASHDRBG || NO_RC4 */

/* for fips */
#include <cyassl/ctaocrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif


WOLFSSL_LOCAL
int wc_GenerateSeed(OS_Seed* os, byte* seed, word32 sz);

#if defined(HAVE_HASHDRBG) || defined(NO_RC4)

#ifdef HAVE_CAVIUM
    WOLFSSL_API int  wc_InitRngCavium(RNG*, int);
#endif

#endif /* HAVE_HASH_DRBG || NO_RC4 */


WOLFSSL_API int  wc_InitRng(RNG*);
WOLFSSL_API int  wc_RNG_GenerateBlock(RNG*, byte*, word32 sz);
WOLFSSL_API int  wc_RNG_GenerateByte(RNG*, byte*);


#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    WOLFSSL_API int wc_FreeRng(RNG*);
    WOLFSSL_API int wc_RNG_HealthTest(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz);
#endif /* HAVE_HASHDRBG || NO_RC4 */


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    WOLFSSL_API int wc_InitRng_fips(RNG* rng);
    WOLFSSL_API int wc_FreeRng_fips(RNG* rng);
    WOLFSSL_API int wc_RNG_GenerateBlock_fips(RNG* rng, byte* buf, word32 bufSz);
    WOLFSSL_API int wc_RNG_HealthTest_fips(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz);
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

#endif /* WOLF_CRYPT_RANDOM_H */

