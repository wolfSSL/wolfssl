/* sha.h
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


#ifndef NO_SHA

#ifndef WOLF_CRYPT_SHA_H
#define WOLF_CRYPT_SHA_H


#include <wolfssl/wolfcrypt/types.h>

/* for fips */
#include <cyassl/ctaocrypt/sha.h>

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int wc_InitSha(Sha*);
WOLFSSL_API int wc_ShaUpdate(Sha*, const byte*, word32);
WOLFSSL_API int wc_ShaFinal(Sha*, byte*);
WOLFSSL_API int wc_ShaHash(const byte*, word32, byte*);


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    WOLFSSL_API int wc_InitSha_fips(Sha*);
    WOLFSSL_API int wc_ShaUpdate_fips(Sha*, const byte*, word32);
    WOLFSSL_API int wc_ShaFinal_fips(Sha*, byte*);
    #ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define wc_InitSha   wc_InitSha_fips
        #define wc_ShaUpdate wc_ShaUpdate_fips
        #define wc_ShaFinal  wc_ShaFinal_fips
    #endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_FIPS */

 
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_SHA_H */
#endif /* NO_SHA */

