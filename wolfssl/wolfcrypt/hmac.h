/* hmac.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifndef NO_HMAC

#ifndef WOLF_CRYPT_HMAC_H
#define WOLF_CRYPT_HMAC_H

/* for fips */
#include <cyassl/ctaocrypt/hmac.h>
#if defined(WOLFSSL_SHA512) && !defined(CYASSL_SHA512)
    #define CYASSL_SHA512
#endif


#ifdef HAVE_CAVIUM
    #include <wolfssl/wolfcrypt/logging.h>
    #include "cavium_common.h"
#endif


#ifdef __cplusplus
    extern "C" {
#endif

/* does init */
WOLFSSL_API int wc_HmacSetKey(Hmac*, int type, const byte* key, word32 keySz);
WOLFSSL_API int wc_HmacUpdate(Hmac*, const byte*, word32);
WOLFSSL_API int wc_HmacFinal(Hmac*, byte*);

#ifdef HAVE_CAVIUM
    WOLFSSL_API int  wc_HmacInitCavium(Hmac*, int);
    WOLFSSL_API void wc_HmacFreeCavium(Hmac*);
#endif

WOLFSSL_API int wc_WolfSSL_GetHmacMaxSize(void);


#ifdef HAVE_HKDF

WOLFSSL_API int wc_HKDF(int type, const byte* inKey, word32 inKeySz,
                    const byte* salt, word32 saltSz,
                    const byte* info, word32 infoSz,
                    byte* out, word32 outSz);

#endif /* HAVE_HKDF */


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    WOLFSSL_API int wc_HmacSetKey_fips(Hmac*, int type, const byte* key,
                                   word32 keySz);
    WOLFSSL_API int wc_HmacUpdate_fips(Hmac*, const byte*, word32);
    WOLFSSL_API int wc_HmacFinal_fips(Hmac*, byte*);
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

#endif /* WOLF_CRYPT_HMAC_H */

#endif /* NO_HMAC */

