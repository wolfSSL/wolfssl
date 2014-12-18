/* des3.h
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


#ifndef NO_DES3

#ifndef WOLF_CRYPT_DES3_H
#define WOLF_CRYPT_DES3_H


#include <wolfssl/wolfcrypt/types.h>

/* included for fips */
#include <cyassl/ctaocrypt/des3.h>

#ifdef __cplusplus
    extern "C" {
#endif


WOLFSSL_API int  wc_Des_SetKey(Des* des, const byte* key, const byte* iv, int dir);
WOLFSSL_API void wc_Des_SetIV(Des* des, const byte* iv);
WOLFSSL_API int  wc_Des_CbcEncrypt(Des* des, byte* out, const byte* in, word32 sz);
WOLFSSL_API int  wc_Des_CbcDecrypt(Des* des, byte* out, const byte* in, word32 sz);
WOLFSSL_API int  wc_Des_EcbEncrypt(Des* des, byte* out, const byte* in, word32 sz);
WOLFSSL_API int  wc_Des_CbcDecryptWithKey(byte* out, const byte* in, word32 sz,
                                               const byte* key, const byte* iv);

WOLFSSL_API int  wc_Des3_SetKey(Des3* des, const byte* key, const byte* iv,int dir);
WOLFSSL_API int  wc_Des3_SetIV(Des3* des, const byte* iv);
WOLFSSL_API int  wc_Des3_CbcEncrypt(Des3* des, byte* out, const byte* in,word32 sz);
WOLFSSL_API int  wc_Des3_CbcDecrypt(Des3* des, byte* out, const byte* in,word32 sz);
WOLFSSL_API int  wc_Des3_CbcDecryptWithKey(byte* out, const byte* in, word32 sz,
                                               const byte* key, const byte* iv);


#ifdef HAVE_CAVIUM
    WOLFSSL_API int  wc_Des3_InitCavium(Des3*, int);
    WOLFSSL_API void wc_Des3_FreeCavium(Des3*);
#endif


#ifdef HAVE_FIPS
    /* fips wrapper calls, user can call direct */
    WOLFSSL_API int  wc_Des3_SetKey_fips(Des3* des, const byte* key, const byte* iv,
                                     int dir);
    WOLFSSL_API int  wc_Des3_SetIV_fips(Des3* des, const byte* iv);
    WOLFSSL_API int  wc_Des3_CbcEncrypt_fips(Des3* des, byte* out, const byte* in,
                                         word32 sz);
    WOLFSSL_API int  wc_Des3_CbcDecrypt_fips(Des3* des, byte* out, const byte* in,
                                         word32 sz);
    #ifndef FIPS_NO_WRAPPERS
        /* if not impl or fips.c impl wrapper force fips calls if fips build */
        #define Des3_SetKey     Des3_SetKey_fips
        #define Des3_SetIV      Des3_SetIV_fips
        #define Des3_CbcEncrypt Des3_CbcEncrypt_fips
        #define Des3_CbcDecrypt Des3_CbcDecrypt_fips
    #endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_FIPS */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_DES3 */
#endif /* CTAO_CRYPT_DES3_H */

