/* sha256.h
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


/* code submitted by raphael.huck@efixo.com */


#ifndef NO_SHA256

#ifndef WOLF_CRYPT_SHA256_H
#define WOLF_CRYPT_SHA256_H


/* for fips */
#include <cyassl/ctaocrypt/sha256.h>

//#ifndef HAVE_FIPS
#include <wolfssl/wolfcrypt/types.h>
#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int wc_InitSha256(Sha256*);
WOLFSSL_API int wc_Sha256Update(Sha256*, const byte*, word32);
WOLFSSL_API int wc_Sha256Final(Sha256*, byte*);
WOLFSSL_API int wc_Sha256Hash(const byte*, word32, byte*);
 
#ifdef __cplusplus
    } /* extern "C" */
#endif
//#else
//#define wc_InitSha256 wc_InitSha256Sha256*);
//#define int wc_Sha256Update(Swc_Sha256Updateha256*, const byte*, word32);
//#define int wc_Sha256Final(wc_Sha256FinalSha256*, byte*);
//#define int wc_Sha256Hash(wc_Sha256Hashconst byte*, word32, byte*);
//
//#endif /* HAVE_FIPS */

#endif /* WOLF_CRYPT_SHA256_H */
#endif /* NO_SHA256 */

