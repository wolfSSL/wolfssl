/* sha3.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* sha3.h for openssl */


#ifndef WOLFSSL_SHA3_H_
#define WOLFSSL_SHA3_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_sha.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif



#ifndef WOLFSSL_NOSHA3_224

WOLFSSL_API int wolfSSL_SHA3_224_Init(WOLFSSL_SHA3_224_CTX*);
WOLFSSL_API int wolfSSL_SHA3_224_Update(WOLFSSL_SHA3_224_CTX*, const void*,
                                     unsigned long);
WOLFSSL_API int wolfSSL_SHA3_224_Final(unsigned char*, WOLFSSL_SHA3_224_CTX*);

#define SHA3_224_Init   wolfSSL_SHA3_224_Init
#define SHA3_224_Update wolfSSL_SHA3_224_Update
#define SHA3_224_Final  wolfSSL_SHA3_224_Final
#if defined(NO_OLD_WC_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    #define SHA3_224 wolfSSL_SHA3_224
#endif
#endif /* WOLFSSL_NOSHA3_224 */


#ifndef WOLFSSL_NOSHA3_256

WOLFSSL_API int wolfSSL_SHA3_256_Init(WOLFSSL_SHA3_256_CTX*);
WOLFSSL_API int wolfSSL_SHA3_256_Update(WOLFSSL_SHA3_256_CTX*, const void*,
                                     unsigned long);
WOLFSSL_API int wolfSSL_SHA3_256_Final(unsigned char*, WOLFSSL_SHA3_256_CTX*);

#define SHA3_256_Init   wolfSSL_SHA3_256_Init
#define SHA3_256_Update wolfSSL_SHA3_256_Update
#define SHA3_256_Final  wolfSSL_SHA3_256_Final
#if defined(NO_OLD_WC_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    #define SHA3_256 wolfSSL_SHA3_256
#endif
#endif /* WOLFSSL_NOSHA3_256 */


WOLFSSL_API int wolfSSL_SHA3_384_Init(WOLFSSL_SHA3_384_CTX*);
WOLFSSL_API int wolfSSL_SHA3_384_Update(WOLFSSL_SHA3_384_CTX*, const void*,
	                                 unsigned long);
WOLFSSL_API int wolfSSL_SHA3_384_Final(unsigned char*, WOLFSSL_SHA3_384_CTX*);


#define SHA3_384_Init   wolfSSL_SHA3_384_Init
#define SHA3_384_Update wolfSSL_SHA3_384_Update
#define SHA3_384_Final  wolfSSL_SHA3_384_Final
#if defined(NO_OLD_WC_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    #define SHA3_384 wolfSSL_SHA3_384
#endif


#ifndef WOLFSSL_NOSHA3_512
WOLFSSL_API int wolfSSL_SHA3_512_Init(WOLFSSL_SHA3_512_CTX*);
WOLFSSL_API int wolfSSL_SHA3_512_Update(WOLFSSL_SHA3_512_CTX*, const void*,
	                                 unsigned long);
WOLFSSL_API int wolfSSL_SHA3_512_Final(unsigned char*, WOLFSSL_SHA3_512_CTX*);

#define SHA3_512_Init   wolfSSL_SHA3_512_Init
#define SHA3_512_Update wolfSSL_SHA3_512_Update
#define SHA3_512_Final  wolfSSL_SHA3_512_Final
#if defined(NO_OLD_WC_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    #define SHA3_512 wolfSSL_SHA3_512
#endif
#endif /* WOLFSSL_NOSHA3_512 */




#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SHA3_H_ */

