/* hmac.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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



/*  hmac.h defines mini hamc openssl compatibility layer 
 *
 */


#ifndef WOLFSSL_HMAC_H_
#define WOLFSSL_HMAC_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_hmac.h"
#endif

#include <wolfssl/wolfcrypt/compat-wolfssl.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFCRYPT_HMAC_CTX HMAC_CTX;

#define HMAC(a,b,c,d,e,f,g) wc_HMAC((a),(b),(c),(d),(e),(f),(g))

#define HMAC_Init    wc_HMAC_Init
#define HMAC_Update  wc_HMAC_Update
#define HMAC_Final   wc_HMAC_Final
#define HMAC_cleanup wc_HMAC_cleanup

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLFSSL_HMAC_H_ */
