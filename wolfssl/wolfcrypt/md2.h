/* md2.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/md2.h
*/


#ifndef WOLF_CRYPT_MD2_H
#define WOLF_CRYPT_MD2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_MD2

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    WC_MD2_BLOCK_SIZE  = 16,
    WC_MD2_DIGEST_SIZE = 16,
    WC_MD2_PAD_SIZE    = 16,
    WC_MD2_X_SIZE      = 48
};


/* Md2 digest */
typedef struct wc_Md2 {
    word32  count;   /* bytes % PAD_SIZE  */
    byte    X[WC_MD2_X_SIZE];
    byte    C[WC_MD2_BLOCK_SIZE];
    byte    buffer[WC_MD2_BLOCK_SIZE];
} wc_Md2;


WOLFSSL_API void wc_InitMd2(wc_Md2* md2);
WOLFSSL_API void wc_Md2Update(wc_Md2* md2, const byte* data, word32 len);
WOLFSSL_API void wc_Md2Final(wc_Md2* md2, byte* hash);
WOLFSSL_API int  wc_Md2Hash(const byte* data, word32 len, byte* hash);

#ifndef OPENSSL_COEXIST

enum {
    MD2             = WC_HASH_TYPE_MD2,
    MD2_BLOCK_SIZE  = WC_MD2_BLOCK_SIZE,
    MD2_DIGEST_SIZE = WC_MD2_DIGEST_SIZE,
    MD2_PAD_SIZE    = WC_MD2_PAD_SIZE,
    MD2_X_SIZE      = WC_MD2_X_SIZE
};


/* Md2 digest */
typedef struct wc_Md2 Md2;

#endif /* !OPENSSL_COEXIST */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_MD2 */
#endif /* WOLF_CRYPT_MD2_H */

