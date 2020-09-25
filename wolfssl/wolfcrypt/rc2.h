/* rc2.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_RC2_H
#define WOLF_CRYPT_RC2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WC_RC2

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    RC2_MAX_KEY_SIZE = 128, /* max effective key size, octets */
    RC2_BLOCK_SIZE   = 8
};

/* RC2 encryption and decryption */
typedef struct RC2 {
    word32 keylen;
    ALIGN16 word16 key[RC2_MAX_KEY_SIZE/2];
} RC2;

WOLFSSL_API int wc_Rc2SetKey(RC2*, const byte*, word32, word32);
WOLFSSL_API int wc_Rc2EcbEncrypt(RC2* rc2, byte* out,
                                 const byte* in, word32 sz);
WOLFSSL_API int wc_Rc2EcbDecrypt(RC2* rc2, byte* out,
                                 const byte* in, word32 sz);
WOLFSSL_API int wc_Rc2CbcEncrypt(RC2* rc2, byte* out,
                                 const byte* in, word32 sz);
WOLFSSL_API int wc_Rc2CbcDecrypt(RC2* rc2, byte* out,
                                 const byte* in, word32 sz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WC_RC2 */
#endif /* WOLF_CRYPT_RC2_H */
