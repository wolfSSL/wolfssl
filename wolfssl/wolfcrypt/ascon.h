/* ascon.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#ifndef WOLF_CRYPT_ASCON_H
#define WOLF_CRYPT_ASCON_H

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_HASH256_SZ                               32

#define ASCON_AEAD128_KEY_SZ                           16
#define ASCON_AEAD128_NONCE_SZ                         16
#define ASCON_AEAD128_TAG_SZ                           16

typedef union AsconState {
#ifdef WORD64_AVAILABLE
    word64 s64[5];
#endif
    word32 s32[10];
    word16 s16[20];
    byte    s8[40];
} AsconState;

typedef struct wc_AsconHash256 {
    AsconState state;
    byte lastBlkSz;
} wc_AsconHash256;

enum {
    ASCON_AEAD128_NOTSET  = 0,
    ASCON_AEAD128_ENCRYPT = 1,
    ASCON_AEAD128_DECRYPT = 2
};

typedef struct wc_AsconAEAD128 {
    /* needed throughout both encrypt and decrypt */
#ifdef WORD64_AVAILABLE
    word64 key[ASCON_AEAD128_KEY_SZ/sizeof(word64)];
#endif
    AsconState state;
    byte lastBlkSz;
    byte keySet:1;   /* has the key been processed */
    byte nonceSet:1; /* has the nonce been processed */
    byte adSet:1;    /* has the associated data been processed */
    byte op:2;       /* 0 for not set, 1 for encrypt, 2 for decrypt */
} wc_AsconAEAD128;

/* AsconHash API */

WOLFSSL_API wc_AsconHash256* wc_AsconHash256_New(void);
WOLFSSL_API void wc_AsconHash256_Free(wc_AsconHash256* a);
WOLFSSL_API int wc_AsconHash256_Init(wc_AsconHash256* a);
WOLFSSL_API void wc_AsconHash256_Clear(wc_AsconHash256* a);
WOLFSSL_API int wc_AsconHash256_Update(wc_AsconHash256* a, const byte* data,
                                       word32 dataSz);
WOLFSSL_API int wc_AsconHash256_Final(wc_AsconHash256* a, byte* hash);

WOLFSSL_API wc_AsconAEAD128* wc_AsconAEAD128_New(void);
WOLFSSL_API void wc_AsconAEAD128_Free(wc_AsconAEAD128* a);
WOLFSSL_API int wc_AsconAEAD128_Init(wc_AsconAEAD128* a);
WOLFSSL_API void wc_AsconAEAD128_Clear(wc_AsconAEAD128* a);

/* AsconAEAD API */

WOLFSSL_API int wc_AsconAEAD128_SetKey(wc_AsconAEAD128* a, const byte* key);
WOLFSSL_API int wc_AsconAEAD128_SetNonce(wc_AsconAEAD128* a, const byte* nonce);
WOLFSSL_API int wc_AsconAEAD128_SetAD(wc_AsconAEAD128* a, const byte* ad,
                                      word32 adSz);

WOLFSSL_API int wc_AsconAEAD128_EncryptUpdate(wc_AsconAEAD128* a, byte* out,
                                              const byte* in, word32 inSz);
WOLFSSL_API int wc_AsconAEAD128_EncryptFinal(wc_AsconAEAD128* a, byte* tag);

WOLFSSL_API int wc_AsconAEAD128_DecryptUpdate(wc_AsconAEAD128* a, byte* out,
                                              const byte* in, word32 inSz);
WOLFSSL_API int wc_AsconAEAD128_DecryptFinal(wc_AsconAEAD128* a,
                                             const byte* tag);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HAVE_ASCON */

#endif /* WOLF_CRYPT_ASCON_H */
