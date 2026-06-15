/* hwpuf.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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


#ifndef WOLF_CRYPT_HWPUF_H
#define WOLF_CRYPT_HWPUF_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HWPUF

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_NXP_HWPUF
    #define HWPUF_ACTIVATION_CODE_SIZE 1192
    /* keyCode size is 52 for key sizes of 16, 24, or 32 */
    #define HWPUF_KEY_SIZE_TO_KEY_CODE_SIZE(keysz) 52
#else
    #error HWPUF: No valid port defined
#endif


/* flags stored in wc_HWPUF.flags */
enum wc_HwpufFlags {
    WC_HWPUF_FLAG_NONE     =    0,  /* Deinit() clears all flags */
    WC_HWPUF_FLAG_INITED   = 0x01,  /* Init() called successfully */
    WC_HWPUF_FLAG_ENROLLED = 0x02,  /* Enroll() called successfully */
    WC_HWPUF_FLAG_READY    = 0x04,  /* Start() called successfully */
    WOLF_ENUM_DUMMY_LAST_ELEMENT(WC_HWPUF_FLAG)
};

/* operation type passed to CryptoCb via wc_CryptoInfo.hwpuf.type */
enum wc_HwpufType {
    WC_HWPUF_TYPE_NONE = 0,
    WC_HWPUF_TYPE_INIT = 1,
    WC_HWPUF_TYPE_DEINIT = 2,
    WC_HWPUF_TYPE_ENROLL = 3,
    WC_HWPUF_TYPE_START = 4,
    WC_HWPUF_TYPE_GENERATE_KEY = 5,
    WC_HWPUF_TYPE_SET_KEY = 6,
    WC_HWPUF_TYPE_GET_KEY = 7,
    WC_HWPUF_TYPE_ZEROIZE = 8,
    WOLF_ENUM_DUMMY_LAST_ELEMENT(WC_HWPUF_TYPE)
};

typedef struct wc_HWPUF {
    word32 flags;
    int devId;
    void* heap;
} wc_HWPUF;

WOLFSSL_API int wc_HWPUF_Register(wc_HWPUF* hwpuf, void* heap, int devId);
WOLFSSL_API int wc_HWPUF_Unregister(wc_HWPUF* hwpuf);

WOLFSSL_API int wc_HWPUF_Init(wc_HWPUF* hwpuf);
WOLFSSL_API int wc_HWPUF_Deinit(wc_HWPUF* hwpuf);
WOLFSSL_API int wc_HWPUF_Enroll(wc_HWPUF* hwpuf,
                                byte* actCode, word32 actCodeSz);
WOLFSSL_API int wc_HWPUF_Start(wc_HWPUF* hwpuf,
                                byte* actCode, word32 actCodeSz);
WOLFSSL_API int wc_HWPUF_GenerateKey(wc_HWPUF* hwpuf,
                                byte keyIdx, word32 keySz,
                                byte* keyCode, word32 keyCodeSz);
WOLFSSL_API int wc_HWPUF_SetKey(wc_HWPUF* hwpuf, byte keyIdx,
                                byte* key, word32 keySz,
                                byte* keyCode, word32 keyCodeSz);
WOLFSSL_API int wc_HWPUF_GetKey(wc_HWPUF* hwpuf,
                                byte* keyCode, word32 keyCodeSz,
                                byte* key, word32 keySz);
WOLFSSL_API int wc_HWPUF_Zeroize(wc_HWPUF* hwpuf);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HWPUF */
#endif /* WOLF_CRYPT_HWPUF_H */
