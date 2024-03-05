/* Crypto.h
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

#ifndef WOLFSSL_CRYPTO_H
#define WOLFSSL_CRYPTO_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* key format */
enum {
    CRYPTO_KE_FORMAT_BIN_OCTET = 0x01,
    CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY = 0x05,
    CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY = 0x06
};

/* implementation specific structure, for now not used */
typedef struct Crypto_ConfigType {
    void* heap;
} Crypto_ConfigType;

WOLFSSL_LOCAL Std_ReturnType Crypto_KeyElementSet(uint32 keyId, uint32 eId,
        const uint8* key, uint32 keySz);
WOLFSSL_LOCAL void Crypto_Init(const Crypto_ConfigType* config);
WOLFSSL_LOCAL Std_ReturnType Crypto_ProcessJob(uint32 objectId,
        Crypto_JobType* job);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_CRYPTO_H */

