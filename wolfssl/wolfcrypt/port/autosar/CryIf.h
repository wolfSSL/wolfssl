/* CryIf.h
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

#ifndef WOLFSSL_CRYIF_H
#define WOLFSSL_CRYIF_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* implementation specific structure, for now not used */
typedef struct CryIf_ConfigType {
    void* heap;
} CryIf_ConfigType;

WOLFSSL_LOCAL void CryIf_Init(const CryIf_ConfigType* in);
WOLFSSL_LOCAL void CryIf_GetVersionInfo(Std_VersionInfoType* ver);
WOLFSSL_LOCAL Std_ReturnType CryIf_ProcessJob(uint32 id, Crypto_JobType* job);
WOLFSSL_LOCAL Std_ReturnType CryIf_CancelJob(uint32 id, Crypto_JobType* job);
WOLFSSL_LOCAL Std_ReturnType CryIf_KeyElementSet(uint32 keyId, uint32 eId,
        const uint8* key, uint32 keySz);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_CRYIF_H */

