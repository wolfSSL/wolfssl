/* vaultic.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* WISeKey/SealSQ VaultIC secure element port (PK callbacks) */

#ifndef WOLFPORT_SEALSQ_VAULTIC_H
#define WOLFPORT_SEALSQ_VAULTIC_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VAULTIC

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int WOLFSSL_VAULTIC_EccKeyGenCb(WOLFSSL* ssl, ecc_key* key,
    word32 keySz, int ecc_curve, void* ctx);

WOLFSSL_API int WOLFSSL_VAULTIC_EccVerifyCb(WOLFSSL* ssl,
   const unsigned char* sig, unsigned int sigSz,
   const unsigned char* hash, unsigned int hashSz,
   const unsigned char* keyDer, unsigned int keySz,
   int* result, void* ctx);

WOLFSSL_API int WOLFSSL_VAULTIC_EccSignCb(WOLFSSL* ssl,
    const byte* in, word32 inSz,
    byte* out, word32* outSz,
    const byte* key, word32 keySz, void* ctx);

WOLFSSL_API int WOLFSSL_VAULTIC_EccSharedSecretCb(WOLFSSL* ssl,
    ecc_key* otherKey,
    unsigned char* pubKeyDer, unsigned int* pubKeySz,
    unsigned char* out, unsigned int* outlen,
    int side, void* ctx);

WOLFSSL_API int WOLFSSL_VAULTIC_LoadCertificates(WOLFSSL_CTX* ctx);

/* Helper APIs for setting up callbacks */
WOLFSSL_API int WOLFSSL_VAULTIC_SetupPkCallbacks(WOLFSSL_CTX* ctx);
WOLFSSL_API int WOLFSSL_VAULTIC_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_VAULTIC */

#endif /* WOLFPORT_SEALSQ_VAULTIC_H */
