/* stsafe.h
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

#ifndef _WOLFPORT_STSAFE_H_
#define _WOLFPORT_STSAFE_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLF_CRYPTO_CB
#include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if !defined(WOLFCRYPT_ONLY) && defined(HAVE_PK_CALLBACKS)
#include <wolfssl/ssl.h>
#endif

#ifdef WOLFSSL_STSAFE

/* -------------------------------------------------------------------------- */
/* External Interface Support (Backwards Compatibility)                       */
/* -------------------------------------------------------------------------- */

/* Define WOLFSSL_STSAFE_INTERFACE_EXTERNAL to use an external stsafe_
 * interface.h file that provides customer-specific implementations.
 * This maintains backwards compatibility with older integrations that
 * used a separate interface file.
 *
 * When NOT set (the default): All code is self-contained in stsafe.c using
 * the appropriate SDK (STSELib for A120, STSAFE-A1xx SDK for A100/A110).
 *
 * When defined: Include customer-provided stsafe_interface.h which must define:
 *   - stsafe_curve_id_t, stsafe_slot_t types
 *   - STSAFE_ECC_CURVE_P256, STSAFE_ECC_CURVE_P384 macros
 *   - STSAFE_KEY_SLOT_0, STSAFE_KEY_SLOT_1, STSAFE_KEY_SLOT_EPHEMERAL macros
 *   - STSAFE_A_OK return code macro
 *   - STSAFE_MAX_KEY_LEN, STSAFE_MAX_PUBKEY_RAW_LEN, STSAFE_MAX_SIG_LEN macros
 *   - Function prototypes for interface functions (see stsafe.c)
 */
#ifdef WOLFSSL_STSAFE_INTERFACE_EXTERNAL
    #include "stsafe_interface.h"
#else

/* -------------------------------------------------------------------------- */
/* STSAFE SDK Type Abstractions                                               */
/* -------------------------------------------------------------------------- */

#ifdef WOLFSSL_STSAFEA120
    /* STSAFE-A120 uses STSELib (open source BSD-3) */
    /* Note: stselib.h is included in stsafe.c to avoid warnings in headers */

    /* Type mappings for STSELib - using byte for curve ID to avoid
     * including full STSELib headers which have strict-prototype warnings */
    typedef byte                 stsafe_curve_id_t;
    typedef byte                 stsafe_slot_t;

    /* Curve ID mappings - values depend on stse_conf.h settings!
     * With only NIST P-256 and P-384 enabled:
     *   STSE_ECC_KT_NIST_P_256 = 0, STSE_ECC_KT_NIST_P_384 = 1
     * NOTE: If other curves are enabled, these values change! */
    #define STSAFE_ECC_CURVE_P256       0  /* STSE_ECC_KT_NIST_P_256 */
    #define STSAFE_ECC_CURVE_P384       1  /* STSE_ECC_KT_NIST_P_384 */
    /* Brainpool curves - only defined when enabled in stse_conf.h */
    /* #define STSAFE_ECC_CURVE_BP256   2 */  /* STSE_ECC_KT_BP_P_256 */
    /* #define STSAFE_ECC_CURVE_BP384   3 */  /* STSE_ECC_KT_BP_P_384 */

    /* Slot mappings */
    #define STSAFE_KEY_SLOT_0           0
    #define STSAFE_KEY_SLOT_1           1
    #define STSAFE_KEY_SLOT_EPHEMERAL   0xFF

    /* Return codes */
    #define STSAFE_A_OK                 0  /* STSE_OK */

    /* Key usage limits */
    #define STSAFE_PERSISTENT_KEY_USAGE_LIMIT  255  /* Usage limit for persistent keys in slot 1 */
    #define STSAFE_EPHEMERAL_KEY_USAGE_LIMIT   255  /* Usage limit for ephemeral keys in slot 0xFF */

    /* Hash types - must match stse_hash_algorithm_t values in STSELib */
    #define STSAFE_HASH_SHA256          0  /* STSE_SHA_256 */
    #define STSAFE_HASH_SHA384          1  /* STSE_SHA_384 */

#else /* WOLFSSL_STSAFEA100 */
    /* STSAFE-A100/A110 uses legacy ST STSAFE-A1xx SDK */
    /* User must provide path to STSAFE-A1xx SDK headers */
    #include <stsafe_a_types.h>

    /* Type mappings for legacy SDK */
    typedef StSafeA_CurveId       stsafe_curve_id_t;
    typedef StSafeA_KeySlotNumber stsafe_slot_t;

    /* Curve ID mappings */
    #define STSAFE_ECC_CURVE_P256       STSAFE_A_NIST_P_256
    #define STSAFE_ECC_CURVE_P384       STSAFE_A_NIST_P_384
    #define STSAFE_ECC_CURVE_BP256      STSAFE_A_BRAINPOOL_P_256
    #define STSAFE_ECC_CURVE_BP384      STSAFE_A_BRAINPOOL_P_384

    /* Slot mappings */
    #define STSAFE_KEY_SLOT_0           STSAFE_A_SLOT_0
    #define STSAFE_KEY_SLOT_1           STSAFE_A_SLOT_1
    #define STSAFE_KEY_SLOT_EPHEMERAL   STSAFE_A_SLOT_EPHEMERAL

    /* Return codes - STSAFE_A_OK already defined in SDK */

    /* Hash types */
    #define STSAFE_HASH_SHA256          STSAFE_A_SHA_256
    #define STSAFE_HASH_SHA384          STSAFE_A_SHA_384

#endif /* WOLFSSL_STSAFEA120 */

/* -------------------------------------------------------------------------- */
/* Common Definitions                                                         */
/* -------------------------------------------------------------------------- */

#ifndef STSAFE_MAX_KEY_LEN
    #define STSAFE_MAX_KEY_LEN          48  /* for up to 384-bit keys */
#endif
#ifndef STSAFE_MAX_PUBKEY_RAW_LEN
    #define STSAFE_MAX_PUBKEY_RAW_LEN   (STSAFE_MAX_KEY_LEN * 2) /* x/y */
#endif
#ifndef STSAFE_MAX_SIG_LEN
    #define STSAFE_MAX_SIG_LEN          (STSAFE_MAX_KEY_LEN * 2) /* r/s */
#endif

/* Default I2C address */
#ifndef STSAFE_I2C_ADDR
    #define STSAFE_I2C_ADDR             0x20
#endif

/* Default curve mode (for signing operations) */
#ifndef STSAFE_DEFAULT_CURVE
    #define STSAFE_DEFAULT_CURVE        STSAFE_ECC_CURVE_P256
#endif

#endif /* !WOLFSSL_STSAFE_INTERFACE_EXTERNAL */

/* -------------------------------------------------------------------------- */
/* Public API Functions                                                       */
/* -------------------------------------------------------------------------- */

/* Initialize STSAFE device - called automatically by wolfCrypt_Init() */
WOLFSSL_API int stsafe_interface_init(void);

/* Load device certificate from STSAFE secure storage */
WOLFSSL_API int SSL_STSAFE_LoadDeviceCertificate(byte** pRawCertificate,
    word32* pRawCertificateLen);

#if !defined(WOLFCRYPT_ONLY) && defined(HAVE_PK_CALLBACKS)
WOLFSSL_API int SSL_STSAFE_CreateKeyCb(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx);
WOLFSSL_API int SSL_STSAFE_VerifyPeerCertCb(WOLFSSL* ssl,
   const unsigned char* sig, unsigned int sigSz,
   const unsigned char* hash, unsigned int hashSz,
   const unsigned char* keyDer, unsigned int keySz,
   int* result, void* ctx);
WOLFSSL_API int SSL_STSAFE_SignCertificateCb(WOLFSSL* ssl,
    const byte* in, word32 inSz,
    byte* out, word32* outSz,
    const byte* key, word32 keySz, void* ctx);
WOLFSSL_API int SSL_STSAFE_SharedSecretCb(WOLFSSL* ssl,
    ecc_key* otherKey,
    unsigned char* pubKeyDer, unsigned int* pubKeySz,
    unsigned char* out, unsigned int* outlen,
    int side, void* ctx);

/* Helper API's for setting up callbacks */
WOLFSSL_API int SSL_STSAFE_SetupPkCallbacks(WOLFSSL_CTX* ctx);
WOLFSSL_API int SSL_STSAFE_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx);
#endif /* HAVE_PK_CALLBACKS */


#ifdef WOLF_CRYPTO_CB

/* Device ID that's unique and valid (not INVALID_DEVID -2) */
#define WOLF_STSAFE_DEVID 0x53545341; /* STSA */

typedef struct wolfSTSAFE_CryptoCb_Ctx {
#ifdef HAVE_ECC
    ecc_key wolfEccKey;
#endif
    int devId;
} wolfSTSAFE_CryptoCb_Ctx;

WOLFSSL_API int wolfSSL_STSAFE_CryptoDevCb(int devId, wc_CryptoInfo* info,
  void* ctx);

#endif /* WOLF_CRYPTO_CB */

#endif /* WOLFSSL_STSAFE */

#endif /* _WOLFPORT_STSAFE_H_ */
