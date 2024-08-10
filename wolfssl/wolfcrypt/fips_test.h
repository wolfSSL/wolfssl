/* fips_test.h
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



#ifndef WOLF_CRYPT_FIPS_TEST_H
#define WOLF_CRYPT_FIPS_TEST_H

#include <wolfssl/wolfcrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif

/* Added for FIPS v5.3 or later */
#if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)
    /* Determine FIPS in core hash type and size */
    #ifndef NO_SHA256
        #define FIPS_IN_CORE_DIGEST_SIZE 32
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA256
        #define FIPS_IN_CORE_KEY_SZ      32
        #define FIPS_IN_CORE_VERIFY_SZ   FIPS_IN_CORE_KEY_SZ
    #elif defined(WOLFSSL_SHA384)
        #define FIPS_IN_CORE_DIGEST_SIZE 48
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA384
        #define FIPS_IN_CORE_KEY_SZ      48
        #define FIPS_IN_CORE_VERIFY_SZ   FIPS_IN_CORE_KEY_SZ
    #else
        #error No FIPS hash (SHA2-256 or SHA2-384)
    #endif
#endif /* FIPS v5.3 or later */


enum FipsCastId {
    /* v5.2.0 & v5.2.1 + */
    FIPS_CAST_AES_CBC           =  0,
    FIPS_CAST_AES_GCM           =  1,
    FIPS_CAST_HMAC_SHA1         =  2,
    FIPS_CAST_HMAC_SHA2_256     =  3,
    FIPS_CAST_HMAC_SHA2_512     =  4,
    FIPS_CAST_HMAC_SHA3_256     =  5,
    FIPS_CAST_DRBG              =  6,
    FIPS_CAST_RSA_SIGN_PKCS1v15 =  7,
    FIPS_CAST_ECC_CDH           =  8,
    FIPS_CAST_ECC_PRIMITIVE_Z   =  9,
    FIPS_CAST_DH_PRIMITIVE_Z    = 10,
    FIPS_CAST_ECDSA             = 11,
    FIPS_CAST_KDF_TLS12         = 12,
    FIPS_CAST_KDF_TLS13         = 13,
    FIPS_CAST_KDF_SSH           = 14,
    /* v6.0.0 + */
    FIPS_CAST_KDF_SRTP          = 15,
    FIPS_CAST_ED25519           = 16,
    FIPS_CAST_ED448             = 17,
    FIPS_CAST_PBKDF2            = 18,
    FIPS_CAST_COUNT             = 19
};

enum FipsCastStateId {
    FIPS_CAST_STATE_INIT        = 0,
    FIPS_CAST_STATE_PROCESSING  = 1,
    FIPS_CAST_STATE_SUCCESS     = 2,
    FIPS_CAST_STATE_FAILURE     = 3
};

enum FipsModeId {
    FIPS_MODE_INIT              = 0,
    FIPS_MODE_NORMAL            = 1,
    FIPS_MODE_DEGRADED          = 2,
    FIPS_MODE_FAILED            = 3
};

/* FIPS failure callback */
typedef void(*wolfCrypt_fips_cb)(int ok, int err, const char* hash);

/* Public set function */
WOLFSSL_API int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf);

/* Public get status functions */
WOLFSSL_API int wolfCrypt_GetStatus_fips(void);
WOLFSSL_API int wolfCrypt_GetMode_fips(void);
WOLFSSL_API const char* wolfCrypt_GetCoreHash_fips(void);
WOLFSSL_API const char* wolfCrypt_GetRawComputedHash_fips(void);

#ifdef HAVE_FORCE_FIPS_FAILURE
    /* Public function to force failure mode for operational testing */
    WOLFSSL_API int wolfCrypt_SetStatus_fips(int status);
#endif

WOLFSSL_LOCAL int DoPOST(char* base16_hash, int base16_hashSz);
WOLFSSL_LOCAL int DoCAST(int type);
WOLFSSL_LOCAL int DoKnownAnswerTests(char* base16_hash, int base16_hashSz); /* FIPSv1 and FIPSv2 */

WOLFSSL_API int wc_RunCast_fips(int type);
WOLFSSL_API int wc_GetCastStatus_fips(int type);
WOLFSSL_API int wc_RunAllCast_fips(void);

#ifdef NO_ATTRIBUTE_CONSTRUCTOR
    /* NOTE: Must be called in OS initialization section outside user control
     * and must prove during operational testing/code review with the lab that
     * this is outside user-control if called by the OS */
    void fipsEntry(void);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_FIPS_TEST_H */

