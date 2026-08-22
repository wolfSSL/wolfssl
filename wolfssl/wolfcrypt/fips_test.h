/* fips_test.h
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



#ifndef WOLF_CRYPT_FIPS_TEST_H
#define WOLF_CRYPT_FIPS_TEST_H

#include <wolfssl/wolfcrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif

/* Added for FIPS v7.0.0 or later */
#if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(7,0)
    /* The v7 integrity test is HMAC-SHA-512 keyed with a full SHA-512
     * block-size (128-byte) key, so the key is used as-is rather than being
     * hashed down by HMAC. This makes FIPS_CAST_HMAC_SHA2_512 boot-critical;
     * it was FIPS_CAST_HMAC_SHA2_256 through v6.0.0. */
    #ifndef WOLFSSL_SHA512
        #error FIPS v7 in core integrity check requires SHA2-512
    #endif
    #define FIPS_IN_CORE_DIGEST_SIZE 64
    #define FIPS_IN_CORE_HASH_TYPE   WC_SHA512
    #define FIPS_IN_CORE_KEY_SZ      128
    #define FIPS_IN_CORE_VERIFY_SZ   FIPS_IN_CORE_KEY_SZ
/* Added for FIPS v5.3 or later */
#elif defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)
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
    FIPS_CAST_DH_PRIMITIVE_Z    = 10, /* RETIRED (v7+): classic DH left the
                                       * module boundary.  Kept for ABI; do
                                       * not reuse this id. */
    FIPS_CAST_ECDSA             = 11,
    FIPS_CAST_KDF_TLS12         = 12,
    FIPS_CAST_KDF_TLS13         = 13,
    FIPS_CAST_KDF_SSH           = 14,
    /* v6.0.0 + */
    FIPS_CAST_KDF_SRTP          = 15,
    FIPS_CAST_ED25519           = 16,
    FIPS_CAST_ED448             = 17,
    FIPS_CAST_PBKDF2            = 18,
    /* v7.0.0 + */
    FIPS_CAST_AES_ECB           = 19,
    FIPS_CAST_ML_KEM            = 20,
    FIPS_CAST_ML_DSA            = 21,
    FIPS_CAST_LMS               = 22,
    FIPS_CAST_XMSS              = 23,
    FIPS_CAST_DRBG_SHA512       = 24,
    FIPS_CAST_SLH_DSA           = 25,
    /* Retired vendor-elected CASTs (v7 lab-prep).  The dedicated AES-CMAC,
     * SHAKE and AES-KW CASTs were removed because FIPS 140-3 IG 10.3.A covers
     * them via the more-complex tier: AES-CMAC and AES-KW by the AES-GCM CAST
     * (1.d items (i) and (ii)), and SHAKE by the HMAC-SHA3-256 CAST (item 3 +
     * Note 2, shared Keccak-p).  AES-KW *unwrap* additionally gates on the
     * AES-CBC CAST, because 1.c requires the inverse cipher to be self-tested
     * and AES-GCM exercises the forward direction only (see
     * wc_AesKeyUnWrap_fips in fips.c).  The ids are KEPT (do not reuse) so code
     * that still references them compiles, and the *services* re-gate onto the
     * covering CAST.
     *
     * State these ids reach, verified by running the module rather than read
     * off this comment (an earlier revision claimed they "stay at INIT", which
     * is only half the story):
     *   - DoPOST() and wc_RunAllCast_fips() never touch them, so after a normal
     *     power-on they read FIPS_CAST_STATE_INIT.
     *   - DoCAST() DOES have a case for each (see fips_test.c) and stores a
     *     terminal FIPS_CAST_STATE_SUCCESS without running any KAT.  So an
     *     operator exercising the on-demand self-test service required by
     *     ISO/IEC 19790:2012 sec 7.10.3 -- wc_RunCast_fips(id) -- gets a 0
     *     return and leaves the slot reading SUCCESS.  The alternative,
     *     omitting the case, leaves the slot at PROCESSING forever while
     *     wc_RunCast_fips() still returns 0: the same false pass, less visible.
     *   - FIPS_CAST_DH_PRIMITIVE_Z (= 10) behaves identically on both counts.
     *   - FIPS_CAST_ECC_CDH (= 8) is a FIFTH id in the same position on the
     *     submitted build.  Its KAT needs HAVE_ECC_CDH_CAST, which no
     *     configure option defines, so the #else arm of its DoCAST() case
     *     stores a terminal SUCCESS with no KAT.  Unlike ids 10 and 26-28 it
     *     is not retired: a build that defines HAVE_ECC_CDH_CAST runs the KAT.
     * A status array holding SUCCESS for these five ids therefore does not mean
     * five extra KATs ran.  The arithmetic is 29 identifiers, 25 with a KAT,
     * 24 executed on the submitted build.  PL-R34 sec 10.5 (the note following
     * the wc_RunCast_fips() input list) and PL-R36 (the paragraph beginning
     * "The FipsCastId enum ... defines twenty-nine (29)") state the same
     * numbers and name all five ids; if you change this comment, check that
     * those two passages still agree with it. */
    FIPS_CAST_AES_CMAC          = 26,
    FIPS_CAST_SHAKE             = 27,
    FIPS_CAST_AES_KW            = 28,
    FIPS_CAST_COUNT             = 29
};
#define WC_FIPS_ENUM_CAST_ID_DEFINED

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

#ifdef WOLFSSL_FIPS_DEV_NO_POST
    #define wc_RunAllCast_fips() 0
    static WC_INLINE int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf) {
        (void)cbf;
        return 0;
    }
    #define wolfCrypt_GetVersion_fips() "wolfCrypt DEV_NO_POST"
    #define wolfCrypt_GetStatus_fips() 0
    #define wolfCrypt_GetCoreHash_fips() ""
    #define wolfCrypt_IntegrityTest_fips() 0
    #define fipsEntry() WC_DO_NOTHING
#else /* !WOLFSSL_FIPS_DEV_NO_POST */

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

#endif /* !WOLFSSL_FIPS_DEV_NO_POST */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_FIPS_TEST_H */

