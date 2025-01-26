/* sha512.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if (defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)) && \
    (!defined(WOLFSSL_ARMASM) && !defined(WOLFSSL_ARMASM_NO_NEON)) && \
    !defined(WOLFSSL_PSOC6_CRYPTO) && !defined(WOLFSSL_RISCV_ASM)

/* determine if we are using Espressif SHA hardware acceleration */
#undef WOLFSSL_USE_ESP32_CRYPT_HASH_HW
#if defined(WOLFSSL_ESP32_CRYPT) && !defined(NO_WOLFSSL_ESP32_CRYPT_HASH)
    #include "sdkconfig.h"
    /* Define a single keyword for simplicity & readability.
     *
     * By default the HW acceleration is on for ESP32 Chipsets,
     * but individual components can be turned off. See user_settings.h
     */
    #define TAG "wc_sha_512"
    #define WOLFSSL_USE_ESP32_CRYPT_HASH_HW
#else
    #undef WOLFSSL_USE_ESP32_CRYPT_HASH_HW
#endif

#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

    #ifdef USE_WINDOWS_API
        #pragma code_seg(".fipsA$m")
        #pragma const_seg(".fipsB$m")
    #endif
#endif

#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef WOLFSSL_IMXRT1170_CAAM
    #include <wolfssl/wolfcrypt/port/caam/wolfcaam_fsl_nxp.h>
#endif

/* deprecated USE_SLOW_SHA2 (replaced with USE_SLOW_SHA512) */
#if defined(USE_SLOW_SHA2) && !defined(USE_SLOW_SHA512)
    #define USE_SLOW_SHA512
#endif

#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha512_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000015 };
    int wolfCrypt_FIPS_SHA512_sanity(void)
    {
        return 0;
    }
#endif


#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    #include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#endif

#if defined(MAX3266X_SHA)
    /* Already brought in by sha512.h */
    /* #include <wolfssl/wolfcrypt/port/maxim/max3266x.h> */
#endif

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP)
    #if defined(__GNUC__) && ((__GNUC__ < 4) || \
                              (__GNUC__ == 4 && __GNUC_MINOR__ <= 8))
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #endif
    #if defined(__clang__) && ((__clang_major__ < 3) || \
                               (__clang_major__ == 3 && __clang_minor__ <= 5))
        #define NO_AVX2_SUPPORT
    #elif defined(__clang__) && defined(NO_AVX2_SUPPORT)
        #undef NO_AVX2_SUPPORT
    #endif

    #define HAVE_INTEL_AVX1
    #ifndef NO_AVX2_SUPPORT
        #define HAVE_INTEL_AVX2
    #endif
#endif

#if defined(HAVE_INTEL_AVX1)
    /* #define DEBUG_XMM  */
#endif

#if defined(HAVE_INTEL_AVX2)
    #define HAVE_INTEL_RORX
    /* #define DEBUG_YMM  */
#endif

#if defined(HAVE_BYTEREVERSE64) && \
        !defined(HAVE_INTEL_AVX1) && !defined(HAVE_INTEL_AVX2)
    #define ByteReverseWords64(out, in, size) ByteReverseWords64_1(out, size)
    #define ByteReverseWords64_1(buf, size) \
        { unsigned int i ;\
            for(i=0; i< size/sizeof(word64); i++){\
                __asm__ volatile("bswapq %0":"+r"(buf[i])::) ;\
            }\
        }
#endif

#if defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_HASH) && \
    !defined(WOLFSSL_QNX_CAAM)
    /* functions defined in wolfcrypt/src/port/caam/caam_sha.c */

#elif defined(WOLFSSL_SILABS_SHA384)
    /* functions defined in wolfcrypt/src/port/silabs/silabs_hash.c */

#elif defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */

#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    int wc_InitSha512(wc_Sha512* sha512)
    {
        if (sha512 == NULL)
            return BAD_FUNC_ARG;
        return se050_hash_init(&sha512->se050Ctx, NULL);
    }
    int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
        (void)devId;
        return se050_hash_init(&sha512->se050Ctx, heap);
    }
    int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
    {
        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }
        if (data == NULL) {
            return BAD_FUNC_ARG;
        }

        return se050_hash_update(&sha512->se050Ctx, data, len);
    }
    int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
    {
        int ret = 0;
        int devId = INVALID_DEVID;
        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
    #ifdef WOLF_CRYPTO_CB
        devId = sha512->devId;
    #endif
        ret = se050_hash_final(&sha512->se050Ctx, hash, WC_SHA512_DIGEST_SIZE,
                               kAlgorithm_SSS_SHA512);
        return ret;
    }
    int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash)
    {
        int ret = 0;
        int devId = INVALID_DEVID;
        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
    #ifdef WOLF_CRYPTO_CB
        devId = sha512->devId;
    #endif
        ret = se050_hash_final(&sha512->se050Ctx, hash, WC_SHA512_DIGEST_SIZE,
                               kAlgorithm_SSS_SHA512);
        return ret;
    }
    void wc_Sha512Free(wc_Sha512* sha512)
    {
        se050_hash_free(&sha512->se050Ctx);
    }
#elif defined(STM32_HASH_SHA512)

    /* Supports CubeMX HAL or Standard Peripheral Library */

    int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        if (sha512 == NULL)
            return BAD_FUNC_ARG;

        (void)devId;
        (void)heap;

        XMEMSET(sha512, 0, sizeof(wc_Sha512));
        wc_Stm32_Hash_Init(&sha512->stmCtx);
        return 0;
    }

    int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
    {
        int ret = 0;

        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }
        if (data == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Update(&sha512->stmCtx,
                HASH_ALGOSELECTION_SHA512, data, len, WC_SHA512_BLOCK_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }
        return ret;
    }

    int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
    {
        int ret = 0;

        if (sha512 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Final(&sha512->stmCtx,
                HASH_ALGOSELECTION_SHA512, hash, WC_SHA512_DIGEST_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }

        (void)wc_InitSha512(sha512); /* reset state */

        return ret;
    }

#else

#ifdef WOLFSSL_SHA512

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
#ifdef WC_C_DYNAMIC_FALLBACK
    #define SHA512_SETTRANSFORM_ARGS int *sha_method
#else
    #define SHA512_SETTRANSFORM_ARGS void
#endif
static void Sha512_SetTransform(SHA512_SETTRANSFORM_ARGS);
#endif

static int InitSha512(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
    sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[4] = W64LIT(0x510e527fade682d1);
    sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[7] = W64LIT(0x5be0cd19137e2179);

    sha512->buffLen = 0;
    sha512->loLen   = 0;
    sha512->hiLen   = 0;

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
#ifdef WC_C_DYNAMIC_FALLBACK
    sha512->sha_method = 0;
    Sha512_SetTransform(&sha512->sha_method);
#else
    Sha512_SetTransform();
#endif
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)

    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed. */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    sha512->flags = 0;
#endif
    return 0;
}

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)

/**
 * Initialize given wc_Sha512 structure with value specific to sha512/224.
 * Note that sha512/224 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static int InitSha512_224(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x8c3d37c819544da2);
    sha512->digest[1] = W64LIT(0x73e1996689dcd4d6);
    sha512->digest[2] = W64LIT(0x1dfab7ae32ff9c82);
    sha512->digest[3] = W64LIT(0x679dd514582f9fcf);
    sha512->digest[4] = W64LIT(0x0f6d2b697bd44da8);
    sha512->digest[5] = W64LIT(0x77e36f7304c48942);
    sha512->digest[6] = W64LIT(0x3f9d85a86a1d36c8);
    sha512->digest[7] = W64LIT(0x1112e6ad91d692a1);

    sha512->buffLen = 0;
    sha512->loLen   = 0;
    sha512->hiLen   = 0;

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
#ifdef WC_C_DYNAMIC_FALLBACK
    sha512->sha_method = 0;
    Sha512_SetTransform(&sha512->sha_method);
#else
    Sha512_SetTransform();
#endif
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed.
    **
    ** Note for original ESP32, there's no HW for SHA512/224
    */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512_224);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    sha512->flags = 0;
#endif
    return 0;
}
#endif /* !WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
/**
 * Initialize given wc_Sha512 structure with value specific to sha512/256.
 * Note that sha512/256 has different initial hash value from sha512.
 * The initial hash value consists of eight 64bit words. They are given
 * in FIPS180-4.
 */
static int InitSha512_256(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x22312194fc2bf72c);
    sha512->digest[1] = W64LIT(0x9f555fa3c84c64c2);
    sha512->digest[2] = W64LIT(0x2393b86b6f53b151);
    sha512->digest[3] = W64LIT(0x963877195940eabd);
    sha512->digest[4] = W64LIT(0x96283ee2a88effe3);
    sha512->digest[5] = W64LIT(0xbe5e1e2553863992);
    sha512->digest[6] = W64LIT(0x2b0199fc2c85b8aa);
    sha512->digest[7] = W64LIT(0x0eb72ddc81c52ca2);

    sha512->buffLen = 0;
    sha512->loLen   = 0;
    sha512->hiLen   = 0;

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
#ifdef WC_C_DYNAMIC_FALLBACK
    sha512->sha_method = 0;
    Sha512_SetTransform(&sha512->sha_method);
#else
    Sha512_SetTransform();
#endif
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed.
    **
    ** Note for original ESP32, there's no HW for SHA512/2256.
    */
    esp_sha_init(&(sha512->ctx), WC_HASH_TYPE_SHA512_256);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    sha512->flags = 0;
#endif
    return 0;
}
#endif /* !WOLFSSL_NOSHA512_256 && !FIPS... */

#endif /* WOLFSSL_SHA512 */

/* Hardware Acceleration */
#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

    /*****
    Intel AVX1/AVX2 Macro Control Structure

    #if defined(HAVE_INTEL_SPEEDUP)
        #define HAVE_INTEL_AVX1
        #define HAVE_INTEL_AVX2
    #endif

    int InitSha512(wc_Sha512* sha512) {
         Save/Recover XMM, YMM
         ...

         Check Intel AVX cpuid flags
    }

    #if defined(HAVE_INTEL_AVX1)|| defined(HAVE_INTEL_AVX2)
      Transform_Sha512_AVX1(); # Function prototype
      Transform_Sha512_AVX2(); #
    #endif

      _Transform_Sha512() {     # Native Transform Function body

      }

      int Sha512Update() {
         Save/Recover XMM, YMM
         ...
      }

      int Sha512Final() {
         Save/Recover XMM, YMM
         ...
      }


    #if defined(HAVE_INTEL_AVX1)

       XMM Instructions/INLINE asm Definitions

    #endif

    #if defined(HAVE_INTEL_AVX2)

       YMM Instructions/INLINE asm Definitions

    #endif

    #if defined(HAVE_INTEL_AVX1)

      int Transform_Sha512_AVX1() {
          Stitched Message Sched/Round
      }

    #endif

    #if defined(HAVE_INTEL_AVX2)

      int Transform_Sha512_AVX2() {
          Stitched Message Sched/Round
      }
    #endif

    */


    /* Each platform needs to query info type 1 from cpuid to see if aesni is
     * supported. Also, let's setup a macro for proper linkage w/o ABI conflicts
     */

#ifdef __cplusplus
    extern "C" {
#endif

    #if defined(HAVE_INTEL_AVX1)
        extern int Transform_Sha512_AVX1(wc_Sha512 *sha512);
        extern int Transform_Sha512_AVX1_Len(wc_Sha512 *sha512, word32 len);
    #endif
    #if defined(HAVE_INTEL_AVX2)
        extern int Transform_Sha512_AVX2(wc_Sha512 *sha512);
        extern int Transform_Sha512_AVX2_Len(wc_Sha512 *sha512, word32 len);
        #if defined(HAVE_INTEL_RORX)
            extern int Transform_Sha512_AVX1_RORX(wc_Sha512 *sha512);
            extern int Transform_Sha512_AVX1_RORX_Len(wc_Sha512 *sha512,
                                                      word32 len);
            extern int Transform_Sha512_AVX2_RORX(wc_Sha512 *sha512);
            extern int Transform_Sha512_AVX2_RORX_Len(wc_Sha512 *sha512,
                                                      word32 len);
        #endif
    #endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

    static word32 intel_flags = 0;

#if defined(WC_C_DYNAMIC_FALLBACK) && !defined(WC_NO_INTERNAL_FUNCTION_POINTERS)
    #define WC_NO_INTERNAL_FUNCTION_POINTERS
#endif

    static int _Transform_Sha512(wc_Sha512 *sha512);

#ifdef WC_NO_INTERNAL_FUNCTION_POINTERS

    enum sha_methods { SHA512_UNSET = 0, SHA512_AVX1, SHA512_AVX2,
                       SHA512_AVX1_RORX, SHA512_AVX2_RORX, SHA512_C };

#ifndef WC_C_DYNAMIC_FALLBACK
    /* note that all write access to this static variable must be idempotent,
     * as arranged by Sha512_SetTransform(), else it will be susceptible to
     * data races.
     */
    static enum sha_methods sha_method = SHA512_UNSET;
#endif

    static void Sha512_SetTransform(SHA512_SETTRANSFORM_ARGS)
    {
    #ifdef WC_C_DYNAMIC_FALLBACK
        #define SHA_METHOD (*sha_method)
    #else
        #define SHA_METHOD sha_method
    #endif
        if (SHA_METHOD != SHA512_UNSET)
            return;

    #ifdef WC_C_DYNAMIC_FALLBACK
        if (! CAN_SAVE_VECTOR_REGISTERS()) {
            SHA_METHOD = SHA512_C;
            return;
        }
    #endif

        if (intel_flags == 0)
            intel_flags = cpuid_get_flags();

    #if defined(HAVE_INTEL_AVX2)
        if (IS_INTEL_AVX2(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                SHA_METHOD = SHA512_AVX2_RORX;
            }
            else
        #endif
            {
                SHA_METHOD = SHA512_AVX2;
            }
        }
        else
    #endif
    #if defined(HAVE_INTEL_AVX1)
        if (IS_INTEL_AVX1(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                SHA_METHOD = SHA512_AVX1_RORX;
            }
            else
        #endif
            {
                SHA_METHOD = SHA512_AVX1;
            }
        }
        else
    #endif
        {
            SHA_METHOD = SHA512_C;
        }
    #undef SHA_METHOD
    }

    static WC_INLINE int Transform_Sha512(wc_Sha512 *sha512) {
    #ifdef WC_C_DYNAMIC_FALLBACK
        #define SHA_METHOD (sha512->sha_method)
    #else
        #define SHA_METHOD sha_method
    #endif
        int ret;
        if (SHA_METHOD == SHA512_C)
            return _Transform_Sha512(sha512);
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        switch (SHA_METHOD) {
        case SHA512_AVX2:
            ret = Transform_Sha512_AVX2(sha512);
            break;
        case SHA512_AVX2_RORX:
            ret = Transform_Sha512_AVX2_RORX(sha512);
            break;
        case SHA512_AVX1:
            ret = Transform_Sha512_AVX1(sha512);
            break;
        case SHA512_AVX1_RORX:
            ret = Transform_Sha512_AVX1_RORX(sha512);
            break;
        case SHA512_C:
        case SHA512_UNSET:
        default:
            ret = _Transform_Sha512(sha512);
            break;
        }
        RESTORE_VECTOR_REGISTERS();
        return ret;
    #undef SHA_METHOD
    }

    static WC_INLINE int Transform_Sha512_Len(wc_Sha512 *sha512, word32 len) {
    #ifdef WC_C_DYNAMIC_FALLBACK
        #define SHA_METHOD (sha512->sha_method)
    #else
        #define SHA_METHOD sha_method
    #endif
        int ret;
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        switch (SHA_METHOD) {
        case SHA512_AVX2:
            ret = Transform_Sha512_AVX2_Len(sha512, len);
            break;
        case SHA512_AVX2_RORX:
            ret = Transform_Sha512_AVX2_RORX_Len(sha512, len);
            break;
        case SHA512_AVX1:
            ret = Transform_Sha512_AVX1_Len(sha512, len);
            break;
        case SHA512_AVX1_RORX:
            ret = Transform_Sha512_AVX1_RORX_Len(sha512, len);
            break;
        case SHA512_C:
        case SHA512_UNSET:
        default:
            ret = 0;
            break;
        }
        RESTORE_VECTOR_REGISTERS();
        return ret;
    #undef SHA_METHOD
    }

#else /* !WC_NO_INTERNAL_FUNCTION_POINTERS */

    static int (*Transform_Sha512_p)(wc_Sha512* sha512) = _Transform_Sha512;
    static int (*Transform_Sha512_Len_p)(wc_Sha512* sha512, word32 len) = NULL;
    static int transform_check = 0;
    static int Transform_Sha512_is_vectorized = 0;

    static WC_INLINE int Transform_Sha512(wc_Sha512 *sha512) {
        int ret;
    #ifdef WOLFSSL_LINUXKM
        if (Transform_Sha512_is_vectorized)
            SAVE_VECTOR_REGISTERS(return _svr_ret;);
    #endif
        ret = (*Transform_Sha512_p)(sha512);
    #ifdef WOLFSSL_LINUXKM
        if (Transform_Sha512_is_vectorized)
            RESTORE_VECTOR_REGISTERS();
    #endif
        return ret;
    }
    static WC_INLINE int Transform_Sha512_Len(wc_Sha512 *sha512, word32 len) {
        int ret;
    #ifdef WOLFSSL_LINUXKM
        if (Transform_Sha512_is_vectorized)
            SAVE_VECTOR_REGISTERS(return _svr_ret;);
    #endif
        ret = (*Transform_Sha512_Len_p)(sha512, len);
    #ifdef WOLFSSL_LINUXKM
        if (Transform_Sha512_is_vectorized)
            RESTORE_VECTOR_REGISTERS();
    #endif
        return ret;
    }

    static void Sha512_SetTransform(void)
    {
        if (transform_check)
            return;

        intel_flags = cpuid_get_flags();

    #if defined(HAVE_INTEL_AVX2)
        if (IS_INTEL_AVX2(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                Transform_Sha512_p = Transform_Sha512_AVX2_RORX;
                Transform_Sha512_Len_p = Transform_Sha512_AVX2_RORX_Len;
                Transform_Sha512_is_vectorized = 1;
            }
            else
        #endif
            {
                Transform_Sha512_p = Transform_Sha512_AVX2;
                Transform_Sha512_Len_p = Transform_Sha512_AVX2_Len;
                Transform_Sha512_is_vectorized = 1;
            }
        }
        else
    #endif
    #if defined(HAVE_INTEL_AVX1)
        if (IS_INTEL_AVX1(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                Transform_Sha512_p = Transform_Sha512_AVX1_RORX;
                Transform_Sha512_Len_p = Transform_Sha512_AVX1_RORX_Len;
                Transform_Sha512_is_vectorized = 1;
            }
            else
        #endif
            {
                Transform_Sha512_p = Transform_Sha512_AVX1;
                Transform_Sha512_Len_p = Transform_Sha512_AVX1_Len;
                Transform_Sha512_is_vectorized = 1;
            }
        }
        else
    #endif
        {
            Transform_Sha512_p = _Transform_Sha512;
            Transform_Sha512_Len_p = NULL;
            Transform_Sha512_is_vectorized = 0;
        }

        transform_check = 1;
    }

#endif /* !WC_NO_INTERNAL_FUNCTION_POINTERS */

#else
    #define Transform_Sha512(sha512) _Transform_Sha512(sha512)

#endif

#ifdef WOLFSSL_SHA512

static int InitSha512_Family(wc_Sha512* sha512, void* heap, int devId,
                             int (*initfp)(wc_Sha512*))
{
    int ret = 0;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }


    sha512->heap = heap;
#ifdef WOLFSSL_SMALL_STACK_CACHE
    sha512->W = NULL;
#endif
#ifdef WOLF_CRYPTO_CB
    sha512->devId = devId;
    sha512->devCtx = NULL;
#endif

    /* call the initialization function pointed to by initfp */
    ret = initfp(sha512);
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_HASH_KEEP
    sha512->msg  = NULL;
    sha512->len  = 0;
    sha512->used = 0;
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    ret = wolfAsync_DevCtxInit(&sha512->asyncDev,
                        WOLFSSL_ASYNC_MARKER_SHA512, sha512->heap, devId);
#else
    (void)devId;
#endif /* WOLFSSL_ASYNC_CRYPT */
#ifdef WOLFSSL_IMXRT1170_CAAM
     ret = wc_CAAM_HashInit(&sha512->hndl, &sha512->ctx, WC_HASH_TYPE_SHA512);
#endif
    return ret;
} /* InitSha512_Family */

int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
{
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    if (sha512->ctx.mode != ESP32_SHA_INIT) {
        ESP_LOGV(TAG, "Set ctx mode from prior value: "
                      "%d", sha512->ctx.mode);
    }
    /* We know this is a fresh, uninitialized item, so set to INIT */
    sha512->ctx.mode = ESP32_SHA_INIT;
#endif

#ifdef MAX3266X_SHA_CB
    if (wc_MXC_TPU_SHA_Init(&(sha512->mxcCtx)) != 0){
        return BAD_FUNC_ARG;
    }
#endif

    return InitSha512_Family(sha512, heap, devId, InitSha512);
}

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int wc_InitSha512_224_ex(wc_Sha512* sha512, void* heap, int devId)
{
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* No SHA512/224 HW support is available, set to SW. */
    sha512->ctx.mode = ESP32_SHA_SW; /* no SHA224 HW, so always SW */
#endif
    return InitSha512_Family(sha512, heap, devId, InitSha512_224);
}
#endif /* !WOLFSSL_NOSHA512_224 ... */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int wc_InitSha512_256_ex(wc_Sha512* sha512, void* heap, int devId)
{
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    /* No SHA512/256 HW support is available on ESP32, set to SW. */
    sha512->ctx.mode = ESP32_SHA_SW;
#endif
    return InitSha512_Family(sha512, heap, devId, InitSha512_256);
}
#endif /* !WOLFSSL_NOSHA512_256 ... */

#endif /* WOLFSSL_SHA512 */


static const word64 K512[80] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

#define blk0(i) (W[i] = sha512->buffer[i])

#define blk2(i) (\
               W[ (i)     & 15] += \
            s1(W[((i)-2)  & 15])+ \
               W[((i)-7)  & 15] + \
            s0(W[((i)-15) & 15])  \
        )

#define Ch(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))

#define a(i) T[(0-(i)) & 7]
#define b(i) T[(1-(i)) & 7]
#define c(i) T[(2-(i)) & 7]
#define d(i) T[(3-(i)) & 7]
#define e(i) T[(4-(i)) & 7]
#define f(i) T[(5-(i)) & 7]
#define g(i) T[(6-(i)) & 7]
#define h(i) T[(7-(i)) & 7]

#define S0(x) (rotrFixed64(x,28) ^ rotrFixed64(x,34) ^ rotrFixed64(x,39))
#define S1(x) (rotrFixed64(x,14) ^ rotrFixed64(x,18) ^ rotrFixed64(x,41))
#define s0(x) (rotrFixed64(x,1)  ^ rotrFixed64(x,8)  ^ ((x)>>7))
#define s1(x) (rotrFixed64(x,19) ^ rotrFixed64(x,61) ^ ((x)>>6))

#define R(i) \
    h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[(i)+j] + (j ? blk2(i) : blk0(i)); \
    d(i) += h(i); \
    h(i) += S0(a(i)) + Maj(a(i),b(i),c(i))

static int _Transform_Sha512(wc_Sha512* sha512)
{
    const word64* K = K512;
    word32 j;
    word64 T[8];

#ifdef WOLFSSL_SMALL_STACK_CACHE
    word64* W = sha512->W;
    if (W == NULL) {
        W = (word64*)XMALLOC(sizeof(word64) * 16, sha512->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (W == NULL)
            return MEMORY_E;
        sha512->W = W;
    }
#elif defined(WOLFSSL_SMALL_STACK)
    word64* W;
    W = (word64*) XMALLOC(sizeof(word64) * 16, sha512->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (W == NULL)
        return MEMORY_E;
#else
    word64 W[16];
#endif

    /* Copy digest to working vars */
    XMEMCPY(T, sha512->digest, sizeof(T));

#ifdef USE_SLOW_SHA512
    /* over twice as small, but 50% slower */
    /* 80 operations, not unrolled */
    for (j = 0; j < 80; j += 16) {
        int m;
        for (m = 0; m < 16; m++) { /* braces needed here for macros {} */
            R(m);
        }
    }
#else
    /* 80 operations, partially loop unrolled */
    for (j = 0; j < 80; j += 16) {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }
#endif /* USE_SLOW_SHA512 */

    /* Add the working vars back into digest */
    sha512->digest[0] += a(0);
    sha512->digest[1] += b(0);
    sha512->digest[2] += c(0);
    sha512->digest[3] += d(0);
    sha512->digest[4] += e(0);
    sha512->digest[5] += f(0);
    sha512->digest[6] += g(0);
    sha512->digest[7] += h(0);

    /* Wipe variables */
    ForceZero(W, sizeof(word64) * 16);
    ForceZero(T, sizeof(T));

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SMALL_STACK_CACHE)
    XFREE(W, sha512->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return 0;
}


static WC_INLINE void AddLength(wc_Sha512* sha512, word32 len)
{
    word64 tmp = sha512->loLen;
    if ( (sha512->loLen += len) < tmp)
        sha512->hiLen++;                       /* carry low to high */
}

static WC_INLINE int Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    int ret = 0;
    /* do block size increments */
    byte* local = (byte*)sha512->buffer;

    /* check that internal buffLen is valid */
    if (sha512->buffLen >= WC_SHA512_BLOCK_SIZE)
        return BUFFER_E;

    if (len == 0)
        return 0;

    AddLength(sha512, len);

    if (sha512->buffLen > 0) {
        word32 add = min(len, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        if (add > 0) {
            XMEMCPY(&local[sha512->buffLen], data, add);

            sha512->buffLen += add;
            data            += add;
            len             -= add;
        }

        if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
    #if defined(LITTLE_ENDIAN_ORDER)
        #if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
            (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
            #ifdef WC_C_DYNAMIC_FALLBACK
            if (sha512->sha_method == SHA512_C)
            #else
            if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
            #endif
        #endif
            {
        #if !defined(WOLFSSL_ESP32_CRYPT) || \
             defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
             defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
        #endif
            }
    #endif
    #if !defined(WOLFSSL_ESP32_CRYPT) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
            ret = Transform_Sha512(sha512);
    #else
            if (sha512->ctx.mode == ESP32_SHA_INIT) {
                esp_sha_try_hw_lock(&sha512->ctx);
            }
            if (sha512->ctx.mode == ESP32_SHA_SW) {
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
                ret = Transform_Sha512(sha512);
            }
            else {
                ret = esp_sha512_process(sha512);
            }
    #endif
            if (ret == 0)
                sha512->buffLen = 0;
            else
                len = 0;
        }
    }

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))

    #ifdef WC_C_DYNAMIC_FALLBACK
    if (sha512->sha_method != SHA512_C)
    #elif defined(WC_NO_INTERNAL_FUNCTION_POINTERS)
    if (sha_method != SHA512_C)
    #else
    if (Transform_Sha512_Len_p != NULL)
    #endif

    {
        word32 blocksLen = len & ~((word32)WC_SHA512_BLOCK_SIZE-1);

        if (blocksLen > 0) {
            sha512->data = data;
            /* Byte reversal performed in function if required. */
            Transform_Sha512_Len(sha512, blocksLen);
            data += blocksLen;
            len  -= blocksLen;
        }
    }
    else
#endif
#if !defined(LITTLE_ENDIAN_ORDER) || (defined(WOLFSSL_X86_64_BUILD) && \
        defined(USE_INTEL_SPEEDUP) && (defined(HAVE_INTEL_AVX1) || \
        defined(HAVE_INTEL_AVX2)))
    {
        while (len >= WC_SHA512_BLOCK_SIZE) {
            XMEMCPY(local, data, WC_SHA512_BLOCK_SIZE);

            data += WC_SHA512_BLOCK_SIZE;
            len  -= WC_SHA512_BLOCK_SIZE;

        #if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
            (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
            #ifdef WC_C_DYNAMIC_FALLBACK
            if (sha512->sha_method == SHA512_C)
            #else
            if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
            #endif
            {
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                          WC_SHA512_BLOCK_SIZE);
            }
        #endif
            /* Byte reversal performed in function if required. */
            ret = Transform_Sha512(sha512);
            if (ret != 0)
                break;
        }
    }
#else
    {
        while (len >= WC_SHA512_BLOCK_SIZE) {
            XMEMCPY(local, data, WC_SHA512_BLOCK_SIZE);

            data += WC_SHA512_BLOCK_SIZE;
            len  -= WC_SHA512_BLOCK_SIZE;
    #if !defined(WOLFSSL_ESP32_CRYPT) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
            ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                       WC_SHA512_BLOCK_SIZE);
    #endif
    #if !defined(WOLFSSL_ESP32_CRYPT) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
            ret = Transform_Sha512(sha512);
    #else
            if(sha512->ctx.mode == ESP32_SHA_INIT) {
                esp_sha_try_hw_lock(&sha512->ctx);
            }
            if (sha512->ctx.mode == ESP32_SHA_SW) {
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                          WC_SHA512_BLOCK_SIZE);
                ret = Transform_Sha512(sha512);
            }
            else {
                ret = esp_sha512_process(sha512);
            }
    #endif
            if (ret != 0)
                break;
        } /* while (len >= WC_SHA512_BLOCK_SIZE) */
    }
#endif

    if (ret == 0 && len > 0) {
        XMEMCPY(local, data, len);
        sha512->buffLen = len;
    }

    return ret;
}

#ifdef WOLFSSL_SHA512

int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha512->devId != INVALID_DEVID)
    #endif
    {
        int ret = wc_CryptoCb_Sha512Hash(sha512, data, len, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    if (sha512->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA512) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha512(&sha512->asyncDev, NULL, data, len);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    return Sha512Update(sha512, data, len);
}

#endif /* WOLFSSL_SHA512 */

#endif /* WOLFSSL_IMX6_CAAM || WOLFSSL_SILABS_SHA384 */


#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_RENESAS_RSIP) && \
   !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/renesas/renesas_fspsm_sha.c */
#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)

#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */
#elif defined(STM32_HASH_SHA512)
#else

static WC_INLINE int Sha512Final(wc_Sha512* sha512)
{
    int ret;
    byte* local;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha512->buffer;

    /* we'll add a 0x80 byte at the end,
    ** so make sure we have appropriate buffer length. */
    if (sha512->buffLen > WC_SHA512_BLOCK_SIZE - 1) {
        return BAD_STATE_E;
    } /* buffLen check */

    local[sha512->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha512->buffLen > WC_SHA512_PAD_SIZE) {
        if (sha512->buffLen < WC_SHA512_BLOCK_SIZE ) {
            XMEMSET(&local[sha512->buffLen], 0,
                WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        }

        sha512->buffLen += WC_SHA512_BLOCK_SIZE - sha512->buffLen;
#if defined(LITTLE_ENDIAN_ORDER)
    #if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
        (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
        #ifdef WC_C_DYNAMIC_FALLBACK
        if (sha512->sha_method == SHA512_C)
        #else
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
        #endif
    #endif
        {

       #if !defined(WOLFSSL_ESP32_CRYPT) || \
            defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
            defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
            ByteReverseWords64(sha512->buffer,sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
       #endif
        }

#endif /* LITTLE_ENDIAN_ORDER */
    #if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
       !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
        if (sha512->ctx.mode == ESP32_SHA_INIT) {
            esp_sha_try_hw_lock(&sha512->ctx);
        }
        if (sha512->ctx.mode == ESP32_SHA_SW) {
            ByteReverseWords64(sha512->buffer,sha512->buffer,
                                                         WC_SHA512_BLOCK_SIZE);
            ret = Transform_Sha512(sha512);
        }
        else {
            ret = esp_sha512_process(sha512);
        }
    #else
        ret = Transform_Sha512(sha512);
    #endif
        if (ret != 0)
            return ret;

        sha512->buffLen = 0;
    } /* (sha512->buffLen > WC_SHA512_PAD_SIZE) pad with zeros */

    XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_PAD_SIZE - sha512->buffLen);

    /* put lengths in bits */
    sha512->hiLen = (sha512->loLen >> (8 * sizeof(sha512->loLen) - 3)) +
                                                         (sha512->hiLen << 3);
    sha512->loLen = sha512->loLen << 3;

    /* store lengths */
#if defined(LITTLE_ENDIAN_ORDER)
    #if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
        (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
        #ifdef WC_C_DYNAMIC_FALLBACK
        if (sha512->sha_method == SHA512_C)
        #else
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
        #endif
    #endif
    #if !defined(WOLFSSL_ESP32_CRYPT) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
         defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
            ByteReverseWords64(sha512->buffer, sha512->buffer, WC_SHA512_PAD_SIZE);
    #endif
#endif
    /* ! length ordering dependent on digest endian type ! */

#if !defined(WOLFSSL_ESP32_CRYPT) || \
     defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
     defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;
#endif

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
    #ifdef WC_C_DYNAMIC_FALLBACK
    if (sha512->sha_method != SHA512_C)
    #else
    if (IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags))
    #endif
        ByteReverseWords64(&(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                           &(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                           WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE);
#endif

#if !defined(WOLFSSL_ESP32_CRYPT) || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH) || \
    defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    ret = Transform_Sha512(sha512);
#else
    if(sha512->ctx.mode == ESP32_SHA_INIT) {
        /* typically for tiny block: first = last */
        esp_sha_try_hw_lock(&sha512->ctx);
    }
    if (sha512->ctx.mode == ESP32_SHA_SW) {
        ByteReverseWords64(sha512->buffer,
                           sha512->buffer,
                           WC_SHA512_BLOCK_SIZE);
        sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
        sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;
        ret = Transform_Sha512(sha512);
    }
    else {
        ret = esp_sha512_digest_process(sha512, 1);
    }
#endif

    if (ret != 0)
        return ret;

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha512->digest, sha512->digest, WC_SHA512_DIGEST_SIZE);
    #endif


    return 0;
}

#endif /* WOLFSSL_KCAPI_HASH */

#ifdef WOLFSSL_SHA512

#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)

#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */
#elif defined(STM32_HASH_SHA512)
#else

static int Sha512FinalRaw(wc_Sha512* sha512, byte* hash, size_t digestSz)
{
    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWords64(sha512->digest, sha512->digest, WC_SHA512_DIGEST_SIZE);
#endif

    XMEMCPY(hash, sha512->digest, digestSz);

    return 0;
}

int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash)
{
    return Sha512FinalRaw(sha512, hash, WC_SHA512_DIGEST_SIZE);
}

static int Sha512_Family_Final(wc_Sha512* sha512, byte* hash, size_t digestSz,
                               int (*initfp)(wc_Sha512*))
{
    int ret;

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha512->devId != INVALID_DEVID)
    #endif
    {
        byte localHash[WC_SHA512_DIGEST_SIZE];
        ret = wc_CryptoCb_Sha512Hash(sha512, NULL, 0, localHash);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            XMEMCPY(hash, localHash, digestSz);
            return ret;
        }
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    if (sha512->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA512) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha512(&sha512->asyncDev, hash, NULL, digestSz);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha512Final(sha512);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha512->digest, digestSz);

    /* initialize Sha512 structure for the next use */
    return initfp(sha512);
}

#ifndef STM32_HASH_SHA512
int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_Final(sha512, hash, WC_SHA512_DIGEST_SIZE, InitSha512);
}
#endif

#endif /* WOLFSSL_KCAPI_HASH */

#if defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */

#else
#if !defined(WOLFSSL_SE050) || !defined(WOLFSSL_SE050_HASH)
int wc_InitSha512(wc_Sha512* sha512)
{
    int devId = INVALID_DEVID;

#ifdef WOLF_CRYPTO_CB
    devId = wc_CryptoCb_DefaultDevID();
#endif
    return wc_InitSha512_ex(sha512, NULL, devId);
}

void wc_Sha512Free(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return;

#if defined(WOLFSSL_ESP32) && \
    !defined(NO_WOLFSSL_ESP32_CRYPT_HASH)  && \
    !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    esp_sha_release_unfinished_lock(&sha512->ctx);
#endif

#ifdef WOLFSSL_SMALL_STACK_CACHE
    if (sha512->W != NULL) {
        ForceZero(sha512->W, sizeof(word64) * 16);
        XFREE(sha512->W, sha512->heap, DYNAMIC_TYPE_TMP_BUFFER);
        sha512->W = NULL;
    }
#endif

#if defined(WOLFSSL_KCAPI_HASH)
    KcapiHashFree(&sha512->kcapi);
#endif

#if defined(WOLFSSL_HASH_KEEP)
    if (sha512->msg != NULL) {
        ForceZero(sha512->msg, sha512->len);
        XFREE(sha512->msg, sha512->heap, DYNAMIC_TYPE_TMP_BUFFER);
        sha512->msg = NULL;
    }
#endif

#ifdef MAX3266X_SHA_CB
    wc_MXC_TPU_SHA_Free(&(sha512->mxcCtx));
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    wolfAsync_DevCtxFree(&sha512->asyncDev, WOLFSSL_ASYNC_MARKER_SHA512);
#endif /* WOLFSSL_ASYNC_CRYPT */

    ForceZero(sha512, sizeof(*sha512));
}
#endif

#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) \
    && !defined(WOLFSSL_KCAPI_HASH)
/* Apply SHA512 transformation to the data                */
/* @param sha  a pointer to wc_Sha512 structure           */
/* @param data data to be applied SHA512 transformation   */
/* @return 0 on successful, otherwise non-zero on failure */
int wc_Sha512Transform(wc_Sha512* sha, const unsigned char* data)
{
    int ret;
    /* back up buffer */
#ifdef WOLFSSL_SMALL_STACK
    word64 *buffer;
#else
    word64  buffer[WC_SHA512_BLOCK_SIZE  / sizeof(word64)];
#endif

    /* sanity check */
    if (sha == NULL || data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    buffer = (word64*)XMALLOC(WC_SHA512_BLOCK_SIZE, sha->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL)
        return MEMORY_E;
#endif

#if defined(LITTLE_ENDIAN_ORDER)
#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
    #ifdef WC_C_DYNAMIC_FALLBACK
    if (sha->sha_method == SHA512_C)
    #else
    if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
    #endif
#endif
    {
        ByteReverseWords64((word64*)data, (word64*)data,
                                                WC_SHA512_BLOCK_SIZE);
    }
#endif /* LITTLE_ENDIAN_ORDER */

    XMEMCPY(buffer, sha->buffer, WC_SHA512_BLOCK_SIZE);
    XMEMCPY(sha->buffer, data, WC_SHA512_BLOCK_SIZE);

    ret = Transform_Sha512(sha);

    XMEMCPY(sha->buffer, buffer, WC_SHA512_BLOCK_SIZE);
#ifdef WOLFSSL_SMALL_STACK
    ForceZero(buffer, WC_SHA512_BLOCK_SIZE);
    XFREE(buffer, sha->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_SHA512 */
#endif /* !WOLFSSL_SE050 || !WOLFSSL_SE050_HASH */


/* -------------------------------------------------------------------------- */
/* SHA384 */
/* -------------------------------------------------------------------------- */
#ifdef WOLFSSL_SHA384

#if defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_HASH) && \
    !defined(WOLFSSL_QNX_CAAM)
    /* functions defined in wolfcrypt/src/port/caam/caam_sha.c */
#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
    {
        if (sha384 == NULL) {
            return BAD_FUNC_ARG;
        }
        (void)devId;
        return se050_hash_init(&sha384->se050Ctx, heap);
    }
    int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
    {
        if (sha384 == NULL) {
            return BAD_FUNC_ARG;
        }
        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }
        if (data == NULL) {
            return BAD_FUNC_ARG;
        }

        return se050_hash_update(&sha384->se050Ctx, data, len);

    }
    int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
    {
        int ret = 0;
        ret = se050_hash_final(&sha384->se050Ctx, hash, WC_SHA384_DIGEST_SIZE,
                               kAlgorithm_SSS_SHA384);
        return ret;
    }
    int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash)
    {
        int ret = 0;
        ret = se050_hash_final(&sha384->se050Ctx, hash, WC_SHA384_DIGEST_SIZE,
                               kAlgorithm_SSS_SHA384);
        return ret;
    }

#elif defined(WOLFSSL_SILABS_SHA512)
    /* functions defined in wolfcrypt/src/port/silabs/silabs_hash.c */

#elif defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */
#elif defined(STM32_HASH_SHA384)

    int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
    {
        if (sha384 == NULL)
            return BAD_FUNC_ARG;

        (void)devId;
        (void)heap;

        XMEMSET(sha384, 0, sizeof(wc_Sha384));
        wc_Stm32_Hash_Init(&sha384->stmCtx);
        return 0;
    }

    int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
    {
        int ret = 0;

        if (sha384 == NULL) {
            return BAD_FUNC_ARG;
        }
        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }
        if (data == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Update(&sha384->stmCtx,
                HASH_ALGOSELECTION_SHA384, data, len, WC_SHA384_BLOCK_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }
        return ret;
    }

    int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
    {
        int ret = 0;

        if (sha384 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Final(&sha384->stmCtx,
                HASH_ALGOSELECTION_SHA384, hash, WC_SHA384_DIGEST_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }

        (void)wc_InitSha384(sha384); /* reset state */

        return ret;
    }

#else

static int InitSha384(wc_Sha384* sha384)
{
    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[1] = W64LIT(0x629a292a367cd507);
    sha384->digest[2] = W64LIT(0x9159015a3070dd17);
    sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[4] = W64LIT(0x67332667ffc00b31);
    sha384->digest[5] = W64LIT(0x8eb44a8768581511);
    sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);

    sha384->buffLen = 0;
    sha384->loLen   = 0;
    sha384->hiLen   = 0;

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    (defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2))
#ifdef WC_C_DYNAMIC_FALLBACK
    sha384->sha_method = 0;
    Sha512_SetTransform(&sha384->sha_method);
#else
    Sha512_SetTransform();
#endif
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW)  && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    /* HW needs to be carefully initialized, taking into account soft copy.
    ** If already in use; copy may revert to SW as needed. */
    esp_sha_init(&(sha384->ctx), WC_HASH_TYPE_SHA384);
#endif

#ifdef WOLFSSL_HASH_FLAGS
    sha384->flags = 0;
#endif

#ifdef HAVE_ARIA
    sha384->hSession = NULL;
#endif

#ifdef WOLFSSL_HASH_KEEP
    sha384->msg  = NULL;
    sha384->len  = 0;
    sha384->used = 0;
#endif

    return 0;
}

int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
{

    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha384->devId != INVALID_DEVID)
    #endif
    {
        int ret = wc_CryptoCb_Sha384Hash(sha384, data, len, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    if (sha384->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA384) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha384(&sha384->asyncDev, NULL, data, len);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    return Sha512Update((wc_Sha512*)sha384, data, len);
}


int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash)
{
    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWords64(sha384->digest, sha384->digest, WC_SHA384_DIGEST_SIZE);
#endif

    XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);

    return 0;
}

int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
{
    int ret;

    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha384->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Sha384Hash(sha384, NULL, 0, hash);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    if (sha384->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA384) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha384(&sha384->asyncDev, hash, NULL,
                                            WC_SHA384_DIGEST_SIZE);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha512Final((wc_Sha512*)sha384);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);

    return InitSha384(sha384);  /* reset state */
}

int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
{
    int ret;

    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha384->heap = heap;
#ifdef WOLFSSL_SMALL_STACK_CACHE
    sha384->W = NULL;
#endif
#ifdef WOLF_CRYPTO_CB
    sha384->devId = devId;
    sha384->devCtx = NULL;
#endif
#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW)  && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    if (sha384->ctx.mode != ESP32_SHA_INIT) {
        ESP_LOGV(TAG, "Set ctx mode from prior value: "
                           "%d", sha384->ctx.mode);
    }
    /* We know this is a fresh, uninitialized item, so set to INIT */
    sha384->ctx.mode = ESP32_SHA_INIT;
#endif

#ifdef MAX3266X_SHA_CB
    ret = wc_MXC_TPU_SHA_Init(&(sha384->mxcCtx));
    if (ret != 0) {
        return ret;
    }
#endif

    ret = InitSha384(sha384);
    if (ret != 0) {
        return ret;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    ret = wolfAsync_DevCtxInit(&sha384->asyncDev, WOLFSSL_ASYNC_MARKER_SHA384,
                                                           sha384->heap, devId);
#else
    (void)devId;
#endif /* WOLFSSL_ASYNC_CRYPT */
#ifdef WOLFSSL_IMXRT1170_CAAM
     ret = wc_CAAM_HashInit(&sha384->hndl, &sha384->ctx, WC_HASH_TYPE_SHA384);
#endif
    return ret;
}

#endif /* WOLFSSL_IMX6_CAAM || WOLFSSL_SILABS_SHA512 || WOLFSSL_KCAPI_HASH */

#if defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */

#else
int wc_InitSha384(wc_Sha384* sha384)
{
    int devId = INVALID_DEVID;

#ifdef WOLF_CRYPTO_CB
    devId = wc_CryptoCb_DefaultDevID();
#endif
    return wc_InitSha384_ex(sha384, NULL, devId);
}

void wc_Sha384Free(wc_Sha384* sha384)
{
    if (sha384 == NULL)
        return;

#if defined(WOLFSSL_ESP32) && !defined(NO_WOLFSSL_ESP32_CRYPT_HASH)  && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    esp_sha_release_unfinished_lock(&sha384->ctx);
#endif

#ifdef WOLFSSL_SMALL_STACK_CACHE
    if (sha384->W != NULL) {
        ForceZero(sha384->W, sizeof(word64) * 16);
        XFREE(sha384->W, sha384->heap, DYNAMIC_TYPE_TMP_BUFFER);
        sha384->W = NULL;
    }
#endif

#if defined(WOLFSSL_KCAPI_HASH)
    KcapiHashFree(&sha384->kcapi);
#endif

#if defined(WOLFSSL_HASH_KEEP)
    if (sha384->msg != NULL) {
        ForceZero(sha384->msg, sha384->len);
        XFREE(sha384->msg, sha384->heap, DYNAMIC_TYPE_TMP_BUFFER);
        sha384->msg = NULL;
    }
#endif

#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
    se050_hash_free(&sha384->se050Ctx);
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    wolfAsync_DevCtxFree(&sha384->asyncDev, WOLFSSL_ASYNC_MARKER_SHA384);
#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef HAVE_ARIA
    if (sha384->hSession != NULL) {
        MC_CloseSession(sha384->hSession);
        sha384->hSession = NULL;
    }
#endif

#ifdef MAX3266X_SHA_CB
    wc_MXC_TPU_SHA_Free(&(sha384->mxcCtx));
#endif

    ForceZero(sha384, sizeof(*sha384));
}

#endif
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512

#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */

#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */

#else

static int Sha512_Family_GetHash(wc_Sha512* sha512, byte* hash,
                                 int (*finalfp)(wc_Sha512*, byte*))
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha512* tmpSha512;
#else
    wc_Sha512  tmpSha512[1];
#endif

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpSha512 = (wc_Sha512*)XMALLOC(sizeof(wc_Sha512), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpSha512 == NULL) {
        return MEMORY_E;
    }
#endif

    /* copy this sha512 into tmpSha */
    ret = wc_Sha512Copy(sha512, tmpSha512);
    if (ret == 0) {
        ret = finalfp(tmpSha512, hash);
        wc_Sha512Free(tmpSha512);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpSha512, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

int wc_Sha512GetHash(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_GetHash(sha512, hash, wc_Sha512Final);
}

int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(dst, src, sizeof(wc_Sha512));
#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = NULL;
#endif

#if defined(WOLFSSL_SILABS_SE_ACCEL) && defined(WOLFSSL_SILABS_SE_ACCEL_3) && \
    defined(WOLFSSL_SILABS_SHA512)
    dst->silabsCtx.hash_ctx.cmd_ctx = &dst->silabsCtx.cmd_ctx;
    dst->silabsCtx.hash_ctx.hash_type_ctx = &dst->silabsCtx.hash_type_ctx;
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    ret = wolfAsync_DevCopy(&src->asyncDev, &dst->asyncDev);
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512)
    #if defined(CONFIG_IDF_TARGET_ESP32)
    if (ret == 0) {
        ret = esp_sha512_ctx_copy(src, dst);
    }
    #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
          defined(CONFIG_IDF_TARGET_ESP8684) || \
          defined(CONFIG_IDF_TARGET_ESP32C3) || \
          defined(CONFIG_IDF_TARGET_ESP32C6)
        ESP_LOGV(TAG, "No SHA-512 HW on the ESP32-C3");

    #elif defined(CONFIG_IDF_TARGET_ESP32S2) || \
          defined(CONFIG_IDF_TARGET_ESP32S3)
        if (ret == 0) {
            ret = esp_sha512_ctx_copy(src, dst);
        }
    #else
        ESP_LOGW(TAG, "No SHA384 HW or not yet implemented for %s",
                       CONFIG_IDF_TARGET);
    #endif

#endif /* WOLFSSL_USE_ESP32_CRYPT_HASH_HW */

#ifdef WOLFSSL_HASH_FLAGS
     dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif

#if defined(WOLFSSL_HASH_KEEP)
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL)
            return MEMORY_E;
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

#ifdef MAX3266X_SHA_CB
    ret = wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
    if (ret != 0) {
        return ret;
    }
#endif

    return ret;
}

#endif /* WOLFSSL_KCAPI_HASH */

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha512SetFlags(wc_Sha512* sha512, word32 flags)
{
    if (sha512) {
        sha512->flags = flags;
    }
    return 0;
}
int wc_Sha512GetFlags(wc_Sha512* sha512, word32* flags)
{
    if (sha512 && flags) {
        *flags = sha512->flags;
    }
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS */

#if !defined(WOLFSSL_NOSHA512_224) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)

#if defined(STM32_HASH_SHA512_224)

int wc_InitSha512_224_ex(wc_Sha512* sha512, void* heap, int devId)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    (void)devId;
    (void)heap;

    XMEMSET(sha512, 0, sizeof(wc_Sha512));
    wc_Stm32_Hash_Init(&sha512->stmCtx);
    return 0;
}

int wc_Sha512_224Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    int ret = 0;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = wc_Stm32_Hash_Update(&sha512->stmCtx,
            HASH_ALGOSELECTION_SHA512_224, data, len, WC_SHA512_224_BLOCK_SIZE);
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

int wc_Sha512_224Final(wc_Sha512* sha512, byte* hash)
{
    int ret = 0;

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = wc_Stm32_Hash_Final(&sha512->stmCtx,
            HASH_ALGOSELECTION_SHA512_224, hash, WC_SHA512_224_DIGEST_SIZE);
        wolfSSL_CryptHwMutexUnLock();
    }

    (void)wc_InitSha512_224(sha512); /* reset state */

    return ret;
}
#endif
int wc_InitSha512_224(wc_Sha512* sha)
{
    return wc_InitSha512_224_ex(sha, NULL, INVALID_DEVID);
}
#if !defined(STM32_HASH_SHA512_224)
int wc_Sha512_224Update(wc_Sha512* sha, const byte* data, word32 len)
{
    return wc_Sha512Update(sha, data, len);
}
#endif
#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
#elif defined(STM32_HASH_SHA512_224)

#else
int wc_Sha512_224FinalRaw(wc_Sha512* sha, byte* hash)
{
    return Sha512FinalRaw(sha, hash, WC_SHA512_224_DIGEST_SIZE);
}

int wc_Sha512_224Final(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_Final(sha512, hash, WC_SHA512_224_DIGEST_SIZE,
                               InitSha512_224);
}
#endif /* else none of the above: WOLFSSL_KCAPI_HASH, WOLFSSL_SE050 */

void wc_Sha512_224Free(wc_Sha512* sha)
{
    wc_Sha512Free(sha);
}

#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)

#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#else
int wc_Sha512_224GetHash(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_GetHash(sha512, hash, wc_Sha512_224Final);
}

int wc_Sha512_224Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}
#endif /* else none of the above: WOLFSSL_KCAPI_HASH, WOLFSSL_SE050 */

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha512_224SetFlags(wc_Sha512* sha, word32 flags)
{
    return wc_Sha512SetFlags(sha, flags);
}
int wc_Sha512_224GetFlags(wc_Sha512* sha, word32* flags)
{
    return wc_Sha512GetFlags(sha, flags);
}
#endif /* WOLFSSL_HASH_FLAGS */

#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)
int wc_Sha512_224Transform(wc_Sha512* sha, const unsigned char* data)
{
    return wc_Sha512Transform(sha, data);
}
#endif /* OPENSSL_EXTRA */


#endif /* !WOLFSSL_NOSHA512_224 && !FIPS ... */

#if !defined(WOLFSSL_NOSHA512_256) && \
   (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
#if defined(STM32_HASH_SHA512_256)

    int wc_InitSha512_256_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        if (sha512 == NULL)
            return BAD_FUNC_ARG;

        (void)devId;
        (void)heap;

        XMEMSET(sha512, 0, sizeof(wc_Sha512));
        wc_Stm32_Hash_Init(&sha512->stmCtx);
        return 0;
    }

    int wc_Sha512_256Update(wc_Sha512* sha512, const byte* data, word32 len)
    {
        int ret = 0;

        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }
        if (data == NULL && len == 0) {
            /* valid, but do nothing */
            return 0;
        }
        if (data == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Update(&sha512->stmCtx,
                HASH_ALGOSELECTION_SHA512_256, data, len, WC_SHA512_256_BLOCK_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }
        return ret;
    }

    int wc_Sha512_256Final(wc_Sha512* sha512, byte* hash)
    {
        int ret = 0;

        if (sha512 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
            ret = wc_Stm32_Hash_Final(&sha512->stmCtx,
                HASH_ALGOSELECTION_SHA512_256, hash, WC_SHA512_256_DIGEST_SIZE);
            wolfSSL_CryptHwMutexUnLock();
        }

        (void)wc_InitSha512_256(sha512); /* reset state */

        return ret;
    }
#endif
int wc_InitSha512_256(wc_Sha512* sha)
{
    return wc_InitSha512_256_ex(sha, NULL, INVALID_DEVID);
}
#if !defined(STM32_HASH_SHA512_256)
int wc_Sha512_256Update(wc_Sha512* sha, const byte* data, word32 len)
{
    return wc_Sha512Update(sha, data, len);
}
#endif
#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#elif defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_HASH)
#elif defined(STM32_HASH_SHA512_256)
#else
int wc_Sha512_256FinalRaw(wc_Sha512* sha, byte* hash)
{
    return Sha512FinalRaw(sha, hash, WC_SHA512_256_DIGEST_SIZE);
}

int wc_Sha512_256Final(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_Final(sha512, hash, WC_SHA512_256_DIGEST_SIZE,
                               InitSha512_256);
}
#endif

void wc_Sha512_256Free(wc_Sha512* sha)
{
    wc_Sha512Free(sha);
}

#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c */

#else
int wc_Sha512_256GetHash(wc_Sha512* sha512, byte* hash)
{
    return Sha512_Family_GetHash(sha512, hash, wc_Sha512_256Final);
}
int wc_Sha512_256Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_Sha512Copy(src, dst);
}
#endif

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha512_256SetFlags(wc_Sha512* sha, word32 flags)
{
    return wc_Sha512SetFlags(sha, flags);
}
int wc_Sha512_256GetFlags(wc_Sha512* sha, word32* flags)
{
    return wc_Sha512GetFlags(sha, flags);
}
#endif /* WOLFSSL_HASH_FLAGS */

#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)
int wc_Sha512_256Transform(wc_Sha512* sha, const unsigned char* data)
{
    return wc_Sha512Transform(sha, data);
}
#endif /* OPENSSL_EXTRA */


#endif /* !WOLFSSL_NOSHA512_256 && !FIPS ... */

#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_SHA384

#if defined(WOLFSSL_KCAPI_HASH)
    /* functions defined in wolfcrypt/src/port/kcapi/kcapi_hash.c */
#elif defined(WOLFSSL_RENESAS_RSIP) && \
     !defined(NO_WOLFSSL_RENESAS_FSPSM_HASH)
    /* functions defined in wolfcrypt/src/port/renesas/renesas_fspsm_sha.c */
#elif defined(MAX3266X_SHA)
    /* Functions defined in wolfcrypt/src/port/maxim/max3266x.c */

#else

int wc_Sha384GetHash(wc_Sha384* sha384, byte* hash)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha384* tmpSha384;
#else
    wc_Sha384  tmpSha384[1];
#endif

    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpSha384 = (wc_Sha384*)XMALLOC(sizeof(wc_Sha384), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpSha384 == NULL) {
        return MEMORY_E;
    }
#endif

    /* copy this sha384 into tmpSha */
    ret = wc_Sha384Copy(sha384, tmpSha384);
    if (ret == 0) {
        ret = wc_Sha384Final(tmpSha384, hash);
        wc_Sha384Free(tmpSha384);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpSha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(dst, src, sizeof(wc_Sha384));

#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = NULL;
#endif

#if defined(WOLFSSL_SILABS_SE_ACCEL) && defined(WOLFSSL_SILABS_SE_ACCEL_3) && \
    defined(WOLFSSL_SILABS_SHA384)
    dst->silabsCtx.hash_ctx.cmd_ctx = &dst->silabsCtx.cmd_ctx;
    dst->silabsCtx.hash_ctx.hash_type_ctx = &dst->silabsCtx.hash_type_ctx;
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    ret = wolfAsync_DevCopy(&src->asyncDev, &dst->asyncDev);
#endif

#if defined(WOLFSSL_USE_ESP32_CRYPT_HASH_HW) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384)
    #if defined(CONFIG_IDF_TARGET_ESP32)
        esp_sha384_ctx_copy(src, dst);
    #elif defined(CONFIG_IDF_TARGET_ESP32C2) || \
          defined(CONFIG_IDF_TARGET_ESP8684) || \
          defined(CONFIG_IDF_TARGET_ESP32C3) || \
          defined(CONFIG_IDF_TARGET_ESP32C6)
        ESP_LOGV(TAG, "No SHA-384 HW on the ESP32-C3");
    #elif defined(CONFIG_IDF_TARGET_ESP32S2) || \
          defined(CONFIG_IDF_TARGET_ESP32S3)
        esp_sha384_ctx_copy(src, dst);
    #else
        ESP_LOGW(TAG, "No SHA384 HW or not yet implemented for %s",
                       CONFIG_IDF_TARGET);
    #endif
#endif

#ifdef HAVE_ARIA
    dst->hSession = NULL;
    if((src->hSession != NULL) && (MC_CopySession(src->hSession, &(dst->hSession)) != MC_OK)) {
        return MEMORY_E;
    }
#endif

#ifdef WOLFSSL_HASH_FLAGS
     dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif

#if defined(WOLFSSL_HASH_KEEP)
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL)
            return MEMORY_E;
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

#ifdef MAX3266X_SHA_CB
    ret = wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
    if (ret != 0) {
        return ret;
    }
#endif

    return ret;
}

#endif /* WOLFSSL_KCAPI_HASH */

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha384SetFlags(wc_Sha384* sha384, word32 flags)
{
    if (sha384) {
        sha384->flags = flags;
    }
    return 0;
}
int wc_Sha384GetFlags(wc_Sha384* sha384, word32* flags)
{
    if (sha384 && flags) {
        *flags = sha384->flags;
    }
    return 0;
}
#endif

#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_HASH_KEEP
/* Some hardware have issues with update, this function stores the data to be
 * hashed into an array. Once ready, the Final operation is called on all of the
 * data to be hashed at once.
 * returns 0 on success
 */
int wc_Sha512_Grow(wc_Sha512* sha512, const byte* in, int inSz)
{
    return _wc_Hash_Grow(&(sha512->msg), &(sha512->used), &(sha512->len), in,
                        inSz, sha512->heap);
}
#ifdef WOLFSSL_SHA384
int wc_Sha384_Grow(wc_Sha384* sha384, const byte* in, int inSz)
{
    return _wc_Hash_Grow(&(sha384->msg), &(sha384->used), &(sha384->len), in,
                        inSz, sha384->heap);
}
#endif /* WOLFSSL_SHA384 */
#endif /* WOLFSSL_HASH_KEEP */
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */
