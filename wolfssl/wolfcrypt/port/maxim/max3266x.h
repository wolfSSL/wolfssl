/* max3266x.h
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

#ifndef _WOLFPORT_MAX3266X_H_
#define _WOLFPORT_MAX3266X_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_MAX_HASH_SIZE
    #define WOLFSSL_MAX_HASH_SIZE  64
#endif

#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)

/* Some extra conditions when using callbacks */
#if defined(WOLF_CRYPTO_CB)
    #define MAX3266X_CB
    #ifdef MAX3266X_MATH
        #error Cannot have MAX3266X_MATH and MAX3266X_CB
    #endif
    #ifdef MAX3266X_SHA
        #undef MAX3266X_SHA /* Turn Off Normal Sha Definition */
        #define MAX3266X_SHA_CB /* Turn On Callback for SHA */
    #endif
#endif

/* Default to all HW acceleration on unless specified in user_settings */
#if !defined(MAX3266X_RNG) && !defined(MAX3266X_AES) && \
        !defined(MAX3266X_AESGCM) && !defined(MAX3266X_SHA) && \
        !defined(MAX3266X_MATH)
    #define MAX3266X_RNG
    #define MAX3266X_AES
    #ifndef MAX3266X_CB
        #define MAX3266X_SHA /* SHA is Supported, but need new definitions */
        #define MAX3266X_MATH  /* MATH is not supported with callbacks */
    #endif
    #ifdef MAX3266X_CB
        #define MAX3266X_SHA_CB /* Turn on Callback for SHA */
    #endif
#endif

/* Crypto HW can be used in parallel on this device */
/* Sets up new Mutexing if desired */
#ifdef WOLFSSL_ALGO_HW_MUTEX
    /* SDK only supports using RNG in parallel with crypto HW */
    /* AES, HASH, and PK must share some mutex */
    #define NO_AES_MUTEX
    #define NO_HASH_MUTEX
    #define NO_PK_MUTEX
#endif /* WOLFSSL_ALGO_HW_MUTEX */

#if defined(WOLFSSL_MAX3266X_OLD)
    /* Support for older SDK API Maxim provides */

    /* These are needed for older SDK */
    #define TARGET MAX32665
    #define TARGET_REV 0x4131
    #include "mxc_sys.h"



    #if defined(MAX3266X_RNG)
        #include "trng.h"   /* Provides TRNG Drivers */
        #define MXC_TPU_TRNG_Read           TRNG_Read
        #warning "TRNG Health Test not available in older Maxim SDK"
        #define MXC_TRNG_HealthTest(...)    0
    #endif
    #if defined(MAX3266X_AES)
        #include "cipher.h" /* Provides Drivers for AES */
        /* AES Defines */
        #define MXC_TPU_CIPHER_TYPE      tpu_ciphersel_t
        #define MXC_TPU_CIPHER_AES128    TPU_CIPHER_AES128
        #define MXC_TPU_CIPHER_AES192    TPU_CIPHER_AES192
        #define MXC_TPU_CIPHER_AES256    TPU_CIPHER_AES256

        #define MXC_TPU_MODE_TYPE        tpu_modesel_t
        #define MXC_TPU_MODE_ECB         TPU_MODE_ECB
        #define MXC_TPU_MODE_CBC         TPU_MODE_CBC
        #define MXC_TPU_MODE_CFB         TPU_MODE_CFB
        #define MXC_TPU_MODE_CTR         TPU_MODE_CTR

        /* AES Functions */
        #define MXC_TPU_Cipher_Config       TPU_Cipher_Config
        #define MXC_TPU_Cipher_AES_Encrypt  TPU_AES_Encrypt
        #define MXC_TPU_Cipher_AES_Decrypt  TPU_AES_Decrypt

    #endif
    #if defined(MAX3266X_SHA) || defined(MAX3266X_SHA_CB)
        #include "hash.h"   /* Proivdes Drivers for SHA */
        /* SHA Defines */
        #define MXC_TPU_HASH_TYPE        tpu_hashfunsel_t
        #define MXC_TPU_HASH_SHA1        TPU_HASH_SHA1
        #define MXC_TPU_HASH_SHA224      TPU_HASH_SHA224
        #define MXC_TPU_HASH_SHA256      TPU_HASH_SHA256
        #define MXC_TPU_HASH_SHA384      TPU_HASH_SHA384
        #define MXC_TPU_HASH_SHA512      TPU_HASH_SHA512

        /* SHA Functions */
        #define MXC_TPU_Hash_Config             TPU_Hash_Config
        #define MXC_TPU_Hash_SHA                TPU_SHA

    #endif
    #if defined(MAX3266X_MATH)
        #include "maa.h"    /* Provides Drivers for math acceleration for   */
                            /* ECDSA and RSA Acceleration                   */
        /* MAA Defines */
        #define MXC_TPU_MAA_TYPE     tpu_maa_clcsel_t
        #define MXC_TPU_MAA_EXP      TPU_MAA_EXP
        #define MXC_TPU_MAA_SQ       TPU_MAA_SQ
        #define MXC_TPU_MAA_MUL      TPU_MAA_MUL
        #define MXC_TPU_MAA_SQMUL    TPU_MAA_SQMUL
        #define MXC_TPU_MAA_ADD      TPU_MAA_ADD
        #define MXC_TPU_MAA_SUB      TPU_MAA_SUB

        /* MAA Functions */
        #define MXC_TPU_MAA_Compute      MAA_Compute
        #define MXC_TPU_MAA_Shutdown     MAA_Shutdown
        #define MXC_TPU_MAA_Init         MAA_Init
        #define MXC_TPU_MAA_Reset        MAA_Reset

    #endif

    /* TPU Functions */
    #define MXC_TPU_Init                SYS_TPU_Init
    #define MXC_TPU_Shutdown            SYS_TPU_Shutdown
    #define MXC_SYS_PERIPH_CLOCK_TPU    SYS_PERIPH_CLOCK_TPU

    #define MXC_SYS_PERIPH_CLOCK_TPU    SYS_PERIPH_CLOCK_TPU
    #define MXC_SYS_PERIPH_CLOCK_TRNG   SYS_PERIPH_CLOCK_TRNG

#else
    /* Defaults to expect newer SDK */
    #if defined(MAX3266X_RNG)
        #include "trng.h"   /* Provides Drivers for TRNG    */
    #endif
    #if defined(MAX3266X_AES) || defined(MAX3266X_SHA) || \
                defined(MAX3266X_MATH) || defined(MAX3266X_RSA) || \
                defined(MAX3266X_RNG)
        #include "tpu.h"    /* SDK Drivers for the TPU unit         */
                            /* Handles AES, SHA, and                */
                            /* MAA driver to accelerate RSA/ECDSA   */

        /* AES Defines */
        #define MXC_TPU_CIPHER_TYPE     mxc_tpu_ciphersel_t
        #define MXC_TPU_MODE_TYPE       mxc_tpu_modesel_t

        /* SHA Defines */
        #define MXC_TPU_HASH_TYPE       mxc_tpu_hashfunsel_t

        /* MAA Defines */
        #define MXC_TPU_MAA_TYPE     mxc_tpu_maa_clcsel_t


    #endif

#endif


/* Provide Driver for RTC if specified, meant for wolfCrypt benchmark only */
#if defined(MAX3266X_RTC)
    #if defined(WOLFSSL_MAX3266X_OLD)
       #error Not Implemented with old SDK
    #endif
    #include "time.h"
    #include "rtc.h"
    #define MXC_SECS_PER_MIN (60)
    #define MXC_SECS_PER_HR  (60 * MXC_SECS_PER_MIN)
    #define MXC_SECS_PER_DAY (24 * MXC_SECS_PER_HR)
#endif

/* Variable Definitions */
#ifdef __cplusplus
    extern "C" {
#endif

    WOLFSSL_LOCAL int wc_MXC_TPU_Init(void);
    WOLFSSL_LOCAL int wc_MXC_TPU_Shutdown(void);
    /* Convert Errors to wolfCrypt Codes */
    WOLFSSL_LOCAL int wc_MXC_error(int *ret);

#ifdef MAX3266X_RTC
    WOLFSSL_LOCAL int wc_MXC_RTC_Init(void);
    WOLFSSL_LOCAL int wc_MXC_RTC_Reset(void);
    WOLFSSL_LOCAL double wc_MXC_RTC_Time(void);
#endif

#ifdef MAX3266X_VERBOSE
    #ifndef DEBUG_WOLFSSL
        #error Need "#define DEBUG_WOLFSSL" to do use "#define MAX3266X_VERBOSE"
    #else
        #define MAX3266X_MSG(...)   WOLFSSL_MSG(__VA_ARGS__)
    #endif
#else
    #define MAX3266X_MSG(...)   /* Compile out Verbose MSGs */
#endif

#ifdef MAX3266X_RNG
    WOLFSSL_LOCAL int wc_MXC_TRNG_Random(unsigned char* output,
                                                unsigned int sz);
#endif

#ifdef MAX3266X_AES
    WOLFSSL_LOCAL int wc_MXC_TPU_AesEncrypt(const unsigned char* in,
                                const unsigned char* iv,
                                const unsigned char* enc_key,
                                MXC_TPU_MODE_TYPE mode,
                                unsigned int data_size,
                                unsigned char* out, unsigned int keySize);
#ifdef HAVE_AES_DECRYPT
    WOLFSSL_LOCAL int wc_MXC_TPU_AesDecrypt(const unsigned char* in,
                                const unsigned char* iv,
                                const unsigned char* enc_key,
                                MXC_TPU_MODE_TYPE mode,
                                unsigned int data_size,
                                unsigned char* out, unsigned int keySize);
#endif /* HAVE_AES_DECRYPT */
#endif /* MAX3266X_AES */

#if defined(MAX3266X_SHA) || defined(MAX3266X_SHA_CB)

    /* Need to update this struct accordingly if other SHA Structs change */
    /* This is a generic struct to use so only this is needed */

    typedef struct {
        unsigned char   *msg;
        unsigned int    used;
        unsigned int    size;
    } wc_MXC_Sha;

    #if !defined(NO_SHA)
        /* Define the SHA digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA1[20] = {
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
            0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09};
    #endif /* NO_SHA */

    #if defined(WOLFSSL_SHA224)
        /* Define the SHA-224 digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA224[28] = {
                0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
                0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
                0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
                0xc5, 0xb3, 0xe4, 0x2f};
    #endif /* WOLFSSL_SHA224 */

    #if !defined(NO_SHA256)
        /* Define the SHA-256 digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA256[32] = {
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    #endif /* NO_SHA256 */

    #if defined(WOLFSSL_SHA384)
        /* Define the SHA-384 digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA384[48] = {
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
            0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
            0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
            0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
            0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
            0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};
    #endif /* WOLFSSL_SHA384 */

    #if defined(WOLFSSL_SHA512)
        /* Does not support these SHA512 Macros */
        #ifndef WOLFSSL_NOSHA512_224
            #warning "MAX3266X Port does not support SHA-512/224"
            #define WOLFSSL_NOSHA512_224
        #endif
        #ifndef WOLFSSL_NOSHA512_256
            #warning "MAX3266X Port does not support SHA-512/256"
            #define WOLFSSL_NOSHA512_256
        #endif

        /* Define the SHA-512 digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA512[64] = {
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
    #endif /* WOLFSSL_SHA512 */


    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Init(wc_MXC_Sha *hash);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Update(wc_MXC_Sha *hash,
                                                const unsigned char* data,
                                                unsigned int size);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Final(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_GetHash(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Copy(wc_MXC_Sha* src, wc_MXC_Sha* dst);
    WOLFSSL_LOCAL void wc_MXC_TPU_SHA_Free(wc_MXC_Sha* hash);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_GetDigest(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);


#endif /* defined(MAX3266X_SHA) && !defined(WOLF_CRYPTO_CB) */

#if defined(MAX3266X_MATH)
    #define WOLFSSL_USE_HW_MP
    /* Setup mapping to fallback if edge case is encountered */
    #if defined(USE_FAST_MATH)
        #define mxc_mod         fp_mod
        #define mxc_addmod      fp_addmod
        #define mxc_submod      fp_submod
        #define mxc_mulmod      fp_mulmod
        #define mxc_exptmod     fp_exptmod
        #define mxc_sqrmod      fp_sqrmod
    #elif defined(WOLFSSL_SP_MATH_ALL)
        #define mxc_mod         sp_mod
        #define mxc_addmod      sp_addmod
        #define mxc_submod      sp_submod
        #define mxc_mulmod      sp_mulmod
        #define mxc_exptmod     sp_exptmod
        #define mxc_sqrmod      sp_sqrmod
    #else
        #error Need to use WOLFSSL_SP_MATH_ALL
    #endif

#endif

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */
#endif /* _WOLFPORT_MAX3266X_H_ */
