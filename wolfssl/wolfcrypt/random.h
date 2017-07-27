/* random.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_RANDOM_H
#define WOLF_CRYPT_RANDOM_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_FIPS
/* for fips @wc_fips */
#include <cyassl/ctaocrypt/random.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

 /* Maximum generate block length */
#ifndef RNG_MAX_BLOCK_LEN
    #ifdef HAVE_INTEL_QA
        #define RNG_MAX_BLOCK_LEN (0xFFFF)
    #else
        #define RNG_MAX_BLOCK_LEN (0x10000)
    #endif
#endif

/* Size of the BRBG seed */
#ifndef DRBG_SEED_LEN
    #define DRBG_SEED_LEN (440/8)
#endif


#if defined(CUSTOM_RAND_GENERATE) && !defined(CUSTOM_RAND_TYPE)
    /* To maintain compatibility the default is byte */
    #define CUSTOM_RAND_TYPE    byte
#endif

/* make sure Hash DRBG is enabled, unless WC_NO_HASHDRBG is defined
    or CUSTOM_RAND_GENERATE_BLOCK is defined*/
#if !defined(WC_NO_HASHDRBG) || !defined(CUSTOM_RAND_GENERATE_BLOCK)
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#endif


#ifndef HAVE_FIPS /* avoid redefining structs and macros */

/* RNG supports the following sources (in order):
 * 1. CUSTOM_RAND_GENERATE_BLOCK: Defines name of function as RNG source and
 *     bypasses the options below.
 * 2. HAVE_INTEL_RDRAND: Uses the Intel RDRAND if supported by CPU.
 * 3. HAVE_HASHDRBG (requires SHA256 enabled): Uses SHA256 based P-RNG
 *     seeded via wc_GenerateSeed. This is the default source.
 */

 /* Seed source can be overriden by defining one of these:
      CUSTOM_RAND_GENERATE_SEED
      CUSTOM_RAND_GENERATE_SEED_OS
      CUSTOM_RAND_GENERATE */


#if defined(CUSTOM_RAND_GENERATE_BLOCK)
    /* To use define the following:
     * #define CUSTOM_RAND_GENERATE_BLOCK myRngFunc
     * extern int myRngFunc(byte* output, word32 sz);
     */
#elif defined(HAVE_HASHDRBG)
    #ifdef NO_SHA256
        #error "Hash DRBG requires SHA-256."
    #endif /* NO_SHA256 */
    #include <wolfssl/wolfcrypt/sha256.h>
#elif defined(HAVE_WNR)
     /* allow whitewood as direct RNG source using wc_GenerateSeed directly */
#else
    #error No RNG source defined!
#endif

#ifdef HAVE_WNR
    #include <wnr.h>
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif


#if defined(USE_WINDOWS_API)
    #if defined(_WIN64)
        typedef unsigned __int64 ProviderHandle;
        /* type HCRYPTPROV, avoid #include <windows.h> */
    #else
        typedef unsigned long ProviderHandle;
    #endif
#endif


/* OS specific seeder */
typedef struct OS_Seed {
    #if defined(USE_WINDOWS_API)
        ProviderHandle handle;
    #else
        int fd;
    #endif
} OS_Seed;


#ifndef WC_RNG_TYPE_DEFINED /* guard on redeclaration */
    typedef struct WC_RNG WC_RNG;
    #define WC_RNG_TYPE_DEFINED
#endif

#ifdef HAVE_HASHDRBG
    /* Private DRBG state */
    struct DRBG;
#endif

/* RNG context */
struct WC_RNG {
    OS_Seed seed;
    void* heap;
#ifdef HAVE_HASHDRBG
    /* Hash-based Deterministic Random Bit Generator */
    struct DRBG* drbg;
    byte status;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
    int devId;
#endif
};

#endif /* HAVE_FIPS */

/* NO_OLD_RNGNAME removes RNG struct name to prevent possible type conflicts,
 * can't be used with CTaoCrypt FIPS */
#if !defined(NO_OLD_RNGNAME) && !defined(HAVE_FIPS)
    #define RNG WC_RNG
#endif


WOLFSSL_LOCAL
int wc_GenerateSeed(OS_Seed* os, byte* seed, word32 sz);


#ifdef HAVE_WNR
    /* Whitewood netRandom client library */
/*!
    \ingroup Random
    
    \brief Init global Whitewood netRandom context
    
    \return 0 Success
    \return BAD_FUNC_ARG Either configFile is null or timeout is negative.
    \return RNG_FAILURE_E There was a failure initializing the rng.
    
    \param configFile Path to configuration file
    \param hmac_cb Optional to create HMAC callback.
    \param timeout A timeout duration.
    
    _Example_
    \code
    char* config = "path/to/config/example.conf";
    int time = // Some sufficient timeout value;

    if (wc_InitNetRandom(config, NULL, time) != 0)
    {
        // Some error occured
    }
    \endcode
    
    \sa wc_FreeNetRandom
*/
    WOLFSSL_API int  wc_InitNetRandom(const char*, wnr_hmac_key, int);
/*!
    \ingroup Random
    
    \brief Free global Whitewood netRandom context.
    
    \return 0 Success
    \return BAD_MUTEX_E Error locking mutex on wnr_mutex
    
    \param none No returns.
    
    _Example_
    \code
    int ret = wc_FreeNetRandom();
    if(ret != 0)
    {
        // Handle the error
    }
    \endcode
    
    \sa wc_InitNetRandom
*/
    WOLFSSL_API int  wc_FreeNetRandom(void);
#endif /* HAVE_WNR */


/*!
    \ingroup Random
    
    \brief Gets the seed (from OS) and key cipher for rng.  rng->drbg (deterministic random bit generator) allocated (should be deallocated with wc_FreeRng).  This is a blocking operation.
    
    \return 0 on success.
    \return MEMORY_E XMALLOC failed
    \return WINCRYPT_E wc_GenerateSeed: failed to acquire context
    \return CRYPTGEN_E wc_GenerateSeed: failed to get random
    \return BAD_FUNC_ARG wc_RNG_GenerateBlock input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E wc_RNG_GenerateBlock: Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E wc_RNG_GenerateBlock: Default error.  rng’s status originally not ok, or set to DRBG_FAILED
    
    \param rng random number generator to be initialized for use with a seed and key cipher
    
    _Example_
    \code
    RNG  rng;
    int ret;
    
    #ifdef HAVE_CAVIUM
    ret = wc_InitRngCavium(&rng, CAVIUM_DEV_ID);
    if (ret != 0){       
        printf(“RNG Nitrox init for device: %d failed”, CAVIUM_DEV_ID);
        return -1;
    }
    #endif
    ret = wc_InitRng(&rng);
    if (ret != 0){
        printf(“RNG init failed”);
        return -1;
    }
    \endcode
    
    \sa wc_InitRngCavium
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
WOLFSSL_API int  wc_InitRng(WC_RNG*);
WOLFSSL_API int  wc_InitRng_ex(WC_RNG* rng, void* heap, int devId);
/*!
    \ingroup Random
    
    \brief Copies a sz bytes of pseudorandom data to output. Will reseed rng if needed (blocking).
    
    \return 0 on success
    \return BAD_FUNC_ARG an input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E Default error. rng’s status originally not ok, or set to DRBG_FAILED
    
    \param rng random number generator initialized with wc_InitRng
    \param output buffer to which the block is copied
    \param sz size of output in bytes
    
    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte block[sz];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }
    
    ret = wc_RNG_GenerateBlock(&rng, block, sz);
    if (ret != 0) {
        return -1; //generating block failed!
    }
    \endcode
    
    \sa wc_InitRngCavium, wc_InitRng
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
WOLFSSL_API int  wc_RNG_GenerateBlock(WC_RNG*, byte*, word32 sz);
/*!
    \ingroup Random
    
    \brief Calls wc_RNG_GenerateBlock to copy a byte of pseudorandom data to b. Will reseed rng if needed.
    
    \return 0 on success
    \return BAD_FUNC_ARG an input is null or sz exceeds MAX_REQUEST_LEN
    \return DRBG_CONT_FIPS_E Hash_gen returned DRBG_CONT_FAILURE
    \return RNG_FAILURE_E Default error.  rng’s status originally not ok, or set to DRBG_FAILED
    
    \param rng: random number generator initialized with wc_InitRng
    \param b one byte buffer to which the block is copied
    
    _Example_
    \code
    RNG  rng;
    int  sz = 32;
    byte b[1];

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    ret = wc_RNG_GenerateByte(&rng, b);
    if (ret != 0) {
        return -1; //generating block failed!
    }
    \endcode
    
    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_FreeRng
    \sa wc_RNG_HealthTest
*/
WOLFSSL_API int  wc_RNG_GenerateByte(WC_RNG*, byte*);
/*!
    \ingroup Random
    
    \brief Should be called when RNG no longer needed in order to securely free drgb.  Zeros and XFREEs rng-drbg.
    
    \return 0 on success
    \return BAD_FUNC_ARG rng or rng->drgb null
    \return RNG_FAILURE_E Failed to deallocated drbg
    
    \param rng random number generator initialized with wc_InitRng
    
    _Example_
    \code
    RNG  rng;
    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    int ret = wc_FreeRng(&rng);
    if (ret != 0) { 
        return -1; //free of rng failed!
    }
    \endcode
    
    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte, 
    \sa wc_RNG_HealthTest
*/
WOLFSSL_API int  wc_FreeRng(WC_RNG*);


#ifdef HAVE_HASHDRBG
/*!
    \ingroup Random
    
    \brief Creates and tests functionality of drbg.
    
    \return 0 on success
    \return BAD_FUNC_ARG entropyA and output must not be null.  If reseed set entropyB must not be null
    \return -1 test failed
    
    \param int reseed: if set, will test reseed functionality
    \param entropyA: entropy to instantiate drgb with
    \param entropyASz: size of entropyA in bytes
    \param entropyB: If reseed set, drbg will be reseeded with entropyB
    \param entropyBSz: size of entropyB in bytes
    \param output: initialized to random data seeded with entropyB if seedrandom is set, and entropyA otherwise
    \param outputSz: length of output in bytes
    
    _Example_
    \code
    byte output[SHA256_DIGEST_SIZE * 4];
    const byte test1EntropyB[] = ....; // test input for reseed false
    const byte test1Output[] = ....;   // testvector: expected output of
                                   // reseed false
    ret = wc_RNG_HealthTest(0, test1Entropy, sizeof(test1Entropy), NULL, 0,
                        output, sizeof(output));
    if (ret != 0)
        return -1;//healthtest without reseed failed

    if (XMEMCMP(test1Output, output, sizeof(output)) != 0)
        return -1; //compare to testvector failed: unexpected output

    const byte test2EntropyB[] = ....; // test input for reseed
    const byte test2Output[] = ....;   // testvector expected output of reseed
    ret = wc_RNG_HealthTest(1, test2EntropyA, sizeof(test2EntropyA),
                        test2EntropyB, sizeof(test2EntropyB),
                        output, sizeof(output));
   
    if (XMEMCMP(test2Output, output, sizeof(output)) != 0)
        return -1; //compare to testvector failed
    \endcode
    
    \sa wc_InitRngCavium
    \sa wc_InitRng
    \sa wc_RNG_GenerateBlock
    \sa wc_RNG_GenerateByte
    \sa wc_FreeRng
*/
    WOLFSSL_API int wc_RNG_HealthTest(int reseed,
                                        const byte* entropyA, word32 entropyASz,
                                        const byte* entropyB, word32 entropyBSz,
                                        byte* output, word32 outputSz);
#endif /* HAVE_HASHDRBG */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_RANDOM_H */

