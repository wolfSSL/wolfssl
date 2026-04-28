/* lkcapi_sha_glue.c -- glue logic for SHA*
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

/* included by linuxkm/lkcapi_glue.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_sha_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS) && defined(USE_INTEL_SPEEDUP)
    #error SHA* WC_LINUXKM_C_FALLBACK_IN_SHIMS is not currently supported.
#endif

#ifdef NO_LINUXKM_DRBG_GET_RANDOM_BYTES
    #undef LINUXKM_DRBG_GET_RANDOM_BYTES
/* setup for LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT is in linuxkm_wc_port.h */
#elif defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT) && \
    (defined(WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS) || \
     defined(WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES))
    #ifndef LINUXKM_DRBG_GET_RANDOM_BYTES
        #define LINUXKM_DRBG_GET_RANDOM_BYTES
    #endif
#else
    #ifdef LINUXKM_DRBG_GET_RANDOM_BYTES
        #error LINUXKM_DRBG_GET_RANDOM_BYTES configured with no callback model configured.
        #undef LINUXKM_DRBG_GET_RANDOM_BYTES
    #endif
#endif

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/hmac.h>

#define WOLFKM_SHA1_NAME "sha1"
#define WOLFKM_SHA2_224_NAME "sha224"
#define WOLFKM_SHA2_256_NAME "sha256"
#define WOLFKM_SHA2_384_NAME "sha384"
#define WOLFKM_SHA2_512_NAME "sha512"
#define WOLFKM_SHA3_224_NAME "sha3-224"
#define WOLFKM_SHA3_256_NAME "sha3-256"
#define WOLFKM_SHA3_384_NAME "sha3-384"
#define WOLFKM_SHA3_512_NAME "sha3-512"

#define WOLFKM_SHA1_HMAC_NAME "hmac(sha1)"
#define WOLFKM_SHA2_224_HMAC_NAME "hmac(sha224)"
#define WOLFKM_SHA2_256_HMAC_NAME "hmac(sha256)"
#define WOLFKM_SHA2_384_HMAC_NAME "hmac(sha384)"
#define WOLFKM_SHA2_512_HMAC_NAME "hmac(sha512)"
#define WOLFKM_SHA3_224_HMAC_NAME "hmac(sha3-224)"
#define WOLFKM_SHA3_256_HMAC_NAME "hmac(sha3-256)"
#define WOLFKM_SHA3_384_HMAC_NAME "hmac(sha3-384)"
#define WOLFKM_SHA3_512_HMAC_NAME "hmac(sha3-512)"

#define WOLFKM_STDRNG_NAME "stdrng"

#if defined(USE_INTEL_SPEEDUP)
    #ifndef NO_AVX2_SUPPORT
        #define WOLFKM_SHA_DRIVER_ISA_EXT "-avx2"
    #else
        #define WOLFKM_SHA_DRIVER_ISA_EXT "-avx"
    #endif
#else
    #define WOLFKM_SHA_DRIVER_ISA_EXT ""
#endif

#define WOLFKM_SHA_DRIVER_SUFFIX \
    WOLFKM_SHA_DRIVER_ISA_EXT WOLFKM_DRIVER_SUFFIX_BASE

#define WOLFKM_SHA1_DRIVER ("sha1" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_224_DRIVER ("sha224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_256_DRIVER ("sha256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_384_DRIVER ("sha384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_512_DRIVER ("sha512" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_224_DRIVER ("sha3-224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_256_DRIVER ("sha3-256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_384_DRIVER ("sha3-384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_512_DRIVER ("sha3-512" WOLFKM_SHA_DRIVER_SUFFIX)

#define WOLFKM_SHA1_HMAC_DRIVER ("hmac-sha1" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_224_HMAC_DRIVER ("hmac-sha224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_256_HMAC_DRIVER ("hmac-sha256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_384_HMAC_DRIVER ("hmac-sha384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_512_HMAC_DRIVER ("hmac-sha512" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_224_HMAC_DRIVER ("hmac-sha3-224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_256_HMAC_DRIVER ("hmac-sha3-256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_384_HMAC_DRIVER ("hmac-sha3-384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_512_HMAC_DRIVER ("hmac-sha3-512" WOLFKM_SHA_DRIVER_SUFFIX)

/* "nopr" signifies no "prediction resistance".  Prediction resistance entails
 * implicit reseeding of the DRBG each time its generator method is called,
 * which reduces performance and can rapidly lead to temporary entropy
 * exhaustion.  A caller that really needs PR can pass in seed data in its call
 * to our rng_alg.generate() implementation.
 */

#ifdef HAVE_ENTROPY_MEMUSE
    #define WOLFKM_STDRNG_WOLFENTROPY "-wolfentropy"
#else
    #define WOLFKM_STDRNG_WOLFENTROPY ""
#endif

#if defined(HAVE_INTEL_RDSEED) || defined(HAVE_AMD_RDSEED)
    #define WOLFKM_STDRNG_RDSEED "-rdseed"
#else
    #define WOLFKM_STDRNG_RDSEED ""
#endif

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES
    #define WOLFKM_STDRNG_DRIVER ("sha2-256-drbg-nopr" \
                                  WOLFKM_STDRNG_WOLFENTROPY \
                                  WOLFKM_STDRNG_RDSEED \
                                  WOLFKM_DRIVER_SUFFIX_BASE \
                                  "-with-global-replace")
#else
    #define WOLFKM_STDRNG_DRIVER ("sha2-256-drbg-nopr" \
                                  WOLFKM_STDRNG_WOLFENTROPY \
                                  WOLFKM_STDRNG_RDSEED \
                                  WOLFKM_DRIVER_SUFFIX_BASE)
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA_ALL
    #define LINUXKM_LKCAPI_REGISTER_SHA1
    #define LINUXKM_LKCAPI_REGISTER_SHA2
    #define LINUXKM_LKCAPI_REGISTER_SHA3
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_SHA_ALL
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA1
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_HMAC_ALL
    #define LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA2_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA3_HMAC
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_HMAC_ALL
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA1_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_HMAC
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2
    #define LINUXKM_LKCAPI_REGISTER_SHA2_224
    #define LINUXKM_LKCAPI_REGISTER_SHA2_256
    #define LINUXKM_LKCAPI_REGISTER_SHA2_384
    #define LINUXKM_LKCAPI_REGISTER_SHA2_512
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_SHA2
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_SHA2_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512_HMAC
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3
    #define LINUXKM_LKCAPI_REGISTER_SHA3_224
    #define LINUXKM_LKCAPI_REGISTER_SHA3_256
    #define LINUXKM_LKCAPI_REGISTER_SHA3_384
    #define LINUXKM_LKCAPI_REGISTER_SHA3_512
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_SHA3
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_224
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_256
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_384
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_512
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    #define LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
#endif

#ifdef LINUXKM_LKCAPI_DONT_REGISTER_SHA3_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_224_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_256_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_384_HMAC
    #define LINUXKM_LKCAPI_DONT_REGISTER_SHA3_512_HMAC
#endif

#if defined(NO_HMAC) && defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_HMAC) && \
    !defined(LINUXKM_LKCAPI_DONT_REGISTER_HMAC_ALL)
    #error Config conflict: target kernel has CONFIG_CRYPTO_HMAC, but module has NO_HMAC
#endif

#ifndef NO_SHA
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA1))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA1)
        #define LINUXKM_LKCAPI_REGISTER_SHA1
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
           (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA1))) && \
          !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1_HMAC) && \
          !defined(LINUXKM_LKCAPI_REGISTER_SHA1_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA1) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA1, but module has NO_SHA
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA1
    #undef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
#endif

#ifdef WOLFSSL_SHA224
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224) &&            \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_224)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_224
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
           (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256))) && \
          !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224_HMAC) &&        \
          !defined(LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA256, but module is missing WOLFSSL_SHA224
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA2_224
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
#endif

#ifndef NO_SHA256
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_256)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_256
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
           (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256))) && \
          !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256_HMAC) &&  \
          !defined(LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA256, but module has NO_SHA256
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA2_256
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
#endif

#ifdef WOLFSSL_SHA384
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_384)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_384
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
           (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512))) && \
          !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384_HMAC) &&  \
          !defined(LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA512, but module is missing WOLFSSL_SHA384
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA2_384
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
#endif

#ifdef WOLFSSL_SHA512
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_512)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_512
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
           (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512))) && \
          !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512_HMAC) &&  \
          !defined(LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA512, but module is missing WOLFSSL_SHA512
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA2_512
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
#endif

#ifdef WOLFSSL_SHA3
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
        (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA3))
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_224) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_224)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_224
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_256) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_256)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_256
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_384) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_384)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_384
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_512) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_512)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_512
        #endif
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    #elif defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
        (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA3))
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_224_HMAC) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_256_HMAC) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_384_HMAC) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
        #endif
        #if !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_512_HMAC) && \
            !defined(LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC)
            #define LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
        #endif
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA3) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3)
        #error Config conflict: target kernel has CONFIG_CRYPTO_SHA3, but module is missing WOLFSSL_SHA3
    #endif

    #undef LINUXKM_LKCAPI_REGISTER_SHA3_224
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_256
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_384
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_512
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    #undef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)) &&  \
    (defined(LINUXKM_LKCAPI_REGISTER_SHA1_HMAC) ||     \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC))
    #error LINUXKM_LKCAPI_REGISTER for HMACs is supported only on Linux kernel versions >= 5.6.0.
#endif

#ifdef HAVE_HASHDRBG
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_HASH_DRBG)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG)
        #define LINUXKM_LKCAPI_REGISTER_HASH_DRBG
    #endif
    /* setup for LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT is in linuxkm_wc_port.h */
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_DRBG) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_HASH_DRBG)
        #error Config conflict: target kernel has CONFIG_CRYPTO_DRBG, but module is missing HAVE_HASHDRBG
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_HASH_DRBG
#endif

struct km_sha_state {
    union {
#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
        struct wc_Sha sha1_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
        struct wc_Sha256 sha2_224_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
        struct wc_Sha256 sha2_256_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
        struct wc_Sha512 sha2_384_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
        struct wc_Sha512 sha2_512_state;
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
        struct wc_Sha3 *sha3_224_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
        struct wc_Sha3 *sha3_256_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
        struct wc_Sha3 *sha3_384_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
        struct wc_Sha3 *sha3_512_state;
#endif
#ifdef WOLFSSL_SHA3
        void *sha3_ptr;
#endif
    };
};

#ifdef WOLFSSL_SHA3
WC_MAYBE_UNUSED static void km_sha3_free_tstate(struct km_sha_state *t_ctx) {
    free(t_ctx->sha3_ptr);
    t_ctx->sha3_ptr = NULL;
}

WC_MAYBE_UNUSED static int sha3_test_once(void) {
    static int once = 0;
    static int ret;
    if (! once) {
        ret = sha3_test();
        once = 1;
    }
    return ret;
}
#endif

#define WC_LINUXKM_SHA_IMPLEMENT(name, digest_size, block_size,            \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  free_f, test_routine)                    \
                                                                           \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = init_f(&ctx-> name ## _state);                               \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = update_f(&ctx-> name ## _state, data, len);                  \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        free_f(&ctx-> name ## _state);                                     \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = final_f(&ctx-> name ## _state, out);                         \
                                                                           \
    free_f(&ctx-> name ## _state);                                         \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _finup(struct shash_desc *desc, const u8 *data,  \
                                 unsigned int len, u8 *out)                \
{                                                                          \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = update_f(&ctx-> name ## _state, data, len);                  \
                                                                           \
    if (ret != 0) {                                                        \
        free_f(&ctx-> name ## _state);                                     \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    return km_ ## name ## _final(desc, out);                               \
}                                                                          \
                                                                           \
static int km_ ## name ## _digest(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len, u8 *out)               \
{                                                                          \
    int ret = km_ ## name ## _init(desc);                                  \
    if (ret != 0)                                                          \
        return ret;                                                        \
    return km_ ## name ## _finup(desc, data, len, out);                    \
}                                                                          \
                                                                           \
                                                                           \
static struct shash_alg name ## _alg =                                     \
{                                                                          \
    .digestsize     =       (digest_size),                                 \
    .init           =       km_ ## name ## _init,                          \
    .update         =       km_ ## name ## _update,                        \
    .final          =       km_ ## name ## _final,                         \
    .finup          =       km_ ## name ## _finup,                         \
    .digest         =       km_ ## name ## _digest,                        \
    .descsize       =       sizeof(struct km_sha_state),                   \
    .base           =       {                                              \
        .cra_name        =      (this_cra_name),                           \
        .cra_driver_name =      (this_cra_driver_name),                    \
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,           \
        .cra_blocksize   =      (block_size),                              \
        .cra_module      =      THIS_MODULE                                \
    }                                                                      \
};                                                                         \
static int name ## _alg_loaded = 0;                                        \
                                                                           \
static int linuxkm_test_ ## name(void) {                                   \
    wc_test_ret_t ret = test_routine();                                    \
    if (ret >= 0)                                                          \
        return check_shash_driver_masking(NULL /* tfm */, this_cra_name,   \
                                          this_cra_driver_name);           \
    else {                                                                 \
        wc_test_render_error_message("linuxkm_test_" #name " failed: ",    \
                                     ret);                                 \
        return WC_TEST_RET_DEC_EC(ret);                                    \
    }                                                                      \
}                                                                          \
                                                                           \
struct wc_swallow_the_semicolon

#define WC_LINUXKM_SHA3_IMPLEMENT(name, digest_size, block_size,           \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  free_f, test_routine)                    \
                                                                           \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
    int ret;                                                               \
                                                                           \
    ctx-> name ## _state = malloc(sizeof *ctx-> name ## _state);           \
    if (! ctx-> name ## _state)                                            \
        return -ENOMEM;                                                    \
    ret = init_f(ctx-> name ## _state, NULL, INVALID_DEVID);               \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = update_f(ctx-> name ## _state, data, len);                   \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        free_f(ctx-> name ## _state);                                      \
        km_sha3_free_tstate(ctx);                                          \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = final_f(ctx-> name ## _state, out);                          \
                                                                           \
    free_f(ctx-> name ## _state);                                          \
    km_sha3_free_tstate(ctx);                                              \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _finup(struct shash_desc *desc, const u8 *data,  \
                                 unsigned int len, u8 *out)                \
{                                                                          \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = update_f(ctx-> name ## _state, data, len);                   \
                                                                           \
    if (ret != 0) {                                                        \
        free_f(ctx-> name ## _state);                                      \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    return km_ ## name ## _final(desc, out);                               \
}                                                                          \
                                                                           \
static int km_ ## name ## _digest(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len, u8 *out)               \
{                                                                          \
    int ret = km_ ## name ## _init(desc);                                  \
    if (ret != 0)                                                          \
        return ret;                                                        \
    return km_ ## name ## _finup(desc, data, len, out);                    \
}                                                                          \
                                                                           \
static struct shash_alg name ## _alg =                                     \
{                                                                          \
    .digestsize     =       (digest_size),                                 \
    .init           =       km_ ## name ## _init,                          \
    .update         =       km_ ## name ## _update,                        \
    .final          =       km_ ## name ## _final,                         \
    .finup          =       km_ ## name ## _finup,                         \
    .digest         =       km_ ## name ## _digest,                        \
    .descsize       =       sizeof(struct km_sha_state),                   \
    .base           =       {                                              \
        .cra_name        =      (this_cra_name),                           \
        .cra_driver_name =      (this_cra_driver_name),                    \
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,           \
        .cra_blocksize   =      (block_size),                              \
        .cra_module      =      THIS_MODULE                                \
    }                                                                      \
};                                                                         \
static int name ## _alg_loaded = 0;                                        \
                                                                           \
static int linuxkm_test_ ## name(void) {                                   \
    wc_test_ret_t ret = test_routine();                                    \
    if (ret >= 0)                                                          \
        return check_shash_driver_masking(NULL /* tfm */, this_cra_name,   \
                                          this_cra_driver_name);           \
    else {                                                                 \
        wc_test_render_error_message("linuxkm_test_" #name " failed: ",    \
                                     ret);                                 \
        return WC_TEST_RET_DEC_EC(ret);                                    \
    }                                                                      \
}                                                                          \
                                                                           \
struct wc_swallow_the_semicolon

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    WC_LINUXKM_SHA_IMPLEMENT(sha1, WC_SHA_DIGEST_SIZE, WC_SHA_BLOCK_SIZE,
                             WOLFKM_SHA1_NAME, WOLFKM_SHA1_DRIVER,
                             wc_InitSha, wc_ShaUpdate, wc_ShaFinal,
                             wc_ShaFree, sha_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    WC_LINUXKM_SHA_IMPLEMENT(sha2_224, WC_SHA224_DIGEST_SIZE, WC_SHA224_BLOCK_SIZE,
                             WOLFKM_SHA2_224_NAME, WOLFKM_SHA2_224_DRIVER,
                             wc_InitSha224, wc_Sha224Update, wc_Sha224Final,
                             wc_Sha224Free, sha224_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    WC_LINUXKM_SHA_IMPLEMENT(sha2_256, WC_SHA256_DIGEST_SIZE, WC_SHA256_BLOCK_SIZE,
                             WOLFKM_SHA2_256_NAME, WOLFKM_SHA2_256_DRIVER,
                             wc_InitSha256, wc_Sha256Update, wc_Sha256Final,
                             wc_Sha256Free, sha256_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    WC_LINUXKM_SHA_IMPLEMENT(sha2_384, WC_SHA384_DIGEST_SIZE, WC_SHA384_BLOCK_SIZE,
                             WOLFKM_SHA2_384_NAME, WOLFKM_SHA2_384_DRIVER,
                             wc_InitSha384, wc_Sha384Update, wc_Sha384Final,
                             wc_Sha384Free, sha384_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    WC_LINUXKM_SHA_IMPLEMENT(sha2_512, WC_SHA512_DIGEST_SIZE, WC_SHA512_BLOCK_SIZE,
                             WOLFKM_SHA2_512_NAME, WOLFKM_SHA2_512_DRIVER,
                             wc_InitSha512, wc_Sha512Update, wc_Sha512Final,
                             wc_Sha512Free, sha512_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_224, WC_SHA3_224_DIGEST_SIZE, WC_SHA3_224_BLOCK_SIZE,
                             WOLFKM_SHA3_224_NAME, WOLFKM_SHA3_224_DRIVER,
                             wc_InitSha3_224, wc_Sha3_224_Update, wc_Sha3_224_Final,
                             wc_Sha3_224_Free, sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_256, WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_BLOCK_SIZE,
                             WOLFKM_SHA3_256_NAME, WOLFKM_SHA3_256_DRIVER,
                             wc_InitSha3_256, wc_Sha3_256_Update, wc_Sha3_256_Final,
                             wc_Sha3_256_Free, sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_384, WC_SHA3_384_DIGEST_SIZE, WC_SHA3_384_BLOCK_SIZE,
                             WOLFKM_SHA3_384_NAME, WOLFKM_SHA3_384_DRIVER,
                             wc_InitSha3_384, wc_Sha3_384_Update, wc_Sha3_384_Final,
                             wc_Sha3_384_Free, sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_512, WC_SHA3_512_DIGEST_SIZE, WC_SHA3_512_BLOCK_SIZE,
                             WOLFKM_SHA3_512_NAME, WOLFKM_SHA3_512_DRIVER,
                             wc_InitSha3_512, wc_Sha3_512_Update, wc_Sha3_512_Final,
                             wc_Sha3_512_Free, sha3_test_once);
#endif

struct km_sha_hmac_pstate {
    struct Hmac wc_hmac;
};
struct km_sha_hmac_state {
    struct Hmac *wc_hmac; /* HASH_MAX_DESCSIZE is 368, but sizeof(struct Hmac) is 832 */
};

#ifndef NO_HMAC

WC_MAYBE_UNUSED static int linuxkm_hmac_setkey_common(struct crypto_shash *tfm, int type, const byte* key, word32 length)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    int ret;

#if defined(HAVE_FIPS) && (FIPS_VERSION3_LT(6, 0, 0) || defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS) || (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)))
    ret = wc_HmacSetKey(&p_ctx->wc_hmac, type, key, length);
#else
    /* kernel 5.10.x crypto manager expects FIPS-undersized keys to succeed. */
    ret = wc_HmacSetKey_ex(&p_ctx->wc_hmac, type, key, length, 1 /* allowFlag */);
#endif

    if (ret == 0)
        return 0;
    else
        return -EINVAL;
}

WC_MAYBE_UNUSED static void km_hmac_free_tstate(struct km_sha_hmac_state *t_ctx) {
    wc_HmacFree(t_ctx->wc_hmac);
    free(t_ctx->wc_hmac);
    t_ctx->wc_hmac = NULL;
}

WC_MAYBE_UNUSED static int km_hmac_init_tfm(struct crypto_shash *tfm)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    int ret = wc_HmacInit(&p_ctx->wc_hmac, NULL /* heap */, INVALID_DEVID);
    if (ret == 0)
        return 0;
    else
        return -EINVAL;
}

WC_MAYBE_UNUSED static void km_hmac_exit_tfm(struct crypto_shash *tfm)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    wc_HmacFree(&p_ctx->wc_hmac);
    return;
}

WC_MAYBE_UNUSED static int km_hmac_init(struct shash_desc *desc) {
    int ret;
    struct km_sha_hmac_state *t_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);

    t_ctx->wc_hmac = malloc(sizeof *t_ctx->wc_hmac);
    if (! t_ctx->wc_hmac)
        return -ENOMEM;

    ret = wc_HmacCopy(&p_ctx->wc_hmac, t_ctx->wc_hmac);
    if (ret != 0) {
        free(t_ctx->wc_hmac);
        t_ctx->wc_hmac = NULL;
        return -EINVAL;
    }

    return 0;
}

WC_MAYBE_UNUSED static int km_hmac_update(struct shash_desc *desc, const u8 *data,
                          unsigned int len)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacUpdate(ctx->wc_hmac, data, len);

    if (ret == 0)
        return 0;
    else {
        km_hmac_free_tstate(ctx);
        return -EINVAL;
    }
}

WC_MAYBE_UNUSED static int km_hmac_final(struct shash_desc *desc, u8 *out) {
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacFinal(ctx->wc_hmac, out);

    km_hmac_free_tstate(ctx);

    if (ret == 0)
        return 0;
    else
        return -EINVAL;
}

WC_MAYBE_UNUSED static int km_hmac_finup(struct shash_desc *desc, const u8 *data,
                      unsigned int len, u8 *out)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacUpdate(ctx->wc_hmac, data, len);

    if (ret != 0)
        return -EINVAL;

    return km_hmac_final(desc, out);
}

WC_MAYBE_UNUSED static int km_hmac_digest(struct shash_desc *desc, const u8 *data,
                      unsigned int len, u8 *out)
{
    int ret = km_hmac_init(desc);
    if (ret != 0)
        return ret;
    return km_hmac_finup(desc, data, len, out);
}

WC_MAYBE_UNUSED static int hmac_sha3_test_once(void) {
    static int once = 0;
    static int ret;
    if (! once) {
        ret = hmac_sha3_test();
        once = 1;
    }
    return ret;
}

#define WC_LINUXKM_HMAC_IMPLEMENT(name, id, digest_size, block_size,      \
                                  this_cra_name, this_cra_driver_name,    \
                                  test_routine)                           \
                                                                          \
static int km_ ## name ## _setkey(struct crypto_shash *tfm, const u8 *key,\
                                  unsigned int keylen)                    \
{                                                                         \
    return linuxkm_hmac_setkey_common(tfm, id, key, keylen);              \
}                                                                         \
                                                                          \
static struct shash_alg name ## _alg =                                    \
{                                                                         \
    .digestsize     =       (digest_size),                                \
    .init           =       km_hmac_init,                                 \
    .update         =       km_hmac_update,                               \
    .final          =       km_hmac_final,                                \
    .finup          =       km_hmac_finup,                                \
    .digest         =       km_hmac_digest,                               \
    .setkey         =       km_ ## name ## _setkey,                       \
    .init_tfm       =       km_hmac_init_tfm,                             \
    .exit_tfm       =       km_hmac_exit_tfm,                             \
    .descsize       =       sizeof(struct km_sha_hmac_state),             \
    .base           =       {                                             \
        .cra_name        =      (this_cra_name),                          \
        .cra_driver_name =      (this_cra_driver_name),                   \
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,          \
        .cra_blocksize   =      (block_size),                             \
        .cra_ctxsize     =      sizeof(struct km_sha_hmac_pstate),        \
        .cra_module      =      THIS_MODULE                               \
    }                                                                     \
};                                                                        \
static int name ## _alg_loaded = 0;                                       \
                                                                          \
static int linuxkm_test_ ## name(void) {                                  \
    wc_test_ret_t ret = test_routine();                                   \
    if (ret >= 0)                                                         \
        return check_shash_driver_masking(NULL /* tfm */, this_cra_name,  \
                                          this_cra_driver_name);          \
    else {                                                                \
        wc_test_render_error_message("linuxkm_test_" #name " failed: ",   \
                                     ret);                                \
        return WC_TEST_RET_DEC_EC(ret);                                   \
    }                                                                     \
}                                                                         \
                                                                          \
struct wc_swallow_the_semicolon

#endif /* !NO_HMAC */

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha1_hmac, WC_SHA, WC_SHA_DIGEST_SIZE,
                              WC_SHA_BLOCK_SIZE, WOLFKM_SHA1_HMAC_NAME,
                              WOLFKM_SHA1_HMAC_DRIVER, hmac_sha_test);
#endif /* LINUXKM_LKCAPI_REGISTER_SHA1_HMAC */

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha2_224_hmac, WC_SHA224, WC_SHA224_DIGEST_SIZE,
                              WC_SHA224_BLOCK_SIZE, WOLFKM_SHA2_224_HMAC_NAME,
                              WOLFKM_SHA2_224_HMAC_DRIVER, hmac_sha224_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha2_256_hmac, WC_SHA256, WC_SHA256_DIGEST_SIZE,
                              WC_SHA256_BLOCK_SIZE, WOLFKM_SHA2_256_HMAC_NAME,
                              WOLFKM_SHA2_256_HMAC_DRIVER, hmac_sha256_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha2_384_hmac, WC_SHA384, WC_SHA384_DIGEST_SIZE,
                              WC_SHA384_BLOCK_SIZE, WOLFKM_SHA2_384_HMAC_NAME,
                              WOLFKM_SHA2_384_HMAC_DRIVER, hmac_sha384_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha2_512_hmac, WC_SHA512, WC_SHA512_DIGEST_SIZE,
                              WC_SHA512_BLOCK_SIZE, WOLFKM_SHA2_512_HMAC_NAME,
                              WOLFKM_SHA2_512_HMAC_DRIVER, hmac_sha512_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha3_224_hmac, WC_SHA3_224, WC_SHA3_224_DIGEST_SIZE,
                              WC_SHA3_224_BLOCK_SIZE, WOLFKM_SHA3_224_HMAC_NAME,
                              WOLFKM_SHA3_224_HMAC_DRIVER, hmac_sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha3_256_hmac, WC_SHA3_256, WC_SHA3_256_DIGEST_SIZE,
                              WC_SHA3_256_BLOCK_SIZE, WOLFKM_SHA3_256_HMAC_NAME,
                              WOLFKM_SHA3_256_HMAC_DRIVER, hmac_sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha3_384_hmac, WC_SHA3_384, WC_SHA3_384_DIGEST_SIZE,
                              WC_SHA3_384_BLOCK_SIZE, WOLFKM_SHA3_384_HMAC_NAME,
                              WOLFKM_SHA3_384_HMAC_DRIVER, hmac_sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    WC_LINUXKM_HMAC_IMPLEMENT(sha3_512_hmac, WC_SHA3_512, WC_SHA3_512_DIGEST_SIZE,
                              WC_SHA3_512_BLOCK_SIZE, WOLFKM_SHA3_512_HMAC_NAME,
                              WOLFKM_SHA3_512_HMAC_DRIVER, hmac_sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG

#ifdef HAVE_ENTROPY_MEMUSE
    #include <wolfssl/wolfcrypt/wolfentropy.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rng_bank.h>

#ifndef WC_RNG_BANK_DEFAULT_SUPPORT
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG requires WC_RNG_BANK_DEFAULT_SUPPORT.
#endif

static volatile int wc_linuxkm_rng_initing_default_bank_flag = 0;

#ifndef WC_LINUXKM_INITRNG_TIMEOUT_SEC
    #define WC_LINUXKM_INITRNG_TIMEOUT_SEC 30
#endif

static int linuxkm_affinity_lock(void *arg) {
    (void)arg;
    if (preempt_count() != 0)
        return ALREADY_E;
#if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_disable(); /* this actually makes irq_count() nonzero, so that
                        * DISABLE_VECTOR_REGISTERS() is superfluous, but
                        * don't depend on that.
                        */
#endif
    local_bh_disable();
    return 0;
}

static int linuxkm_affinity_get_id(void *arg, int *id) {
    (void)arg;
    *id = raw_smp_processor_id();
    return 0;
}

static int linuxkm_affinity_unlock(void *arg) {
    (void)arg;
    local_bh_enable();
#if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_enable();
#endif
    return 0;
}

static int wc_linuxkm_rng_bank_init(struct wc_rng_bank *ctx)
{
    int ret;
    word32 flags = WC_RNG_BANK_FLAG_CAN_WAIT;

    if (wc_linuxkm_rng_initing_default_bank_flag)
        flags |= WC_RNG_BANK_FLAG_NO_VECTOR_OPS;

    ret = wc_rng_bank_init(
        ctx, nr_cpu_ids + 4, flags, WC_LINUXKM_INITRNG_TIMEOUT_SEC,
        NULL /* heap */, INVALID_DEVID);

    if (ret == 0) {
        ret = wc_rng_bank_set_affinity_handlers(
            ctx,
            linuxkm_affinity_lock,
            linuxkm_affinity_get_id,
            linuxkm_affinity_unlock,
            NULL);
        if (ret == 0) {
            if (wc_linuxkm_rng_initing_default_bank_flag) {
                ret = wc_rng_bank_default_set(ctx);
                if (ret != 0) {
                    (void)wc_rng_bank_fini(ctx);
                    pr_err("ERROR: wc_rng_bank_default_set() in wc_linuxkm_rng_bank_init() returned err %d\n", ret);
                    WC_DUMP_BACKTRACE_NONDEBUG;
                }
            }
        }
        else {
            (void)wc_rng_bank_fini(ctx);
            pr_err("ERROR: wc_rng_bank_set_affinity_handlers() in wc_linuxkm_rng_bank_init() returned err %d\n", ret);
            WC_DUMP_BACKTRACE_NONDEBUG;
        }
    }
    else {
        pr_err("ERROR: wc_rng_bank_init() in wc_linuxkm_rng_bank_init() returned err %d\n", ret);
        if (ret == WC_NO_ERR_TRACE(MEMORY_E))
            ret = -ENOMEM;
        else if (ret == WC_NO_ERR_TRACE(WC_TIMEOUT_E))
            ret = -ETIMEDOUT;
        else if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
            ret = -EINTR;
        else
            ret = -EINVAL;
    }

    return ret;
}

static int wc_linuxkm_drbg_init_tfm(struct crypto_tfm *tfm)
{
    return wc_linuxkm_rng_bank_init((struct wc_rng_bank *)crypto_tfm_ctx(tfm));
}

static void wc_linuxkm_drbg_exit_tfm(struct crypto_tfm *tfm)
{
    struct wc_rng_bank *ctx = (struct wc_rng_bank *)crypto_tfm_ctx(tfm);
    int ret;

    ret = wc_rng_bank_default_clear(ctx);
    if (ret && (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)))
        pr_err("ERROR: wc_rng_bank_default_clear() in wc_linuxkm_drbg_exit_tfm() returned unexpected code %d\n", ret);

    ret = wc_rng_bank_fini(ctx);

    if (ret != 0)
        pr_err("ERROR: wc_rng_bank_fini() in wc_linuxkm_drbg_exit_tfm() returned err %d\n", ret);

    return;
}

static int wc_linuxkm_drbg_default_instance_registered = 0;

static struct wc_rng_bank_inst *linuxkm_get_drbg(struct wc_rng_bank *ctx) {
    int err;
    struct wc_rng_bank_inst *ret;
    word32 flags =
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_CAN_WAIT |
        WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST;

    if (preempt_count() == 0)
        flags |= WC_RNG_BANK_FLAG_AFFINITY_LOCK;
    else
        flags |= WC_RNG_BANK_FLAG_NO_VECTOR_OPS;

    err = wc_rng_bank_checkout(ctx, &ret, 0, WC_LINUXKM_INITRNG_TIMEOUT_SEC, flags);

    if (err != 0) {
        pr_err("ERROR: wc_rng_bank_checkout() in linuxkm_get_drbg() returned err %d.\n", err);
        WC_DUMP_BACKTRACE_NONDEBUG;
        return NULL;
    }

    return ret;
}

static void linuxkm_put_drbg(struct wc_rng_bank *ctx, struct wc_rng_bank_inst **drbg) {
    int ret = wc_rng_bank_checkin(ctx, drbg);
    if (ret != 0) {
        pr_err("ERROR: wc_rng_bank_checkin() in linuxkm_put_drbg() returned err %d.\n", ret);
        WC_DUMP_BACKTRACE_NONDEBUG;
    }
}

#if defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT) && defined(HAVE_HASHDRBG)

int wc_linux_kernel_rng_is_wolfcrypt(struct crypto_rng *rng) {
    if (rng &&
        wc_linuxkm_drbg_default_instance_registered &&
        (rng->base.__crt_alg->cra_init == wc_linuxkm_drbg_init_tfm))
    {
        return 1;
    }
    else {
        return 0;
    }
}

#ifndef WC_DRBG_BANKREF
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT requires WC_DRBG_BANKREF support.
#endif

WC_MAYBE_UNUSED static int linuxkm_InitRng_DefaultRef(WC_RNG* rng) {
    struct wc_rng_bank *ctx;
    int ret = wc_rng_bank_default_checkout(&ctx);

    if (ret == 0) {
        ret = wc_InitRng_BankRef(ctx, rng);
        (void)wc_rng_bank_default_checkin(&ctx);
        return ret;
    }
    else {
        pr_warn_once("WARNING: linuxkm_InitRng_DefaultRef() called with null default_wc_rng_bank; falling through to wc_InitRng().\n");
        return wc_InitRng(rng);
    }

    __builtin_unreachable();
}
#define LKCAPI_INITRNG(rng) linuxkm_InitRng_DefaultRef(rng)

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT && HAVE_HASHDRBG */

static int wc_linuxkm_drbg_generate(struct wc_rng_bank *ctx,
                                    const u8 *src, unsigned int slen,
                                    u8 *dst, unsigned int dlen)
{
    int ret, retried = 0;
    struct wc_rng_bank_inst *drbg = linuxkm_get_drbg(ctx);

    if (! drbg) {
        pr_err_once("BUG: linuxkm_get_drbg() failed.\n");
        return -EFAULT;
    }

    if (slen > 0) {
        ret = wc_RNG_DRBG_Reseed(WC_RNG_BANK_INST_TO_RNG(drbg), src, slen);
        if (ret != 0) {
            pr_warn_once("WARNING: wc_RNG_DRBG_Reseed returned %d\n",ret);
            ret = -EINVAL;
            goto out;
        }
    }

    for (;;) {
        #define RNG_MAX_BLOCK_LEN_ROUNDED (RNG_MAX_BLOCK_LEN & ~0xfU)
        if (dlen > RNG_MAX_BLOCK_LEN_ROUNDED) {
            ret = wc_RNG_GenerateBlock(WC_RNG_BANK_INST_TO_RNG(drbg), dst, RNG_MAX_BLOCK_LEN_ROUNDED);
            if (ret == 0) {
                dlen -= RNG_MAX_BLOCK_LEN_ROUNDED;
                dst += RNG_MAX_BLOCK_LEN_ROUNDED;
            }
        }
        #undef RNG_MAX_BLOCK_LEN_ROUNDED
        else {
            ret = wc_RNG_GenerateBlock(WC_RNG_BANK_INST_TO_RNG(drbg), dst, dlen);
            if (ret == 0)
                dlen = 0;
        }

        if (dlen == 0)
            break;

        if (ret == 0)
            continue;

        if (unlikely(ret == WC_NO_ERR_TRACE(RNG_FAILURE_E)) && (! retried)) {
            if (slen > 0)
                break;

            retried = 1;

            ret = wc_rng_bank_inst_reinit(ctx,
                                          drbg,
                                          WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                                          WC_RNG_BANK_FLAG_CAN_WAIT);

            if (ret == 0) {
                pr_warn("WARNING: reinitialized DRBG #%d after RNG_FAILURE_E from wc_RNG_GenerateBlock().\n", raw_smp_processor_id());
                continue;
            }
            else {
                pr_warn_once("ERROR: reinitialization of DRBG #%d after RNG_FAILURE_E failed with ret %d.\n", raw_smp_processor_id(), ret);
                ret = -EINVAL;
                break;
            }
        }
        else {
            pr_warn_once("ERROR: wc_linuxkm_drbg_generate() wc_RNG_GenerateBlock returned %d.\n",ret);
            ret = -EINVAL;
            break;
        }
    }

out:

    linuxkm_put_drbg(ctx, &drbg);

    return ret;
}

static int wc_linuxkm_drbg_generate_tfm(struct crypto_rng *tfm,
                        const u8 *src, unsigned int slen,
                        u8 *dst, unsigned int dlen)
{
    if (tfm->base.__crt_alg->cra_init != wc_linuxkm_drbg_init_tfm)
    {
        pr_err_once("BUG: mismatched tfm.\n");
        return -EFAULT;
    }

    return wc_linuxkm_drbg_generate((struct wc_rng_bank *)crypto_rng_ctx(tfm),
                                    src, slen, dst, dlen);
}

static int wc_linuxkm_drbg_seed(struct wc_rng_bank *ctx,
                        const u8 *seed, unsigned int slen)
{
    int ret;

    if (slen == 0)
        return 0;

    ret = wc_rng_bank_seed(ctx, seed, slen, WC_LINUXKM_INITRNG_TIMEOUT_SEC, WC_RNG_BANK_FLAG_CAN_WAIT);
    if (ret != 0) {
        pr_err("wc_rng_bank_seed() in wc_linuxkm_drbg_seed() returned err %d.\n", ret);
        ret = -EINVAL;
    }

    return ret;
}

static int wc_linuxkm_drbg_seed_tfm(struct crypto_rng *tfm,
                                    const u8 *seed, unsigned int slen)
{
    if (tfm->base.__crt_alg->cra_init != wc_linuxkm_drbg_init_tfm)
    {
        pr_err_once("BUG: mismatched tfm.\n");
        return -EFAULT;
    }

    return wc_linuxkm_drbg_seed((struct wc_rng_bank *)crypto_rng_ctx(tfm),
                                seed, slen);
}

static struct rng_alg wc_linuxkm_drbg = {
    .generate = wc_linuxkm_drbg_generate_tfm,
    .seed =     wc_linuxkm_drbg_seed_tfm,
    .seedsize = 0,
    .base           =       {
        .cra_name        =      WOLFKM_STDRNG_NAME,
        .cra_driver_name =      WOLFKM_STDRNG_DRIVER,
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
        .cra_ctxsize     =      sizeof(struct wc_rng_bank),
        .cra_init        =      wc_linuxkm_drbg_init_tfm,
        .cra_exit        =      wc_linuxkm_drbg_exit_tfm,
        .cra_module      =      THIS_MODULE
    }
};
static int wc_linuxkm_drbg_loaded = 0;

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES

#ifndef WOLFSSL_SMALL_STACK_CACHE
    /* WOLFSSL_SMALL_STACK_CACHE eliminates post-init heap allocations in SHA-2
     * and the Hash DRBG, fixing circular call dependencies between
     * get_random_u32() from kernel heap and wolfCrypt DRBG.
     */
    #error LINUXKM_DRBG_GET_RANDOM_BYTES requires WOLFSSL_SMALL_STACK_CACHE.
#endif

#if !(defined(HAVE_ENTROPY_MEMUSE) || defined(HAVE_INTEL_RDSEED) ||    \
      defined(HAVE_AMD_RDSEED) || defined(WC_LINUXKM_RDSEED_IN_GLUE_LAYER))
    #error LINUXKM_DRBG_GET_RANDOM_BYTES requires a native or intrinsic entropy source.
#endif

#if defined(WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS) && defined(WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES)
    #error Conflicting callback model for LINUXKM_DRBG_GET_RANDOM_BYTES.
#endif

#ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS

static int wc__get_random_bytes(void *buf, size_t len)
{
    struct wc_rng_bank *current_default_wc_rng_bank;
    int ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc__get_random_bytes() returned %d.\n", ret);
#endif
        return -EFAULT;
    }
    else {
        ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, buf, len);
        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);
        if (ret) {
            pr_warn("BUG: wc__get_random_bytes falling through to native get_random_bytes with wc_linuxkm_drbg_default_instance_registered, ret=%d.\n", ret);
        }
        return ret;
    }
    __builtin_unreachable();
}

/* used by kernel >=5.14.0 */
static ssize_t wc_get_random_bytes_user(struct iov_iter *iter) {
    struct wc_rng_bank *current_default_wc_rng_bank;
    int ret;
    if (unlikely(!iov_iter_count(iter)))
        return 0;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_get_random_bytes_user() returned %d.\n", ret);
#endif
        return -ECANCELED;
    }
    else {
        size_t this_copied, total_copied = 0;
        byte block[WC_SHA256_BLOCK_SIZE];

        for (;;) {
            ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, block, sizeof block);
            if (unlikely(ret != 0)) {
                pr_err("ERROR: wc_get_random_bytes_user() wc_linuxkm_drbg_generate() returned %d.\n", ret);
                break;
            }

            /* note copy_to_iter() cannot be safely executed with
             * DISABLE_VECTOR_REGISTERS() or kprobes status, i.e.
             * irq_count() must be zero here.
             */
            this_copied = copy_to_iter(block, sizeof(block), iter);
            total_copied += this_copied;
            if (!iov_iter_count(iter) || this_copied != sizeof(block))
                break;

            wc_static_assert(PAGE_SIZE % sizeof(block) == 0);
            if (total_copied % PAGE_SIZE == 0) {
                if (signal_pending(current))
                    break;
                cond_resched();
            }
        }

        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);

        ForceZero(block, sizeof(block));

        if (total_copied == 0) {
            if (ret == 0)
                ret = -EFAULT;
            else
                ret = -ECANCELED;
        }

        if (ret == 0)
            ret = (ssize_t)total_copied;

        return ret;
    }
    __builtin_unreachable();
}

/* used by kernel 4.9.0-5.13.x */
static ssize_t wc_extract_crng_user(void __user *buf, size_t nbytes) {
    int ret;
    struct wc_rng_bank *current_default_wc_rng_bank;
    if (unlikely(!nbytes))
        return 0;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_extract_crng_user() returned %d.\n", ret);
#endif
        return -ECANCELED;
    }
    else {
        size_t this_copied, total_copied = 0;
        byte block[WC_SHA256_BLOCK_SIZE];

        for (;;) {
            ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, block, sizeof block);
            if (unlikely(ret != 0)) {
                pr_err("ERROR: wc_extract_crng_user() wc_linuxkm_drbg_generate() returned %d.\n", ret);
                break;
            }

            this_copied = min(nbytes - total_copied, sizeof(block));
            if (copy_to_user((byte *)buf + total_copied, block, this_copied)) {
                ret = -EFAULT;
                break;
            }
            total_copied += this_copied;
            if (this_copied != sizeof(block))
                break;

            wc_static_assert(PAGE_SIZE % sizeof(block) == 0);
            if (total_copied % PAGE_SIZE == 0) {
                if (signal_pending(current))
                    break;
                cond_resched();
            }
        }

        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);

        ForceZero(block, sizeof(block));

        if ((total_copied == 0) && (ret == 0)) {
            ret = -ECANCELED;
        }

        if (ret == 0)
            ret = (ssize_t)total_copied;

        return ret;
    }
    __builtin_unreachable();
}

static int wc_mix_pool_bytes(const void *buf, size_t len) {
    int ret;
    struct wc_rng_bank *ctx;
    size_t i;
    int n;
    int can_sleep = (preempt_count() == 0);

    if (len == 0)
        return 0;

    ret = wc_rng_bank_default_checkout(&ctx);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_mix_pool_bytes() returned %d.\n", ret);
#endif
        return -EFAULT;
    }

    ret = 0;

    for (n = ctx->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_bank_inst *drbg;

        int V_offset;

        if (wc_rng_bank_checkout(ctx, &drbg, n, 0, WC_RNG_BANK_FLAG_NONE) != 0)
            continue;

#ifdef WOLFSSL_DRBG_SHA512
        if (WC_RNG_BANK_INST_TO_RNG(drbg)->drbgType == WC_DRBG_SHA512) {
            for (i = 0, V_offset = 0; i < len; ++i) {
                ((struct DRBG_SHA512_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg512)->V[V_offset++] += ((byte *)buf)[i];
                if (V_offset == (int)sizeof ((struct DRBG_SHA512_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg512)->V)
                    V_offset = 0;
            }
        }
        else
#endif /* WOLFSSL_DRBG_SHA512 */
        {
            for (i = 0, V_offset = 0; i < len; ++i) {
                ((struct DRBG_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg)->V[V_offset++] += ((byte *)buf)[i];
                if (V_offset == (int)sizeof ((struct DRBG_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg)->V)
                    V_offset = 0;
            }
        }

        wc_rng_bank_checkin(ctx, &drbg);
        if (can_sleep) {
            if (signal_pending(current)) {
                ret = -EINTR;
                break;
            }
            cond_resched();
        }
    }

    (void)wc_rng_bank_default_checkin(&ctx);

    return ret;
}

static int wc_crng_reseed(void) {
    struct wc_rng_bank *ctx;
    int can_sleep = (preempt_count() == 0);
    int ret = wc_rng_bank_default_checkout(&ctx);

    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_crng_reseed() returned %d.\n", ret);
#endif
        return -EFAULT;
    }

    ret = wc_rng_bank_reseed(ctx, WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                             can_sleep
                             ?
                             WC_RNG_BANK_FLAG_CAN_WAIT
                             :
                             WC_RNG_BANK_FLAG_NONE);

    (void)wc_rng_bank_default_checkin(&ctx);

    if (ret != 0) {
        pr_err("ERROR: wc_rng_bank_reseed() returned err %d.\n", ret);
        return -EINVAL;
    }
    else {
        return 0;
    }
}

struct wolfssl_linuxkm_random_bytes_handlers random_bytes_handlers = {
    ._get_random_bytes = wc__get_random_bytes,

    /* pass handlers for both old and new user-mode rng, and let the kernel
     * patch decide which one to use.
     */
    .get_random_bytes_user = wc_get_random_bytes_user,
    .extract_crng_user = wc_extract_crng_user,

    .mix_pool_bytes = wc_mix_pool_bytes,
    /* .credit_init_bits not implemented */
    .crng_reseed = wc_crng_reseed
};

static int wc_get_random_bytes_callbacks_installed = 0;

#elif defined(WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES)

#ifndef CONFIG_KPROBES
    #error WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES without CONFIG_KPROBES.
#endif

#ifndef CONFIG_X86
    #error WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES requires CONFIG_X86.
#endif

static int wc_get_random_bytes_by_kprobe(struct kprobe *p, struct pt_regs *regs)
{
    void *buf = (void *)regs->di;
    size_t len = (size_t)regs->si;

    if (wc_linuxkm_drbg_default_instance_registered) {
        int ret = crypto_rng_get_bytes(crypto_default_rng, buf, len);
        if (ret == 0) {
            regs->ip = (unsigned long)p->addr + p->ainsn.size;
            return 1; /* Handled. */
        }
        pr_warn("BUG: wc_get_random_bytes_by_kprobe falling through to native get_random_bytes with wc_linuxkm_drbg_default_instance_registered, ret=%d.\n", ret);
    }
    else
        pr_warn("BUG: wc_get_random_bytes_by_kprobe called without wc_linuxkm_drbg_default_instance_registered.\n");

    /* Not handled.  Fall through to native implementation, given
     * that the alternative is an immediate kernel panic.
     *
     * Because we're jumping straight to the native implementation, we need to
     * restore the argument registers first.
     */

    asm volatile (
        "movq %0, %%rsi\n\t"
        "movq %1, %%rdi\n\t"
        "pushq %2\n\t"       /* Push original flags */
        "popfq\n\t"          /* Restore flags */
        :
        : "r" (regs->si),
          "r" (regs->di),
          "r" (regs->flags)
        : "memory"
    );

    return 0;
}

static struct kprobe wc_get_random_bytes_kprobe = {
    .symbol_name = "get_random_bytes",
    .pre_handler = wc_get_random_bytes_by_kprobe,
};
static int wc_get_random_bytes_kprobe_installed = 0;

/* note, we can't kprobe _get_random_bytes() because it's inlined. */

#ifdef WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE

#warning Interception of /dev/random, /dev/urandom, and getrandom() using \
    wc_get_random_bytes_user_kretprobe_enter() is known to destabilize large \
    one-shot reads of randomness, due to conflicts with the kretprobe run \
    context (uninterruptible).  In particular, cryptsetup will fail on \
    /dev/urandom reads.  When in doubt, patch your kernel, activating \
    WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS.

struct wc_get_random_bytes_user_kretprobe_ctx {
    unsigned long retval;
};

static int wc_get_random_bytes_user_kretprobe_enter(struct kretprobe_instance *p, struct pt_regs *regs)
{
    struct iov_iter *iter = (struct iov_iter *)regs->di;
    struct wc_get_random_bytes_user_kretprobe_ctx *ctx = (struct wc_get_random_bytes_user_kretprobe_ctx *)p->data;

    int ret;
    size_t this_copied = (size_t)(-1L), total_copied = 0;
    byte block[WC_SHA256_BLOCK_SIZE];

    if (unlikely(!wc_linuxkm_drbg_default_instance_registered)) {
        pr_warn("BUG: wc_get_random_bytes_user_kretprobe_enter() without wc_linuxkm_drbg_default_instance_registered.\n");
        ret = -ENOENT;
        goto out;
    }

    if (unlikely(!iov_iter_count(iter))) {
        ret = 0;
        goto out;
    }

    for (;;) {
        ret = crypto_rng_get_bytes(crypto_default_rng, block, sizeof block);
        if (ret != 0) {
            pr_err("ERROR: wc_get_random_bytes_user_kretprobe_enter() crypto_rng_get_bytes() returned %d.\n", ret);
            break;
        }

        /* note, in a kprobe/kretprobe, this can persistently return 0 (no
         * progress) with nonzero iov_iter_count(iter).
         */
        this_copied = copy_to_iter(block, sizeof(block), iter);

        total_copied += this_copied;
        if ((!iov_iter_count(iter)) || (this_copied != sizeof block))
            break;

        wc_static_assert(PAGE_SIZE % sizeof(block) == 0);
        /* we are in a kprobe context here, so we can't do any scheduler ops. */
        #if 0
        if (total_copied % PAGE_SIZE == 0) {
            if (signal_pending(current))
                break;
            cond_resched();
        }
        #endif
    }

    ForceZero(block, sizeof(block));

    if ((total_copied == 0) && (ret == 0))
        total_copied = (size_t)(-EFAULT);

out:

    if ((ret != 0) && (this_copied == (size_t)(-1L))) {
        /* crypto_rng_get_bytes() failed on the first call, before any update to the iov_iter. */
        pr_warn("WARNING: wc_get_random_bytes_user_kretprobe_enter() falling through to native get_random_bytes_user().\n");
        return -EFAULT;
    }

    /* if any progress was made, report that progress.  crypto_rng_get_bytes()
     * failing after some progress is benign.
     */

    regs->ax = ctx->retval = total_copied;

    /* skip the native get_random_bytes_user() by telling kprobes to jump
     * straight to the return address.
     */
    regs->ip = (unsigned long)get_kretprobe_retaddr(p);

    /* return 0 to tell kprobes that the handler succeeded, so that
     * wc_get_random_bytes_user_kretprobe_exit() will be called -- fixing up the
     * return value (regs->ax) is necessary.
     */
    return 0;
}

static int wc_get_random_bytes_user_kretprobe_exit(struct kretprobe_instance *p, struct pt_regs *regs)
{
    struct wc_get_random_bytes_user_kretprobe_ctx *ctx = (struct wc_get_random_bytes_user_kretprobe_ctx *)p->data;

    if (unlikely(!wc_linuxkm_drbg_default_instance_registered)) {
        pr_warn("BUG: wc_get_random_bytes_user_kretprobe_exit without wc_linuxkm_drbg_default_instance_registered.\n");
        return -EFAULT;
    }

    regs->ax = ctx->retval;

    return 0;
}

static struct kretprobe wc_get_random_bytes_user_kretprobe = {
    .kp.symbol_name = "get_random_bytes_user",
    .entry_handler  = wc_get_random_bytes_user_kretprobe_enter,
    .handler        = wc_get_random_bytes_user_kretprobe_exit,
    .data_size      = sizeof(struct wc_get_random_bytes_user_kretprobe_ctx)
};
static int wc_get_random_bytes_user_kretprobe_installed = 0;

#endif /* WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE */

#else /* !WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS && !(CONFIG_KPROBES && CONFIG_X86) */
    #error LINUXKM_DRBG_GET_RANDOM_BYTES implementation missing for target architecture/configuration.
#endif

#endif /* LINUXKM_DRBG_GET_RANDOM_BYTES */

#if defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0))
static struct wc_rng_bank default_bank;
static int default_bank_inited;
#endif

static int wc_linuxkm_drbg_startup(void)
{
    int ret;

    if (wc_linuxkm_drbg_loaded) {
        pr_err("ERROR: wc_linuxkm_drbg_set_default called with wc_linuxkm_drbg_loaded.\n");
        return -EBUSY;
    }

    ret = random_test();
    if (ret) {
        pr_err("ERROR: self-test for %s failed "
                           "with return code %d.\n",
                           wc_linuxkm_drbg.base.cra_driver_name, ret);
        return -EINVAL;
    }

    ret = crypto_register_rng(&wc_linuxkm_drbg);
    if (ret != 0) {
        pr_err("ERROR: crypto_register_rng: %d\n", ret);
        return ret;
    }

    {
        struct crypto_rng *tfm = crypto_alloc_rng(wc_linuxkm_drbg.base.cra_name, 0, 0);
        if (IS_ERR(tfm)) {
            pr_err("ERROR: allocating rng algorithm %s failed: %ld\n",
                   wc_linuxkm_drbg.base.cra_name, PTR_ERR(tfm));
            ret = PTR_ERR(tfm);
            tfm = NULL;
        }
        else
            ret = 0;
#ifndef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
        if (! ret) {
            const char *actual_driver_name = crypto_tfm_alg_driver_name(crypto_rng_tfm(tfm));
            if (strcmp(actual_driver_name, wc_linuxkm_drbg.base.cra_driver_name)) {
                pr_err("ERROR: unexpected implementation for %s: %s (expected %s)\n",
                       wc_linuxkm_drbg.base.cra_name,
                       actual_driver_name,
                       wc_linuxkm_drbg.base.cra_driver_name);
                ret = -ENOENT;
            }
        }
#endif

        if (! ret) {
            u8 buf1[16], buf2[17];
            int i, j;

            memset(buf1, 0, sizeof buf1);
            memset(buf2, 0, sizeof buf2);

            ret = crypto_rng_generate(tfm, NULL, 0, buf1, (unsigned int)sizeof buf1);
            if (! ret)
                ret = crypto_rng_generate(tfm, buf1, (unsigned int)sizeof buf1, buf2, (unsigned int)sizeof buf2);
            if (! ret) {
                if (memcmp(buf1, buf2, sizeof buf1) == 0)
                    ret = -EBADMSG;
            }

            if (! ret) {
                /*
                 * Given a correctly functioning PRNG (perfectly rectangular
                 * PDF), There's a 94% chance that 17 random bytes will all be
                 * nonzero, or a 6% chance that at least one of them will be
                 * zero.  Iterate up to 20 times to push that 6% chance to 1.5
                 * E-24, an effective certainty on a functioning PRNG.  With the
                 * contributions from iterations on shorter blocks, the overall
                 * expectation of failure is 2.13 E-24.
                 */
                for (i = 1; i <= (int)sizeof buf2; ++i) {
                    for (j = 0; j < 20; ++j) {
                        memset(buf2, 0, (size_t)i);
                        ret = crypto_rng_generate(tfm, NULL, 0, buf2, (unsigned int)i);
                        if (ret)
                            break;
                        ret = -EBADMSG;
                        if (! memchr(buf2, 0, (size_t)i)) {
                            ret = 0;
                            break;
                        }
                    }
                    if (ret)
                        break;
                }

                if (ret)
                    pr_err("ERROR: wc_linuxkm_drbg_startup: PRNG quality test failed, block length %d, iters %d, ret %d\n",
                           i, j, ret);
            }
        }

        if (tfm)
            crypto_free_rng(tfm);

        if (ret) {
            crypto_unregister_rng(&wc_linuxkm_drbg);
            return ret;
        }

    }

    wc_linuxkm_drbg_loaded = 1;

    WOLFKM_INSTALL_NOTICE(wc_linuxkm_drbg);

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    /* for the default RNG, make sure we don't cache an underlying SHA256
     * method that uses vector insns (forbidden from irq handlers).
     */
    wc_linuxkm_rng_initing_default_bank_flag = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 0)

    ret = crypto_del_default_rng();
    if (ret) {
        wc_linuxkm_rng_initing_default_bank_flag = 0;
        pr_err("ERROR: crypto_del_default_rng returned %d\n", ret);
        return ret;
    }

    ret = crypto_get_default_rng();

    wc_linuxkm_rng_initing_default_bank_flag = 0;

    if (ret) {
        pr_err("ERROR: crypto_get_default_rng returned %d\n", ret);
        return ret;
    }

    {
        int cur_refcnt = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);
        if (cur_refcnt < 2) {
            pr_err("ERROR: wc_linuxkm_drbg refcnt = %d after crypto_get_default_rng()\n", cur_refcnt);
            crypto_put_default_rng();
            return -EINVAL;
        }
    }

    if (! crypto_default_rng) {
        pr_err("ERROR: crypto_default_rng is null\n");
        crypto_put_default_rng();
        return -EINVAL;
    }

    if (crypto_default_rng->base.__crt_alg->cra_init != wc_linuxkm_drbg_init_tfm) {
        pr_err("ERROR: %s NOT registered as systemwide default stdrng -- found \"%s\".\n", wc_linuxkm_drbg.base.cra_driver_name, crypto_tfm_alg_driver_name(&crypto_default_rng->base));
        crypto_put_default_rng();
        return -EINVAL;
    }

    crypto_put_default_rng();

#else /* >= 7.1.0 */

#ifdef CONFIG_CRYPTO_FIPS
    if (fips_enabled) {
        char buf[16];

        ret = crypto_del_default_rng();
        if (ret) {
            wc_linuxkm_rng_initing_default_bank_flag = 0;
            pr_err("ERROR: crypto_del_default_rng returned %d\n", ret);
            return ret;
        }

        ret = __crypto_stdrng_get_bytes(buf, (unsigned int)sizeof buf);

        wc_linuxkm_rng_initing_default_bank_flag = 0;

        if (ret) {
            pr_err("ERROR: __crypto_stdrng_get_bytes returned %d\n", ret);
            return ret;
        }
    }
    else
#endif /* CONFIG_CRYPTO_FIPS */
    {
        ret = wc_linuxkm_rng_bank_init(&default_bank);
        wc_linuxkm_rng_initing_default_bank_flag = 0;
        if (ret) {
            pr_err("ERROR: wc_linuxkm_rng_bank_init returned %d\n", ret);
            return ret;
        }
        default_bank_inited = 1;
    }

#endif /* >= 7.1.0 */

    {
        struct wc_rng_bank *current_default_wc_rng_bank;
        ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
        if (ret)
            pr_err("ERROR: wc_rng_bank_default_checkout() after default stdrng registration returned %d\n", ret);
        else {
            ret = wc_rng_bank_default_checkin(&current_default_wc_rng_bank);
            if (ret)
                pr_err("ERROR: wc_rng_bank_default_checkin() after wc_rng_bank_default_checkout() returned %d\n", ret);
        }
        if (ret != 0) {
#if defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT) && \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0))
            if (default_bank_inited) {
                (void)wc_rng_bank_default_clear(&default_bank);
                (void)wc_rng_bank_fini(&default_bank);
                default_bank_inited = 0;
            }
#endif
            return -ECANCELED;
        }
    }

    wc_linuxkm_drbg_default_instance_registered = 1;
    pr_info("%s registered as systemwide default stdrng.\n", wc_linuxkm_drbg.base.cra_driver_name);
    pr_info("libwolfssl: to unload module, first echo 1 > /sys/module/libwolfssl/deinstall_algs\n");

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES

    #ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS

    ret = wolfssl_linuxkm_register_random_bytes_handlers(
        THIS_MODULE,
        &random_bytes_handlers);

    if (ret == 0) {
        wc_get_random_bytes_callbacks_installed = 1;
        pr_info("libwolfssl: kernel global random_bytes handlers installed.\n");
    }
    else {
        pr_err("ERROR: wolfssl_linuxkm_register_random_bytes_handlers() failed: %d\n", ret);
        return ret;
    }

    #elif defined(WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES)

    ret = register_kprobe(&wc_get_random_bytes_kprobe);
    if (ret == 0) {
        wc_get_random_bytes_kprobe_installed = 1;
        pr_info("libwolfssl: wc_get_random_bytes_kprobe installed\n");
    }
    else {
        pr_err("ERROR: wc_get_random_bytes_kprobe installation failed: %d\n", ret);
        return ret;
    }

    #ifdef WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE
    ret = register_kretprobe(&wc_get_random_bytes_user_kretprobe);
    if (ret == 0) {
        wc_get_random_bytes_user_kretprobe_installed = 1;
        pr_info("libwolfssl: wc_get_random_bytes_user_kretprobe installed\n");
    }
    else {
        pr_err("ERROR: wc_get_random_bytes_user_kprobe installation failed: %d\n", ret);
        return ret;
    }
    #endif /* WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE */

    #else
        #error LINUXKM_DRBG_GET_RANDOM_BYTES missing installation calls.
    #endif

    #ifdef DEBUG_DRBG_RESEEDS
    {
        byte scratch[4];
        ret = wc__get_random_bytes(scratch, sizeof(scratch));
        if (ret != 0) {
            pr_err("ERROR: wc__get_random_bytes() returned %d\n", ret);
            return -EINVAL;
        }
        ret = wc_mix_pool_bytes(scratch, sizeof(scratch));
        if (ret != 0) {
            pr_err("ERROR: wc_mix_pool_bytes() returned %d\n", ret);
            return -EINVAL;
        }
        ret = wc_crng_reseed();
        if (ret != 0) {
            pr_err("ERROR: wc_crng_reseed() returned %d\n", ret);
            return -EINVAL;
        }
        ret = wc__get_random_bytes(scratch, sizeof(scratch));
        if (ret != 0) {
            pr_err("ERROR: wc__get_random_bytes() returned %d\n", ret);
            return -EINVAL;
        }
    }
    #endif

#endif /* LINUXKM_DRBG_GET_RANDOM_BYTES */

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

    return 0;
}

static int wc_linuxkm_drbg_cleanup(void) {
    int cur_refcnt;

    if (! wc_linuxkm_drbg_loaded) {
        pr_err("ERROR: wc_linuxkm_drbg_cleanup called with ! wc_linuxkm_drbg_loaded\n");
        return -EINVAL;
    }

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    if (wc_linuxkm_drbg_default_instance_registered) {
        /* These deinstallations are racey, but the kernel doesn't provide any other
         * way.  It's written to be retryable.
         */
        int ret;

    #ifdef LINUXKM_DRBG_GET_RANDOM_BYTES

        /* we need to unregister the get_random_bytes handlers first to remove
         * the chance that a caller will race with the crypto_unregister_rng()
         * below.
         */

        #ifdef WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS

        if (wc_get_random_bytes_callbacks_installed) {
            ret = wolfssl_linuxkm_unregister_random_bytes_handlers();
            if (ret != 0) {
                pr_err("ERROR: wolfssl_linuxkm_unregister_random_bytes_handlers returned %d\n", ret);
                return ret;
            }
            pr_info("libwolfssl: kernel global random_bytes handlers uninstalled\n");
            wc_get_random_bytes_callbacks_installed = 0;
        }

        #elif defined(WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES)

        if (wc_get_random_bytes_kprobe_installed) {
            unregister_kprobe(&wc_get_random_bytes_kprobe);
            barrier();
            wc_get_random_bytes_kprobe_installed = 0;
            pr_info("libwolfssl: wc_get_random_bytes_kprobe uninstalled\n");
        }
        #ifdef WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE
        if (wc_get_random_bytes_user_kretprobe_installed) {
            unregister_kretprobe(&wc_get_random_bytes_user_kretprobe);
            barrier();
            wc_get_random_bytes_user_kretprobe_installed = 0;
            pr_info("libwolfssl: wc_get_random_bytes_user_kretprobe uninstalled\n");
        }
        #endif /* WOLFSSL_LINUXKM_USE_GET_RANDOM_USER_KRETPROBE */

        #else
            #error LINUXKM_DRBG_GET_RANDOM_BYTES missing deinstallation calls.
        #endif

    #endif /* LINUXKM_DRBG_GET_RANDOM_BYTES */

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 0)
        ret = crypto_del_default_rng();
        if (ret) {
            pr_err("ERROR: crypto_del_default_rng failed: %d\n", ret);
            return ret;
        }
#else /* >= 7.1.0 */

#ifdef CONFIG_CRYPTO_FIPS
        if (fips_enabled) {
            ret = crypto_del_default_rng();
            if (ret) {
                pr_err("ERROR: crypto_del_default_rng failed: %d\n", ret);
                return ret;
            }
        }
        else
#endif /* CONFIG_CRYPTO_FIPS */
        if (default_bank_inited) {
            ret = wc_rng_bank_default_clear(&default_bank);
            if (ret)
                pr_err("ERROR: wc_rng_bank_default_clear in wc_linuxkm_drbg_cleanup failed: %d\n", ret);
            else {
                ret = wc_rng_bank_fini(&default_bank);
                if (ret)
                    pr_err("ERROR: wc_rng_bank_fini in wc_linuxkm_drbg_cleanup failed: %d\n", ret);
            }
            default_bank_inited = 0;
        }
#endif /* >= 7.1.0 */

        wc_linuxkm_drbg_default_instance_registered = 0;
    }
#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

    cur_refcnt = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);

    if (cur_refcnt != 1) {
        pr_err("ERROR: wc_linuxkm_drbg_cleanup called with refcnt = %d\n", cur_refcnt);
        return -EBUSY;
    }

    crypto_unregister_rng(&wc_linuxkm_drbg);

    if (! (wc_linuxkm_drbg.base.cra_flags & CRYPTO_ALG_DEAD)) {
        pr_warn("WARNING: wc_linuxkm_drbg_cleanup: after crypto_unregister_rng, wc_linuxkm_drbg isn't dead.\n");
        return -EBUSY;
    }

    wc_linuxkm_drbg_loaded = 0;

    return 0;
}

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG */

#ifndef LKCAPI_INITRNG
    #define LKCAPI_INITRNG(rng) wc_InitRng(rng)
#endif

#endif /* !WC_SKIP_INCLUDED_C_FILES */
