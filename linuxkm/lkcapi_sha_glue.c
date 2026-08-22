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
    (defined(LINUXKM_LKCAPI_REGISTER_SHA3_224)      || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_256)      || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_384)      || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_512)      || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA1_HMAC)     || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC))
    #error LINUXKM_LKCAPI_REGISTER for SHA-3 and HMACs is supported only on Linux kernel versions >= 5.6.0.
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

/* HASH_MAX_STATESIZE added by 2b1a29ce33, kernel 6.16.  Before that it was
 * implicitly same as HASH_MAX_DESCSIZE.
 */
#ifndef HASH_MAX_STATESIZE
    #define HASH_MAX_STATESIZE HASH_MAX_DESCSIZE
#endif

#if defined(WOLFSSL_SHA3) && \
    (defined(LINUXKM_LKCAPI_REGISTER_SHA3_224) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_256) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_384) || \
     defined(LINUXKM_LKCAPI_REGISTER_SHA3_512))

struct km_sha3_state {
    union {
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
        struct wc_Sha3 sha3_224_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
        struct wc_Sha3 sha3_256_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
        struct wc_Sha3 sha3_384_state;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
        struct wc_Sha3 sha3_512_state;
#endif
        struct wc_Sha3 sha3_state;
    };
    /* pointers for the cleanup list */
    struct list_head desc_ent;
};

/* struct wc_Sha3 won't fit in HASH_MAX_DESCSIZE. */
struct km_sha3_state_by_pointer {
    struct km_sha3_state *sha3_state;
    /* Latched by a failed ->update().  Needed as well as the NULL test because
     * km_sha3_free_tstate() leaves sha3_state intact if the lock is refused. */
    int failed;
    /* LIVENESS MARKER -- see km_sha3_alloc_tstate().  Equal to the owning
     * tfm's non-zero tfm_cookie exactly while sha3_state points at a node on
     * that tfm's desc_list; zero otherwise.  The kernel does not zero
     * shash_desc_ctx() for a fresh desc, so sha3_state alone cannot be tested
     * for liveness -- it is whatever bytes the caller's buffer happened to
     * hold. */
    word64 live_cookie;
};

wc_static_assert(sizeof(struct km_sha3_state_by_pointer) <= HASH_MAX_DESCSIZE);

#ifdef WOLFSSL_LINUXKM_USE_MUTEXES
    #error LINUXKM_LKCAPI_REGISTER_SHA3 requires spinlock-based mutexes.
#endif

/* The kernel list macros provoke "pointer of type `void *' used in arithmetic",
 * and on older kernels, "nested extern declaration of
 * `__compiletime_assert_foo'".
 */
PRAGMA_DIAG_PUSH
PRAGMA("GCC diagnostic ignored \"-Wpointer-arith\"");
PRAGMA("GCC diagnostic ignored \"-Wnested-externs\"");

#include <linux/list.h>

struct km_Sha3TfmCtx {
    wolfSSL_Mutex desc_list_lock;
    struct list_head desc_list;
    /* Identifies this tfm to its descs; see km_sha3_alloc_tstate(). */
    word64 tfm_cookie;
};

WC_MAYBE_UNUSED static int km_sha3_init_tfm(struct crypto_shash *tfm)
{
    struct km_Sha3TfmCtx *t_ctx = (struct km_Sha3TfmCtx *)crypto_shash_ctx(tfm);
    if (wc_InitMutex(&t_ctx->desc_list_lock) != 0)
        return -EINVAL;
    INIT_LIST_HEAD(&t_ctx->desc_list);
    /* Never zero: zero is the desc-side "no live state" value, so a cookie of
     * zero would make an uninitialized desc look live. */
    do {
        t_ctx->tfm_cookie = get_random_u64();
    } while (t_ctx->tfm_cookie == 0);
    return 0;
}

WC_MAYBE_UNUSED static void km_sha3_exit_tfm(struct crypto_shash *tfm)
{
    struct km_Sha3TfmCtx *t_ctx = (struct km_Sha3TfmCtx *)crypto_shash_ctx(tfm);
    struct km_sha3_state *s_ctx_i;
    struct km_sha3_state *next_ent;

    /* Don't need to lock the mutex to clean up, because the API contract
     * forbids any use of descs at/after exit of the associated TFM -- i.e. the
     * list holds only abandoned descs -- and we're deallocating the lock
     * besides.  Moreover, we definitely don't want to lock, so that the
     * iteration and heap operations aren't in a locked context that might make
     * desc deallocation awkward or impossible (leak).
     */
    list_for_each_entry_safe(s_ctx_i, next_ent, &t_ctx->desc_list, desc_ent) {
        list_del(&s_ctx_i->desc_ent);
        /* Use wc_Sha3_256_Free() as a proxy for unexported wc_Sha3Free()
         * (currently a no-op in kernel configs, but that could change).
         */
        wc_Sha3_256_Free(&s_ctx_i->sha3_state);
        ForceZero(s_ctx_i, sizeof(*s_ctx_i));
        free(s_ctx_i);
    }
    (void)wc_FreeMutex(&t_ctx->desc_list_lock);
}

WC_MAYBE_UNUSED static void km_sha3_free_tstate(struct shash_desc *desc);

WC_MAYBE_UNUSED static int km_sha3_alloc_tstate(struct shash_desc *desc) {
    struct km_Sha3TfmCtx *t_ctx =
        (struct km_Sha3TfmCtx *)crypto_shash_ctx(desc->tfm);
    struct km_sha3_state_by_pointer *s_ctx = (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);

    /* ->init() ON A DESC THAT STILL HOLDS A STATE.
     *
     * The shash API lets a caller restart a desc without finalizing it, and
     * the retryable -EBUSY on ->update() invites exactly that: a
     * vector-register refusal leaves the state in place on purpose so the desc
     * stays usable, and a caller that restarts instead of repeating the same
     * ->update() arrives here with one still attached.  Assigning over it
     * stranded the old allocation on t_ctx->desc_list until ->exit_tfm().
     * Measured before this reclaim, 6.6.152 x86_64, 20,000 restarts of one
     * sha3-256 desc: 19,999 nodes survived to ->exit_tfm() and Slab grew
     * 9,980 kB, against a paired init/update/final arm that stranded none.
     *
     * The test CANNOT be "sha3_state != NULL".  shash_desc_ctx() is not zeroed
     * for a fresh desc, so on first use that pointer is whatever the caller's
     * buffer held; treating it as a node and freeing it faults, and does so
     * inside this module's own export/import self-test, which reaches here via
     * km_sha3_*_import() with a deliberately poisoned desc.  live_cookie is a
     * marker the desc state actually carries: it equals this tfm's non-zero
     * random cookie only if THIS tfm installed the node it accompanies.
     *
     * If the reclaim cannot take desc_list_lock the state is still attached;
     * refuse retryably rather than strand it. */
    if (s_ctx->live_cookie == t_ctx->tfm_cookie) {
        km_sha3_free_tstate(desc);
        if (s_ctx->live_cookie == t_ctx->tfm_cookie)
            return -EBUSY;
    }
    s_ctx->live_cookie = 0;

    /* Fresh desc: clear any latch left by a previous use of this descsize. */
    s_ctx->failed = 0;

    s_ctx->sha3_state = (struct km_sha3_state *)malloc(sizeof(struct km_sha3_state));
    if (! s_ctx->sha3_state)
        return -ENOMEM;

    /* Must zero here to make unconditionally safe for wc_Sha3_256_Free() in
     * km_sha3_exit_tfm() (currently a no-op in kernel configs, but that could
     * change).
     */
    XMEMSET(&s_ctx->sha3_state->sha3_state, 0, sizeof s_ctx->sha3_state->sha3_state);

    if (wc_LockMutex(&t_ctx->desc_list_lock) != 0) {
        free(s_ctx->sha3_state);
        s_ctx->sha3_state = NULL;
        return -EINVAL;
    }
    list_add(&s_ctx->sha3_state->desc_ent, &t_ctx->desc_list);
    (void)wc_UnLockMutex(&t_ctx->desc_list_lock);

    /* Installed and listed: the desc now demonstrably holds one of this tfm's
     * nodes, so mark it so. */
    s_ctx->live_cookie = t_ctx->tfm_cookie;

    return 0;
}

WC_MAYBE_UNUSED static void km_sha3_free_tstate(struct shash_desc *desc) {
    struct km_Sha3TfmCtx *t_ctx =
        (struct km_Sha3TfmCtx *)crypto_shash_ctx(desc->tfm);
    struct km_sha3_state_by_pointer *s_ctx = (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);

    if (s_ctx->sha3_state == NULL) {
        /* Nothing to release, so nothing is live.  Clearing here as well as
         * below keeps a marker set without a state from wedging
         * km_sha3_alloc_tstate() at a permanent -EBUSY. */
        s_ctx->live_cookie = 0;
        return;
    }

    if (wc_LockMutex(&t_ctx->desc_list_lock) != 0)
        return;
    list_del(&s_ctx->sha3_state->desc_ent);
    (void)wc_UnLockMutex(&t_ctx->desc_list_lock);

    wc_Sha3_256_Free(&s_ctx->sha3_state->sha3_state);
    ForceZero(s_ctx->sha3_state, sizeof *s_ctx->sha3_state);
    free(s_ctx->sha3_state);
    s_ctx->sha3_state = NULL;
    s_ctx->live_cookie = 0;
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

PRAGMA_DIAG_POP

/* Serialized SHA-3 state for .export / .import.  This is the canonical
 * {core, block, len} form the kernel budgets HASH_MAX_STATESIZE for -- worst
 * case sha3-224, 200 + 144 + 1.  Deliberately NOT a struct copy of wc_Sha3:
 * that carries the full 200-byte t[] plus heap/devId/fn-ptrs, which would both
 * blow the statesize budget and ship non-portable, non-state fields across
 * descs.  s[] and t[] are stored in native byte order -- export/import always
 * round-trips within one host, so no canonical encoding is needed. */
struct km_sha3_export_state {
    byte   s[sizeof(((struct wc_Sha3 *)0)->s)]; /* KECCAK sponge, 200 bytes */
    byte   t[WC_SHA3_224_BLOCK_SIZE];           /* pending block; 144 = max rate
                                                 * of the registered SHA-3
                                                 * variants (sha3-224) */
    byte   i;                                   /* valid bytes in t[]; always
                                                 * < rate <= 144, since
                                                 * Sha3Final rejects i >= rate */
};

wc_static_assert(sizeof(struct km_sha3_export_state) <= HASH_MAX_STATESIZE);

/* Non-destructive: serialize the live sponge into the caller's statesize
 * buffer, leaving the desc (and its cleanup-list node) intact for continued
 * streaming.  Variant-agnostic -- s/t/i live at the same offset in every union
 * member, so the generic .sha3_state accessor serves all four. */
WC_MAYBE_UNUSED static int km_sha3_export(struct shash_desc *desc, void *out)
{
    struct km_sha3_state_by_pointer *ctx = (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);
    struct km_sha3_export_state *blob = (struct km_sha3_export_state *)out;
    const struct wc_Sha3 *sha3;

    /* A spent desc has no state worth serializing.  The export blob carries
     * only the sponge, so refusing here is what keeps ->import() honest. */
    if (ctx->failed || (ctx->sha3_state == NULL))
        return -EINVAL;
    sha3 = &ctx->sha3_state->sha3_state;

    /* i < rate <= sizeof(blob->t) always; guard defensively so a corrupted
     * live state can't overrun blob->t. */
    if (sha3->i > sizeof(blob->t))
        return -EINVAL;

    XMEMCPY(blob->s, sha3->s, sizeof(blob->s));
    XMEMSET(blob->t, 0, sizeof(blob->t));
    XMEMCPY(blob->t, sha3->t, sha3->i);
    blob->i = (byte)sha3->i;

    return 0;
}

/* Kernel-API export/import test coverage.  Exercises the cross-desc path that
 * distinguishes real state serialization from pointer aliasing: testmgr's
 * reimport divisions are same-desc, so a default memcpy of the desc pointer
 * would round-trip within one desc yet double-free across two.  Here we export
 * mid-stream, import into a distinct poisoned desc, finish BOTH independently,
 * and require both to match a one-shot reference -- plus statesize and
 * malformed-blob rejection probes.
 */
WC_MAYBE_UNUSED static int km_sha3_test_export_import(
    const char *cra_name, const char *cra_driver_name, unsigned int block_size)
{
    int ret;
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    struct shash_desc *desc2 = NULL;
    struct km_sha3_export_state *blob = NULL;
    size_t desc_size = 0;
    unsigned int split, i;
    byte msg[300];
    byte ref[WC_SHA3_512_DIGEST_SIZE];
    byte tag[WC_SHA3_512_DIGEST_SIZE];

    for (i = 0; i < (unsigned int)sizeof(msg); i++)
        msg[i] = (byte)(i * 7 + 1);

    tfm = crypto_alloc_shash(cra_name, 0, 0);
    if (IS_ERR(tfm)) {
        ret = (int)PTR_ERR(tfm);
        pr_err("error: crypto_alloc_shash(%s) failed: %d\n", cra_name, ret);
        return ret;
    }

    if (crypto_shash_statesize(tfm) != sizeof(struct km_sha3_export_state)) {
        pr_err("error: %s statesize %u != expected %u\n", cra_driver_name,
               crypto_shash_statesize(tfm),
               (unsigned int)sizeof(struct km_sha3_export_state));
        ret = -EINVAL;
        goto out;
    }

    desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = (struct shash_desc *)malloc(desc_size);
    desc2 = (struct shash_desc *)malloc(desc_size);
    blob = (struct km_sha3_export_state *)malloc(sizeof(*blob));
    if ((desc == NULL) || (desc2 == NULL) || (blob == NULL)) {
        ret = -ENOMEM;
        goto out;
    }
    XMEMSET(desc, 0, desc_size);
    desc->tfm = tfm;

    /* Reference digest over the whole message. */
    ret = crypto_shash_init(desc);
    if (ret == 0)
        ret = crypto_shash_update(desc, msg, sizeof(msg));
    if (ret == 0)
        ret = crypto_shash_final(desc, ref);
    if (ret) {
        pr_err("error: %s reference digest failed: %d\n", cra_driver_name, ret);
        goto out;
    }

    /* Split leaves block_size/2 unabsorbed bytes, so the export blob carries a
     * non-empty partial block for every variant (rate 72..144).
     */
    split = block_size + block_size / 2;

    ret = crypto_shash_init(desc);
    if (ret == 0)
        ret = crypto_shash_update(desc, msg, split);
    if (ret == 0)
        ret = crypto_shash_export(desc, blob);
    if (ret) {
        pr_err("error: %s export sequence failed: %d\n", cra_driver_name, ret);
        goto out;
    }

    /* Import into a poisoned second desc: import must not read prior ctx. */
    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm;
    ret = crypto_shash_import(desc2, blob);
    if (ret == 0)
        ret = crypto_shash_update(desc2, msg + split, sizeof(msg) - split);
    if (ret == 0)
        ret = crypto_shash_final(desc2, tag);
    if (ret) {
        pr_err("error: %s import sequence failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    if (XMEMCMP(tag, ref, crypto_shash_digestsize(tfm)) != 0) {
        pr_err("error: %s import-continuation digest mismatch\n",
               cra_driver_name);
        ret = -EBADMSG;
        goto out;
    }

    /* The exporting desc must remain live and independent of desc2. */
    ret = crypto_shash_update(desc, msg + split, sizeof(msg) - split);
    if (ret == 0)
        ret = crypto_shash_final(desc, tag);
    if (ret) {
        pr_err("error: %s post-export continuation failed: %d\n",
               cra_driver_name, ret);
        goto out;
    }
    if (XMEMCMP(tag, ref, crypto_shash_digestsize(tfm)) != 0) {
        pr_err("error: %s post-export digest mismatch\n", cra_driver_name);
        ret = -EBADMSG;
        goto out;
    }

    /* Malformed state (partial length >= rate) must be rejected before any
     * allocation or installation.
     */
    blob->i = (byte)block_size;
    if (crypto_shash_import(desc2, blob) == 0) {
        pr_err("error: %s import accepted out-of-range partial length\n",
               cra_driver_name);
        ret = -EINVAL;
        goto out;
    }

    ret = 0;

out:

    free(blob);
    free(desc2);
    free(desc);
    if (tfm)
        crypto_free_shash(tfm);

    return ret;
}

#endif /* WOLFSSL_SHA3 && LINUXKM_LKCAPI_REGISTER_SHA3_* */

/* ---- all-or-nothing vector-register bracket for a shash entry point -------
 *
 * SAVE_VECTOR_REGISTERS lives inside inline_XTRANSFORM(), i.e. per 64-byte
 * BLOCK (wolfcrypt/src/sha256.c).  Left there, a refusal partway through a
 * multi-block update leaves the earlier blocks ALREADY ABSORBED into the
 * state, so a caller that retried the same buffer would absorb them twice and
 * get a WRONG DIGEST.  Returning a retryable -EBUSY from that position would
 * be an invitation to corrupt the hash.
 *
 * Taking the bracket once here makes the entry point atomic: either the
 * registers were unavailable and NOTHING ran -- state untouched, -EBUSY, safe
 * to retry -- or they are held for the whole operation and every inner
 * per-block acquire merely nests, which cannot fail
 * (wc_save_vector_registers_x86() returns 0 on depth > 0 for
 * WC_SVR_FLAG_NONE).
 *
 * The kernel brackets the same way -- one kernel_fpu_begin() around the whole
 * update, no chunking: arch/x86/crypto/sha256_ssse3_glue.c _sha256_update().
 * The difference is what it does when SIMD is unusable: it calls
 * crypto_sha256_update(), a second C implementation.  This module has exactly
 * one implementation and must refuse instead -- retryably, so the caller comes
 * back to us rather than to somebody else's crypto.
 *
 * wc_lkm_errno() maps WC_ACCEL_INHIBIT_E -> -EBUSY and everything else to
 * -EINVAL.  Nothing retries this automatically: no kernel hook patch under
 * linuxkm/patches/ touches the shash API at all, and the generic crypto layer
 * retries -EBUSY only for asynchronous requests that asked for a backlog
 * (CRYPTO_TFM_REQ_MAY_BACKLOG).  The distinction is a report to the caller in
 * the kernel's own vocabulary -- -EBUSY says "transient, this request may be
 * repeated", -EINVAL says "this request is wrong" -- and it matters because
 * dm-crypt turns the latter into BLK_STS_IOERR.  An earlier version of this
 * comment claimed the hook patch retried on it; it does not.
 */
#define KM_SHA_SVR_BEGIN(ret_var)                                          \
    do {                                                                   \
        (ret_var) = SAVE_VECTOR_REGISTERS2();                              \
        if ((ret_var) != 0)                                                \
            return wc_lkm_errno(ret_var);                                  \
    } while (0)
#define KM_SHA_SVR_END() RESTORE_VECTOR_REGISTERS()

#define WC_LINUXKM_SHA1_IMPLEMENT(name, s_name, digest_size, block_size,   \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  free_f, test_routine)                    \
                                                                           \
                                                                           \
/* PER-DESC FAILURE LATCH.                                                 \
 *                                                                         \
 * Without it, a caller that ignores the error from ->update() and calls   \
 * ->final() anyway gets a digest of the PARTIAL message, with a success   \
 * status.  A wrong digest with no indicator is the worst answer a hash    \
 * service can give, and it is not something free_f() prevents: measured on\
 * this build, wc_ShaFree()/wc_Sha256Free()/wc_Sha512Free() do NOT zeroize \
 * the message state.  They release the .W cache, which the glue already \
 * owns and has already set to NULL via WC_LINUXKM_SHA2_POP_W(), and then\
 * nothing else compiles here (no crypto-cb, no async, no ESP32).  So the  \
 * free_f(ctx) on the error path was doing nothing at all, and the context \
 * it left behind was a perfectly usable partial state.                    \
 *                                                                         \
 * The shash API has no way to mark a desc unusable, so the latch lives in \
 * the desc: the ctx is wrapped and .descsize covers the wrapper.  Note that\
 * with no ->export, the kernel sets statesize = descsize and export/import\
 * become a memcpy of the whole wrapper (crypto/shash.c shash_prepare_alg),\
 * so the latch survives an export/import cycle, which is what you want, \
 * importing a failed state must not resurrect it as a good one.           \
 *                                                                         \
 * Why this branch and not before: with a C fallback absorbing every       \
 * vector-register refusal, ->update() effectively could not fail.  It can \
 * now, from an irqs-disabled caller, so the sequence is reachable.        \
 */                                                                        \
struct km_ ## name ## _shash_ctx {                                         \
    struct s_name inner;                                                   \
    int failed;                                                            \
};                                                                         \
                                                                           \
wc_static_assert(sizeof(struct km_ ## name ## _shash_ctx)                  \
                 <= HASH_MAX_DESCSIZE);                                    \
wc_static_assert(sizeof(struct km_ ## name ## _shash_ctx)                  \
                 <= HASH_MAX_STATESIZE);                                   \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
                                                                           \
    int ret;                                                               \
                                                                           \
    wrap->failed = 0;                                                      \
    ret = init_f(ctx);                                                     \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
                                                                           \
    int ret;                                                               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = update_f(ctx, data, len);                                        \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        wrap->failed = 1;                                                  \
        free_f(ctx);                                                       \
        /* Wipe the message state, but NOT the latch: ForceZero(wrap)      \
         * would clear ->failed.  ISO/IEC 19790:2012 7.9. */               \
        ForceZero(ctx, sizeof(*ctx));                                      \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
                                                                           \
    /* A failed ->update() latched here.  Returning a digest now would be a\
     * digest of the partial message, reported as success. */              \
    if (wrap->failed) {                                                    \
        free_f(ctx);                                                       \
        /* free_f() does not zeroize the message state (see above), so the \
         * partial-message residue, last block, chaining variables and   \
         * length, would outlive the desc.  Harmless for a plain hash,   \
         * not for a desc backing HMAC/HKDF/PBKDF2 over sensitive input.   \
         * ISO/IEC 19790:2012 7.9. */                                      \
        ForceZero(wrap, sizeof(*wrap));                                    \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    int ret;                                                               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = final_f(ctx, out);                                               \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(ctx);                                                           \
    /* Digest emitted; the message state is spent.  free_f() leaves it in  \
     * place, so clear it here too. */                                     \
    ForceZero(wrap, sizeof(*wrap));                                        \
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
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
                                                                           \
    /* A failed ->update() latched here.  Returning a digest now would be a\
     * digest of the partial message, reported as success. */              \
    if (wrap->failed) {                                                    \
        free_f(ctx);                                                       \
        /* free_f() does not zeroize the message state (see above), so the \
         * partial-message residue, last block, chaining variables and   \
         * length, would outlive the desc.  Harmless for a plain hash,   \
         * not for a desc backing HMAC/HKDF/PBKDF2 over sensitive input.   \
         * ISO/IEC 19790:2012 7.9. */                                      \
        ForceZero(wrap, sizeof(*wrap));                                    \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    int ret;                                                               \
                                                                           \
    /* ONE bracket for the update AND the final.  Two brackets meant a     \
     * refusal of the second returned an error with the bytes ALREADY      \
     * ABSORBED, so repeating the call absorbed them twice and produced a  \
     * wrong digest with a success status.  The refusal is reachable       \
     * without any debug option: wc_save_vector_registers_x86() consults   \
     * WC_CHECK_FOR_INTR_SIGNALS() on the OUTERMOST acquisition only, so a \
     * signal that becomes pending while the first bracket is open is      \
     * invisible to it and fatal to the second.  Measured.                 \
     *                                                                     \
     * free_f() stays OUTSIDE the bracket: km_hmac_finup() learned that    \
     * the hard way in 32feac15f, where the free took a mutex inside the   \
     * section and the guard skipped it, leaking the node.  free_f() here  \
     * takes no lock, but the placement is the same rule. */               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = update_f(ctx, data, len);                                        \
    if (ret == 0)                                                          \
        ret = final_f(ctx, out);                                           \
    else                                                                   \
        wrap->failed = 1;                                                  \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(ctx);                                                           \
    if (wrap->failed) {                                                    \
        /* Wipe the message state, but NOT the latch: ForceZero(wrap)      \
         * would clear ->failed.  ISO/IEC 19790:2012 7.9. */               \
        ForceZero(ctx, sizeof(*ctx));                                      \
        return -EINVAL;                                                    \
    }                                                                      \
    /* Digest emitted, or the final failed; the desc is spent either way.  \
     * free_f() leaves the message state in place, so clear it here. */    \
    ForceZero(wrap, sizeof(*wrap));                                        \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
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
    .descsize       =       sizeof(struct km_ ## name ## _shash_ctx),      \
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

#if defined(WOLFSSL_SMALL_STACK_CACHE) && \
    (!defined(WC_HAVE_SHA2_NO_SMALL_STACK) || !defined(WC_SHA2_NO_SMALL_STACK))
    /* The glue layer needs to take ownership of the .W working buffer to assure
     * it can't leak on abandoned descs, or double-free on export-import cycled
     * descs.  It's small enough to fit comfortably on the stack, so there's
     * almost no overhead associated with this.
     *
     * Eager allocation of .W in SHA-2 init is to assure no heap operations in
     * SHA-2 after init, mitigating an infinite recursion:  The wolfCrypt DRBG
     * sits atop SHA-2, and when LINUXKM_DRBG_GET_RANDOM_BYTES &&
     * WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS && CONFIG_SLAB_FREELIST_RANDOM,
     * it sits _under_ the kernel heap.
     */
    #define WC_LINUXKM_SHA2_FREE_W(s) do { free((s)->W); (s)->W = NULL; } while (0)
    #define WC_LINUXKM_SHA2_DECL_W(s, l) wc_static_assert((l) % sizeof (s)->W[0] == 0); \
                                         typeof((s)->W[0]) w_buf[(l) / sizeof (s)->W[0]]
    #define WC_LINUXKM_SHA2_PUSH_W(s) { (s)->W = w_buf
    #define WC_LINUXKM_SHA2_POP_W(s) ForceZero(w_buf, sizeof w_buf); (s)->W = NULL; } WC_DO_NOTHING
#else
    #define WC_LINUXKM_SHA2_FREE_W(s) WC_DO_NOTHING
    #define WC_LINUXKM_SHA2_DECL_W(s, l) struct wc_swallow_the_semicolon
    #define WC_LINUXKM_SHA2_PUSH_W(s) { WC_DO_NOTHING
    #define WC_LINUXKM_SHA2_POP_W(s) } WC_DO_NOTHING
#endif

/* WC_SHA*_W_SIZE are only used when WC_LINUXKM_SHA2_FREE_W() and friends are
 * substantively implemented.
 */
#ifndef WC_SHA256_W_SIZE
    #define WC_SHA256_W_SIZE (sizeof(word32) * WC_SHA256_BLOCK_SIZE)
#endif
#ifndef WC_SHA512_W_SIZE
    #define WC_SHA512_W_SIZE ((sizeof(word64) * 16) + WC_SHA512_BLOCK_SIZE)
#endif

#define WC_LINUXKM_SHA2_IMPLEMENT(name, s_name, digest_size, block_size,   \
                                  W_size,                                  \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  free_f, test_routine)                    \
                                                                           \
                                                                           \
/* PER-DESC FAILURE LATCH.                                                 \
 *                                                                         \
 * Without it, a caller that ignores the error from ->update() and calls   \
 * ->final() anyway gets a digest of the PARTIAL message, with a success   \
 * status.  A wrong digest with no indicator is the worst answer a hash    \
 * service can give, and it is not something free_f() prevents: measured on\
 * this build, wc_ShaFree()/wc_Sha256Free()/wc_Sha512Free() do NOT zeroize \
 * the message state.  They release the .W cache, which the glue already \
 * owns and has already set to NULL via WC_LINUXKM_SHA2_POP_W(), and then\
 * nothing else compiles here (no crypto-cb, no async, no ESP32).  So the  \
 * free_f(ctx) on the error path was doing nothing at all, and the context \
 * it left behind was a perfectly usable partial state.                    \
 *                                                                         \
 * The shash API has no way to mark a desc unusable, so the latch lives in \
 * the desc: the ctx is wrapped and .descsize covers the wrapper.  Note that\
 * with no ->export, the kernel sets statesize = descsize and export/import\
 * become a memcpy of the whole wrapper (crypto/shash.c shash_prepare_alg),\
 * so the latch survives an export/import cycle, which is what you want, \
 * importing a failed state must not resurrect it as a good one.           \
 *                                                                         \
 * Why this branch and not before: with a C fallback absorbing every       \
 * vector-register refusal, ->update() effectively could not fail.  It can \
 * now, from an irqs-disabled caller, so the sequence is reachable.        \
 */                                                                        \
struct km_ ## name ## _shash_ctx {                                         \
    struct s_name inner;                                                   \
    int failed;                                                            \
};                                                                         \
                                                                           \
wc_static_assert(sizeof(struct km_ ## name ## _shash_ctx)                  \
                 <= HASH_MAX_DESCSIZE);                                    \
wc_static_assert(sizeof(struct km_ ## name ## _shash_ctx)                  \
                 <= HASH_MAX_STATESIZE);                                   \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
                                                                           \
    int ret;                                                               \
                                                                           \
    wrap->failed = 0;                                                      \
    ret = init_f(ctx);                                                     \
    if (ret == 0) {                                                        \
        WC_LINUXKM_SHA2_FREE_W(ctx);                                       \
        return 0;                                                          \
    }                                                                      \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = update_f(ctx, data, len);                                        \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        wrap->failed = 1;                                                  \
        free_f(ctx);                                                       \
        /* Wipe the message state, but NOT the latch: ForceZero(wrap)      \
         * would clear ->failed.  ISO/IEC 19790:2012 7.9. */               \
        ForceZero(ctx, sizeof(*ctx));                                      \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    /* A failed ->update() latched here.  Returning a digest now would be a\
     * digest of the partial message, reported as success. */              \
    if (wrap->failed) {                                                    \
        free_f(ctx);                                                       \
        /* free_f() does not zeroize the message state (see above), so the \
         * partial-message residue, last block, chaining variables and   \
         * length, would outlive the desc.  Harmless for a plain hash,   \
         * not for a desc backing HMAC/HKDF/PBKDF2 over sensitive input.   \
         * ISO/IEC 19790:2012 7.9. */                                      \
        ForceZero(wrap, sizeof(*wrap));                                    \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = final_f(ctx, out);                                               \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(ctx);                                                           \
    /* Digest emitted; the message state is spent.  free_f() leaves it in  \
     * place, so clear it here too. */                                     \
    ForceZero(wrap, sizeof(*wrap));                                        \
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
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    /* A failed ->update() latched here.  Returning a digest now would be a\
     * digest of the partial message, reported as success. */              \
    if (wrap->failed) {                                                    \
        free_f(ctx);                                                       \
        /* free_f() does not zeroize the message state (see above), so the \
         * partial-message residue, last block, chaining variables and   \
         * length, would outlive the desc.  Harmless for a plain hash,   \
         * not for a desc backing HMAC/HKDF/PBKDF2 over sensitive input.   \
         * ISO/IEC 19790:2012 7.9. */                                      \
        ForceZero(wrap, sizeof(*wrap));                                    \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    /* ONE bracket for the update AND the final.  Two brackets meant a     \
     * refusal of the second returned an error with the bytes ALREADY      \
     * ABSORBED, so repeating the call absorbed them twice and produced a  \
     * wrong digest with a success status.  The refusal is reachable       \
     * without any debug option: wc_save_vector_registers_x86() consults   \
     * WC_CHECK_FOR_INTR_SIGNALS() on the OUTERMOST acquisition only, so a \
     * signal that becomes pending while the first bracket is open is      \
     * invisible to it and fatal to the second.  Measured.                 \
     *                                                                     \
     * free_f() stays OUTSIDE the bracket: km_hmac_finup() learned that    \
     * the hard way in 32feac15f, where the free took a mutex inside the   \
     * section and the guard skipped it, leaking the node.  free_f() here  \
     * takes no lock, but the placement is the same rule. */               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = update_f(ctx, data, len);                                        \
    if (ret == 0)                                                          \
        ret = final_f(ctx, out);                                           \
    else                                                                   \
        wrap->failed = 1;                                                  \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(ctx);                                                           \
    if (wrap->failed) {                                                    \
        /* Wipe the message state, but NOT the latch: ForceZero(wrap)      \
         * would clear ->failed.  ISO/IEC 19790:2012 7.9. */               \
        ForceZero(ctx, sizeof(*ctx));                                      \
        return -EINVAL;                                                    \
    }                                                                      \
    /* Digest emitted, or the final failed; the desc is spent either way.  \
     * free_f() leaves the message state in place, so clear it here. */    \
    ForceZero(wrap, sizeof(*wrap));                                        \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _digest(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len, u8 *out)               \
{                                                                          \
    struct km_ ## name ## _shash_ctx *wrap =                               \
        (struct km_ ## name ## _shash_ctx *)shash_desc_ctx(desc);          \
    struct s_name *ctx = &wrap->inner;                                     \
    int ret;                                                               \
                                                                           \
    /* One-shot: bracket the WHOLE operation.  crypto_shash_digest() binds     \
     * straight here, so this -- not ->finup() -- is the path a caller takes, \
     * and leaving it unbracketed made the per-block refusal surface as        \
     * -EINVAL (permanent) instead of -EBUSY (retryable).  Measured.           \
     */                                                                       \
    KM_SHA_SVR_BEGIN(ret);                                                 \
                                                                           \
    wrap->failed = 0;                                                      \
    ret = init_f(ctx);                                                     \
    if (ret != 0) {                                                        \
        wrap->failed = 1;                                                  \
        KM_SHA_SVR_END();                                                  \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    ret = update_f(ctx, data, len);                                        \
                                                                           \
    if (ret == 0)                                                          \
        ret = final_f(ctx, out);                                           \
                                                                           \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(ctx);                                                           \
    /* One-shot: digest emitted, desc spent.  free_f() leaves the          \
     * message state in place.  ISO/IEC 19790:2012 7.9. */                 \
    ForceZero(wrap, sizeof(*wrap));                                        \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
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
    .descsize       =       sizeof(struct km_ ## name ## _shash_ctx),      \
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
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
    int ret;                                                               \
                                                                           \
    ret = km_sha3_alloc_tstate(desc);                                      \
    if (ret)                                                               \
        return ret;                                                        \
    ret = init_f(&ctx->sha3_state-> name ## _state, NULL, INVALID_DEVID);  \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        ctx->failed = 1;                                                   \
        km_sha3_free_tstate(desc);                                         \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
                                                                           \
    /* Spent by an earlier failed ->update().  The latch is not            \
     * redundant with the NULL test: a refused desc_list_lock makes        \
     * km_sha3_free_tstate() leave sha3_state intact and partial. */       \
    if (ctx->failed || (ctx->sha3_state == NULL))                          \
        return -EINVAL;                                                    \
                                                                           \
    int ret;                                                               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = update_f(&ctx->sha3_state-> name ## _state, data, len);          \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        ctx->failed = 1;                                                   \
        km_sha3_free_tstate(desc);                                         \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
                                                                           \
    /* Spent by an earlier failed ->update().  The latch is not            \
     * redundant with the NULL test: a refused desc_list_lock makes        \
     * km_sha3_free_tstate() leave sha3_state intact and partial. */       \
    if (ctx->failed || (ctx->sha3_state == NULL))                          \
        return -EINVAL;                                                    \
                                                                           \
    int ret;                                                               \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = final_f(&ctx->sha3_state-> name ## _state, out);                 \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    km_sha3_free_tstate(desc);                                             \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _finup(struct shash_desc *desc, const u8 *data,  \
                                 unsigned int len, u8 *out)                \
{                                                                          \
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
                                                                           \
    /* Spent by an earlier failed ->update().  The latch is not            \
     * redundant with the NULL test: a refused desc_list_lock makes        \
     * km_sha3_free_tstate() leave sha3_state intact and partial. */       \
    if (ctx->failed || (ctx->sha3_state == NULL))                          \
        return -EINVAL;                                                    \
                                                                           \
    int ret;                                                               \
                                                                           \
    /* ONE bracket for the update AND the final.  Two brackets meant a     \
     * refusal of the second returned an error with the bytes ALREADY      \
     * ABSORBED, so repeating the call absorbed them twice and produced a  \
     * wrong digest with a success status.  The refusal is reachable       \
     * without any debug option: wc_save_vector_registers_x86() consults   \
     * WC_CHECK_FOR_INTR_SIGNALS() on the OUTERMOST acquisition only, so a \
     * signal that becomes pending while the first bracket is open is      \
     * invisible to it and fatal to the second.  Measured.                 \
     *                                                                     \
     * km_sha3_free_tstate() STAYS OUTSIDE the bracket -- it takes         \
     * desc_list_lock, and wc_lkm_LockMutex() refuses a mutex inside a     \
     * vector-register section, which is exactly the leak 32feac15f fixed  \
     * in km_hmac_finup(). */                                              \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = update_f(&ctx->sha3_state-> name ## _state, data, len);          \
    if (ret == 0)                                                          \
        ret = final_f(&ctx->sha3_state-> name ## _state, out);             \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    if (ret != 0)                                                          \
        ctx->failed = 1;                                                   \
    km_sha3_free_tstate(desc);                                             \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _digest(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len, u8 *out)               \
{                                                                          \
    struct km_sha3_state sha3_state;                                       \
    int ret;                                                               \
                                                                           \
    (void)desc;                                                            \
    /* One-shot: bracket the whole operation, so a refusal means NOTHING   \
     * ran and -EBUSY is safe to retry.  See KM_SHA_SVR_BEGIN.          \
     */                                                                    \
    KM_SHA_SVR_BEGIN(ret);                                                 \
    ret = init_f(&sha3_state. name ## _state, NULL, INVALID_DEVID);        \
    if (ret != 0) {                                                        \
        KM_SHA_SVR_END();                                                  \
        return -EINVAL;                                                    \
    }                                                                      \
    ret = update_f(&sha3_state. name ## _state, data, len);                \
    if (ret == 0)                                                          \
        ret = final_f(&sha3_state. name ## _state, out);                   \
    KM_SHA_SVR_END();                                                      \
                                                                           \
    free_f(&sha3_state. name ## _state);                                   \
    ForceZero(&sha3_state, sizeof sha3_state);                             \
                                                                           \
    return ret == 0 ? 0 : -EINVAL;                                         \
}                                                                          \
                                                                           \
static int km_ ## name ## _import(struct shash_desc *desc,                 \
                                  const void *in)                          \
{                                                                          \
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
    const struct km_sha3_export_state *blob =                              \
        (const struct km_sha3_export_state *)in;                           \
    struct wc_Sha3 *sha3;                                                  \
    int ret;                                                               \
                                                                           \
    if (blob->i >= (block_size))                                           \
        return -EINVAL;                                                    \
                                                                           \
    ret = km_sha3_alloc_tstate(desc);                                      \
    if (ret)                                                               \
        return ret;                                                        \
                                                                           \
    sha3 = &ctx->sha3_state-> name ## _state;                              \
    ret = init_f(sha3, NULL, INVALID_DEVID);                               \
    if (ret != 0) {                                                        \
        ctx->failed = 1;                                                   \
        km_sha3_free_tstate(desc);                                         \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    XMEMCPY(sha3->s, blob->s, sizeof(sha3->s));                            \
    XMEMCPY(sha3->t, blob->t, blob->i);                                    \
    XMEMSET(sha3->t + blob->i, 0, sizeof(sha3->t) - blob->i);              \
    sha3->i = blob->i;                                                     \
                                                                           \
    return 0;                                                              \
}                                                                          \
                                                                           \
wc_static_assert((block_size) <=                                           \
                 sizeof(((struct km_sha3_export_state *)0)->t));           \
                                                                           \
                                                                           \
static struct shash_alg name ## _alg =                                     \
{                                                                          \
    .init_tfm       =       km_sha3_init_tfm,                              \
    .digestsize     =       (digest_size),                                 \
    .init           =       km_ ## name ## _init,                          \
    .update         =       km_ ## name ## _update,                        \
    .final          =       km_ ## name ## _final,                         \
    .finup          =       km_ ## name ## _finup,                         \
    .digest         =       km_ ## name ## _digest,                        \
    .descsize       =       sizeof(struct km_sha3_state_by_pointer),       \
    .export         =       km_sha3_export,                                \
    .import         =       km_ ## name ## _import,                        \
    .statesize      =       sizeof(struct km_sha3_export_state),           \
    .exit_tfm       =       km_sha3_exit_tfm,                              \
    .base           =       {                                              \
        .cra_name        =      (this_cra_name),                           \
        .cra_driver_name =      (this_cra_driver_name),                    \
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,           \
        .cra_blocksize   =      (block_size),                              \
        .cra_ctxsize     =      sizeof(struct km_Sha3TfmCtx),              \
        .cra_module      =      THIS_MODULE                                \
    }                                                                      \
};                                                                         \
static int name ## _alg_loaded = 0;                                        \
                                                                           \
static int linuxkm_test_ ## name(void) {                                   \
    wc_test_ret_t ret = test_routine();                                    \
    if (ret < 0) {                                                         \
        wc_test_render_error_message("linuxkm_test_" #name " failed: ",    \
                                     ret);                                 \
        return WC_TEST_RET_DEC_EC(ret);                                    \
    }                                                                      \
    ret = check_shash_driver_masking(NULL /* tfm */, this_cra_name,        \
                                      this_cra_driver_name);               \
    if (ret)                                                               \
        return ret;                                                        \
    return km_sha3_test_export_import(this_cra_name, this_cra_driver_name, \
                                      (block_size));                       \
}                                                                          \
                                                                           \
struct wc_swallow_the_semicolon

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    WC_LINUXKM_SHA1_IMPLEMENT(sha1, wc_Sha, WC_SHA_DIGEST_SIZE, WC_SHA_BLOCK_SIZE,
                             WOLFKM_SHA1_NAME, WOLFKM_SHA1_DRIVER,
                             wc_InitSha, wc_ShaUpdate, wc_ShaFinal,
                             wc_ShaFree, sha_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    WC_LINUXKM_SHA2_IMPLEMENT(sha2_224, wc_Sha256, WC_SHA224_DIGEST_SIZE, WC_SHA224_BLOCK_SIZE,
                             WC_SHA256_W_SIZE,
                             WOLFKM_SHA2_224_NAME, WOLFKM_SHA2_224_DRIVER,
                             wc_InitSha224, wc_Sha224Update, wc_Sha224Final,
                             wc_Sha224Free, sha224_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    WC_LINUXKM_SHA2_IMPLEMENT(sha2_256, wc_Sha256, WC_SHA256_DIGEST_SIZE, WC_SHA256_BLOCK_SIZE,
                             WC_SHA256_W_SIZE,
                             WOLFKM_SHA2_256_NAME, WOLFKM_SHA2_256_DRIVER,
                             wc_InitSha256, wc_Sha256Update, wc_Sha256Final,
                             wc_Sha256Free, sha256_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    WC_LINUXKM_SHA2_IMPLEMENT(sha2_384, wc_Sha512, WC_SHA384_DIGEST_SIZE, WC_SHA384_BLOCK_SIZE,
                             WC_SHA512_W_SIZE,
                             WOLFKM_SHA2_384_NAME, WOLFKM_SHA2_384_DRIVER,
                             wc_InitSha384, wc_Sha384Update, wc_Sha384Final,
                             wc_Sha384Free, sha384_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    WC_LINUXKM_SHA2_IMPLEMENT(sha2_512, wc_Sha512, WC_SHA512_DIGEST_SIZE, WC_SHA512_BLOCK_SIZE,
                             WC_SHA512_W_SIZE,
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

#ifndef NO_HMAC

struct km_sha_hmac_node {
    struct Hmac wc_hmac;
    /* linkage for the tfm-owned cleanup list */
    struct list_head desc_ent;
    word64 desc_id;
};
struct km_sha_hmac_state {
    /* HASH_MAX_DESCSIZE is 368, but sizeof(struct Hmac) is 832, so the working
     * Hmac lives in a heap node hung off the desc and tracked on the tfm
     * cleanup list for garbage collection at .exit_tfm. */
    struct km_sha_hmac_node *node;
    /* Latched by a failed ->update().  Needed as well as the NULL test because
     * km_hmac_free_tstate() leaves node intact if the lock is refused. */
    int failed;
    /* LIVENESS MARKER -- see km_hmac_alloc_tstate().  Equal to the owning
     * tfm's non-zero tfm_cookie exactly while node points at a node on that
     * tfm's desc_list; zero otherwise.  The kernel does not zero
     * shash_desc_ctx() for a fresh desc, so node alone cannot be tested for
     * liveness -- it is whatever bytes the caller's buffer happened to hold. */
    word64 live_cookie;
};
struct km_sha_hmac_pstate {
    /* keyed, pristine Hmac, deep-copied into each desc's node at .init */
    struct Hmac wc_hmac;
    /* desc_list_lock guards BOTH lists below. */
    wolfSSL_Mutex desc_list_lock;
    /* cleanup list of live/abandoned desc working nodes (abandonment GC) */
    struct list_head desc_list;
    /* bounded ring of .export snapshots; import validates handles against it */
    struct list_head export_list;
    unsigned int export_list_len;
    word64 cur_desc_id;
    word64 tfm_cookie;
};

/* Serialized HMAC state for .export / .import.  sizeof(struct Hmac) is 832, and
 * an HMAC-over-SHA-3 state is two full sponges, so real state cannot fit
 * HASH_MAX_STATESIZE (345).  .export deep-copies the live Hmac into a snapshot
 * node on the tfm's export_list and the blob carries only a desc_id; .import
 * looks it up by desc_id, validated using the tfm_cookie, and copies from the
 * snapshot.  Snapshots are deallocated at exit_tfm.
 */
#define WC_LINUXKM_HMAC_EXPORT_MAGIC W64LIT(0x57435F484d414331) /* "WC_HMAC1" */

/* Upper bound on live .export snapshots per tfm.  Bounds worst-case memory to
 * this many nodes (~832B each): without it, algif_hash's export-on-accept lets
 * userspace grow the parent's list without limit (close(accept(fd)) in a loop).
 * The accept-clone path imports immediately after export, so a snapshot is
 * consumed long before it can be evicted; this need only exceed the max
 * concurrent in-flight export->import pairs on one tfm (accept drops the sock
 * lock between the two).  Over-cap merely degrades a stale import to graceful
 * -EINVAL, never corruption.  Override at build time if a workload needs more.
 *
 * Note the default expression is runtime-evaluated to scale with host size.
 */
#ifndef WC_LINUXKM_HMAC_EXPORT_LIST_MAX
    #define WC_LINUXKM_HMAC_EXPORT_LIST_MAX (nr_cpu_ids * 2)
#else
    wc_static_assert_if_const(WC_LINUXKM_HMAC_EXPORT_LIST_MAX > 0,
                              "WC_LINUXKM_HMAC_EXPORT_LIST_MAX must be positive.");
#endif

struct km_sha_hmac_export_state {
    word64 magic;      /* identifies the export as an HMAC handle. */
    word64 tfm_cookie; /* associates the export unambiguously with this TFM. */
    word64 desc_id;    /* local to this TFM, allocated serially from zero. */
};

wc_static_assert(sizeof(struct km_sha_hmac_state) <= HASH_MAX_DESCSIZE);

wc_static_assert(sizeof(struct km_sha_hmac_export_state) <= HASH_MAX_STATESIZE);

#ifdef WOLFSSL_LINUXKM_USE_MUTEXES
    #error LINUXKM_LKCAPI_REGISTER_HMAC requires spinlock-based mutexes.
#endif

/* The kernel list macros provoke "pointer of type `void *' used in arithmetic",
 * and on older kernels, "nested extern declaration of
 * `__compiletime_assert_foo'".
 */
PRAGMA_DIAG_PUSH
PRAGMA("GCC diagnostic ignored \"-Wpointer-arith\"");
PRAGMA("GCC diagnostic ignored \"-Wnested-externs\"");

#include <linux/list.h>

WC_MAYBE_UNUSED static int linuxkm_hmac_setkey_common(struct crypto_shash *tfm, int type, const byte* key, word32 length)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    int ret;

#if defined(HAVE_FIPS) && (FIPS_VERSION3_LT(6, 0, 0) || \
                           !defined(WC_LINUX_CONFIG_SELFTESTS) || \
                           (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)))
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

WC_MAYBE_UNUSED static void km_hmac_free_tstate(struct shash_desc *desc);

WC_MAYBE_UNUSED static int km_hmac_alloc_tstate(struct shash_desc *desc) {
    struct km_sha_hmac_pstate *p_ctx =
        (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    /* ->init() ON A DESC THAT STILL HOLDS A NODE.  Same case as
     * km_sha3_alloc_tstate(); read the reasoning there.  Measured before this
     * reclaim, 6.6.152 x86_64, 20,000 restarts of one
     * hmac-sha256-avx2-wolfcrypt-fips-140-3 desc: 19,999 nodes survived to
     * ->exit_tfm() and Slab grew 19,972 kB (kmalloc-1k +20,016 objects),
     * against a paired init/update/final arm that stranded none. */
    if (s_ctx->live_cookie == p_ctx->tfm_cookie) {
        km_hmac_free_tstate(desc);
        if (s_ctx->live_cookie == p_ctx->tfm_cookie)
            return -EBUSY;
    }
    s_ctx->live_cookie = 0;

    /* Fresh desc: clear any latch left by a previous use of this descsize. */
    s_ctx->failed = 0;

    s_ctx->node = (struct km_sha_hmac_node *)malloc(sizeof(struct km_sha_hmac_node));
    if (! s_ctx->node)
        return -ENOMEM;
    /* Must zero to assure the Hmac object is safe to pass to wc_HmacFree() even
     * if init fails.
     */
    XMEMSET(s_ctx->node, 0, sizeof *s_ctx->node);

    if (wc_LockMutex(&p_ctx->desc_list_lock) != 0) {
        free(s_ctx->node);
        s_ctx->node = NULL;
        return -EINVAL;
    }
    s_ctx->node->desc_id = p_ctx->cur_desc_id++;
    list_add(&s_ctx->node->desc_ent, &p_ctx->desc_list);
    (void)wc_UnLockMutex(&p_ctx->desc_list_lock);

    /* Installed and listed: the desc now demonstrably holds one of this tfm's
     * nodes, so mark it so. */
    s_ctx->live_cookie = p_ctx->tfm_cookie;

    return 0;
}

WC_MAYBE_UNUSED static void km_hmac_free_tstate(struct shash_desc *desc) {
    struct km_sha_hmac_pstate *p_ctx =
        (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    if (s_ctx->node == NULL) {
        /* Nothing to release, so nothing is live.  Clearing here as well as
         * below keeps a marker set without a node from wedging
         * km_hmac_alloc_tstate() at a permanent -EBUSY. */
        s_ctx->live_cookie = 0;
        return;
    }

    if (wc_LockMutex(&p_ctx->desc_list_lock) != 0)
        return;
    list_del(&s_ctx->node->desc_ent);
    (void)wc_UnLockMutex(&p_ctx->desc_list_lock);

    /* wc_HmacFree is NOT a no-op: a wc_HmacCopy'd node can own inner/outer hash
     * heap (e.g. SMALL_STACK_CACHE W buffers), so it must run before free().
     */
    wc_HmacFree(&s_ctx->node->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(s_ctx->node, sizeof *s_ctx->node);
#endif
    free(s_ctx->node);
    s_ctx->node = NULL;
    s_ctx->live_cookie = 0;
}

WC_MAYBE_UNUSED static int km_hmac_init_tfm(struct crypto_shash *tfm)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    int ret = wc_HmacInit(&p_ctx->wc_hmac, NULL /* heap */, INVALID_DEVID);
    if (ret != 0)
        return -EINVAL;
    if (wc_InitMutex(&p_ctx->desc_list_lock) != 0) {
        wc_HmacFree(&p_ctx->wc_hmac);
        return -EINVAL;
    }
    INIT_LIST_HEAD(&p_ctx->desc_list);
    INIT_LIST_HEAD(&p_ctx->export_list);
    p_ctx->export_list_len = 0;
    p_ctx->cur_desc_id = 0;
    /* Never zero: zero is the desc-side "no live state" value, so a cookie of
     * zero would make an uninitialized desc look live. */
    do {
        p_ctx->tfm_cookie = get_random_u64();
    } while (p_ctx->tfm_cookie == 0);
    return 0;
}

WC_MAYBE_UNUSED static void km_hmac_exit_tfm(struct crypto_shash *tfm)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(tfm);
    struct km_sha_hmac_node *node_i;
    struct km_sha_hmac_node *next_ent;

    /* Don't need to lock the mutex to clean up, because the API contract
     * forbids any use of descs at/after exit of the associated TFM -- i.e. the
     * list holds only abandoned descs -- and we're deallocating the lock
     * besides.  Moreover, we definitely don't want to lock, so that the
     * iteration and heap operations aren't in a locked context that might make
     * desc deallocation awkward or impossible (leak).
     */
    list_for_each_entry_safe(node_i, next_ent, &p_ctx->desc_list, desc_ent) {
        list_del(&node_i->desc_ent);
        wc_HmacFree(&node_i->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
        ForceZero(node_i, sizeof(*node_i));
#endif
        free(node_i);
    }
    list_for_each_entry_safe(node_i, next_ent, &p_ctx->export_list, desc_ent) {
        list_del(&node_i->desc_ent);
        wc_HmacFree(&node_i->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
        ForceZero(node_i, sizeof(*node_i));
#endif
        free(node_i);
    }
    wc_HmacFree(&p_ctx->wc_hmac);
    (void)wc_FreeMutex(&p_ctx->desc_list_lock);
}

WC_MAYBE_UNUSED static int km_hmac_init(struct shash_desc *desc) {
    int ret;
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);

    ret = km_hmac_alloc_tstate(desc);
    if (ret)
        return ret;

    ret = wc_HmacCopy(&p_ctx->wc_hmac, &s_ctx->node->wc_hmac);
    if (ret != 0) {
        /* A transient vector-register refusal is retryable and must NOT latch
         * the desc failed -- drop the tstate so a retry re-allocates, and
         * report -EBUSY.  Any other error is a real failure and still latches. */
        if (ret != WC_ACCEL_INHIBIT_E)
            s_ctx->failed = 1;
        km_hmac_free_tstate(desc);
        return wc_lkm_errno(ret);
    }

    return 0;
}

WC_MAYBE_UNUSED static int km_hmac_update(struct shash_desc *desc, const u8 *data,
                          unsigned int len)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    /* Spent by an earlier failed ->update(); see km_hmac_final(). */
    if (ctx->failed || (ctx->node == NULL))
        return -EINVAL;

    int ret;

    /* Take the bracket ONCE here, for the same reason as KM_SHA_SVR_BEGIN():
     * wc_HmacUpdate() saves the vector registers per block, so a refusal part
     * way through would leave bytes already absorbed and a retry of the same
     * buffer would absorb them twice -- a WRONG MAC.  Acquired here, either the
     * registers were unavailable and NOTHING ran, or they are held for the
     * whole call and every inner save is a no-op (wc_save_vector_registers_x86()
     * returns 0 on depth > 0 for WC_SVR_FLAG_NONE).
     *
     * On refusal the ctx is left EXACTLY as it was: not latched failed, node
     * not freed, so the caller can retry.  Before this, a transient refusal
     * spent the desc permanently and reported it as -EINVAL, which the kernel
     * hook patch does not retry on. */
    KM_SHA_SVR_BEGIN(ret);

    ret = wc_HmacUpdate(&ctx->node->wc_hmac, data, len);

    KM_SHA_SVR_END();

    if (ret == 0)
        return 0;
    else {
        ctx->failed = 1;
        km_hmac_free_tstate(desc);
        return wc_lkm_errno(ret);
    }
}

WC_MAYBE_UNUSED static int km_hmac_final(struct shash_desc *desc, u8 *out) {
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    /* A failed ->update() freed the node and NULLed it, which is this path's
     * equivalent of the SHA-2 wrappers' failure latch: the desc is spent.  A
     * caller that ignores the -EINVAL and finalizes anyway must not be allowed
     * to dereference it.  wc_HmacUpdate() can genuinely fail here (a
     * vector-register save refusal from an irqs-disabled caller), so this is a
     * reachable sequence, not a theoretical one. */
    if (ctx->failed || (ctx->node == NULL))
        return -EINVAL;

    int ret;

    /* Bracket once, before the node is freed: a refusal here must leave the
     * desc finalizable on retry, not consumed. */
    KM_SHA_SVR_BEGIN(ret);

    ret = wc_HmacFinal(&ctx->node->wc_hmac, out);

    KM_SHA_SVR_END();

    km_hmac_free_tstate(desc);

    if (ret == 0)
        return 0;
    else
        return wc_lkm_errno(ret);
}

WC_MAYBE_UNUSED static int km_hmac_finup(struct shash_desc *desc, const u8 *data,
                      unsigned int len, u8 *out)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    /* Spent by an earlier failed ->update(); see km_hmac_final(). */
    if (ctx->failed || (ctx->node == NULL))
        return -EINVAL;

    int ret;

    /* One bracket for the update+final pair, so the MAC cannot be split across
     * two acquisitions.  Do NOT call km_hmac_final() from inside it: that ends
     * with km_hmac_free_tstate(), which takes desc_list_lock, and the module
     * refuses a mutex inside a vector-register section -- the guard WARNs
     * ("wc_LockMutex() called inside SAVE_VECTOR_REGISTERS()") and then SKIPS
     * the list_del() and wc_HmacFree(), leaking the node.  Latent until 6.16
     * made crypto_shash_final() an inline over ->finup(), which is what made
     * this path reachable.  Inline the final here and free after the bracket
     * closes. */
    KM_SHA_SVR_BEGIN(ret);

    ret = wc_HmacUpdate(&ctx->node->wc_hmac, data, len);
    if (ret == 0)
        ret = wc_HmacFinal(&ctx->node->wc_hmac, out);
    else
        ctx->failed = 1;

    KM_SHA_SVR_END();

    km_hmac_free_tstate(desc);

    return (ret == 0) ? 0 : wc_lkm_errno(ret);
}

WC_MAYBE_UNUSED static int km_hmac_digest(struct shash_desc *desc, const u8 *data,
                      unsigned int len, u8 *out)
{
    /* One-shot: no abandonment or export window, so skip the cleanup list.
     * sizeof(struct Hmac) is 832 -- too large for the stack (cf. the SHA-3
     * digest's stack state), so use a bare heap Hmac that is always freed
     * here rather than a listed node.
     */
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct Hmac *h;
    int ret;

    h = (struct Hmac *)malloc(sizeof *h);
    if (! h)
        return -ENOMEM;

    ret = wc_HmacCopy(&p_ctx->wc_hmac, h);
    if (ret != 0) {
        ForceZero(h, sizeof *h);
        free(h);
        return wc_lkm_errno(ret);
    }

    /* Bracket the whole one-shot.  Refused here means nothing was absorbed, so
     * the caller can retry; taken here means every inner per-block save is a
     * no-op and the MAC cannot be split across two acquisitions. */
    {
        int svr_ret = SAVE_VECTOR_REGISTERS2();
        if (svr_ret != 0) {
            ForceZero(h, sizeof *h);
            free(h);
            return wc_lkm_errno(svr_ret);
        }
    }

    ret = wc_HmacUpdate(h, data, len);
    if (ret == 0)
        ret = wc_HmacFinal(h, out);

    RESTORE_VECTOR_REGISTERS();

    wc_HmacFree(h);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(h, sizeof(*h));
#endif
    free(h);

    return ret == 0 ? 0 : wc_lkm_errno(ret);
}

/* Note that km_hmac_export() is implementing a pseudo-export -- the "out"
 * buffer only gets a pointer to the actual deep-copied HMAC state, not a bona
 * fide serialization of it, because HASH_MAX_STATESIZE is simply too small to
 * accommodate the full state.
 */
WC_MAYBE_UNUSED static int km_hmac_export(struct shash_desc *desc, void *out)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
    struct km_sha_hmac_export_state *blob = (struct km_sha_hmac_export_state *)out;
    struct km_sha_hmac_node *snapshot;
    struct km_sha_hmac_node *evicted = NULL;
    int ret;
    typeof(snapshot->desc_id) snapshot_desc_id;

    /* A spent desc has nothing worth snapshotting; refusing here keeps a
     * failed state from being handed back as a live import handle. */
    if (s_ctx->failed || (s_ctx->node == NULL))
        return -EINVAL;

    /* Snapshot the live state into a fresh node.  Allocate and deep-copy
     * OUTSIDE the lock -- wc_HmacCopy may allocate inner-hash heap.  Copying
     * from this desc's own working node needs no lock (a desc is not used
     * concurrently); the lock protects the lists, not the nodes. */
    snapshot = (struct km_sha_hmac_node *)malloc(sizeof(struct km_sha_hmac_node));
    if (! snapshot)
        return -ENOMEM;
    ret = wc_HmacCopy(&s_ctx->node->wc_hmac, &snapshot->wc_hmac);
    if (ret != 0) {
        ForceZero(snapshot, sizeof(*snapshot));
        free(snapshot);
        return -EINVAL;
    }

    if (wc_LockMutex(&p_ctx->desc_list_lock) != 0) {
        wc_HmacFree(&snapshot->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
        ForceZero(snapshot, sizeof(*snapshot));
#endif
        free(snapshot);
        return -EINVAL;
    }
    /* Bound the ring: at capacity, unlink the oldest (list tail) under the lock;
     * it is freed below, outside the lock.  Unlinking under the lock is what
     * lets .import lookup-and-copy under the same lock without racing a free.
     */
    if (p_ctx->export_list_len >= WC_LINUXKM_HMAC_EXPORT_LIST_MAX) {
        evicted = list_last_entry(&p_ctx->export_list,
                                  struct km_sha_hmac_node, desc_ent);
        list_del(&evicted->desc_ent);
        p_ctx->export_list_len--;
    }
    snapshot_desc_id = snapshot->desc_id = p_ctx->cur_desc_id++;
    /* list_add() prepends, so the tail from list_last_entry() is the oldest. */
    list_add(&snapshot->desc_ent, &p_ctx->export_list);
    p_ctx->export_list_len++;
    (void)wc_UnLockMutex(&p_ctx->desc_list_lock);

    /* The evicted node is now unlinked and unreachable (any outstanding handle
     * to it will fail import lookup), so free it outside the lock.
     */
    if (evicted != NULL) {
        wc_HmacFree(&evicted->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
        ForceZero(evicted, sizeof(*evicted));
#endif
        free(evicted);
    }

    /* Zero first so no uninitialized padding leaks into the caller's buffer. */
    XMEMSET(blob, 0, sizeof(*blob));
    blob->magic = WC_LINUXKM_HMAC_EXPORT_MAGIC;
    blob->tfm_cookie = p_ctx->tfm_cookie;
    blob->desc_id = snapshot_desc_id;

    return 0;
}

WC_MAYBE_UNUSED static int km_hmac_import(struct shash_desc *desc, const void *in)
{
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
    const struct km_sha_hmac_export_state *blob = (const struct km_sha_hmac_export_state *)in;
    struct km_sha_hmac_node *node_i;
    struct km_sha_hmac_node *newnode;
    struct km_sha_hmac_node *oldnode = NULL;
    int found = 0;
    int ret;

    if (blob->magic != WC_LINUXKM_HMAC_EXPORT_MAGIC)
        return -EINVAL;

    if (blob->tfm_cookie != p_ctx->tfm_cookie)
        return -EINVAL;

    /* Fresh working node, allocated outside the lock; its inner Hmac heap is
     * populated by the copy under the lock below.
     */
    newnode = (struct km_sha_hmac_node *)malloc(sizeof(struct km_sha_hmac_node));
    if (! newnode)
        return -ENOMEM;

    /* Validate the handle AND copy from the snapshot under ONE lock hold, so a
     * concurrent export's eviction cannot free the snapshot between the match
     * and the copy.  A handle from another tfm, an evicted snapshot, or a
     * forged/poisoned blob is not a live member -> graceful -EINVAL, with no
     * dereference of attacker-influenced memory.
     */
    if (wc_LockMutex(&p_ctx->desc_list_lock) != 0) {
        free(newnode);
        return -EINVAL;
    }
    list_for_each_entry(node_i, &p_ctx->export_list, desc_ent) {
        if (node_i->desc_id == blob->desc_id) {
            found = 1;
            break;
        }
    }
    if (! found) {
        (void)wc_UnLockMutex(&p_ctx->desc_list_lock);
        free(newnode);
        return -EINVAL;
    }
    ret = wc_HmacCopy(&node_i->wc_hmac, &newnode->wc_hmac);
    if (ret != 0) {
        (void)wc_UnLockMutex(&p_ctx->desc_list_lock);
        /* No need for wc_HmacFree() here -- failed wc_HmacCopy() guarantees no
         * allocations are held under the Hmac -- in fact, it leaves the object
         * in an indeterminate state that's unsafe to pass to wc_HmacFree(),
         * since we aren't zeroing it after the malloc() (zeroing would be
         * frivolous for allocations to be handed immediately to wc_HmacCopy()).
         */
        ForceZero(newnode, sizeof(*newnode));
        free(newnode);
        return -EINVAL;
    }
    /* Publish: link the working node onto desc_list and into the desc ctx.
     *
     * A prior node belonging to THIS tfm is released rather than orphaned --
     * the same stranding km_hmac_alloc_tstate() fixes, reached by importing
     * into a desc that already holds a state instead of by re-initializing it.
     * live_cookie is what makes that safe: a poisoned or foreign prior pointer
     * does not match, and is overwritten without ever being read.  Unlink here,
     * under the lock we already hold; free below, outside it, because
     * wc_HmacFree() may touch the heap.
     */
    if ((s_ctx->live_cookie == p_ctx->tfm_cookie) && (s_ctx->node != NULL)) {
        oldnode = s_ctx->node;
        list_del(&oldnode->desc_ent);
    }
    newnode->desc_id = p_ctx->cur_desc_id++;
    list_add(&newnode->desc_ent, &p_ctx->desc_list);
    s_ctx->node = newnode;
    /* This path does not go through km_hmac_alloc_tstate(), so set the marker
     * and clear the latch explicitly: a successful import is a live state,
     * whatever the desc held. */
    s_ctx->live_cookie = p_ctx->tfm_cookie;
    s_ctx->failed = 0;
    (void)wc_UnLockMutex(&p_ctx->desc_list_lock);

    if (oldnode != NULL) {
        wc_HmacFree(&oldnode->wc_hmac);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
        ForceZero(oldnode, sizeof(*oldnode));
#endif
        free(oldnode);
    }

    return 0;
}

/* Kernel-API export/import test coverage: cross-desc round-trip through a
 * poisoned desc; the two rejection cases the design relies on (corrupted
 * handle, and a valid handle presented to a different tfm); and eviction of an
 * aged-out handle once WC_LINUXKM_HMAC_EXPORT_LIST_MAX exports have intervened.
 */
WC_MAYBE_UNUSED static int km_hmac_test_export_import(
    const char *cra_name, const char *cra_driver_name)
{
    int ret;
    struct crypto_shash *tfm = NULL;
    struct crypto_shash *tfm2 = NULL;
    struct shash_desc *desc = NULL;
    struct shash_desc *desc2 = NULL;
    struct km_sha_hmac_export_state *blob = NULL;
    struct km_sha_hmac_export_state old_blob;
    size_t desc_size = 0;
    unsigned int split, i, dsz;
    byte key[32];
    byte msg[300];
    byte ref[WC_MAX_DIGEST_SIZE];
    byte tag[WC_MAX_DIGEST_SIZE];

    for (i = 0; i < (unsigned int)sizeof(key); i++)
        key[i] = (byte)(i + 1);
    for (i = 0; i < (unsigned int)sizeof(msg); i++)
        msg[i] = (byte)(i * 7 + 1);

    tfm = crypto_alloc_shash(cra_name, 0, 0);
    if (IS_ERR(tfm)) {
        ret = (int)PTR_ERR(tfm);
        pr_err("error: crypto_alloc_shash(%s) failed: %d\n", cra_name, ret);
        return ret;
    }

    ret = crypto_shash_setkey(tfm, key, sizeof(key));
    if (ret) {
        pr_err("error: %s setkey failed: %d\n", cra_driver_name, ret);
        goto out;
    }

    if (crypto_shash_statesize(tfm) != sizeof(struct km_sha_hmac_export_state)) {
        pr_err("error: %s statesize %u != expected %u\n", cra_driver_name,
               crypto_shash_statesize(tfm),
               (unsigned int)sizeof(struct km_sha_hmac_export_state));
        ret = -EINVAL;
        goto out;
    }

    dsz = crypto_shash_digestsize(tfm);
    desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = (struct shash_desc *)malloc(desc_size);
    desc2 = (struct shash_desc *)malloc(desc_size);
    blob = (struct km_sha_hmac_export_state *)malloc(sizeof(*blob));
    if ((desc == NULL) || (desc2 == NULL) || (blob == NULL)) {
        ret = -ENOMEM;
        goto out;
    }
    XMEMSET(desc, 0, desc_size);
    desc->tfm = tfm;

    /* Reference digest over the whole message. */
    ret = crypto_shash_init(desc);
    if (ret == 0)
        ret = crypto_shash_update(desc, msg, sizeof(msg));
    if (ret == 0)
        ret = crypto_shash_final(desc, ref);
    if (ret) {
        pr_err("error: %s reference digest failed: %d\n", cra_driver_name, ret);
        goto out;
    }

    /* Export mid-stream, import into a poisoned desc, finish BOTH, require both
     * to match the reference.
     */
    split = 150;
    ret = crypto_shash_init(desc);
    if (ret == 0)
        ret = crypto_shash_update(desc, msg, split);
    if (ret == 0)
        ret = crypto_shash_export(desc, blob);
    if (ret) {
        pr_err("error: %s export sequence failed: %d\n", cra_driver_name, ret);
        goto out;
    }

    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm;
    ret = crypto_shash_import(desc2, blob);
    if (ret == 0)
        ret = crypto_shash_update(desc2, msg + split, sizeof(msg) - split);
    if (ret == 0)
        ret = crypto_shash_final(desc2, tag);
    if (ret) {
        pr_err("error: %s import sequence failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    if (XMEMCMP(tag, ref, dsz) != 0) {
        pr_err("error: %s import-continuation digest mismatch\n", cra_driver_name);
        ret = -EBADMSG;
        goto out;
    }

    /* Exporting desc stays live and independent. */
    ret = crypto_shash_update(desc, msg + split, sizeof(msg) - split);
    if (ret == 0)
        ret = crypto_shash_final(desc, tag);
    if (ret) {
        pr_err("error: %s post-export continuation failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    if (XMEMCMP(tag, ref, dsz) != 0) {
        pr_err("error: %s post-export digest mismatch\n", cra_driver_name);
        ret = -EBADMSG;
        goto out;
    }

    /* Corrupted handle (bad magic) must be rejected. */
    ret = crypto_shash_init(desc);
    if (ret == 0)
        ret = crypto_shash_update(desc, msg, split);
    if (ret == 0)
        ret = crypto_shash_export(desc, blob);
    if (ret) {
        pr_err("error: %s re-export failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    old_blob = *blob;
    blob->magic ^= 0xffffffffU;
    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm;
    if (crypto_shash_import(desc2, blob) == 0) {
        pr_err("error: %s import accepted a corrupted handle magic\n", cra_driver_name);
        ret = -EINVAL;
        goto out;
    }

    /* Valid handle, wrong tfm: snapshot is on tfm's list, not tfm2's. */
    tfm2 = crypto_alloc_shash(cra_name, 0, 0);
    if (IS_ERR(tfm2)) {
        ret = (int)PTR_ERR(tfm2);
        tfm2 = NULL;
        pr_err("error: %s second crypto_alloc_shash failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    ret = crypto_shash_setkey(tfm2, key, sizeof(key));
    if (ret) {
        pr_err("error: %s tfm2 setkey failed: %d\n", cra_driver_name, ret);
        goto out;
    }
    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm2;
    if (crypto_shash_import(desc2, &old_blob) == 0) {
        pr_err("error: %s cross-tfm import was accepted\n", cra_driver_name);
        ret = -EINVAL;
        goto out;
    }

    /* Eviction: after WC_LINUXKM_HMAC_EXPORT_LIST_MAX further exports, the aged
     * handle (old_blob) is evicted and no longer importable, while the newest
     * remains valid.
     */
    for (i = 0; i < (unsigned int)WC_LINUXKM_HMAC_EXPORT_LIST_MAX; i++) {
        ret = crypto_shash_export(desc, blob);
        if (ret) {
            pr_err("error: %s eviction-fill export failed: %d\n", cra_driver_name, ret);
            goto out;
        }
    }
    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm;
    if (crypto_shash_import(desc2, &old_blob) == 0) {
        pr_err("error: %s evicted handle still importable\n", cra_driver_name);
        ret = -EINVAL;
        goto out;
    }
    XMEMSET(desc2, 0xa5, desc_size);
    desc2->tfm = tfm;
    ret = crypto_shash_import(desc2, blob);
    if (ret == 0)
        ret = crypto_shash_final(desc2, tag);
    if (ret) {
        pr_err("error: %s newest handle not importable: %d\n", cra_driver_name, ret);
        goto out;
    }

    /* Finish the still-open exporting desc to free its working node. */
    (void)crypto_shash_final(desc, tag);

    ret = 0;

out:

    free(blob);
    free(desc2);
    free(desc);
    if (tfm2)
        crypto_free_shash(tfm2);
    if (tfm)
        crypto_free_shash(tfm);

    return ret;
}

PRAGMA_DIAG_POP

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
    .export         =       km_hmac_export,                               \
    .import         =       km_hmac_import,                               \
    .statesize      =       sizeof(struct km_sha_hmac_export_state),      \
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
    if (ret < 0) {                                                        \
        wc_test_render_error_message("linuxkm_test_" #name " failed: ",   \
                                     ret);                                \
        return WC_TEST_RET_DEC_EC(ret);                                   \
    }                                                                     \
    ret = check_shash_driver_masking(NULL /* tfm */, this_cra_name,       \
                                      this_cra_driver_name);              \
    if (ret)                                                              \
        return ret;                                                       \
    return km_hmac_test_export_import(this_cra_name, this_cra_driver_name);\
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

/* Registering wolfCrypt's DRBG as the kernel stdrng does NOT require the
 * per-core bank.  The bank supplies one DRBG instance per core behind a
 * checkout protocol; a single WC_RNG per tfm serves the same interface, and it
 * is what the certifiable flavors carry, since WC_RNG_BANK_SUPPORT is compiled
 * out of them (settings.h).  Requiring the bank here made stdrng registration
 * impossible in exactly the builds that ship.
 *
 * Cross-CPU exclusion for the shared instance comes from WC_RNG_HAVE_INST_EXCL,
 * the per-instance compare-and-swap taken inside wc_RNG_GenerateBlock():
 * 0 duplicate blocks over 960,000 blocks at 2/8/16/24/48 threads, against
 * 26,490 with the exclusion removed as a negative control.  Without that macro
 * there is no exclusion at all, so refuse rather than race.
 *
 * The _DEFAULT variant is a different feature and still needs the bank: it
 * installs a process-wide default that wolfCrypt's own callers reach through
 * wc_InitRng_BankRef(), which is a bank reference by construction.
 * See linuxkm/SVR-FALLBACK-ANALYSIS.md sec 11. */
#if !defined(WC_RNG_BANK_DEFAULT_SUPPORT) && !defined(WC_RNG_HAVE_INST_EXCL)
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG without the RNG bank requires WC_RNG_HAVE_INST_EXCL.
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT) && \
    !defined(WC_RNG_BANK_DEFAULT_SUPPORT)
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT requires WC_RNG_BANK_DEFAULT_SUPPORT.
#endif

/* The tfm context: the bank itself where there is one, otherwise a single
 * generator.  Both spellings carry the same interface, so the crypto_rng
 * callbacks below are shared. */
#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    typedef struct wc_rng_bank wc_linuxkm_drbg_ctx;
#else
    typedef struct { WC_RNG rng; } wc_linuxkm_drbg_ctx;
#endif

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT

static volatile int wc_linuxkm_rng_initing_default_bank_flag = 0;

#ifndef WC_LINUXKM_INITRNG_TIMEOUT_SEC
    #define WC_LINUXKM_INITRNG_TIMEOUT_SEC 30
#endif

static int linuxkm_affinity_lock(void *arg) {
    (void)arg;
    if (! wc_linuxkm_can_block())
        return ALREADY_E;

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS

    /* Must use SVR to pin the core, so that we can unconditionally use RVR to
     * unpin it in linuxkm_affinity_unlock().  This gives the default DRBG full
     * access to vector acceleration, while keeping it fully compatible with
     * DEBUG_VECTOR_REGISTER_ACCESS_FUZZING.
     */
    return SAVE_VECTOR_REGISTERS_MAYBE_INHIBIT();

#else /* !WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

#if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_disable(); /* this actually makes irq_count() nonzero, so that
                        * DISABLE_VECTOR_REGISTERS() is superfluous, but
                        * don't depend on that.
                        */
#endif
    local_bh_disable();
    return 0;

#endif /* !WOLFSSL_USE_SAVE_VECTOR_REGISTERS */
}

static int linuxkm_affinity_get_id(void *arg, int *id) {
    (void)arg;
    *id = raw_smp_processor_id();
    return 0;
}

static int linuxkm_affinity_unlock(void *arg) {
    (void)arg;

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS

    RESTORE_VECTOR_REGISTERS_MAYBE_INHIBITED();
    return 0;

#else /* !WOLFSSL_USE_SAVE_VECTOR_REGISTERS */

    local_bh_enable();
#if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    migrate_enable();
#endif
    return 0;

#endif /* !WOLFSSL_USE_SAVE_VECTOR_REGISTERS */
}

static int wc_linuxkm_rng_bank_init(struct wc_rng_bank *ctx)
{
    int ret;
    word32 flags = WC_RNG_BANK_FLAG_CAN_WAIT;


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
    return wc_linuxkm_rng_bank_init((wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm));
}

static void wc_linuxkm_drbg_exit_tfm(struct crypto_tfm *tfm)
{
    wc_linuxkm_drbg_ctx *ctx = (wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm);
    int ret;

    ret = wc_rng_bank_default_clear(ctx);
    if (ret && (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)))
        pr_err("ERROR: wc_rng_bank_default_clear() in wc_linuxkm_drbg_exit_tfm() returned unexpected code %d\n", ret);

    ret = wc_rng_bank_fini(ctx);

    if (ret != 0)
        pr_err("ERROR: wc_rng_bank_fini() in wc_linuxkm_drbg_exit_tfm() returned err %d\n", ret);

    return;
}

#else /* !WC_RNG_BANK_DEFAULT_SUPPORT -- single shared generator per tfm */

static int wc_linuxkm_drbg_init_tfm(struct crypto_tfm *tfm)
{
    wc_linuxkm_drbg_ctx *ctx = (wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm);
    int ret = wc_InitRng(&ctx->rng);

    if (ret != 0) {
        pr_err("ERROR: wc_InitRng() in wc_linuxkm_drbg_init_tfm() returned err %d\n", ret);
        WC_DUMP_BACKTRACE_NONDEBUG;
        if (ret == WC_NO_ERR_TRACE(MEMORY_E))
            return -ENOMEM;
        else
            return -EINVAL;
    }

    return 0;
}

static void wc_linuxkm_drbg_exit_tfm(struct crypto_tfm *tfm)
{
    wc_linuxkm_drbg_ctx *ctx = (wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm);
    int ret = wc_FreeRng(&ctx->rng);

    if (ret != 0)
        pr_err("ERROR: wc_FreeRng() in wc_linuxkm_drbg_exit_tfm() returned err %d\n", ret);

    return;
}

#endif /* !WC_RNG_BANK_DEFAULT_SUPPORT */

/* Every reader of this is in a _DEFAULT path, so it has no users at all in a
 * plain-registration build. */
#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
static int wc_linuxkm_drbg_default_instance_registered = 0;
#endif

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT

static struct wc_rng_bank_inst *linuxkm_get_drbg(wc_linuxkm_drbg_ctx *ctx) {
    int err;
    struct wc_rng_bank_inst *ret;
    word32 flags =
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_CAN_WAIT |
        WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST;

    /* No vector-register inhibit in the can't-block path.  Vector registers are
     * usable wherever this DRBG is legitimately entered from, irq_fpu_usable()
     * is true throughout softirq, and hardirq/NMI is already refused at the
     * top of wc_save_vector_registers_x86().  The old inhibit existed to force
     * the C twin, which no longer exists.  See linuxkm/SVR-FALLBACK-ANALYSIS.md.
     */
    if (wc_linuxkm_can_block())
        flags |= WC_RNG_BANK_FLAG_AFFINITY_LOCK;

    err = wc_rng_bank_checkout(ctx, &ret, 0, WC_LINUXKM_INITRNG_TIMEOUT_SEC, flags);

    if (err != 0) {
        pr_err("ERROR: wc_rng_bank_checkout() in linuxkm_get_drbg() returned err %d.\n", err);
        WC_DUMP_BACKTRACE_NONDEBUG;
        return NULL;
    }

    return ret;
}

static void linuxkm_put_drbg(wc_linuxkm_drbg_ctx *ctx, struct wc_rng_bank_inst **drbg) {
    int ret = wc_rng_bank_checkin(ctx, drbg);
    if (ret != 0) {
        pr_err("ERROR: wc_rng_bank_checkin() in linuxkm_put_drbg() returned err %d.\n", ret);
        WC_DUMP_BACKTRACE_NONDEBUG;
    }
}

#endif /* WC_RNG_BANK_DEFAULT_SUPPORT */

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

#ifndef WC_HAVE_RNG_BANKREF
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT requires WC_HAVE_RNG_BANKREF.
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

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT

static int wc_linuxkm_drbg_generate(wc_linuxkm_drbg_ctx *ctx,
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

        if (unlikely(ret == WC_NO_ERR_TRACE(RNG_FAILURE_E))) {
            if (slen > 0)
                break;

            if (retried)
                break;
            retried = 1;

            ret = wc_rng_bank_inst_reinit(ctx,
                                          drbg,
                                          WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                                          WC_RNG_BANK_FLAG_CAN_WAIT);

            if (ret == 0) {
                pr_warn_ratelimited("WARNING: reinitialized DRBG #%d after RNG_FAILURE_E from wc_RNG_GenerateBlock().\n", raw_smp_processor_id());
                continue;
            }
            else {
                pr_err_ratelimited("ERROR: reinitialization of DRBG #%d after RNG_FAILURE_E failed with ret %d.\n", raw_smp_processor_id(), ret);
                break;
            }
        }
        else
            break;
    }

    if (ret != 0) {
        pr_err_ratelimited("ERROR: wc_linuxkm_drbg_generate() failing on wolfCrypt code %d.\n",ret);
        ret = -EINVAL;
    }

out:

    linuxkm_put_drbg(ctx, &drbg);

    return ret;
}

#else /* !WC_RNG_BANK_DEFAULT_SUPPORT */

static int wc_linuxkm_drbg_generate(wc_linuxkm_drbg_ctx *ctx,
                                    const u8 *src, unsigned int slen,
                                    u8 *dst, unsigned int dlen)
{
    int ret;
    WC_RNG *rng = &ctx->rng;

    /* Exclusion is taken inside wc_RNG_GenerateBlock() by WC_RNG_HAVE_INST_EXCL;
     * there is no checkout to bracket here, and no affinity to hold, because
     * there is one generator rather than one per core.  Vector registers are
     * saved and restored by the SHA-2 code underneath, in whatever context this
     * is entered from. */
    if (slen > 0) {
        ret = wc_RNG_DRBG_Reseed(rng, src, slen);
        if (ret != 0) {
            pr_warn_once("WARNING: wc_RNG_DRBG_Reseed returned %d\n", ret);
            return -EINVAL;
        }
    }

    for (;;) {
        #define RNG_MAX_BLOCK_LEN_ROUNDED (RNG_MAX_BLOCK_LEN & ~0xfU)
        if (dlen > RNG_MAX_BLOCK_LEN_ROUNDED) {
            ret = wc_RNG_GenerateBlock(rng, dst, RNG_MAX_BLOCK_LEN_ROUNDED);
            if (ret == 0) {
                dlen -= RNG_MAX_BLOCK_LEN_ROUNDED;
                dst += RNG_MAX_BLOCK_LEN_ROUNDED;
            }
        }
        #undef RNG_MAX_BLOCK_LEN_ROUNDED
        else {
            ret = wc_RNG_GenerateBlock(rng, dst, dlen);
            if (ret == 0)
                dlen = 0;
        }

        if (dlen == 0)
            break;

        /* No reinit-and-retry, and nothing to fail over to: a DRBG that has
         * failed is not answered by another instance of the same DRBG.  The
         * error is returned to the caller.  ISO/IEC 19790:2012 sec 7.10.1
         * [10.10]; see linuxkm/SVR-FALLBACK-ANALYSIS.md sec 11.5. */
        if (ret != 0)
            break;
    }

    if (ret != 0) {
        pr_err_ratelimited("ERROR: wc_linuxkm_drbg_generate() failing on wolfCrypt code %d.\n", ret);
        ret = -EINVAL;
    }

    return ret;
}

#endif /* !WC_RNG_BANK_DEFAULT_SUPPORT */

static int wc_linuxkm_drbg_generate_tfm(struct crypto_rng *tfm,
                        const u8 *src, unsigned int slen,
                        u8 *dst, unsigned int dlen)
{
    if (tfm->base.__crt_alg->cra_init != wc_linuxkm_drbg_init_tfm)
    {
        pr_err_once("BUG: mismatched tfm.\n");
        return -EFAULT;
    }

    return wc_linuxkm_drbg_generate((wc_linuxkm_drbg_ctx *)crypto_rng_ctx(tfm),
                                    src, slen, dst, dlen);
}

static int wc_linuxkm_drbg_seed(wc_linuxkm_drbg_ctx *ctx,
                        const u8 *seed, unsigned int slen)
{
    int ret;

    if (slen == 0)
        return 0;

#ifdef WC_RNG_BANK_DEFAULT_SUPPORT
    ret = wc_rng_bank_seed(ctx, seed, slen, WC_LINUXKM_INITRNG_TIMEOUT_SEC, WC_RNG_BANK_FLAG_CAN_WAIT);
    if (ret != 0) {
        pr_err("wc_rng_bank_seed() in wc_linuxkm_drbg_seed() returned err %d.\n", ret);
        ret = -EINVAL;
    }
#else
    ret = wc_RNG_DRBG_Reseed(&ctx->rng, seed, slen);
    if (ret != 0) {
        pr_err("wc_RNG_DRBG_Reseed() in wc_linuxkm_drbg_seed() returned err %d.\n", ret);
        ret = -EINVAL;
    }
#endif

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

    return wc_linuxkm_drbg_seed((wc_linuxkm_drbg_ctx *)crypto_rng_ctx(tfm),
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
        .cra_ctxsize     =      sizeof(wc_linuxkm_drbg_ctx),
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
    int ret;

    if (len > WC_MAX_UINT_OF(unsigned int))
        return -EINVAL;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc__get_random_bytes() returned %d.\n", ret);
#endif
        return -EFAULT;
    }
    else {
        ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, buf, (unsigned int)len);
        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);
        if (ret) {
            /* NOT a fall-through.  A registered handler that returns non-zero
             * is retried by drivers/char/random.c and then panic()s; the
             * kernel's own generator is reached only when nothing is
             * registered at all. */
            pr_warn("BUG: wc__get_random_bytes declined with wc_linuxkm_drbg_default_instance_registered, ret=%d.\n", ret);
        }
        return ret;
    }
    __builtin_unreachable();
}

/* used by kernel >=5.14.0 */
static ssize_t wc_get_random_bytes_user(struct iov_iter *iter) {
    struct wc_rng_bank *current_default_wc_rng_bank;
    ssize_t ret;
    if (unlikely(!iov_iter_count(iter)))
        return 0;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_get_random_bytes_user() returned %ld.\n", ret);
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
                pr_err("ERROR: wc_get_random_bytes_user() wc_linuxkm_drbg_generate() returned %ld.\n", ret);
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
    ssize_t ret;
    struct wc_rng_bank *current_default_wc_rng_bank;
    if (unlikely(!nbytes))
        return 0;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in wc_extract_crng_user() returned %ld.\n", ret);
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
                pr_err("ERROR: wc_extract_crng_user() wc_linuxkm_drbg_generate() returned %ld.\n", ret);
                break;
            }

            this_copied = nbytes - total_copied;
            if (this_copied > sizeof(block))
                this_copied = sizeof(block);
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
    int can_sleep = wc_linuxkm_can_block();

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
#ifndef NO_SHA256
        else
#endif
#endif /* WOLFSSL_DRBG_SHA512 */
        /* random.h gates ->drbg / struct DRBG_internal on !NO_SHA256, so the
         * SHA-256 arm only exists when SHA-256 is compiled in. */
#ifndef NO_SHA256
        {
            for (i = 0, V_offset = 0; i < len; ++i) {
                ((struct DRBG_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg)->V[V_offset++] += ((byte *)buf)[i];
                if (V_offset == (int)sizeof ((struct DRBG_internal *)WC_RNG_BANK_INST_TO_RNG(drbg)->drbg)->V)
                    V_offset = 0;
            }
        }
#endif

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
    int can_sleep = wc_linuxkm_can_block();
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

#ifndef WOLFSSL_EXPERIMENTAL_SETTINGS
    #error WOLFSSL_LINUXKM_USE_GET_RANDOM_KPROBES requires WOLFSSL_EXPERIMENTAL_SETTINGS.
#endif

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
            pr_err("ERROR: allocating rng algorithm %s failed: %d\n",
                   wc_linuxkm_drbg.base.cra_name, (int)PTR_ERR(tfm));
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

            XMEMSET(buf1, 0, sizeof buf1);
            XMEMSET(buf2, 0, sizeof buf2);

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
                        XMEMSET(buf2, 0, (size_t)i);
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
