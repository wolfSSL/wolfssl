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

#if defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WC_DEBUG_FORCE_KERNEL_SETTINGS)
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

#ifdef LINUXKM_LKCAPI_REGISTER
    _Pragma("GCC diagnostic push");
    _Pragma("GCC diagnostic ignored \"-Wunused-parameter\"");
    _Pragma("GCC diagnostic ignored \"-Wpointer-arith\"");
    _Pragma("GCC diagnostic ignored \"-Wshadow\"");
    _Pragma("GCC diagnostic ignored \"-Wnested-externs\"");
    _Pragma("GCC diagnostic ignored \"-Wredundant-decls\"");
    _Pragma("GCC diagnostic ignored \"-Wsign-compare\"");
    _Pragma("GCC diagnostic ignored \"-Wpointer-sign\"");
    _Pragma("GCC diagnostic ignored \"-Wbad-function-cast\"");
#ifndef __clang__
    _Pragma("GCC diagnostic ignored \"-Wdiscarded-qualifiers\"");
#endif
#if defined(__GNUC__) && (__GNUC__ >= 17)
    _Pragma("GCC diagnostic ignored \"-Wconstant-logical-operand\"");
#endif
    #include <linux/acpi.h>
    #include <linux/io.h>
    _Pragma("GCC diagnostic pop");
#endif

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

#ifdef WOLFSSL_DRBG_SHA512
    #define WOLFKM_STDRNG_DRIVER_BASE "sha2-512-drbg-nopr"
#else
    #define WOLFKM_STDRNG_DRIVER_BASE "sha2-256-drbg-nopr"
#endif

#ifdef LINUXKM_DRBG_GET_RANDOM_BYTES
    #define WOLFKM_STDRNG_DRIVER (WOLFKM_STDRNG_DRIVER_BASE \
                                  WOLFKM_STDRNG_WOLFENTROPY \
                                  WOLFKM_STDRNG_RDSEED \
                                  WOLFKM_DRIVER_SUFFIX_BASE \
                                  "-with-global-replace")
#else
    #define WOLFKM_STDRNG_DRIVER (WOLFKM_STDRNG_DRIVER_BASE \
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
};

WC_MAYBE_UNUSED static int km_sha3_init_tfm(struct crypto_shash *tfm)
{
    struct km_Sha3TfmCtx *t_ctx = (struct km_Sha3TfmCtx *)crypto_shash_ctx(tfm);
    if (wc_InitMutex(&t_ctx->desc_list_lock) != 0)
        return -EINVAL;
    INIT_LIST_HEAD(&t_ctx->desc_list);
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

WC_MAYBE_UNUSED static int km_sha3_alloc_tstate(struct shash_desc *desc) {
    struct km_Sha3TfmCtx *t_ctx =
        (struct km_Sha3TfmCtx *)crypto_shash_ctx(desc->tfm);
    struct km_sha3_state_by_pointer *s_ctx = (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);
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

    return 0;
}

WC_MAYBE_UNUSED static void km_sha3_free_tstate(struct shash_desc *desc) {
    struct km_Sha3TfmCtx *t_ctx =
        (struct km_Sha3TfmCtx *)crypto_shash_ctx(desc->tfm);
    struct km_sha3_state_by_pointer *s_ctx = (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);

    if (s_ctx->sha3_state == NULL)
        return;

    if (wc_LockMutex(&t_ctx->desc_list_lock) != 0)
        return;
    list_del(&s_ctx->sha3_state->desc_ent);
    (void)wc_UnLockMutex(&t_ctx->desc_list_lock);

    wc_Sha3_256_Free(&s_ctx->sha3_state->sha3_state);
    ForceZero(s_ctx->sha3_state, sizeof *s_ctx->sha3_state);
    free(s_ctx->sha3_state);
    s_ctx->sha3_state = NULL;
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

    if (ctx->sha3_state == NULL)
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

#define WC_LINUXKM_SHA1_IMPLEMENT(name, s_name, digest_size, block_size,   \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  free_f, test_routine)                    \
                                                                           \
                                                                           \
wc_static_assert(sizeof(struct s_name) <= HASH_MAX_DESCSIZE);              \
wc_static_assert(sizeof(struct s_name) <= HASH_MAX_STATESIZE);             \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
                                                                           \
    int ret = init_f(ctx);                                                 \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _update(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len)                        \
{                                                                          \
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
                                                                           \
    int ret = update_f(ctx, data, len);                                    \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        free_f(ctx);                                                       \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
                                                                           \
    int ret = final_f(ctx, out);                                           \
                                                                           \
    free_f(ctx);                                                           \
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
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
                                                                           \
    int ret = update_f(ctx, data, len);                                    \
                                                                           \
    if (ret != 0) {                                                        \
        free_f(ctx);                                                       \
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
    .descsize       =       sizeof(struct s_name),                         \
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
wc_static_assert(sizeof(struct s_name) <= HASH_MAX_DESCSIZE);              \
wc_static_assert(sizeof(struct s_name) <= HASH_MAX_STATESIZE);             \
                                                                           \
static int km_ ## name ## _init(struct shash_desc *desc) {                 \
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
                                                                           \
    int ret = init_f(ctx);                                                 \
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
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = update_f(ctx, data, len);                                        \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        free_f(ctx);                                                       \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = final_f(ctx, out);                                               \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
                                                                           \
    free_f(ctx);                                                           \
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
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
    int ret;                                                               \
    WC_LINUXKM_SHA2_DECL_W(ctx, W_size);                                   \
                                                                           \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = update_f(ctx, data, len);                                        \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
                                                                           \
    if (ret != 0) {                                                        \
        free_f(ctx);                                                       \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    WC_LINUXKM_SHA2_PUSH_W(ctx);                                           \
    ret = final_f(ctx, out);                                               \
    WC_LINUXKM_SHA2_POP_W(ctx);                                            \
                                                                           \
    free_f(ctx);                                                           \
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
    struct s_name *ctx = (struct s_name *)shash_desc_ctx(desc);            \
    int ret;                                                               \
                                                                           \
    ret = init_f(ctx);                                                     \
    if (ret != 0)                                                          \
        return -EINVAL;                                                    \
                                                                           \
    ret = update_f(ctx, data, len);                                        \
                                                                           \
    if (ret == 0)                                                          \
        ret = final_f(ctx, out);                                           \
                                                                           \
    free_f(ctx);                                                           \
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
    .descsize       =       sizeof(struct s_name),                         \
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
    int ret = update_f(&ctx->sha3_state-> name ## _state, data, len);      \
                                                                           \
    if (ret == 0)                                                          \
        return 0;                                                          \
    else {                                                                 \
        km_sha3_free_tstate(desc);                                         \
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_sha3_state_by_pointer *ctx =                                 \
        (struct km_sha3_state_by_pointer *)shash_desc_ctx(desc);           \
                                                                           \
    int ret = final_f(&ctx->sha3_state-> name ## _state, out);             \
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
    int ret = update_f(&ctx->sha3_state-> name ## _state, data, len);      \
                                                                           \
    if (ret != 0) {                                                        \
        km_sha3_free_tstate(desc);                                         \
        return -EINVAL;                                                    \
    }                                                                      \
                                                                           \
    return km_ ## name ## _final(desc, out);                               \
}                                                                          \
                                                                           \
static int km_ ## name ## _digest(struct shash_desc *desc, const u8 *data, \
                                  unsigned int len, u8 *out)               \
{                                                                          \
    struct km_sha3_state sha3_state;                                       \
    int ret;                                                               \
                                                                           \
    (void)desc;                                                            \
    ret = init_f(&sha3_state. name ## _state, NULL, INVALID_DEVID);        \
    if (ret != 0)                                                          \
        return -EINVAL;                                                    \
    ret = update_f(&sha3_state. name ## _state, data, len);                \
    if (ret == 0)                                                          \
        ret = final_f(&sha3_state. name ## _state, out);                   \
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

WC_MAYBE_UNUSED static int linuxkm_hmac_setkey_common(struct crypto_shash *tfm,
                                                      int type, const byte* key, word32 length)
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

WC_MAYBE_UNUSED static int km_hmac_alloc_tstate(struct shash_desc *desc) {
    struct km_sha_hmac_pstate *p_ctx =
        (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
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

    return 0;
}

WC_MAYBE_UNUSED static void km_hmac_free_tstate(struct shash_desc *desc) {
    struct km_sha_hmac_pstate *p_ctx =
        (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);
    struct km_sha_hmac_state *s_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    if (s_ctx->node == NULL)
        return;

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
    p_ctx->tfm_cookie = get_random_u64();
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
        km_hmac_free_tstate(desc);
        return -EINVAL;
    }

    return 0;
}

WC_MAYBE_UNUSED static int km_hmac_update(struct shash_desc *desc, const u8 *data,
                          unsigned int len)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacUpdate(&ctx->node->wc_hmac, data, len);

    if (ret == 0)
        return 0;
    else {
        km_hmac_free_tstate(desc);
        return -EINVAL;
    }
}

WC_MAYBE_UNUSED static int km_hmac_final(struct shash_desc *desc, u8 *out) {
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacFinal(&ctx->node->wc_hmac, out);

    km_hmac_free_tstate(desc);

    if (ret == 0)
        return 0;
    else
        return -EINVAL;
}

WC_MAYBE_UNUSED static int km_hmac_finup(struct shash_desc *desc, const u8 *data,
                      unsigned int len, u8 *out)
{
    struct km_sha_hmac_state *ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);

    int ret = wc_HmacUpdate(&ctx->node->wc_hmac, data, len);

    if (ret != 0) {
        km_hmac_free_tstate(desc);
        return -EINVAL;
    }

    return km_hmac_final(desc, out);
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
        return -EINVAL;
    }
    ret = wc_HmacUpdate(h, data, len);
    if (ret == 0)
        ret = wc_HmacFinal(h, out);

    wc_HmacFree(h);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(h, sizeof(*h));
#endif
    free(h);

    return ret == 0 ? 0 : -EINVAL;
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

    if (s_ctx->node == NULL)
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
    /* Publish: link the working node onto desc_list and into the desc ctx,
     * overwriting any poisoned prior pointer without reading it.  A real prior
     * node orphans onto desc_list and is reaped at exit_tfm.
     */
    newnode->desc_id = p_ctx->cur_desc_id++;
    list_add(&newnode->desc_ent, &p_ctx->desc_list);
    s_ctx->node = newnode;
    (void)wc_UnLockMutex(&p_ctx->desc_list_lock);

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

PRAGMA_DIAG_POP /* -Wno-pointer-arith -Wno-nested-externs, for linux/list.h */

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

#ifndef WC_RNG_BANK_DEFAULT_SUPPORT
    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG requires WC_RNG_BANK_DEFAULT_SUPPORT.
#endif

#ifdef WC_RNG_DEBUG_STATS
    #if defined(SIZEOF_LONG) && (SIZEOF_LONG == 8)
        #define WC_RNG_STAT_FMT "%ld"
    #else
        #define WC_RNG_STAT_FMT "%lld"
    #endif
#endif

static volatile int wc_linuxkm_rng_initing_default_bank_flag = 0;
static struct wc_rng_bank *default_bank;

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

/* one per CPU for each of task, softirq, hardirq, and NMI, plus 4 slop */
#define LINUXKM_RNG_BANK_SIZE (nr_cpu_ids * 4 + 4)
#define LINUXKM_RNG_BANK_LAST_SAFELY_CONTENDABLE (nr_cpu_ids * 2 - 1)
#define LINUXKM_RNG_BANK_FIRST_FAILOVER (nr_cpu_ids * 4)

static int linuxkm_affinity_get_id(void *arg, int *id) {
    (void)arg;
    *id = raw_smp_processor_id();
    /* Stratify by execution context class -- one band of nr_cpu_ids
     * instances each for task, softirq, hardirq, and NMI -- so that
     * same-CPU context nesting never contends for an instance.  Note
     * in_serving_softirq(), NOT in_softirq(): the latter is also true
     * whenever softirqs are merely disabled (local_bh_disable(),
     * spin_lock_bh(), including our own affinity-lock callback), which
     * would misroute task-context callers into the softirq band.
     * Order matters: NMI context also carries hardirq state.
     * Misclassification is never unsafe -- the per-instance CAS lease
     * is the enforcement -- it only costs the structural-noncontention
     * property.
     */
    if (in_nmi())
        *id += nr_cpu_ids * 3;
    else if (hardirq_count())
        *id += nr_cpu_ids * 2;
    else if (in_serving_softirq())
        *id += nr_cpu_ids * 1;
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

#define WC_LINUXKM_ENTROPY_DAEMON_MAGIC 0x6f77666c

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)

#define WC_LINUXKM_HAVE_RNG_REGISTRY

/* Registry of every kernel-module RNG object needing state-invalidation
 * coverage: banks (default and tfm-private) and long-lived process-context
 * RBGC leaves from LKCAPI_INITRNG().  Atomic-born leaves are deliberately
 * excluded (see linuxkm_InitRng_DefaultRBGC()): the mutex is thereby never
 * taken from atomic context, so it can sleep, and the daemon's leaf pass
 * may gather entropy under it.
 *
 * Not usable on old FIPS because the mechanism fundamentally depends on
 * wc_RNG_register_free_hook().
 */
struct linuxkm_rng_object {
    struct linuxkm_rng_object *prev, *next;
    int is_bank;
    union {
        WC_RNG *rng;
        struct wc_rng_bank *bank;
    };
};
static DEFINE_MUTEX(wc_linuxkm_rng_registry_mutex);
static struct linuxkm_rng_object *wc_linuxkm_rng_registry_head;
/* Generation counter gating the daemon's registered-leaf recovery sweep:
 * incremented by wc_linuxkm_rng_state_invalidate() before it releases the registry
 * mutex, snapshotted by the daemon at sweep start, CAS'd from the snapshot
 * to 0 at completion.  A CAS failure means an invalidation landed since
 * the snapshot -- the counter stays hot and the next pass re-sweeps.  The
 * daemon thereby pays one atomic load per iteration instead of a mutexed
 * list walk. */
static wolfSSL_Atomic_Int wc_linuxkm_rng_registry_needs_recovery = 0;

static void wc_linuxkm_rng_registry_link(struct linuxkm_rng_object *obj)
{
    mutex_lock(&wc_linuxkm_rng_registry_mutex);
    obj->prev = NULL;
    obj->next = wc_linuxkm_rng_registry_head;
    if (obj->next)
        obj->next->prev = obj;
    wc_linuxkm_rng_registry_head = obj;
    mutex_unlock(&wc_linuxkm_rng_registry_mutex);
}

static void wc_linuxkm_rng_registry_unlink(struct linuxkm_rng_object *obj)
{
    mutex_lock(&wc_linuxkm_rng_registry_mutex);
    if (obj->prev)
        obj->prev->next = obj->next;
    else
        wc_linuxkm_rng_registry_head = obj->next;
    if (obj->next)
        obj->next->prev = obj->prev;
    mutex_unlock(&wc_linuxkm_rng_registry_mutex);
}

/* wc_FreeRng() free hook for registered leaves: O(1) unlink (arg is the
 * registry entry), then free the entry.  Process context by the atomic-born
 * exclusion rule. */
static int wc_linuxkm_rng_registry_free_hook(const WC_RNG *rng, void *arg)
{
    struct linuxkm_rng_object *obj = (struct linuxkm_rng_object *)arg;
    (void)rng;
    wc_linuxkm_rng_registry_unlink(obj);
    kfree(obj);
    return 0;
}

static void wc_linuxkm_rng_registry_add_rng(WC_RNG *rng)
{
    struct linuxkm_rng_object *obj = kmalloc(sizeof(*obj), GFP_KERNEL);
    if (obj == NULL)
        return; /* best-effort: an unregistered leaf is merely unprotected */
    obj->is_bank = 0;
    obj->rng = rng;
    if (wc_RNG_register_free_hook(rng, wc_linuxkm_rng_registry_free_hook,
                                  obj) != 0)
    {
        kfree(obj);
        return;
    }
    wc_linuxkm_rng_registry_link(obj);
}

static int wc_linuxkm_rng_registry_bank_free_hook(
    const struct wc_rng_bank *bank, void *arg)
{
    struct linuxkm_rng_object *obj = (struct linuxkm_rng_object *)arg;
    (void)bank;
    wc_linuxkm_rng_registry_unlink(obj);
    kfree(obj);
    return 0;
}

static void wc_linuxkm_rng_registry_add_bank(struct wc_rng_bank *bank)
{
    struct linuxkm_rng_object *obj = kmalloc(sizeof(*obj), GFP_KERNEL);
    if (obj == NULL)
        return; /* best-effort: an unregistered bank is merely unprotected */
    obj->is_bank = 1;
    obj->bank = bank;
    if (wc_rng_bank_register_free_hook(bank,
            wc_linuxkm_rng_registry_bank_free_hook, obj) != 0)
    {
        kfree(obj);
        return;
    }
    wc_linuxkm_rng_registry_link(obj);
}

/* platform announcement (VM fork/clone, resume from hibernation) that RNG
 * state assumptions no longer hold: invalidate the daemon's local root
 * directly (it is unleased by design), invalidate every bank instance,
 * and wake the daemon -- its loop-head check recovers the root first, and
 * consumers recover per-instance through the NEEDS_RECOVERY_E protocol
 * and the daemon's recovery pass. */
static int wc_linuxkm_rng_state_invalidate(void) {
    struct linuxkm_rng_object *obj;
    int ret = 0;

    /* Process context (vmfork notifier / pm notifier); the registry mutex
     * is sleepable and never taken from atomic context. */
    mutex_lock(&wc_linuxkm_rng_registry_mutex);
    for (obj = wc_linuxkm_rng_registry_head; obj != NULL; obj = obj->next) {
        if (obj->is_bank) {
            WC_RNG *daemon_root;
            int this_ret = wc_rng_bank_invalidate_entropy(obj->bank, 0);
            if ((this_ret != 0) && (ret == 0))
                ret = this_ret;
#ifndef WC_LINUXKM_NO_ENTROPY_DAEMON
            daemon_root = wc_rng_bank_daemon_root_get(obj->bank);
            if (daemon_root != NULL)
                (void)wc_RNG_invalidate_entropy(daemon_root);
            if (WOLFSSL_ATOMIC_LOAD(obj->bank->daemon_magic) ==
                WC_LINUXKM_ENTROPY_DAEMON_MAGIC)
            {
                struct task_struct *t = (struct task_struct *)obj->bank->daemon;
                if (t != NULL)
                    wake_up_process(t);
            }
            else
#endif
            {
                /* daemon-less bank: recover synchronously -- the
                 * FOR_RECOVERY claim path in wc_rng_bank_reseed_range()'s
                 * checkouts claims the quarantined instances. */
                this_ret = wc_rng_bank_reseed_range(obj->bank, 0, -1,
                    WC_LINUXKM_INITRNG_TIMEOUT_SEC, WC_RNG_BANK_FLAG_CAN_WAIT);
                if ((this_ret != 0) && (ret == 0))
                    ret = this_ret;
            }
        }
        else {
            (void)wc_RNG_invalidate_entropy(obj->rng);
        }
    }
    (void)wolfSSL_Atomic_Int_FetchAdd(&wc_linuxkm_rng_registry_needs_recovery,
                                      1);
    mutex_unlock(&wc_linuxkm_rng_registry_mutex);

    if (ret != 0) {
        pr_err("ERROR: wc_linuxkm_rng_state_invalidate() walk returned err %d.\n", ret);
        return -EINVAL;
    }
    pr_notice("wolfssl: RNG state invalidated; all instances will recover by credited reseed\n");
    return 0;
}

/* Stock-kernel event coverage for the invalidation machinery: the kernel
 * already broadcasts the two state-duplication events publicly -- VM fork
 * (vmgenid, via the random_vmfork notifier chain, kernels >= 5.18) and
 * resume from hibernation (pm notifier) -- so no kernel patch is needed to
 * receive them.  Both chains are blocking (process context), so the
 * handler's registry mutex is legal, and both unregister calls return only
 * after in-flight callbacks complete, so uninstall-before-teardown is
 * race-free. */

#if IS_ENABLED(CONFIG_VMGENID)
static int wc_linuxkm_rng_vmfork_notify(struct notifier_block *nb,
                                        unsigned long action, void *data)
{
    int ret;
    (void)nb;
    (void)action;
    (void)data; /* the vmfork chain carries no payload; on kernels with the
                 * callback patch, the fork id itself reaches the module as
                 * harvest via the mix_pool_bytes hook. */
    ret = wc_linuxkm_rng_state_invalidate();
    if (ret != 0)
        pr_err("libwolfssl: wc_linuxkm_rng_vmfork_notify: "
               "wc_linuxkm_rng_state_invalidate failed with code %d.\n", ret);
    return NOTIFY_OK;
}
static struct notifier_block wc_linuxkm_rng_vmfork_nb = {
    .notifier_call = wc_linuxkm_rng_vmfork_notify
};
#endif /* CONFIG_VMGENID */

#ifdef CONFIG_PM_SLEEP
static int wc_linuxkm_rng_pm_notify(struct notifier_block *nb,
                                    unsigned long action, void *data)
{
    (void)nb;
    (void)data;
    /* mirror the native crng's policy: hibernation writes RNG state to
     * disk (duplication-class); suspend-to-RAM does not. */
    if ((action == PM_POST_HIBERNATION) || (action == PM_POST_RESTORE)) {
        int ret = wc_linuxkm_rng_state_invalidate();
        if (ret != 0)
            pr_err("libwolfssl: wc_linuxkm_rng_pm_notify for action 0x%lx: "
                   "wc_linuxkm_rng_state_invalidate failed with code %d.\n", action, ret);
    }
    return NOTIFY_OK;
}
static struct notifier_block wc_linuxkm_rng_pm_nb = {
    .notifier_call = wc_linuxkm_rng_pm_notify
};
#endif /* CONFIG_PM_SLEEP */

static int wc_linuxkm_rng_notifiers_installed = 0;

static void wc_linuxkm_rng_notifiers_install(void)
{
    if (wc_linuxkm_rng_notifiers_installed)
        return;
#if IS_ENABLED(CONFIG_VMGENID)
    if (register_random_vmfork_notifier(&wc_linuxkm_rng_vmfork_nb) != 0)
        pr_warn("libwolfssl: register_random_vmfork_notifier failed -- "
                "no VM-fork RNG invalidation coverage.\n");
#endif
#ifdef CONFIG_PM_SLEEP
    if (register_pm_notifier(&wc_linuxkm_rng_pm_nb) != 0)
        pr_warn("libwolfssl: register_pm_notifier failed -- "
                "no hibernation RNG invalidation coverage.\n");
#endif
    wc_linuxkm_rng_notifiers_installed = 1;
}

static void wc_linuxkm_rng_notifiers_uninstall(void)
{
    if (! wc_linuxkm_rng_notifiers_installed)
        return;
#ifdef CONFIG_PM_SLEEP
    (void)unregister_pm_notifier(&wc_linuxkm_rng_pm_nb);
#endif
#if IS_ENABLED(CONFIG_VMGENID)
    (void)unregister_random_vmfork_notifier(&wc_linuxkm_rng_vmfork_nb);
#endif
    wc_linuxkm_rng_notifiers_installed = 0;
}

static ssize_t wc_linuxkm_rng_state_invalidate_handler(
    WC_MODULE_ATTR_CONST struct module_attribute *mattr,
    struct module_kobject *mk,
    const char *buf, size_t count)
{
    int mode = 0;
    int ret;

    (void)mattr;
    (void)mk;

    if (kstrtoint(buf, 10, &mode) < 0)
        return -EINVAL;
    if (mode == 1) {
        /* direct local exercise */
        ret = wc_linuxkm_rng_state_invalidate();
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        pr_info("wc_linuxkm_rng_state_invalidate_handler: called "
                "wc_linuxkm_rng_state_invalidate, retval %d.\n", ret);
#endif
        return ret ? -EIO : (ssize_t)count;
    }
#if IS_ENABLED(CONFIG_VMGENID)
    if (mode == 2) {
        u8 fake_id[16];
#if !IS_MODULE(CONFIG_VMGENID) && defined(WC_LINUXKM_HAVE_MY_KALLSYMS_LOOKUP_NAME)
        static typeof(add_vmfork_randomness) *my_add_vmfork_randomness = NULL;
#endif

        get_random_bytes(fake_id, sizeof fake_id);  /* any unique blob */

#if IS_MODULE(CONFIG_VMGENID)
        add_vmfork_randomness(fake_id, sizeof fake_id);  /* full wire */
#elif defined(WC_LINUXKM_HAVE_MY_KALLSYMS_LOOKUP_NAME)
        /* add_vmfork_randomness() is exported only if vmgenid is a module --
         * work around it. */
        if (my_add_vmfork_randomness == NULL)
            my_add_vmfork_randomness = my_kallsyms_lookup_name("add_vmfork_randomness");
        if (my_add_vmfork_randomness == NULL)
            return -ENOSYS;
        my_add_vmfork_randomness(fake_id, sizeof fake_id);  /* full wire */
#else
        return -ENOSYS;
#endif

#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        pr_info("wc_linuxkm_rng_state_invalidate_handler: called add_vmfork_randomness.\n");
#endif
        return (ssize_t)count;
    }
#endif /* CONFIG_VMGENID */
#if IS_ENABLED(CONFIG_PM_SLEEP)
    if (mode == 3) {
        /* synthetic PM_POST_HIBERNATION delivered directly to our own pm
         * callback: exercises the wake-from-hibernation leg from the
         * notifier boundary inward.  (Injecting into the kernel's pm chain
         * itself would deliver a fake hibernation event to every
         * registered subsystem -- not a test, an incident.) */
        ret = wc_linuxkm_rng_pm_notify(&wc_linuxkm_rng_pm_nb,
                                       PM_POST_HIBERNATION, NULL);
#ifdef WOLFSSL_LINUXKM_VERBOSE_DEBUG
        pr_info("wc_linuxkm_rng_state_invalidate_handler: called "
                "wc_linuxkm_rng_pm_notify(PM_POST_HIBERNATION), retval %d.\n", ret);
#endif
        return (ret == NOTIFY_OK) ? (ssize_t)count : -EIO;
    }
#endif /* CONFIG_PM_SLEEP */

    return -EINVAL;
}

static struct module_attribute wc_linuxkm_rng_state_invalidate_attr =
    __ATTR(rng_state_invalidate, 0220, NULL, wc_linuxkm_rng_state_invalidate_handler);

#define WC_LINUXKM_HAVE_RNG_STATE_INVALIDATE_HANDLER

#endif /* !HAVE_FIPS || FIPS_VERSION3_GE(7,0,0) */

#ifndef WC_LINUXKM_NO_ENTROPY_DAEMON

#ifdef WC_LINUXKM_HAVE_RNG_REGISTRY

#if defined(WC_LINUXKM_VMGENID_POLL) || \
    (defined(CONFIG_ACPI) && !IS_ENABLED(CONFIG_VMGENID))
/* Without CONFIG_VMGENID, we can only detect VM fork events by polling.
 * Mainline gained vmgenid and the random_vmfork notifier chain together in
 * kernel 5.18, so on older kernels and kernels with CONFIG_VMGENID configured
 * off, there is no event to subscribe to -- but the ACPI VM Generation ID
 * device (Microsoft spec; exposed by QEMU, Hyper-V, VMware) is still present,
 * and its 16-byte counter changes exactly when the hypervisor
 * forks/clones/restores the VM.  The daemon polls it each iteration (a 16-byte
 * compare of a memremap'd page -- effectively free) and, on change, invalidates
 * all module RNG state and recovers its own root immediately, folding the new
 * generation id into the credited recovery reseed as nonce.  Detection latency
 * is bounded by the daemon nap.
 *
 * All state is per-daemon, on the daemon's stack: wc_linuxkm_entropy_daemon()
 * is threadsafe, and concurrent daemons discover, map, and poll
 * independently.  Redundant detections by multiple daemons are benign:
 * wc_linuxkm_rng_state_invalidate() is idempotent, and the sweep generation
 * counter dedups the recovery work.
 */

#ifndef WC_LINUXKM_VMGENID_POLL
    #define WC_LINUXKM_VMGENID_POLL
#endif

struct wc_linuxkm_vmgenid_poll_state {
    void *map;
    int state; /* 0 untried, 1 mapped, -1 absent */
    u8 last[16];
};

static acpi_status wc_linuxkm_vmgenid_acpi_cb(acpi_handle handle, u32 depth,
                                              void *context, void **ret)
{
    struct wc_linuxkm_vmgenid_poll_state *st =
        (struct wc_linuxkm_vmgenid_poll_state *)context;
    struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER, NULL };
    union acpi_object *obj;
    u64 gpa;

    (void)depth;

    if (ACPI_FAILURE(acpi_evaluate_object(handle, (acpi_string)"ADDR", NULL, &buf)))
        return AE_OK; /* not it -- keep walking */
    obj = (union acpi_object *)buf.pointer;
    if ((obj != NULL) && (obj->type == ACPI_TYPE_PACKAGE) &&
        (obj->package.count == 2) &&
        (obj->package.elements[0].type == ACPI_TYPE_INTEGER) &&
        (obj->package.elements[1].type == ACPI_TYPE_INTEGER))
    {
        gpa = (obj->package.elements[0].integer.value & 0xffffffffULL) |
              (obj->package.elements[1].integer.value << 32);
        if (gpa != 0) {
            st->map = memremap(gpa, 16, MEMREMAP_WB);
            if (st->map != NULL) {
                kfree(buf.pointer);
                *ret = st->map;
                return AE_CTRL_TERMINATE;
            }
        }
    }
    kfree(buf.pointer);
    return AE_OK;
}

static void wc_linuxkm_vmgenid_poll(struct wc_linuxkm_vmgenid_poll_state *st,
                                    WC_RNG *local_root)
{
    if (st->state == 0) {
        /* one-time discovery, in daemon task context.  The device's _CID
         * is "VM_Gen_Counter" per the Microsoft spec (QEMU adds _HID
         * "QEMUVGID"); acpi_get_devices() matches against both HID and
         * CID lists. */
        void *found = NULL;
        (void)acpi_get_devices("VM_Gen_Counter", wc_linuxkm_vmgenid_acpi_cb,
                               st, &found);
        if (found == NULL)
            (void)acpi_get_devices("QEMUVGID", wc_linuxkm_vmgenid_acpi_cb,
                                   st, &found);
        if (found != NULL) {
            memcpy(st->last, st->map, 16);
            st->state = 1;
            pr_info("libwolfssl: vmgenid ACPI poller active (VM-fork "
                    "RNG invalidation coverage).\n");
        }
        else {
            st->state = -1; /* bare metal or no device */
        }
        return;
    }
    if (st->state != 1)
        return;

    if (memcmp(st->map, st->last, 16) != 0) {
        memcpy(st->last, st->map, 16);
        pr_notice("libwolfssl: VM generation change detected by poller.\n");
        (void)wc_linuxkm_rng_state_invalidate();
        /* recover our root immediately, folding the new generation id in
         * as the credited reseed's nonce; the loop-head recovery check
         * then finds the flag already clear.  (Invalidate-then-reseed
         * ordering keeps the recovery-entry scrub ahead of the fold.) */
        if (local_root != NULL)
            (void)wc_RNG_DRBG_Reseed_Now(local_root, (const byte *)st->last,
                                         16);
    }
}

static void wc_linuxkm_vmgenid_poll_teardown(
    struct wc_linuxkm_vmgenid_poll_state *st)
{
    if (st->map != NULL) {
        memunmap(st->map);
        st->map = NULL;
    }
    st->state = 0;
}
#endif /* CONFIG_ACPI && !CONFIG_VMGENID */

#endif /* WC_LINUXKM_HAVE_RNG_REGISTRY */

/* Entropy-banking daemon for the default rng bank: cycles the bank's
 * instances, keeping each DRBG's nextSeed aperture full so that
 * WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED checkouts can perform credited
 * reseeds as pure computation, patrolling for out-of-service
 * instances (taking their lease and reinitializing them, per
 * wc_rng_bank_recover_inst()), and topping off each instance's output
 * pool (wc_RNG_Pool_Collect2()) from a daemon-local source DRBG --
 * serviced by the module's normal inline reseed machinery, in task
 * context -- so that lease-holding extractors in atomic contexts find
 * pre-generated output.  The daemon is a control plane only for seed
 * material -- entropy moves from the module's seed source to the
 * in-boundary aperture without ever crossing into daemon-visible
 * storage -- and the pool top-off path likewise never holds a lease on
 * the destination: publication is by CAS against the pool aperture,
 * with lost races abandoned in place per the pool protocol.
 *
 * Policy: the daemon sleeps only when it runs out of work, or makes no
 * progress on any instance -- it must keep pace with a consumer
 * draining nextSeeds as fast as it can.  Per-turn classification of
 * wc_rng_bank_next_seed_generate() returns:
 *   0        gathered/published -- progress;
 *   NOT_READY_E  transient (incl. a burned bank, which is refill-eligible
 *            now, and an environmental TestSeed miss with the aperture
 *            preserved) -- progress, so a forced burn can never induce
 *            a nap;
 *   ALREADY_E  ready or consuming -- no work on this instance;
 *   BUSY_E   instance-op gate held by a reinit -- no progress here,
 *            but the gate holder is making it;
 *   MISSING_RNG_E  no DRBG behind the instance -- nothing to bank;
 *   ENTROPY_RT_E / ENTROPY_APT_E and anything else: entropy source
 *            suspect or code defect; shout (unconditionally -- the
 *            library layer deliberately doesn't), and treat as
 *            no-progress so retry is nap-paced, not spin-paced.
 *
 * Lifecycle: spawned when the default bank is installed, reaped
 * (kthread_stop(), which joins) in wc_linuxkm_drbg_exit_tfm() before
 * wc_rng_bank_default_clear()/wc_rng_bank_fini() -- the join is what
 * makes the daemon's use of the bank safe without a separate refcount
 * hold.
 */

#ifndef WC_LINUXKM_ENTROPY_DAEMON_NAP_MS
    #define WC_LINUXKM_ENTROPY_DAEMON_NAP_MS 100
#endif
#ifndef WC_LINUXKM_ENTROPY_DAEMON_GRANULE
    /* wc_Entropy_Get() gathers and hashes in 32 byte blocks -- smaller
     * requests cost the same. */
    #define WC_LINUXKM_ENTROPY_DAEMON_GRANULE 32
#endif
#if !defined(WC_LINUXKM_BONUS_RESEED_INTERVAL)
    /* Opportunistic supplementary reseed interval, for daemon seeding and
     * wc_RNG_DRBG_NextSeedNow().  Pass rate is load-variable (e.g. nap-paced
     * when idle, cond_resched()-paced when busy), so a busy RNG reseeds more
     * often -- the conservative direction.  wolfcrypt's internal
     * WC_RESEED_INTERVAL auto-reseed remains the backstop if this schedule is
     * somehow starved. */
    #define WC_LINUXKM_BONUS_RESEED_INTERVAL 1000
    #if WC_LINUXKM_BONUS_RESEED_INTERVAL >= WC_RESEED_INTERVAL / 2
        #undef WC_LINUXKM_BONUS_RESEED_INTERVAL
        #define WC_LINUXKM_BONUS_RESEED_INTERVAL (WC_RESEED_INTERVAL / 2)
    #endif
#endif

wc_static_assert(WC_LINUXKM_BONUS_RESEED_INTERVAL >= 0 &&
                 WC_LINUXKM_BONUS_RESEED_INTERVAL < WC_RESEED_INTERVAL / 2);

#if defined(WC_RNG_HAVE_POOL) && !defined(WC_LINUXKM_RNG_POOL_SIZE)
    /* per-instance output pool ring size (2..65535).  256 = 8 native
     * get_random_u32-batch-sized draws between top-offs. */
    #define WC_LINUXKM_RNG_POOL_SIZE 256
#endif

static int wc_linuxkm_entropy_daemon(void *arg)
{
    struct wc_rng_bank *bank = (struct wc_rng_bank *)arg;
    int i;
    int ret;
#ifdef WC_LINUXKM_VMGENID_POLL
    struct wc_linuxkm_vmgenid_poll_state vmgenid_poll_state = {};
#endif

    if (WOLFSSL_ATOMIC_LOAD(bank->daemon_magic) != WC_LINUXKM_ENTROPY_DAEMON_MAGIC)
        return -EINVAL;

#if defined(WC_RNG_HAVE_POOL) || defined(WC_RNG_HAVE_NEXT_SEED)
    /* Daemon-local source DRBG for pool top-offs: a full peer of the bank's
     * instances, inline-reseeded at WC_LINUXKM_BONUS_RESEED_INTERVAL cadence in
     * the daemon's task context, torn down through wc_FreeRng() at shutdown.
     * wc_RNG_Pool_Collect2() is called to generate bytes into the destination
     * pools with flow that stays confined within random.c, hence inside the
     * FIPS boundary. */
    WC_RNG *local_root = (WC_RNG *)XMALLOC(sizeof(*local_root), NULL,
                                         DYNAMIC_TYPE_RNG);
    int local_root_reseed_countdown = WC_LINUXKM_BONUS_RESEED_INTERVAL;

    if (local_root != NULL) {
        unsigned long uncredited_nonce = random_get_entropy();
        ret = wc_InitRngNonce(local_root, (byte *)&uncredited_nonce, sizeof uncredited_nonce);
        ForceZero(&uncredited_nonce, (word32)sizeof uncredited_nonce);
        if (ret != 0) {
            pr_err("wc_entropyd: pool source DRBG init failed: %d -- "
                   "pool top-off disabled\n", ret);
            XFREE(local_root, NULL, DYNAMIC_TYPE_RNG);
            local_root = NULL;
        }
        else {
            /* published for wc_linuxkm_rng_state_invalidate(); retracted before
             * teardown.  safe: the random_bytes handlers are unregistered
             * (and drained) before the daemon is stopped. */
            (void)wc_rng_bank_daemon_root_set(bank, local_root);
        }
    }

#ifdef WC_RNG_HAVE_POOL
    if (local_root != NULL) {
        /* One-time pool allocation for every instance, before any
         * extractor can hold a lease against a nonempty ring.  A
         * failure leaves that instance poolless: extract-side callers
         * fall through to direct generates, and Collect2() skips it
         * (BAD_STATE_E) each turn. */
        for (i = 0; i < bank->n_rngs; i++) {
            ret = wc_RNG_Pool_Alloc(WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]),
                                    WC_LINUXKM_RNG_POOL_SIZE);
            if ((ret != 0) && (ret != WC_NO_ERR_TRACE(ALREADY_E))) {
                /* ALREADY_E: already allocated (daemon restart) */
                pr_err("wc_entropyd: pool alloc for DRBG inst %d "
                       "failed: %d\n", i, ret);
            }
        }
    }
#endif /* WC_RNG_HAVE_POOL */
#endif /* WC_RNG_HAVE_POOL || WC_RNG_HAVE_NEXT_SEED */

    for (;;) {
        int progress = 0;
        int congested_progress = 0;

        if (kthread_should_stop())
            break;

#ifdef WC_LINUXKM_VMGENID_POLL
        wc_linuxkm_vmgenid_poll(&vmgenid_poll_state, local_root);
#endif

#if defined(WC_RNG_HAVE_LOCK) && \
    (defined(WC_RNG_HAVE_POOL) || defined(WC_RNG_HAVE_NEXT_SEED))
        /* deterministic local_root recovery after a state-invalidation
         * event: the saturated reseedCtr from wc_RNG_invalidate_entropy()
         * also forces this, but that write races our own generates (the
         * root is unleased by design), so the flag is the authoritative
         * signal and this the authoritative response. */
        if (local_root != NULL) {
            WC_RNG_lock_arg_t root_lock_state;
            if ((wc_RNG_lock_read(local_root, &root_lock_state) == 0) &&
                (root_lock_state & WC_RNG_LOCK_ENTROPY_INVALIDATED))
            {
                int inv_ret = wc_RNG_DRBG_Reseed_Now(local_root, NULL, 0);
                if (inv_ret != 0)
                    pr_err_ratelimited("wc_entropyd: post-invalidation "
                        "local_root reseed failed: %d\n", inv_ret);
            }
        }
#endif

#ifdef HAVE_HASHDRBG
        /* recovery pass: fix out-of-service instances.  The status
         * peek is lockless and possibly stale -- worst case it sends a
         * recover_inst() at a healthy instance (no-op) or misses one
         * cycle; the instance-op gate arbitrates any race with an
         * inline recovery (BUSY_E). */
        for (i = 0; i < bank->n_rngs; i++) {
            if (wc_RNG_GetStatus(WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]))
                == WC_DRBG_OK)
            {
                continue;
            }
            ret = wc_rng_bank_recover_inst(bank, i, 0 /* timeout_secs */,
                                           0 /* flags */);
            if (ret == 0) {
                (void)wc_rng_bank_inst_flags_down(
                    &bank->rngs[i], WC_RNG_BANK_INST_FLAG_ALREADY_WARNED);
                progress = 1;
            }
            else if (ret != WC_NO_ERR_TRACE(BUSY_E)) {
                if (wc_rng_bank_inst_flags_up(
                        &bank->rngs[i], WC_RNG_BANK_INST_FLAG_ALREADY_WARNED))
                {
                    pr_err_ratelimited(
                        "ERROR: wc_entropyd: recovery of DRBG inst %d failed: %d\n",
                        i, ret);
                }
            }
        }
#endif /* HAVE_HASHDRBG */

#ifdef WC_RNG_HAVE_NEXT_SEED
        if (local_root != NULL) {
            /* congestion-triggered RBGC seed pass. */
            for (i = 0; i < bank->n_rngs; i++) {
                wc_drbg_reseed_ctr_t this_reseedCtr;
                ret = wc_RNG_DRBG_GetReseedCtr(WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]),
                                               &this_reseedCtr);
                if ((ret == 0) && (this_reseedCtr > WC_RESEED_INTERVAL / 2)) {
                    WC_ATOMIC_INT_ARG this_NextSeedCurrent;
                    ret = wc_RNG_DRBG_NextSeedCurrent(
                        WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]), &this_NextSeedCurrent);
                    if ((ret == 0) &&
                        (this_NextSeedCurrent != WC_DRBG_NEXT_SEED_READY) &&
                        (this_NextSeedCurrent != WC_DRBG_NEXT_SEED_CONSUMING))
                    {
                        ret = wc_rng_bank_next_seed_generate_rbgc(
                            bank, i, WC_DRBG_NEXT_SEED_LEN, local_root);
                        congested_progress = 1;
                        if (ret == 0)
                            progress = 1;
                    }
                }
            }
        }
#endif /* WC_RNG_HAVE_NEXT_SEED */

#ifdef WC_RNG_HAVE_POOL
        /* pooling pass -- run this pass even if there was high-load seed
         * generation, as it is good defense against reseedCtr exhaustion.
         */
        for (i = 0; i < bank->n_rngs; i++) {
            /* pool top-off: fill whatever free span the ring reports.
             * The fullness peek is a lockless aperture load; Collect2()
             * re-clamps against a fresh snapshot and publishes by CAS,
             * so staleness costs at most a wasted attempt.  Progress
             * accounting keys on the peek, not the call: a full ring is
             * not work, and NOT_READY_E means a racing consumer is making
             * the progress. */
            if (local_root != NULL) {
                word32 pool_n = 0;
                WC_RNG *inst_rng = WC_RNG_BANK_INST_TO_RNG(&bank->rngs[i]);

                if ((wc_RNG_Pool_Current(inst_rng, &pool_n) == 0) &&
                    (inst_rng->pool != NULL) &&
                    (pool_n < (word32)inst_rng->poolSize))
                {
                    unsigned long uncredited_nonce = random_get_entropy();
                    (void)wc_RNG_DRBG_Stir(local_root,
                                                        (byte *)&uncredited_nonce,
                                                        (word32)sizeof uncredited_nonce);
                    ForceZero(&uncredited_nonce, (word32)sizeof uncredited_nonce);
                    ret = wc_RNG_Pool_Collect2(inst_rng, local_root,
                                               (word32)inst_rng->poolSize
                                               - pool_n);
                    if (ret == 0) {
                        progress = 1;
                    }
                    else if ((ret == WC_NO_ERR_TRACE(NOT_READY_E)) ||
                             (ret == WC_NO_ERR_TRACE(BAD_STATE_E)))
                    {
                        /* contention (consumer active) or no pool --
                         * nothing to do here this turn. */
                    }
                    else {
                        pr_err_ratelimited(
                            "wc_entropyd: pool top-off on DRBG inst %d "
                            "returned %d\n", i, ret);
                    }
                }
            }
        }
#endif /* WC_RNG_HAVE_POOL */

        /* if we're coping with congestion hits, continue here, don't bog down
         * in primary seed ops. */
#if defined(WC_RNG_HAVE_NEXT_SEED) && defined(WC_RNG_HAVE_RBGC)
        /* registered-leaf pass: bank RBGC seeds from local_root into
         * long-lived leaves that are invalidated or chain-backed, so their
         * next generate recovers/promotes in place
         * (WC_RNG_INIT_FLAGS_RECOVER_AND_PROMOTE_FROM_NEXT_SEED).
         * Sleepable-mutex context; entropy gathers are legal under it by
         * the atomic-born exclusion rule. */
        if (local_root != NULL) {
            WC_ATOMIC_INT_ARG needs_recovery_snapshot =
                WOLFSSL_ATOMIC_LOAD(wc_linuxkm_rng_registry_needs_recovery);
            if (needs_recovery_snapshot != 0) {
                struct linuxkm_rng_object *obj;
                mutex_lock(&wc_linuxkm_rng_registry_mutex);
                for (obj = wc_linuxkm_rng_registry_head; obj != NULL;
                     obj = obj->next)
                {
                    WC_RNG_lock_arg_t leaf_lock_state;
                    if (obj->is_bank)
                        continue;
                    if (wc_RNG_lock_read(obj->rng, &leaf_lock_state) != 0)
                        continue;
                    if ((leaf_lock_state & WC_RNG_LOCK_ENTROPY_INVALIDATED) ||
                        (wc_RNG_DRBG_GetRBGCStratum(obj->rng) > 0))
                    {
                        if (wc_RNG_DRBG_NextSeedGenerate_RBGC(obj->rng,
                                local_root, WC_DRBG_NEXT_SEED_LEN) == 0)
                            progress = 1;
                    }
                }
                mutex_unlock(&wc_linuxkm_rng_registry_mutex);
                /* on failure, an invalidation landed since the snapshot:
                 * leave the counter hot and re-sweep next pass. */
                (void)wolfSSL_Atomic_Int_CompareExchange(
                    &wc_linuxkm_rng_registry_needs_recovery,
                    &needs_recovery_snapshot, 0);
            }
        }
#endif /* WC_RNG_HAVE_NEXT_SEED && WC_RNG_HAVE_RBGC */

        if (congested_progress)
            goto next_pass;

#if defined(WC_RNG_HAVE_POOL) || defined(WC_RNG_HAVE_NEXT_SEED)

        /* Periodic explicit reseed of the daemon-local pool source, with
         * a fresh cycle-counter nonce -- scheduled fresh entropy in task
         * context, rather than waiting for the counter-forced internal
         * reseed. */
        if ((local_root != NULL) && (--local_root_reseed_countdown < 0)) {
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
            ret = wc_RNG_DRBG_Reseed_Now(local_root, NULL, 0);
#else
            unsigned long uncredited_nonce = random_get_entropy();
            ret = wc_RNG_DRBG_Reseed_Now(local_root,
                                         (byte *)&uncredited_nonce,
                                         sizeof uncredited_nonce);
            ForceZero(&uncredited_nonce, sizeof uncredited_nonce);
#endif
            if (ret == 0) {
                local_root_reseed_countdown =
                    WC_LINUXKM_BONUS_RESEED_INTERVAL;
            }
            else {
                pr_err_ratelimited(
                    "wc_entropyd: pool source reseed failed: %d\n", ret);
            }
        }
#endif /* WC_RNG_HAVE_POOL || WC_RNG_HAVE_NEXT_SEED */

#ifdef WC_RNG_HAVE_NEXT_SEED
        /* seed banking pass: one gather granule per instance per turn. */
        for (i = 0; i < bank->n_rngs; i++) {

            ret = wc_rng_bank_next_seed_generate(
                bank, i, WC_LINUXKM_ENTROPY_DAEMON_GRANULE);
            if ((ret == 0) || (ret == WC_NO_ERR_TRACE(NOT_READY_E))) {
                progress = 1;
            }
            else if ((ret == WC_NO_ERR_TRACE(ALREADY_E)) ||
                     (ret == WC_NO_ERR_TRACE(BUSY_E)) ||
                     (ret == WC_NO_ERR_TRACE(MISSING_RNG_E)))
            {
                /* nothing to do here this turn. */
            }
            else if ((ret == WC_NO_ERR_TRACE(ENTROPY_RT_E)) ||
                     (ret == WC_NO_ERR_TRACE(ENTROPY_APT_E)))
            {
#ifdef WC_VERBOSE_RNG
                pr_err_ratelimited(
                    "WARNING: wc_entropyd: seed health test failed on DRBG inst "
                    "%d: %d -- entropy source suspect\n", i, ret);
#endif
            }
            else {
                pr_err_ratelimited(
                    "ERROR: wc_entropyd: next_seed_generate on DRBG inst %d "
                    "returned %d\n", i, ret);
            }
        }
#endif /* WC_RNG_HAVE_NEXT_SEED */

        next_pass:

        if (progress) {
            cond_resched();
        }
        else {
            if (! kthread_should_stop())
                schedule_timeout_interruptible(msecs_to_jiffies(WC_LINUXKM_ENTROPY_DAEMON_NAP_MS));
        }
    }

#if defined(WC_RNG_HAVE_POOL) || defined(WC_RNG_HAVE_NEXT_SEED)
    if (local_root != NULL) {
#ifdef WC_RNG_DEBUG_STATS
        struct wc_rng_debug_stats_snapshot s;
        if (wc_rng_debug_stats_snap(&s, local_root) == 0) {
            pr_info("RNG INFO: wc_entropyd root total_bytes_requested=" WC_RNG_STAT_FMT "\n"
                    "    total_bytes_produced=" WC_RNG_STAT_FMT
                        " total_requests=" WC_RNG_STAT_FMT "\n"
                    "    reseeds=" WC_RNG_STAT_FMT
                        " stirs=" WC_RNG_STAT_FMT
                        " seed_failures=" WC_RNG_STAT_FMT "\n"
                    "    nextstirs_banked=" WC_RNG_STAT_FMT
                        " nextstirs_redeemed=" WC_RNG_STAT_FMT "\n",
                    s._stats_total_bytes_requested,
                    s._stats_total_bytes_produced,
                    s._stats_total_requests,
                    s._stats_reseeds,
                    s._stats_stirs,
                    s._stats_seed_failures,
                    s._stats_nextstirs_banked,
                    s._stats_nextstirs_redeemed);
        }
#endif /* WC_RNG_DEBUG_STATS */
#ifdef WC_LINUXKM_VMGENID_POLL
        wc_linuxkm_vmgenid_poll_teardown(&vmgenid_poll_state);
#endif
        (void)wc_rng_bank_daemon_root_set(bank, NULL);
        (void)wc_FreeRng(local_root);
        XFREE(local_root, NULL, DYNAMIC_TYPE_RNG);
    }
#endif

    return 0;
}

#endif /* !WC_LINUXKM_NO_ENTROPY_DAEMON */

static int wc_linuxkm_rng_bank_init(struct wc_rng_bank *ctx)
{
    int ret;
    word32 flags = WC_RNG_BANK_FLAG_CAN_WAIT;
    unsigned long uncredited_nonce = random_get_entropy();

    if (wc_linuxkm_rng_initing_default_bank_flag && (default_bank != NULL)) {
        pr_err("BUG: wc_linuxkm_rng_bank_init() called with "
               "wc_linuxkm_rng_initing_default_bank_flag asserted and default_bank != NULL.\n");
        return -EINVAL;
    }

#if defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) && \
    defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
    /* before v7, the SHA-2 implementations couldn't dynamically switch between
     * C and asm in a given wc_Sha256 instance.  With WC_SVR_USE_NATIVE_REG_BUFS
     * built in, the pin is needed only if the native facility failed to come
     * up at runtime (missing OSXSAVE/FXSR, allocation failure, or selftest
     * failure) -- wc_svr_native_init() runs from
     * allocate_wolfcrypt_linuxkm_fpu_states() during module setup, before any
     * bank init, so wc_linuxkm_svr_native_is_ready() is settled here.
     */
    if (wc_linuxkm_rng_initing_default_bank_flag
#ifdef WC_SVR_USE_NATIVE_REG_BUFS
        && (! wc_linuxkm_svr_native_is_ready())
#endif
        )
    {
        flags |= WC_RNG_BANK_FLAG_NO_VECTOR_OPS;
    }
#endif

    /* The bank is embedded in the tfm context: its lifetime encloses all
     * checkouts by kernel crypto API teardown ordering, so per-checkout
     * refcounting buys nothing here and is the one bank-global RMW pair
     * on the readout hot path. */
    ret = wc_rng_bank_init_nonce(
        ctx, LINUXKM_RNG_BANK_SIZE,
        flags | WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING | WC_RNG_BANK_FLAG_INIT_RBGC,
        WC_LINUXKM_INITRNG_TIMEOUT_SEC,
        NULL /* heap */, INVALID_DEVID,
        (byte *)&uncredited_nonce, (word32)sizeof uncredited_nonce);

    if (ret == 0) {
        (void)wc_rng_bank_first_failover_inst_set(ctx, LINUXKM_RNG_BANK_FIRST_FAILOVER);
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
                    pr_err("ERROR: wc_rng_bank_default_set() in "
                           "wc_linuxkm_rng_bank_init() returned err %d\n", ret);
                    WC_DUMP_BACKTRACE_NONDEBUG;
                }
                else {
                    default_bank = ctx;
#ifndef WC_LINUXKM_NO_ENTROPY_DAEMON
                    /* Try to launch the entropy daemon.  Failure is nonfatal:
                     * the inline reseed and recovery paths serve daemonless
                     * operation. */
                    ret = wc_rng_bank_daemon_reserve(
                        ctx, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
                    if (ret != 0) {
                        pr_err("ERROR: wc_rng_bank_daemon_reserve() in "
                               "wc_linuxkm_rng_bank_init() returned err %d\n",
                               ret);
                        ret = 0;
                    }
                    else {
                        struct task_struct *t = kthread_run(
                            wc_linuxkm_entropy_daemon, ctx, "wc_entropyd");
                        if (IS_ERR(t)) {
                            (void)wc_rng_bank_daemon_release(
                                ctx, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
                            pr_err("WARNING: wc_entropyd spawn failed: %d "
                                   "(falling back to synchronous entropy strategy)\n",
                                   (int)PTR_ERR(t));
                        }
                        else {
                            ret = wc_rng_bank_daemon_register(
                                ctx, t, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
                            if (ret != 0) {
                                pr_err("ERROR: wc_rng_bank_daemon_register() "
                                       "in wc_linuxkm_rng_bank_init() returned err %d\n",
                                       ret);
                                (void)kthread_stop(t);
                                (void)wc_rng_bank_daemon_release(
                                    ctx, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
                                ret = 0;
                            }
                        }
                    }
#endif /* !WC_LINUXKM_NO_ENTROPY_DAEMON */
                }
            }
        }
        else {
            (void)wc_rng_bank_fini(ctx);
            pr_err("ERROR: wc_rng_bank_set_affinity_handlers() in "
                   "wc_linuxkm_rng_bank_init() returned err %d\n", ret);
            WC_DUMP_BACKTRACE_NONDEBUG;
        }
    }
    else {
        pr_err("ERROR: wc_rng_bank_init() in wc_linuxkm_rng_bank_init() "
               "returned err %d\n", ret);
        if (ret == WC_NO_ERR_TRACE(MEMORY_E))
            ret = -ENOMEM;
        else if (ret == WC_NO_ERR_TRACE(WC_TIMEOUT_E))
            ret = -ETIMEDOUT;
        else if (ret == WC_NO_ERR_TRACE(INTERRUPTED_E))
            ret = -EINTR;
        else
            ret = -EINVAL;
    }

#ifdef WC_LINUXKM_HAVE_RNG_REGISTRY
    if (ret == 0)
        wc_linuxkm_rng_registry_add_bank(ctx);
#endif

    return ret;
}

#ifdef WC_RNG_DEBUG_STATS
/* Dump the default bank's aggregate stats, and (when reachable via the
 * daemon-root slot) the entropy daemon's root stats, to the kernel log.
 * Snapshots are racy by design (debug stats doctrine); callable any time
 * from task context. */
static void wc_linuxkm_rng_dump_stats(struct wc_rng_bank *ctx)
{
    struct wc_rng_debug_stats_snapshot s;

    {
        WC_RNG *daemon_root = wc_rng_bank_daemon_root_get(ctx);
        if ((daemon_root != NULL) &&
            (wc_rng_debug_stats_snap(&s, daemon_root) == 0))
        {
            pr_info("RNG INFO: wc_entropyd root total_bytes_requested=" WC_RNG_STAT_FMT "\n"
                    "    total_bytes_produced=" WC_RNG_STAT_FMT
                        " total_requests=" WC_RNG_STAT_FMT "\n"
                    "    reseeds=" WC_RNG_STAT_FMT
                        " stirs=" WC_RNG_STAT_FMT
                        " seed_failures=" WC_RNG_STAT_FMT "\n"
                    "    stirs_banked=" WC_RNG_STAT_FMT
                        " stirs_redeemed=" WC_RNG_STAT_FMT "\n",
                    s._stats_total_bytes_requested,
                    s._stats_total_bytes_produced,
                    s._stats_total_requests,
                    s._stats_reseeds,
                    s._stats_stirs,
                    s._stats_seed_failures,
                    s._stats_nextstirs_banked,
                    s._stats_nextstirs_redeemed);
        }
    }

    if (wc_rng_bank_debug_stats_snap(&s, ctx) == 0) {
            pr_info("RNG INFO: default bank size=%d total_bytes_requested=" WC_RNG_STAT_FMT "\n"
                    "    total_bytes_produced=" WC_RNG_STAT_FMT
                        " total_requests=" WC_RNG_STAT_FMT "\n"
                    "    reseeds=" WC_RNG_STAT_FMT
                        " stirs=" WC_RNG_STAT_FMT
                        " seed_failures=" WC_RNG_STAT_FMT "\n"
                    "    locks_taken=" WC_RNG_STAT_FMT
                        " locks_released=" WC_RNG_STAT_FMT
                        " locks_refused=" WC_RNG_STAT_FMT "\n"
#ifdef WC_RNG_HAVE_RBGC
                    "    RBGC_bytes_produced=" WC_RNG_STAT_FMT
                        " RBGC_reseeds=" WC_RNG_STAT_FMT "\n"
#endif
#ifdef WC_RNG_HAVE_POOL
                    "    pool_bytes_produced=" WC_RNG_STAT_FMT
                        " pool_bytes_missed=" WC_RNG_STAT_FMT "\n"
#endif
#ifdef WC_RNG_HAVE_NEXT_SEED
                    "    nextseedsprimary_redeemed=" WC_RNG_STAT_FMT
                        " nextseedsRBGC_redeemed=" WC_RNG_STAT_FMT "\n"
                    "    nextseedsbanked=" WC_RNG_STAT_FMT
                        " nextstirs_banked=" WC_RNG_STAT_FMT
                        " nextstirs_redeemed=" WC_RNG_STAT_FMT "\n"
#endif
                    ,
                    ctx->n_rngs,
                    s._stats_total_bytes_requested,
                    s._stats_total_bytes_produced,
                    s._stats_total_requests,
                    s._stats_reseeds,
                    s._stats_stirs,
                    s._stats_seed_failures,
                    s._stats_locks_taken,
                    s._stats_locks_released,
                    s._stats_locks_refused
#ifdef WC_RNG_HAVE_RBGC
                    ,s._stats_RBGC_bytes_produced
                    ,s._stats_RBGC_reseeds
#endif
#ifdef WC_RNG_HAVE_POOL
                    ,s._stats_pool_bytes_produced
                    ,s._stats_pool_bytes_missed
#endif
#ifdef WC_RNG_HAVE_NEXT_SEED
                    ,s._stats_nextseedsprimary_redeemed
                    ,s._stats_nextseedsRBGC_redeemed
                    ,s._stats_nextseedsbanked
                    ,s._stats_nextstirs_banked
                    ,s._stats_nextstirs_redeemed
#endif
                );
    }
}
#endif /* WC_RNG_DEBUG_STATS */

static int wc_linuxkm_rng_bank_fini(struct wc_rng_bank *ctx) {
    int ret;

#ifndef WC_LINUXKM_NO_ENTROPY_DAEMON
    if (WOLFSSL_ATOMIC_LOAD(ctx->daemon_magic) == WC_LINUXKM_ENTROPY_DAEMON_MAGIC) {
        struct task_struct *t;
        ret = wc_rng_bank_daemon_unregister(
            ctx, (void **)&t, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
        if ((ret == 0) || (ret == WC_NO_ERR_TRACE(ALREADY_E))) {
            if (ret == 0)
                (void)kthread_stop(t);
            ret = wc_rng_bank_daemon_release(
                ctx, WC_LINUXKM_ENTROPY_DAEMON_MAGIC);
            if (ret != 0)
                pr_err("ERROR: wc_rng_bank_daemon_release() in "
                       "wc_linuxkm_rng_bank_fini() returned code %d\n", ret);
        }
        else
            pr_err("ERROR: wc_rng_bank_daemon_unregister() in "
                   "wc_linuxkm_rng_bank_fini() returned code %d\n", ret);
    }
#endif /* !WC_LINUXKM_NO_ENTROPY_DAEMON */

    if (ctx->flags & WC_RNG_BANK_FLAG_DEFAULT_BANK) {
        /* clear the _inited flag unconditionally -- if either
         * wc_rng_bank_default_clear() or wc_rng_bank_fini() fails, then the ctx
         * is in an indeterminate state and should not be accessed. */
        default_bank = NULL;

        ret = wc_rng_bank_default_clear(ctx);
        if (ret != 0)
            pr_err("ERROR: wc_rng_bank_default_clear() in "
                   "wc_linuxkm_rng_bank_fini() returned code %d\n", ret);

#ifdef WC_RNG_DEBUG_STATS
        wc_linuxkm_rng_dump_stats(ctx);
#endif
    }

    ret = wc_rng_bank_fini(ctx);

    if (ret != 0)
        pr_err("ERROR: wc_rng_bank_fini() in wc_linuxkm_rng_bank_fini() "
               "returned err %d\n", ret);

    return ret;
}

static int wc_linuxkm_drbg_init_tfm(struct crypto_tfm *tfm)
{
    return wc_linuxkm_rng_bank_init((struct wc_rng_bank *)crypto_tfm_ctx(tfm));
}

static void wc_linuxkm_drbg_exit_tfm(struct crypto_tfm *tfm)
{
    struct wc_rng_bank *ctx = (struct wc_rng_bank *)crypto_tfm_ctx(tfm);

    (void)wc_linuxkm_rng_bank_fini(ctx);
}

static int wc_linuxkm_drbg_default_instance_registered = 0;

static struct wc_rng_bank_inst *linuxkm_get_drbg(struct wc_rng_bank *ctx) {
    int err;
    struct wc_rng_bank_inst *ret;
    word32 flags =
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_CAN_WAIT |
        WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST;

#ifdef WC_SVR_USE_NATIVE_REG_BUFS
    if (wc_linuxkm_svr_native_is_ready())
        flags |= WC_RNG_BANK_FLAG_AFFINITY_LOCK;
    else
#endif
    if (wc_linuxkm_can_block())
        flags |= WC_RNG_BANK_FLAG_AFFINITY_LOCK;
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
    else
        flags |= WC_RNG_BANK_FLAG_NO_VECTOR_OPS;
#endif

    if (! wc_linuxkm_can_block()) {
        /* atomic-context callers can't wait out a quarantine: accept
         * admission to an invalidated instance and recover it inline
         * (below) with a synchronous credited primary reseed.  The
         * entropy gather rides wc_LockMutex()'s atomic-context arm. */
        flags |= WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY;
    }

    err = wc_rng_bank_checkout(ctx, &ret, 0, WC_LINUXKM_INITRNG_TIMEOUT_SEC, flags);

    if ((err == WC_NO_ERR_TRACE(NEEDS_RECOVERY_E)) && (ret != NULL)) {
        /* leased-but-quarantined per WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY:
         * we own the recovery obligation. */
        err = wc_RNG_DRBG_Reseed_Now(WC_RNG_BANK_INST_TO_RNG(ret), NULL, 0);
        if (err == 0)
            return ret;
        pr_err_ratelimited("ERROR: inline recovery reseed in "
                           "linuxkm_get_drbg() returned err %d.\n", err);
        (void)wc_rng_bank_inst_checkin(&ret);
        return NULL;
    }

    if (err != 0) {
        pr_err("ERROR: wc_rng_bank_checkout() in linuxkm_get_drbg() returned "
               "err %d.\n", err);
        WC_DUMP_BACKTRACE_NONDEBUG;
        return NULL;
    }

    return ret;
}

static void linuxkm_put_drbg(struct wc_rng_bank_inst **drbg) {
    int ret = wc_rng_bank_inst_checkin(drbg);
    if (ret == WC_NO_ERR_TRACE(NEEDS_RECOVERY_E)) {
        /* informational: checked in successfully; the instance is
         * entropy-invalidated (e.g. a state-invalidation event landed
         * mid-lease) and recovers via the checkout admissions or the
         * patrol. */
    }
    else if (ret != 0) {
        pr_err("ERROR: wc_rng_bank_inst_checkin() in linuxkm_put_drbg() "
               "returned err %d.\n", ret);
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

#ifdef WC_RNG_HAVE_RBGC

WC_MAYBE_UNUSED static int linuxkm_InitRng_DefaultRBGC(WC_RNG* rng) {
    unsigned long uncredited_nonce = random_get_entropy();
    int can_sleep = wc_linuxkm_can_block();
    int ret = wc_rng_bank_spawn(NULL /* bank */, rng, (byte *)&uncredited_nonce,
                                sizeof uncredited_nonce,
                                0 /* preferred_inst_offset */,
                                0 /* timeout_secs */,
                                WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
                                WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST |
                                (can_sleep ?
                                 WC_RNG_BANK_FLAG_SPAWN_RECOVER_AND_PROMOTE :
                                 0));
    ForceZero(&uncredited_nonce, (word32)sizeof uncredited_nonce);
    if (ret != 0) {
        pr_warn_ratelimited("WARNING: linuxkm_InitRng_DefaultRBGC() failed "
                            "with code %d; falling through to wc_InitRng().\n",
                            ret);
        ret = wc_InitRng(rng);
    }
#ifdef WC_LINUXKM_HAVE_RNG_REGISTRY
    if (ret == 0) {
        /* Long-lived process-context leaves join the invalidation registry;
         * atomic-born leaves are excluded by rule (and are transient by
         * nature).  Registration is best-effort. */
        if (can_sleep)
            wc_linuxkm_rng_registry_add_rng(rng);
    }
#endif
    return ret;
}

#define LKCAPI_INITRNG(rng) linuxkm_InitRng_DefaultRBGC(rng)

#elif defined(WC_HAVE_RNG_BANKREF)

WC_MAYBE_UNUSED static int linuxkm_InitRng_DefaultRef(WC_RNG* rng) {
    struct wc_rng_bank *ctx;
    int ret = wc_rng_bank_default_checkout(&ctx);

    if (ret == 0) {
        ret = wc_InitRng_BankRef(ctx, rng);
        (void)wc_rng_bank_default_checkin(&ctx);
        return ret;
    }
    else {
        pr_warn_once("WARNING: linuxkm_InitRng_DefaultRef() called with null "
                     "default_wc_rng_bank; falling through to wc_InitRng().\n");
        return wc_InitRng(rng);
    }

    __builtin_unreachable();
}
#define LKCAPI_INITRNG(rng) linuxkm_InitRng_DefaultRef(rng)

#else /* !WC_RNG_HAVE_RBGC && !WC_HAVE_RNG_BANKREF */

    #error LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT requires WC_RNG_HAVE_RBGC or WC_HAVE_RNG_BANKREF.

#endif /* !WC_RNG_HAVE_RBGC && !WC_HAVE_RNG_BANKREF */

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT && HAVE_HASHDRBG */

#ifndef WC_LINUXKM_DRBG_SMALL_LIMIT
    #define WC_LINUXKM_DRBG_SMALL_LIMIT 8
#endif

#ifdef WC_RNG_HAVE_POOL
wc_static_assert(WC_LINUXKM_DRBG_SMALL_LIMIT <= WC_LINUXKM_RNG_POOL_SIZE);
#endif

static int wc_linuxkm_drbg_generate(struct wc_rng_bank *ctx,
                                    const u8 *src, unsigned int slen,
                                    u8 *dst, unsigned int dlen, int pr)
{
    int ret, retried = 0;
    /* can_block() is false whenever the affinity lock is held -- blockability
     * must be sampled before checkout. */
    int can_wait = wc_linuxkm_can_block();
    wc_drbg_reseed_ctr_t cur_counter = 0;
    struct wc_rng_bank_inst *drbg;

    if (pr && !can_wait)
        return -EAGAIN;

    drbg = linuxkm_get_drbg(ctx);

    if (! drbg) {
        pr_err_once("BUG: linuxkm_get_drbg() failed.\n");
        return -EFAULT;
    }

#ifdef WC_RNG_HAVE_POOL
    if ((! pr) && (slen == 0) && (dlen <= WC_LINUXKM_DRBG_SMALL_LIMIT)) {
        for (retried = 0; retried < 2; ++retried) {
            word32 dlen_before_pool_extraction = dlen;
            if (wc_RNG_Pool_Extract(WC_RNG_BANK_INST_TO_RNG(drbg), dst, &dlen) == 0) {
                dst += dlen;
                dlen = dlen_before_pool_extraction - dlen;
                if (dlen == 0) {
                    ret = 0;
                    goto out;
                }
            }
            else {
                if (wc_RNG_Pool_Collect(WC_RNG_BANK_INST_TO_RNG(drbg),
                                        can_wait ? WC_LINUXKM_RNG_POOL_SIZE :
                                                   WC_SHA256_BLOCK_SIZE)
                    != 0)
                {
                    break;
                }
            }
        }
    }
    retried = 0;
#endif

    if (slen > 0) {
        /* The kernel crypto API's generate-op src is additional data (cf.
         * crypto/drbg.c, which passes it as SP 800-90A additional input).
         * Mix it in without entropy credit -- the reseed counter is
         * unmodified, so only the module's own seed source resets the
         * reseed schedule. */
        ret = wc_RNG_DRBG_Stir(WC_RNG_BANK_INST_TO_RNG(drbg),
                                            src, slen);
        if (ret != 0) {
            pr_warn_once("WARNING: wc_RNG_DRBG_Stir returned %d\n",ret);
            ret = -EINVAL;
            goto out;
        }
    }

    if (pr || (wc_RNG_DRBG_GetReseedCtr(
                   WC_RNG_BANK_INST_TO_RNG(drbg), &cur_counter) == 0))
    {
#ifdef WC_RNG_HAVE_NEXT_SEED
        WC_ATOMIC_INT_ARG NextSeedCurrent;
        ret = wc_RNG_DRBG_NextSeedCurrent(
            WC_RNG_BANK_INST_TO_RNG(drbg), &NextSeedCurrent);
        if ((! pr) &&
            (ret == 0) &&
            (NextSeedCurrent == WC_DRBG_NEXT_SEED_READY) &&
            ((cur_counter >= WC_LINUXKM_BONUS_RESEED_INTERVAL)
#ifdef WC_RNG_HAVE_RBGC
             ||
             ((wc_RNG_DRBG_GetRBGCStratum(WC_RNG_BANK_INST_TO_RNG(drbg)) > 0) &&
              (wc_RNG_DRBG_GetNextSeedRBGCStratum(WC_RNG_BANK_INST_TO_RNG(drbg)) == 0)))
#endif
           )
        {
            unsigned long uncredited_nonce = random_get_entropy();
            ret = wc_RNG_DRBG_NextSeedNow_Nonce(WC_RNG_BANK_INST_TO_RNG(drbg),
                                                (byte *)&uncredited_nonce,
                                                (word32)sizeof uncredited_nonce);
            ForceZero(&uncredited_nonce, (word32)sizeof uncredited_nonce);
            if (ret == 0)
            {
                /* Consumed a daemon-banked seed: full reseed, counter reset, no
                 * entropy gathering, safe in any context -- nothing more to do.
                 * On any nonzero return (typically nothing banked), fall through
                 * to the direct-reseed leg below.
                 */
                cur_counter = 0;
            }
        }
#endif
        if (pr || (can_wait && (cur_counter > WC_RESEED_INTERVAL / 2))) {
#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
            /* carefully restore preemptibility for the reseed operation. */

            #if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_disable();
            #endif

            /* wc_RNG_lock_read()/wc_RNG_lock_clear_extra() suffice here without
             * stronger synchronization: WC_RNG_LOCK_HELD is held invariantly
             * across the span, so this holder is the latch's sole writer -- the
             * exact owner-only contract those accessors encode. */

            /* both levels can be held (an affinity-locked check-out with
             * WC_RNG_BANK_FLAG_NO_VECTOR_OPS, whether from the caller's flags
             * or bank-wide bank->flags, also takes the vector-ops inhibit) --
             * release each held level separately, innermost first, mirroring
             * wc_rng_bank_inst_checkin(). */
            {
                WC_RNG_lock_arg_t lock_state = 0;
                (void)wc_rng_bank_inst_lock_read(drbg, &lock_state);
                if (lock_state & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH)
                    REENABLE_VECTOR_REGISTERS();
                if (lock_state & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
                    RESTORE_VECTOR_REGISTERS_MAYBE_INHIBITED();
            }
#endif

            /* Reseed synchronously.  wc_RNG_DRBG_Reseed_Now() resets the reseed
             * counter iff the reseed succeeds; on failure it leaves the counter
             * unmodified (the WC_RESEED_INTERVAL backstop still governs) and
             * marks the instance out of service, exactly as an interval-forced
             * reseed failure would. */
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
            ret = wc_RNG_DRBG_Reseed_Now(WC_RNG_BANK_INST_TO_RNG(drbg), NULL, 0);
#else
            {
                unsigned long uncredited_nonce = random_get_entropy();
                ret = wc_RNG_DRBG_Reseed_Now(WC_RNG_BANK_INST_TO_RNG(drbg),
                                             (byte *)&uncredited_nonce,
                                             (word32)sizeof uncredited_nonce);

                ForceZero(&uncredited_nonce, (word32)sizeof uncredited_nonce);
            }
#endif
            if (ret != 0) {
                pr_warn_ratelimited("WARNING: wc_RNG_DRBG_Reseed_Now() failed "
                                    "for RNG #%d: %d\n",
                                    wc_rng_bank_get_inst_id(drbg), ret);
            }

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
            /* re-establish each level separately, in acquisition order (the
             * affinity save first, then the vector-ops inhibit), mirroring
             * wc_rng_bank_checkout(); a failed re-acquisition clears only its
             * own lock bit, so check-in unwinds exactly the levels actually
             * held. */
            {
                WC_RNG_lock_arg_t lock_state = 0;
                (void)wc_rng_bank_inst_lock_read(drbg, &lock_state);
                if (lock_state & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED) {
                    int ret2 = SAVE_VECTOR_REGISTERS2();
                    if (ret2 != 0)
                        (void)wc_rng_bank_inst_lock_clear_extra(drbg,
                            WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED);
                }
                if (lock_state & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH) {
                    int ret2 = DISABLE_VECTOR_REGISTERS();
                    if (ret2 != 0)
                        (void)wc_rng_bank_inst_lock_clear_extra(drbg,
                            WC_RNG_BANK_INST_LOCK_VEC_OPS_INH);
                }
            }

            #if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_enable();
            #endif
#endif
        }
    }

    for (;;) {
        #define RNG_MAX_BLOCK_LEN_ROUNDED (RNG_MAX_BLOCK_LEN & ~0xfU)
        if (dlen > RNG_MAX_BLOCK_LEN_ROUNDED) {
            ret = wc_RNG_GenerateBlock(
                WC_RNG_BANK_INST_TO_RNG(drbg), dst, RNG_MAX_BLOCK_LEN_ROUNDED);
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

            if (! can_wait)
                break;

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
            /* carefully restore preemptibility for the reinit operation. */

            #if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_disable();
            #endif

            /* both levels can be held (an affinity-locked checkout with
             * WC_RNG_BANK_FLAG_NO_VECTOR_OPS, whether from the caller's flags
             * or bank-wide bank->flags, also takes the vector-ops inhibit) --
             * release each held level separately, innermost first, mirroring
             * wc_rng_bank_inst_checkin(). */
            {
                WC_RNG_lock_arg_t lock_state = 0;
                (void)wc_rng_bank_inst_lock_read(drbg, &lock_state);
                if (lock_state & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH)
                    REENABLE_VECTOR_REGISTERS();
                if (lock_state & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED)
                    RESTORE_VECTOR_REGISTERS_MAYBE_INHIBITED();
            }
#endif

            ret = wc_rng_bank_inst_reinit(NULL, drbg,
                                          WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                                          WC_RNG_BANK_FLAG_CAN_WAIT);

#ifdef WOLFSSL_USE_SAVE_VECTOR_REGISTERS
            /* re-establish each level separately, in acquisition order (the
             * affinity save first, then the vector-ops inhibit), mirroring
             * wc_rng_bank_checkout(); a failed re-acquisition clears only its
             * own lock bit, so check-in unwinds exactly the levels actually
             * held. */
            {
                /* the latch (annotation bits included) is preserved
                 * across wc_rng_bank_inst_reinit()'s _InitRng() by the
                 * module, so this post-reinit read is authoritative. */
                WC_RNG_lock_arg_t lock_state = 0;
                (void)wc_rng_bank_inst_lock_read(drbg, &lock_state);
                if (lock_state & WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED) {
                    int ret2 = SAVE_VECTOR_REGISTERS2();
                    if (ret2 != 0)
                        (void)wc_rng_bank_inst_lock_clear_extra(drbg,
                            WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED);
                }
                if (lock_state & WC_RNG_BANK_INST_LOCK_VEC_OPS_INH) {
                    int ret2 = DISABLE_VECTOR_REGISTERS();
                    if (ret2 != 0)
                        (void)wc_rng_bank_inst_lock_clear_extra(drbg,
                            WC_RNG_BANK_INST_LOCK_VEC_OPS_INH);
                }
            }

            #if defined(CONFIG_SMP) && (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0))
            migrate_enable();
            #endif
#endif

            if (ret == 0) {
                pr_warn_ratelimited("WARNING: reinitialized DRBG #%d after "
                                    "RNG_FAILURE_E from wc_RNG_GenerateBlock().\n",
                                    wc_rng_bank_get_inst_id(drbg));
                continue;
            }
            else {
                pr_err_ratelimited("ERROR: reinitialization of DRBG #%d after "
                                   "RNG_FAILURE_E failed with ret %d.\n",
                                   wc_rng_bank_get_inst_id(drbg), ret);
                break;
            }
        }
        else
            break;
    }

    if (ret != 0) {
        pr_err_ratelimited("ERROR: wc_linuxkm_drbg_generate() failing on "
                           "wolfCrypt code %d.\n",ret);
        ret = -EIO;
    }

out:

    linuxkm_put_drbg(&drbg);

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
                                    src, slen, dst, dlen, 0 /* pr */);
}

static int wc_linuxkm_drbg_seed(struct wc_rng_bank *ctx,
                        const u8 *seed, unsigned int slen)
{
    int ret;

    if (slen == 0)
        return 0;

    /* The kernel crypto API's seed op carries caller-supplied material (cf.
     * crypto/drbg.c, which maps it to an SP 800-90A personalization string /
     * additional input, never crediting it as entropy).  Mix it into every
     * instance without credit; the reseed schedule stays governed solely by
     * the module's own seed source. */
    ret = wc_rng_bank_seed_range(ctx, 0, LINUXKM_RNG_BANK_LAST_SAFELY_CONTENDABLE,
                                 seed, slen, WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                                 WC_RNG_BANK_FLAG_CAN_WAIT |
                                 WC_RNG_BANK_FLAG_STIR);
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

#if defined(HAVE_FIPS) && !defined(WOLFSSL_LINUXKM_GET_RANDOM_NO_FALLTHROUGH)
    #define WOLFSSL_LINUXKM_GET_RANDOM_NO_FALLTHROUGH
#endif

static int wc__get_random_bytes(void *buf, size_t len)
{
    struct wc_rng_bank *current_default_wc_rng_bank;
    int ret;

    if (len > WC_MAX_UINT_OF(unsigned int))
        return -EINVAL;

    ret = wc_rng_bank_default_checkout(&current_default_wc_rng_bank);
    if (ret) {
#ifdef WOLFSSL_LINUXKM_GET_RANDOM_NO_FALLTHROUGH
        pr_emerg_ratelimited("ERROR: FIPS RNG source failed in "
                             "wc__get_random_bytes(): wc_rng_bank_default_checkout() "
                             "returned %d.\n", ret);
#else
        pr_err_ratelimited("ERROR: FIPS RNG source failed in wc__get_random_bytes(): "
                           "wc_rng_bank_default_checkout() returned %d.\n", ret);
#endif
        /* kernel must-succeed call used from hard IRQ contexts etc. -- the
         * callback dispatch point will always fall through to native DRBG, but
         * we log the condition loudly from here. */
        return -ECANCELED;
    }
    else {
        ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                       NULL, 0, buf, (unsigned int)len, 0 /* pr */);
        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);
        if (ret) {
#ifdef WOLFSSL_LINUXKM_GET_RANDOM_NO_FALLTHROUGH
            pr_emerg_ratelimited("ERROR: FIPS RNG source failed: "
                                 "wc__get_random_bytes(): wc_linuxkm_drbg_generate() "
                                 "failed with code %d.\n", ret);
#else
            pr_err_ratelimited("ERROR: FIPS RNG source failed: "
                               "wc__get_random_bytes(): wc_linuxkm_drbg_generate() "
                               "failed with code %d.\n", ret);
#endif
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
        pr_emerg_ratelimited("ERROR: wc_rng_bank_default_checkout() in "
                             "wc_get_random_bytes_user() returned %ld.\n", ret);
        return -EIO; /* no fallthrough to native randomness */
    }
    else {
        size_t this_copied, total_copied = 0;
        byte *block;
        byte block_small[WC_SHA256_BLOCK_SIZE];
        size_t block_size;

        if (iov_iter_count(iter) <= sizeof block_small)
            block = NULL;
        else
            block = (byte *)malloc(PAGE_SIZE);
        if (block == NULL) {
            block = block_small;
            block_size = sizeof block_small;
        }
        else
            block_size = PAGE_SIZE;

        for (;;) {
            size_t n = min_t(size_t, iov_iter_count(iter), block_size);
            ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, block, n, 0 /* pr */);
            if (unlikely(ret != 0)) {
                pr_emerg_ratelimited("ERROR: wc_get_random_bytes_user() "
                                     "wc_linuxkm_drbg_generate() returned %ld.\n", ret);
                break;
            }

            /* note copy_to_iter() cannot be safely executed with
             * DISABLE_VECTOR_REGISTERS() or kprobes status, i.e.
             * irq_count() must be zero here.
             */
            this_copied = copy_to_iter(block, n, iter);
            total_copied += this_copied;
            if (!iov_iter_count(iter) || this_copied != n)
                break;

            if (signal_pending(current))
                break;
            cond_resched();
        }

        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);

        ForceZero(block, block_size);

        if (block != block_small)
            free(block);

        if (total_copied == 0) {
            if (ret == 0)
                ret = -EFAULT;
            else {
                ret = -EIO;
            }
        }

        if (total_copied != 0)
            ret = (ssize_t)total_copied;   /* partial success wins */

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
        pr_emerg_ratelimited("ERROR: wc_rng_bank_default_checkout() in "
                             "wc_extract_crng_user() returned %ld.\n", ret);
        return -EIO; /* no fallthrough to native randomness */
    }
    else {
        size_t this_copied, total_copied = 0;
        byte *block;
        byte block_small[WC_SHA256_BLOCK_SIZE];
        size_t block_size;

        if (nbytes <= sizeof block_small)
            block = NULL;
        else
            block = (byte *)malloc(PAGE_SIZE);
        if (block == NULL) {
            block = block_small;
            block_size = sizeof block_small;
        }
        else
            block_size = PAGE_SIZE;

        for (;;) {
            size_t n = min_t(size_t, nbytes - total_copied, block_size);
            ret = wc_linuxkm_drbg_generate(current_default_wc_rng_bank,
                                           NULL, 0, block, n, 0 /* pr */);
            if (unlikely(ret != 0)) {
                pr_emerg_ratelimited("ERROR: wc_extract_crng_user() "
                                     "wc_linuxkm_drbg_generate() returned %ld.\n", ret);
                break;
            }

            /* note copy_to_user() cannot be safely executed with
             * DISABLE_VECTOR_REGISTERS() or kprobes status, i.e.
             * irq_count() must be zero here.
             */
            this_copied = n - copy_to_user((byte *)buf + total_copied,
                                           block, n);
            total_copied += this_copied;
            if ((total_copied == nbytes) || (this_copied != n))
                break;

            if (signal_pending(current))
                break;
            cond_resched();
        }

        (void)wc_rng_bank_default_checkin(&current_default_wc_rng_bank);

        ForceZero(block, block_size);

        if (block != block_small)
            free(block);

        if (total_copied == 0) {
            if (ret == 0)
                ret = -EFAULT;
            else
                ret = -EIO;
        }

        if (total_copied != 0)
            ret = (ssize_t)total_copied;   /* partial success wins */

        return ret;
    }
    __builtin_unreachable();
}

/* Note, wc_mix_pool_bytes() only injects the supplied entropy into one RNG,
 * CPU-local when uncontended.  This routine can be pegged by unprivileged
 * users, so its impact needs to stay as CPU-local as possible. */
static int wc_mix_pool_bytes(const void *buf, size_t len) {
    int ret;
    struct wc_rng_bank *ctx = NULL;
    word32 flags =
        WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST |
        WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST;
    struct wc_rng_bank_inst *drbg = NULL;

    if (len > WC_MAX_UINT_OF(word32))
        return -EFBIG;

    /* Continue even if len == 0 -- churning the DRBG is still meaningful. */

    ret = wc_rng_bank_default_checkout(&ctx);
    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in "
                           "wc_mix_pool_bytes() returned %d.\n", ret);
#endif
        return -EFAULT;
    }

    if (wc_linuxkm_can_block())
        flags |= WC_RNG_BANK_FLAG_AFFINITY_LOCK;
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
    else
        flags |= WC_RNG_BANK_FLAG_NO_VECTOR_OPS;
#endif

    ret = wc_rng_bank_checkout(ctx, &drbg, 0, 0, flags);
    if (ret != 0) {
        ret = -EINVAL;
        goto out;
    }

    if (! wc_RNG_DRBG_Present(WC_RNG_BANK_INST_TO_RNG(drbg))) {
        ret = 0; /* consistent with wc_RNG_DRBG_Reseed() behavior in RDRAND configs. */
        goto out;
    }

    /* Mix without crediting the contributed entropy --
     * wc_RNG_DRBG_Stir() leaves the reseed counter unmodified,
     * so only the module's own seed source resets the reseed schedule. */
    ret = wc_RNG_DRBG_Stir(WC_RNG_BANK_INST_TO_RNG(drbg), buf,
                                        (word32)len);
#ifdef WC_RNG_HAVE_NEXT_SEED
    /* The leased instance was just stirred directly, above.  The daemon root --
     * the one node the harvest wire otherwise never reaches -- is single-owner
     * and can't be stirred from here; deposit the fragment into its uncredited
     * accumulator instead (writer-safe without a lease: read-copy-store, see
     * wc_RNG_DRBG_NextStirStore()), for consumption at the root's own
     * next generate.  The supplied entropy is unconditionally absorbed by
     * wc_RNG_DRBG_NextStirStore() -- if nextStirLen is
     * already full, the absorption is by xorbuf(). */
    if (len > 0) {
        WC_RNG *stir_root = wc_rng_bank_daemon_root_get(ctx);
        if (stir_root != NULL)
            (void)wc_RNG_DRBG_NextStirStore(stir_root, (const byte *)buf,
                                                      (word32)len);
    }
#endif /* WC_RNG_HAVE_NEXT_SEED */
    if (ret != 0)
        ret = -EINVAL;

out:

    if (drbg)
        (void)wc_rng_bank_inst_checkin(&drbg);
    if (ctx)
        (void)wc_rng_bank_default_checkin(&ctx);

    return ret;
}

static int wc_crng_reseed(void) {
    struct wc_rng_bank *ctx;
    int can_sleep = wc_linuxkm_can_block();
    int ret = wc_rng_bank_default_checkout(&ctx);

    if (ret) {
#ifdef WC_VERBOSE_RNG
        pr_err_ratelimited("ERROR: wc_rng_bank_default_checkout() in "
                           "wc_crng_reseed() returned %d.\n", ret);
#endif
        return -EFAULT;
    }

    ret = wc_rng_bank_reseed_range(ctx, 0,
                                   LINUXKM_RNG_BANK_LAST_SAFELY_CONTENDABLE,
                                   WC_LINUXKM_INITRNG_TIMEOUT_SEC,
                                   can_sleep
                                   ?
                                   WC_RNG_BANK_FLAG_CAN_WAIT
                                   :
                                   WC_RNG_BANK_FLAG_NONE);

    (void)wc_rng_bank_default_checkin(&ctx);

    if (ret != 0) {
        pr_err("ERROR: wc_rng_bank_reseed_range() returned err %d.\n", ret);
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
    .crng_reseed = wc_crng_reseed,
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
#ifdef HAVE_FIPS
        pr_emerg_ratelimited("ERROR: wc_get_random_bytes_by_kprobe falling "
                             "through to native get_random_bytes with "
                             "wc_linuxkm_drbg_default_instance_registered, ret=%d.\n", ret);
#else
        pr_warn_ratelimited("ERROR: wc_get_random_bytes_by_kprobe falling "
                            "through to native get_random_bytes with "
                            "wc_linuxkm_drbg_default_instance_registered, ret=%d.\n", ret);
#endif
    }
    else {
        pr_warn("BUG: wc_get_random_bytes_by_kprobe called without "
                "wc_linuxkm_drbg_default_instance_registered.\n");
    }

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

#ifdef WC_RNG_DEBUG_STATS
/* control channel at /sys/module/libwolfssl/rng_stats: echo 1 to dump the
 * current RNG stats to the kernel log on demand (they otherwise appear
 * only at teardown). */
static ssize_t wc_linuxkm_rng_stats_handler(WC_MODULE_ATTR_CONST struct module_attribute *mattr,
                                            struct module_kobject *mk,
                                            const char *buf, size_t count)
{
    int arg;

    (void)mattr;
    (void)mk;

    if (kstrtoint(buf, 10, &arg) || (arg != 1))
        return -EINVAL;
    if (! default_bank)
        return -ENODEV;
    wc_linuxkm_rng_dump_stats(default_bank);
    return (ssize_t)count;
}
static struct module_attribute wc_linuxkm_rng_stats_attr =
    __ATTR(rng_stats, 0220, NULL, wc_linuxkm_rng_stats_handler);
#endif /* WC_RNG_DEBUG_STATS */

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
        pr_err("ERROR: %s NOT registered as systemwide default stdrng -- found \"%s\".\n",
               wc_linuxkm_drbg.base.cra_driver_name, crypto_tfm_alg_driver_name(&crypto_default_rng->base));
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
        static struct wc_rng_bank local_default_bank;
        ret = wc_linuxkm_rng_bank_init(&local_default_bank);
        wc_linuxkm_rng_initing_default_bank_flag = 0;
        if (ret) {
            pr_err("ERROR: wc_linuxkm_rng_bank_init returned %d\n", ret);
            return ret;
        }
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
            if (default_bank != NULL) {
                (void)wc_linuxkm_rng_bank_fini(default_bank);
            }
#endif
            return -ECANCELED;
        }
    }

    wc_linuxkm_drbg_default_instance_registered = 1;
    pr_info("%s registered as systemwide default stdrng.\n", wc_linuxkm_drbg.base.cra_driver_name);
    pr_info("libwolfssl: to unload module, first echo 1 > /sys/module/libwolfssl/deinstall_algs\n");

#ifdef WC_LINUXKM_HAVE_RNG_REGISTRY
    /* stock-notifier invalidation coverage rides with the registered
     * DRBGs, patched and unpatched kernels alike. */
    wc_linuxkm_rng_notifiers_install();
#endif

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

#ifdef WC_LINUXKM_HAVE_RNG_REGISTRY
        /* the notifier callbacks walk the RNG registry: uninstall them
         * before any of what they reference is dismantled.  unregister
         * returns only after in-flight callbacks complete. */
        wc_linuxkm_rng_notifiers_uninstall();
#endif

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
        if (default_bank) {
            ret = wc_linuxkm_rng_bank_fini(default_bank);
            if (ret)
                pr_err("ERROR: wc_linuxkm_rng_bank_fini in wc_linuxkm_drbg_cleanup failed: %d\n", ret);
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
