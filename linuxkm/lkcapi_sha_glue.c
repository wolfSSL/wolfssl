/* lkcapi_sha_glue.c -- glue logic for SHA*
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

/* included by linuxkm/lkcapi_glue.c */

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

#if defined(USE_INTEL_SPEEDUP)
    #define WOLFKM_SHA_DRIVER_ISA_EXT "-avx"
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
#define WOLFKM_SHA1_HMAC_DRIVER ("hmac(sha1)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_224_HMAC_DRIVER ("hmac(sha224)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_256_HMAC_DRIVER ("hmac(sha256)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_384_HMAC_DRIVER ("hmac(sha384)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_512_HMAC_DRIVER ("hmac(sha512)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_224_HMAC_DRIVER ("hmac(sha3-224)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_256_HMAC_DRIVER ("hmac(sha3-256)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_384_HMAC_DRIVER ("hmac(sha3-384)" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_512_HMAC_DRIVER ("hmac(sha3-512)" WOLFKM_SHA_DRIVER_SUFFIX)

#ifndef NO_SHA
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA1)
        #define LINUXKM_LKCAPI_REGISTER_SHA1
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA1
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_SHA1) && !defined(NO_HMAC)
    #define LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
#endif

#ifdef WOLFSSL_SHA224
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_224)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_224
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_224
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_224) && !defined(NO_HMAC)
    #define LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
#endif

#ifndef NO_SHA256
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_256)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_256
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_256
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_256) && !defined(NO_HMAC)
    #define LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
#endif

#ifdef WOLFSSL_SHA384
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_384)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_384
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_384
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_384) && !defined(NO_HMAC)
    #define LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
#endif

#ifdef WOLFSSL_SHA512
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_512)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_512
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_512
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_512) && !defined(NO_HMAC)
    #define LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
#endif

#ifdef WOLFSSL_SHA3
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_224)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA3_224)
        #define LINUXKM_LKCAPI_REGISTER_SHA3_224
    #endif
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_256)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA3_256)
        #define LINUXKM_LKCAPI_REGISTER_SHA3_256
    #endif
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_384)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA3_384)
        #define LINUXKM_LKCAPI_REGISTER_SHA3_384
    #endif
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA3_512)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA3_512)
        #define LINUXKM_LKCAPI_REGISTER_SHA3_512
    #endif
#else
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_224
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_256
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_384
        #undef LINUXKM_LKCAPI_REGISTER_SHA3_512
#endif
#ifndef NO_HMAC
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
        #define LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
        #define LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
        #define LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
        #define LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    #endif
#endif


#if defined(LINUXKM_LKCAPI_REGISTER_SHA1) && !defined(NO_HMAC)

#endif

#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_224) && !defined(NO_HMAC)

#endif

#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_256) && !defined(NO_HMAC)

#endif

#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_384) && !defined(NO_HMAC)

#endif

#if defined(LINUXKM_LKCAPI_REGISTER_SHA2_512) && !defined(NO_HMAC)

#endif


    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224

    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256

    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384

    #endif
    #ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512

    #endif
