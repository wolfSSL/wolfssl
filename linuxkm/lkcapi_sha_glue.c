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

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_sha_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS) && defined(USE_INTEL_SPEEDUP)
    #error SHA* WC_LINUXKM_C_FALLBACK_IN_SHIMS is not currently supported.
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
#define WOLFKM_STDRNG_DRIVER ("sha2-256-drbg-nopr" WOLFKM_SHA_DRIVER_SUFFIX)

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

#if defined(NO_HMAC) && defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_HMAC)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA1)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA256)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA512)
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
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_SHA3)
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
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_HASH_DRBG_DEFAULT)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT)
        #define LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    #endif
#else
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
        .cra_name        =      this_cra_name,                             \
        .cra_driver_name =      this_cra_driver_name,                      \
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
        .cra_name        =      this_cra_name,                             \
        .cra_driver_name =      this_cra_driver_name,                      \
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
    struct km_sha_hmac_state *t_ctx = (struct km_sha_hmac_state *)shash_desc_ctx(desc);
    struct km_sha_hmac_pstate *p_ctx = (struct km_sha_hmac_pstate *)crypto_shash_ctx(desc->tfm);

    t_ctx->wc_hmac = malloc(sizeof *t_ctx->wc_hmac);
    if (! t_ctx->wc_hmac)
        return -ENOMEM;

    XMEMCPY(t_ctx->wc_hmac, &p_ctx->wc_hmac, sizeof *t_ctx->wc_hmac);

#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* The cached W buffer from the persistent ctx can't be used because it
     * would be double-freed, first by km_hmac_free_tstate(), then by
     * km_hmac_exit_tfm().
     */
    switch (t_ctx->wc_hmac->macType) {

    #ifndef NO_SHA256
        case WC_SHA256:
    #ifdef WOLFSSL_SHA224
        case WC_SHA224:
    #endif
            t_ctx->wc_hmac->hash.sha256.W = NULL;
            break;
    #endif /* WOLFSSL_SHA256 */

    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
    #endif
            t_ctx->wc_hmac->hash.sha512.W = NULL;
            break;
    #endif /* WOLFSSL_SHA512 */
    }
#endif /* WOLFSSL_SMALL_STACK_CACHE */

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
        .cra_name        =      this_cra_name,                            \
        .cra_driver_name =      this_cra_driver_name,                     \
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

#include <wolfssl/wolfcrypt/random.h>

struct wc_linuxkm_drbg_ctx {
    struct wc_rng_inst {
        wolfSSL_Mutex lock;
        WC_RNG rng;
    } *rngs; /* one per CPU ID */
};

static inline void wc_linuxkm_drbg_ctx_clear(struct wc_linuxkm_drbg_ctx * ctx)
{
    unsigned int i;

    if (ctx->rngs) {
        for (i = 0; i < nr_cpu_ids; ++i) {
            (void)wc_FreeMutex(&ctx->rngs[i].lock);
            wc_FreeRng(&ctx->rngs[i].rng);
        }
        free(ctx->rngs);
        ctx->rngs = NULL;
    }

    return;
}

static int wc_linuxkm_drbg_init_tfm(struct crypto_tfm *tfm)
{
    struct wc_linuxkm_drbg_ctx *ctx = (struct wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm);
    unsigned int i;
    int ret;

    ctx->rngs = (struct wc_rng_inst *)malloc(sizeof(*ctx->rngs) * nr_cpu_ids);
    if (! ctx->rngs)
        return -ENOMEM;
    XMEMSET(ctx->rngs, 0, sizeof(*ctx->rngs) * nr_cpu_ids);

    for (i = 0; i < nr_cpu_ids; ++i) {
        ret = wc_InitMutex(&ctx->rngs[i].lock);
        if (ret != 0) {
            ret = -EINVAL;
            break;
        }

        /* Note the new DRBG instance is seeded, and later reseeded, from system
         * get_random_bytes() via wc_GenerateSeed().
         */
        ret = wc_InitRng(&ctx->rngs[i].rng);
        if (ret != 0) {
            ret = -EINVAL;
            break;
        }
    }

    if (ret != 0) {
        wc_linuxkm_drbg_ctx_clear(ctx);
    }

    return ret;
}

static void wc_linuxkm_drbg_exit_tfm(struct crypto_tfm *tfm)
{
    struct wc_linuxkm_drbg_ctx *ctx = (struct wc_linuxkm_drbg_ctx *)crypto_tfm_ctx(tfm);

    wc_linuxkm_drbg_ctx_clear(ctx);

    return;
}

static int wc_linuxkm_drbg_generate(struct crypto_rng *tfm,
                        const u8 *src, unsigned int slen,
                        u8 *dst, unsigned int dlen)
{
    struct wc_linuxkm_drbg_ctx *ctx = (struct wc_linuxkm_drbg_ctx *)crypto_rng_ctx(tfm);
    int ret;
    /* Note, core is not locked, so the actual core ID may change while
     * executing, hence the mutex.
     * The mutex is also needed to coordinate with wc_linuxkm_drbg_seed(), which
     * seeds all instances.
     */
    int my_cpu = raw_smp_processor_id();
    wolfSSL_Mutex *lock = &ctx->rngs[my_cpu].lock;
    WC_RNG *rng = &ctx->rngs[my_cpu].rng;

    if (wc_LockMutex(lock) != 0)
        return -EINVAL;

    if (slen > 0) {
        ret = wc_RNG_DRBG_Reseed(rng, src, slen);
        if (ret != 0) {
            ret = -EINVAL;
            goto out;
        }
    }

    ret = wc_RNG_GenerateBlock(rng, dst, dlen);
    if (ret != 0)
        ret = -EINVAL;

out:

    wc_UnLockMutex(lock);

    return ret;
}

static int wc_linuxkm_drbg_seed(struct crypto_rng *tfm,
                        const u8 *seed, unsigned int slen)
{
    struct wc_linuxkm_drbg_ctx *ctx = (struct wc_linuxkm_drbg_ctx *)crypto_rng_ctx(tfm);
    u8 *seed_copy = NULL;
    int ret;
    unsigned int i;

    if (slen == 0)
        return 0;

    seed_copy = (u8 *)malloc(slen + 2);
    if (! seed_copy)
        return -ENOMEM;
    XMEMCPY(seed_copy + 2, seed, slen);

    for (i = 0; i < nr_cpu_ids; ++i) {
        wolfSSL_Mutex *lock = &ctx->rngs[i].lock;
        WC_RNG *rng = &ctx->rngs[i].rng;

        /* perturb the seed with the CPU ID, so that no DRBG has the exact same
         * seed.
         */
        seed_copy[0] = (u8)(i >> 8);
        seed_copy[1] = (u8)i;

        if (wc_LockMutex(lock) != 0)
            return -EINVAL;

        ret = wc_RNG_DRBG_Reseed(rng, seed_copy, slen + 2);
        if (ret != 0) {
            ret = -EINVAL;
        }

        wc_UnLockMutex(lock);

        if (ret != 0)
            break;
    }

    free(seed_copy);

    return ret;
}

static struct rng_alg wc_linuxkm_drbg = {
    .generate = wc_linuxkm_drbg_generate,
    .seed =     wc_linuxkm_drbg_seed,
    .seedsize = 0,
    .base           =       {
        .cra_name        =      WOLFKM_STDRNG_NAME,
        .cra_driver_name =      WOLFKM_STDRNG_DRIVER,
        .cra_priority    =      WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
        .cra_ctxsize     =      sizeof(struct wc_linuxkm_drbg_ctx),
        .cra_init        =      wc_linuxkm_drbg_init_tfm,
        .cra_exit        =      wc_linuxkm_drbg_exit_tfm,
        .cra_module      =      THIS_MODULE
    }
};
static int wc_linuxkm_drbg_loaded = 0;
static int wc_linuxkm_drbg_default_instance_registered = 0;

WC_MAYBE_UNUSED static int wc_linuxkm_drbg_startup(void)
{
    int ret;
#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    int cur_refcnt;
#endif

    if (wc_linuxkm_drbg_loaded) {
        pr_err("wc_linuxkm_drbg_set_default called with wc_linuxkm_drbg_loaded.");
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
        pr_err("crypto_register_rng: %d", ret);
        return ret;
    }

    {
        struct crypto_rng *tfm = crypto_alloc_rng(wc_linuxkm_drbg.base.cra_name, 0, 0);
        if (IS_ERR(tfm)) {
            pr_err("error: allocating rng algorithm %s failed: %ld\n",
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
                pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
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
                    pr_err("wc_linuxkm_drbg_startup: PRNG quality test failed, block length %d, iters %d, ret %d",
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
    ret = crypto_del_default_rng();
    if (ret) {
        pr_err("crypto_del_default_rng returned %d", ret);
        return ret;
    }

    ret = crypto_get_default_rng();
    if (ret) {
        pr_err("crypto_get_default_rng returned %d", ret);
        return ret;
    }

    cur_refcnt = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);
    if (cur_refcnt < 2) {
        pr_err("wc_linuxkm_drbg refcnt = %d after crypto_get_default_rng()", cur_refcnt);
        crypto_put_default_rng();
        return -EINVAL;
    }

    if (! crypto_default_rng) {
        pr_err("crypto_default_rng is null");
        crypto_put_default_rng();
        return -EINVAL;
    }

    if (strcmp(crypto_tfm_alg_driver_name(&crypto_default_rng->base), wc_linuxkm_drbg.base.cra_driver_name) == 0) {
        crypto_put_default_rng();
        wc_linuxkm_drbg_default_instance_registered = 1;
        pr_info("%s registered as systemwide default stdrng.", wc_linuxkm_drbg.base.cra_driver_name);
        pr_info("to unload module, first echo 1 > /sys/module/libwolfssl/deinstall_algs");
    }
    else {
        pr_err("%s NOT registered as systemwide default stdrng -- found \"%s\".", wc_linuxkm_drbg.base.cra_driver_name, crypto_tfm_alg_driver_name(&crypto_default_rng->base));
        crypto_put_default_rng();
        return -EINVAL;
    }
#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

    return 0;
}

WC_MAYBE_UNUSED static int wc_linuxkm_drbg_cleanup(void) {
    int cur_refcnt = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);

    if (! wc_linuxkm_drbg_loaded) {
        pr_err("wc_linuxkm_drbg_cleanup called with ! wc_linuxkm_drbg_loaded");
        return -EINVAL;
    }

    if (cur_refcnt - wc_linuxkm_drbg_default_instance_registered != 1) {
        pr_err("wc_linuxkm_drbg_cleanup called with refcnt = %d, with wc_linuxkm_drbg %sset as default rng",
               cur_refcnt, wc_linuxkm_drbg_default_instance_registered ? "" : "not ");
        return -EBUSY;
    }

    /* The below is racey, but the kernel doesn't provide any other way.  It's
     * written to be retryable.
     */

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    if (wc_linuxkm_drbg_default_instance_registered) {
        int ret = crypto_del_default_rng();
        if (ret) {
            pr_err("crypto_del_default_rng failed: %d", ret);
            return ret;
        }
        cur_refcnt = WC_LKM_REFCOUNT_TO_INT(wc_linuxkm_drbg.base.cra_refcnt);
        if (cur_refcnt != 1) {
            pr_err("wc_linuxkm_drbg refcnt = %d after crypto_del_default_rng()", cur_refcnt);
            return -EINVAL;
        }
    }
#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

    crypto_unregister_rng(&wc_linuxkm_drbg);

    if (! (wc_linuxkm_drbg.base.cra_flags & CRYPTO_ALG_DEAD)) {
        pr_err("wc_linuxkm_drbg_cleanup: after crypto_unregister_rng, wc_linuxkm_drbg isn't dead.");
        return -EBUSY;
    }

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT
    wc_linuxkm_drbg_default_instance_registered = 0;
#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT */

    wc_linuxkm_drbg_loaded = 0;

    return 0;
}

#endif /* LINUXKM_LKCAPI_REGISTER_HASH_DRBG */
