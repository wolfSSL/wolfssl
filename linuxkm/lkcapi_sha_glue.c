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

#define WOLFKM_SHA1_HMAC_DRIVER ("hmac-sha1" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_224_HMAC_DRIVER ("hmac-sha224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_256_HMAC_DRIVER ("hmac-sha256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_384_HMAC_DRIVER ("hmac-sha384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA2_512_HMAC_DRIVER ("hmac-sha512" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_224_HMAC_DRIVER ("hmac-sha3-224" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_256_HMAC_DRIVER ("hmac-sha3-256" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_384_HMAC_DRIVER ("hmac-sha3-384" WOLFKM_SHA_DRIVER_SUFFIX)
#define WOLFKM_SHA3_512_HMAC_DRIVER ("hmac-sha3-512" WOLFKM_SHA_DRIVER_SUFFIX)

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

#ifndef NO_SHA
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA1)
        #define LINUXKM_LKCAPI_REGISTER_SHA1
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA1_HMAC)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA1_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_SHA1
    #undef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
#endif

#ifdef WOLFSSL_SHA224
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_224)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_224
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_224_HMAC)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_224
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
#endif

#ifndef NO_SHA256
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_256)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_256
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_256_HMAC)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_256
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
#endif

#ifdef WOLFSSL_SHA384
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_384)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_384
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_384_HMAC)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_384
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
#endif

#ifdef WOLFSSL_SHA512
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_512)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_512
    #endif
    #ifdef NO_HMAC
        #undef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    #elif (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_SHA2_512_HMAC)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC)
        #define LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_512
    #undef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
#endif

#ifdef WOLFSSL_SHA3
    #ifdef LINUXKM_LKCAPI_REGISTER_ALL
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
    #elif defined(LINUXKM_LKCAPI_REGISTER_ALL)
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
                                  test_routine)                            \
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
    else                                                                   \
        return -EINVAL;                                                    \
}                                                                          \
                                                                           \
static int km_ ## name ## _final(struct shash_desc *desc, u8 *out) {       \
    struct km_sha_state *ctx = (struct km_sha_state *)shash_desc_ctx(desc);\
                                                                           \
    int ret = final_f(&ctx-> name ## _state, out);                         \
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
    if (ret != 0)                                                          \
        return -EINVAL;                                                    \
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
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
struct wc_swallow_the_semicolon

#define WC_LINUXKM_SHA3_IMPLEMENT(name, digest_size, block_size,           \
                                  this_cra_name, this_cra_driver_name,     \
                                  init_f, update_f, final_f,               \
                                  test_routine)                            \
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
    if (ret != 0)                                                          \
        return -EINVAL;                                                    \
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
        return -EINVAL;                                                    \
    }                                                                      \
}                                                                          \
                                                                           \
struct wc_swallow_the_semicolon

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    WC_LINUXKM_SHA_IMPLEMENT(sha1, WC_SHA_DIGEST_SIZE, WC_SHA_BLOCK_SIZE,
                             WOLFKM_SHA1_NAME, WOLFKM_SHA1_DRIVER,
                             wc_InitSha, wc_ShaUpdate, wc_ShaFinal,
                             sha_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    WC_LINUXKM_SHA_IMPLEMENT(sha2_224, WC_SHA224_DIGEST_SIZE, WC_SHA224_BLOCK_SIZE,
                             WOLFKM_SHA2_224_NAME, WOLFKM_SHA2_224_DRIVER,
                             wc_InitSha224, wc_Sha224Update, wc_Sha224Final,
                             sha224_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    WC_LINUXKM_SHA_IMPLEMENT(sha2_256, WC_SHA256_DIGEST_SIZE, WC_SHA256_BLOCK_SIZE,
                             WOLFKM_SHA2_256_NAME, WOLFKM_SHA2_256_DRIVER,
                             wc_InitSha256, wc_Sha256Update, wc_Sha256Final,
                             sha256_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    WC_LINUXKM_SHA_IMPLEMENT(sha2_384, WC_SHA384_DIGEST_SIZE, WC_SHA384_BLOCK_SIZE,
                             WOLFKM_SHA2_384_NAME, WOLFKM_SHA2_384_DRIVER,
                             wc_InitSha384, wc_Sha384Update, wc_Sha384Final,
                             sha384_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    WC_LINUXKM_SHA_IMPLEMENT(sha2_512, WC_SHA512_DIGEST_SIZE, WC_SHA512_BLOCK_SIZE,
                             WOLFKM_SHA2_512_NAME, WOLFKM_SHA2_512_DRIVER,
                             wc_InitSha512, wc_Sha512Update, wc_Sha512Final,
                             sha512_test);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_224, WC_SHA3_224_DIGEST_SIZE, WC_SHA3_224_BLOCK_SIZE,
                             WOLFKM_SHA3_224_NAME, WOLFKM_SHA3_224_DRIVER,
                             wc_InitSha3_224, wc_Sha3_224_Update, wc_Sha3_224_Final,
                             sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_256, WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_BLOCK_SIZE,
                             WOLFKM_SHA3_256_NAME, WOLFKM_SHA3_256_DRIVER,
                             wc_InitSha3_256, wc_Sha3_256_Update, wc_Sha3_256_Final,
                             sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_384, WC_SHA3_384_DIGEST_SIZE, WC_SHA3_384_BLOCK_SIZE,
                             WOLFKM_SHA3_384_NAME, WOLFKM_SHA3_384_DRIVER,
                             wc_InitSha3_384, wc_Sha3_384_Update, wc_Sha3_384_Final,
                             sha3_test_once);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    WC_LINUXKM_SHA3_IMPLEMENT(sha3_512, WC_SHA3_512_DIGEST_SIZE, WC_SHA3_512_BLOCK_SIZE,
                             WOLFKM_SHA3_512_NAME, WOLFKM_SHA3_512_DRIVER,
                             wc_InitSha3_512, wc_Sha3_512_Update, wc_Sha3_512_Final,
                             sha3_test_once);
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

#ifdef HAVE_FIPS
    ret = wc_HmacSetKey(&p_ctx->wc_hmac, type, key, length);
#else
    ret = wc_HmacSetKey_ex(&p_ctx->wc_hmac, type, key, length, 1 /* allowFlag */);
#endif

    if (ret == 0)
        return 0;
    else
        return -EINVAL;
}

WC_MAYBE_UNUSED static void km_hmac_free_tstate(struct km_sha_hmac_state *t_ctx) {
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
        return -EINVAL;                                                   \
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
