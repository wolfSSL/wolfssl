/* lkcapi_aes_glue.c -- glue logic for AES modes
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_aes_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
     defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
     (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_AES))) && \
    !defined(LINUXKM_LKCAPI_DONT_REGISTER_AES_ALL) && \
    !defined(LINUXKM_LKCAPI_REGISTER_AES)
    #define LINUXKM_LKCAPI_REGISTER_AES
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_AESCBC) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESXTS) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCTR) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESOFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESECB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AES_ALL)

    #ifdef NO_AES
        #error LINUXKM_LKCAPI_REGISTER_AES* requires !defined(NO_AES)
    #endif

    #ifndef LINUXKM_LKCAPI_REGISTER_AES
        #define LINUXKM_LKCAPI_REGISTER_AES
    #endif
#endif

#ifdef NO_AES
    #undef LINUXKM_LKCAPI_REGISTER_AES
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && !defined(CONFIG_CRYPTO_AES)
    #undef LINUXKM_LKCAPI_REGISTER_AES
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_AES) && \
    !defined(LINUXKM_LKCAPI_REGISTER_AES)
    #error Config conflict: CONFIG_CRYPTO_AES is defined, but LINUXKM_LKCAPI_REGISTER_AES is not.
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_AES

#include <wolfssl/wolfcrypt/aes.h>

#if defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS) && !defined(WC_FLAG_DONT_USE_AESNI)
    #error WC_LINUXKM_C_FALLBACK_IN_SHIMS is defined but WC_FLAG_DONT_USE_AESNI is missing.
#endif

/* note the FIPS code will be returned on failure even in non-FIPS builds. */
#define LINUXKM_LKCAPI_AES_KAT_MISMATCH_E AES_KAT_FIPS_E
#define LINUXKM_LKCAPI_AESGCM_KAT_MISMATCH_E AESGCM_KAT_FIPS_E

#define WOLFKM_AESCBC_NAME   "cbc(aes)"
#define WOLFKM_AESCFB_NAME   "cfb(aes)"
#define WOLFKM_AESGCM_NAME   "gcm(aes)"
#define WOLFKM_AESGCM_RFC4106_NAME   "rfc4106(gcm(aes))"
#define WOLFKM_AESXTS_NAME   "xts(aes)"
#define WOLFKM_AESCTR_NAME   "ctr(aes)"
#define WOLFKM_AESOFB_NAME   "ofb(aes)"
#define WOLFKM_AESECB_NAME   "ecb(aes)"

#if defined(USE_INTEL_SPEEDUP) || defined(USE_INTEL_SPEEDUP_FOR_AES)
    #define WOLFKM_AES_DRIVER_ISA_EXT "-aesni-avx"
#elif defined(WOLFSSL_AESNI)
    #define WOLFKM_AES_DRIVER_ISA_EXT "-aesni"
#else
    #define WOLFKM_AES_DRIVER_ISA_EXT ""
#endif

#define WOLFKM_AES_DRIVER_SUFFIX \
    WOLFKM_AES_DRIVER_ISA_EXT WOLFKM_DRIVER_SUFFIX_BASE

#define WOLFKM_AESCBC_DRIVER ("cbc-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESCFB_DRIVER ("cfb-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESGCM_DRIVER ("gcm-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESGCM_RFC4106_DRIVER ("rfc4106-gcm-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESXTS_DRIVER ("xts-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESCTR_DRIVER ("ctr-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESOFB_DRIVER ("ofb-aes" WOLFKM_AES_DRIVER_SUFFIX)
#define WOLFKM_AESECB_DRIVER ("ecb-aes" WOLFKM_AES_DRIVER_SUFFIX)

#ifdef HAVE_AES_CBC
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
        (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_CBC))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESCBC) &&               \
        !defined(LINUXKM_LKCAPI_REGISTER_AESCBC)
        #define LINUXKM_LKCAPI_REGISTER_AESCBC
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_CBC)
        #error Config conflict: target kernel has CONFIG_CRYPTO_CBC, but module is missing HAVE_AES_CBC.
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_AESCBC
#endif
#ifdef WOLFSSL_AES_CFB
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL)) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESCFB) &&      \
        !defined(LINUXKM_LKCAPI_REGISTER_AESCFB)
        #define LINUXKM_LKCAPI_REGISTER_AESCFB
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_AESCFB
#endif
#ifdef HAVE_AESGCM
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_GCM))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESGCM) &&               \
        !defined(LINUXKM_LKCAPI_REGISTER_AESGCM)
        #define LINUXKM_LKCAPI_REGISTER_AESGCM
    #endif
    #if ((defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
          defined(LINUXKM_LKCAPI_REGISTER_AES_ALL)) &&                  \
         !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESGCM_RFC4106)) &&      \
        !defined(LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106)
        #define LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_GCM)
        #error Config conflict: target kernel has CONFIG_CRYPTO_GCM, but module is missing HAVE_AESGCM.
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_AESGCM
    #undef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
#endif
#ifdef WOLFSSL_AES_XTS
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_XTS))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESXTS) &&               \
        !defined(LINUXKM_LKCAPI_REGISTER_AESXTS)
        #define LINUXKM_LKCAPI_REGISTER_AESXTS
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_XTS)
        #error Config conflict: target kernel has CONFIG_CRYPTO_GCM, but module is missing WOLFSSL_AES_XTS.
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_AESXTS
#endif
#ifdef WOLFSSL_AES_COUNTER
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_CTR))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESCTR) &&               \
        !defined(LINUXKM_LKCAPI_REGISTER_AESCTR)
        #define LINUXKM_LKCAPI_REGISTER_AESCTR
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_CTR)
        #error Config conflict: target kernel has CONFIG_CRYPTO_CTR, but module is missing WOLFSSL_AES_COUNTER.
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_AESCTR
#endif
#ifdef WOLFSSL_AES_OFB
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL)) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESOFB) &&      \
        !defined(LINUXKM_LKCAPI_REGISTER_AESOFB)
        #define LINUXKM_LKCAPI_REGISTER_AESOFB
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_AESOFB
#endif
#ifdef HAVE_AES_ECB
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         defined(LINUXKM_LKCAPI_REGISTER_AES_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECB))) && \
         !defined(LINUXKM_LKCAPI_DONT_REGISTER_AESECB) &&   \
        !defined(LINUXKM_LKCAPI_REGISTER_AESECB)
        #define LINUXKM_LKCAPI_REGISTER_AESECB
    #endif
#else
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECB)
        #error Config conflict: target kernel has CONFIG_CRYPTO_ECB, but module is missing HAVE_AES_ECB.
    #endif
    #undef LINUXKM_LKCAPI_REGISTER_AESECB
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC
    static int  linuxkm_test_aescbc(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB
    static int  linuxkm_test_aescfb(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM
    static int  linuxkm_test_aesgcm(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    static int  linuxkm_test_aesgcm_rfc4106(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS
    static int  linuxkm_test_aesxts(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR
    static int  linuxkm_test_aesctr(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB
    static int  linuxkm_test_aesofb(void);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESECB
    static int  linuxkm_test_aesecb(void);
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_AESCBC) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCTR) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESOFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESECB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106)
    #define LINUXKM_LKCAPI_NEED_AES_COMMON_FUNCS
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_AESCBC) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESCTR) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESOFB) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESECB)
    #define LINUXKM_LKCAPI_NEED_AES_SKCIPHER_COMMON_FUNCS
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_AESGCM) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106)
    #define LINUXKM_LKCAPI_REGISTER_AEADS
#endif

/* km_AesX(): wrappers to wolfcrypt wc_AesX functions and
 * structures.  */

struct km_AesCtx {
    Aes          *aes_encrypt; /* allocated in km_AesInitCommon() to assure
                                * alignment, needed for AESNI.
                                */
    Aes          *aes_decrypt; /* same. */
#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS
    Aes          *aes_encrypt_C; /* fallback if vector registers aren't available. */
    Aes          *aes_decrypt_C;
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    byte rfc4106_nonce[4];
#endif
};

#ifdef LINUXKM_LKCAPI_NEED_AES_COMMON_FUNCS

static void km_AesExitCommon(struct km_AesCtx * ctx);

static int km_AesInitCommon(
    struct km_AesCtx * ctx,
    const char * name,
    int need_decryption)
{
    int err;

    ctx->aes_encrypt = (Aes *)malloc(sizeof(*ctx->aes_encrypt));

    if (! ctx->aes_encrypt) {
        pr_err("%s: allocation of %zu bytes for encryption key failed.\n",
               name, sizeof(*ctx->aes_encrypt));
        err = -MEMORY_E;
        goto out;
    }

    err = wc_AesInit(ctx->aes_encrypt, NULL, INVALID_DEVID);

    if (unlikely(err)) {
        pr_err("%s: wc_AesInit failed: %d\n", name, err);
        free(ctx->aes_encrypt);
        ctx->aes_encrypt = NULL;
        err = -EINVAL;
        goto out;
    }

    if (! need_decryption) {
        ctx->aes_decrypt = NULL;
    }
    else {
        ctx->aes_decrypt = (Aes *)malloc(sizeof(*ctx->aes_decrypt));

        if (! ctx->aes_decrypt) {
            pr_err("%s: allocation of %zu bytes for decryption key failed.\n",
                   name, sizeof(*ctx->aes_decrypt));
            err = -MEMORY_E;
            goto out;
        }

        err = wc_AesInit(ctx->aes_decrypt, NULL, INVALID_DEVID);

        if (unlikely(err)) {
            pr_err("%s: wc_AesInit failed: %d\n", name, err);
            free(ctx->aes_decrypt);
            ctx->aes_decrypt = NULL;
            err = -EINVAL;
            goto out;
        }
    }

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS

    ctx->aes_encrypt_C = (Aes *)malloc(sizeof(*ctx->aes_encrypt_C));

    if (! ctx->aes_encrypt_C) {
        pr_err("%s: allocation of %zu bytes for encryption key failed.\n",
               name, sizeof(*ctx->aes_encrypt_C));
        err = -MEMORY_E;
        goto out;
    }

    err = wc_AesInit(ctx->aes_encrypt_C, NULL, INVALID_DEVID);

    if (unlikely(err)) {
        pr_err("%s: wc_AesInit failed: %d\n", name, err);
        free(ctx->aes_encrypt_C);
        ctx->aes_encrypt_C = NULL;
        err = -EINVAL;
        goto out;
    }

    if (! need_decryption) {
        ctx->aes_decrypt_C = NULL;
    }
    else {
        ctx->aes_decrypt_C = (Aes *)malloc(sizeof(*ctx->aes_decrypt_C));

        if (! ctx->aes_decrypt_C) {
            pr_err("%s: allocation of %zu bytes for decryption key failed.\n",
                   name, sizeof(*ctx->aes_decrypt_C));
            err = -MEMORY_E;
            goto out;
        }

        err = wc_AesInit(ctx->aes_decrypt_C, NULL, INVALID_DEVID);

        if (unlikely(err)) {
            pr_err("%s: wc_AesInit failed: %d\n", name, err);
            free(ctx->aes_decrypt_C);
            ctx->aes_decrypt_C = NULL;
            err = -EINVAL;
            goto out;
        }
    }

#endif /* WC_LINUXKM_C_FALLBACK_IN_SHIMS */

out:

    if (err != 0)
        km_AesExitCommon(ctx);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesInitCommon: %s: %d\n", name, err);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesGet(struct km_AesCtx *ctx, int decrypt_p, int copy_p, Aes **aes) {
    Aes *ret;

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS
    /* First, check if AESNI was disabled in the main SetKey for the requested
     * direction.  If so, use it (the fallback schedule won't even be inited).
     */
    if (((! decrypt_p) || (! ctx->aes_decrypt)) && (! ctx->aes_encrypt->use_aesni))
        ret = ctx->aes_encrypt;
    else if (decrypt_p && ctx->aes_decrypt && (! ctx->aes_decrypt->use_aesni))
        ret = ctx->aes_decrypt;
    else if (
#ifdef TEST_WC_LINUXKM_C_FALLBACK_IN_SHIMS
             1
#else
             ! CAN_SAVE_VECTOR_REGISTERS()
#endif
        )
    {
        if (decrypt_p && ctx->aes_decrypt_C)
            ret = ctx->aes_decrypt_C;
        else
            ret = ctx->aes_encrypt_C;
        if (ret->use_aesni)
            return -EINVAL;
    }
    else
#endif /* WC_LINUXKM_C_FALLBACK_IN_SHIMS */
    {
        if (decrypt_p && ctx->aes_decrypt)
            ret = ctx->aes_decrypt;
        else
            ret = ctx->aes_encrypt;
    }

    if (copy_p) {
        /* Copy the cipher state to mitigate races on Aes.reg, Aes.tmp, and dynamic Aes.use_aesni. */
        Aes *aes_copy = (struct Aes *)malloc(sizeof(Aes));
        if (aes_copy == NULL)
            return -ENOMEM;
        XMEMCPY(aes_copy, ret, sizeof(Aes));
#if defined(WOLFSSL_AESGCM_STREAM) && defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_AESNI)
        aes_copy->streamData = NULL;
#endif
        *aes = aes_copy;
    }
    else {
        *aes = ret;
    }

    return 0;
}

static void km_AesFree(Aes **aes) {
    if ((! aes) || (! *aes))
        return;
    wc_AesFree(*aes);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(*aes, sizeof **aes);
#endif
    free(*aes);
    *aes = NULL;
}

static void km_AesExitCommon(struct km_AesCtx * ctx)
{
    if (ctx->aes_encrypt) {
        km_AesFree(&ctx->aes_encrypt);
    }
    if (ctx->aes_decrypt) {
        km_AesFree(&ctx->aes_decrypt);
    }

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS
    if (ctx->aes_encrypt_C) {
        km_AesFree(&ctx->aes_encrypt_C);
    }
    if (ctx->aes_decrypt_C) {
        km_AesFree(&ctx->aes_decrypt_C);
    }
#endif

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesExitCommon\n");
    #endif /* WOLFKM_DEBUG_AES */
}

#ifdef LINUXKM_LKCAPI_NEED_AES_SKCIPHER_COMMON_FUNCS

static int km_AesSetKeyCommon(struct km_AesCtx * ctx, const u8 *in_key,
                              unsigned int key_len, const char * name)
{
    int err;

    err = wc_AesSetKey(ctx->aes_encrypt, in_key, key_len, NULL, AES_ENCRYPTION);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesSetKey for encryption key failed: %d\n", name, err);
        return -EINVAL;
    }

    if (ctx->aes_decrypt) {
        err = wc_AesSetKey(ctx->aes_decrypt, in_key, key_len, NULL,
                           AES_DECRYPTION);

        if (unlikely(err)) {
            if (! disable_setkey_warnings)
                pr_err("%s: wc_AesSetKey for decryption key failed: %d\n",
                       name, err);
            return -EINVAL;
        }
    }

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS

    if (ctx->aes_encrypt->use_aesni) {
        ctx->aes_encrypt_C->use_aesni = WC_FLAG_DONT_USE_AESNI;

        err = wc_AesSetKey(ctx->aes_encrypt_C, in_key, key_len, NULL, AES_ENCRYPTION);

        if (unlikely(err)) {
            if (! disable_setkey_warnings)
                pr_err("%s: wc_AesSetKey for encryption key failed: %d\n", name, err);
            return -EINVAL;
        }

        if (ctx->aes_encrypt_C->use_aesni)
            pr_err("%s: after wc_AesSetKey, ctx->aes_encrypt_C has AES-NI asserted.\n", name);

    }

    if (ctx->aes_decrypt_C && ctx->aes_decrypt->use_aesni) {
        ctx->aes_decrypt_C->use_aesni = WC_FLAG_DONT_USE_AESNI;

        err = wc_AesSetKey(ctx->aes_decrypt_C, in_key, key_len, NULL,
                           AES_DECRYPTION);

        if (unlikely(err)) {
            if (! disable_setkey_warnings)
                pr_err("%s: wc_AesSetKey for decryption key failed: %d\n",
                       name, err);
            return -EINVAL;
        }

        if (ctx->aes_decrypt_C->use_aesni)
            pr_err("%s: after wc_AesSetKey, ctx->aes_decrypt_C has AES-NI asserted.\n", name);
    }

#endif /* WC_LINUXKM_C_FALLBACK_IN_SHIMS */

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesSetKeyCommon: %s: %d\n", name, key_len);
    #endif /* WOLFKM_DEBUG_AES */
    return 0;
}

static void km_AesExit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    km_AesExitCommon(ctx);
}

#endif /* LINUXKM_LKCAPI_NEED_AES_SKCIPHER_COMMON_FUNCS */

#endif /* LINUXKM_LKCAPI_NEED_AES_COMMON_FUNCS */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC

static int km_AesCbcInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESCBC_DRIVER, 1);
}

static int km_AesCbcSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_AESCBC_DRIVER);
}

static int km_AesCbcEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);
    if (unlikely(err)) {
        return err;
    }

    err = km_AesGet(ctx, 0 /* decrypt_p */, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        pr_err("%s: wc_AesSetIV failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while ((nbytes = walk.nbytes) != 0) {
        err = wc_AesCbcEncrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes & (~(WC_AES_BLOCK_SIZE - 1)));

        if (unlikely(err)) {
            pr_err("%s: wc_AesCbcEncrypt failed for %u bytes: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), nbytes, err);
            err = -EINVAL;
            goto out;
        }

        nbytes &= WC_AES_BLOCK_SIZE - 1;
        err = skcipher_walk_done(&walk, nbytes);
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCbcEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesCbcDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        return err;
    }

    err = km_AesGet(ctx, 1 /* decrypt_p */, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesSetKey failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while ((nbytes = walk.nbytes) != 0) {
        err = wc_AesCbcDecrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes & (~(WC_AES_BLOCK_SIZE - 1)));

        if (unlikely(err)) {
            pr_err("%s: wc_AesCbcDecrypt failed for %u bytes: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), nbytes, err);
            err = -EINVAL;
            goto out;
        }

        nbytes &= WC_AES_BLOCK_SIZE - 1;
        err = skcipher_walk_done(&walk, nbytes);
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCbcDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg cbcAesAlg = {
    .base.cra_name        = WOLFKM_AESCBC_NAME,
    .base.cra_driver_name = WOLFKM_AESCBC_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = WC_AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesCbcInit,
    .exit                 = km_AesExit,
    .min_keysize          = AES_128_KEY_SIZE,
    .max_keysize          = AES_256_KEY_SIZE,
    .ivsize               = WC_AES_BLOCK_SIZE,
    .setkey               = km_AesCbcSetKey,
    .encrypt              = km_AesCbcEncrypt,
    .decrypt              = km_AesCbcDecrypt,
};
static int cbcAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESCBC */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB

static int km_AesCfbInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESCFB_DRIVER, 0);
}

static int km_AesCfbSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_AESCFB_DRIVER);
}

static int km_AesCfbEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    err = km_AesGet(ctx, 0 /* decrypt_p */, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        pr_err("%s: wc_AesSetIV failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        err = wc_AesCfbEncrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesCfbEncrypt failed %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            goto out;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCfbEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesCfbDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    err = km_AesGet(ctx, 1 /* decrypt_p */, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesSetIV failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        err = wc_AesCfbDecrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesCfbDecrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            goto out;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCfbDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg cfbAesAlg = {
    .base.cra_name        = WOLFKM_AESCFB_NAME,
    .base.cra_driver_name = WOLFKM_AESCFB_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesCfbInit,
    .exit                 = km_AesExit,
    .min_keysize          = AES_128_KEY_SIZE,
    .max_keysize          = AES_256_KEY_SIZE,
    .ivsize               = WC_AES_BLOCK_SIZE,
    .setkey               = km_AesCfbSetKey,
    .encrypt              = km_AesCfbEncrypt,
    .decrypt              = km_AesCfbDecrypt,
};
static int cfbAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESCBC */

#if defined(LINUXKM_LKCAPI_REGISTER_AESGCM) || \
    defined(LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106)

static int km_AesGcmInit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESGCM_DRIVER, 0);
}

static void km_AesGcmExit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    km_AesExitCommon(ctx);
}

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM

static int km_AesGcmSetKey(struct crypto_aead *tfm, const u8 *in_key,
                           unsigned int key_len)
{
    int err;
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);

    err = wc_AesGcmSetKey(ctx->aes_encrypt, in_key, key_len);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesGcmSetKey failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
        return -EINVAL;
    }

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS
    if (ctx->aes_encrypt->use_aesni) {
        ctx->aes_encrypt_C->use_aesni = WC_FLAG_DONT_USE_AESNI;

        err = wc_AesGcmSetKey(ctx->aes_encrypt_C, in_key, key_len);

        if (unlikely(err)) {
            if (! disable_setkey_warnings)
                pr_err("%s: wc_AesGcmSetKey failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
            return -EINVAL;
        }

        if (ctx->aes_encrypt_C->use_aesni)
            pr_err("%s: after wc_AesGcmSetKey, ctx->aes_encrypt_C has AES-NI asserted.\n", WOLFKM_AESGCM_DRIVER);
    }
#endif

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesGcmSetKey: %d\n", key_len);
    #endif /* WOLFKM_DEBUG_AES */
    return 0;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106

static int km_AesGcmSetKey_Rfc4106(struct crypto_aead *tfm, const u8 *in_key,
                           unsigned int key_len)
{
    int err;
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);

    if (key_len < 4)
        return -EINVAL;
    key_len -= 4;
    memcpy(ctx->rfc4106_nonce, in_key + key_len, 4);

    err = wc_AesGcmSetKey(ctx->aes_encrypt, in_key, key_len);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesGcmSetKey failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
        return -EINVAL;
    }

#ifdef WC_LINUXKM_C_FALLBACK_IN_SHIMS
    if (ctx->aes_encrypt->use_aesni) {
        ctx->aes_encrypt_C->use_aesni = WC_FLAG_DONT_USE_AESNI;

        err = wc_AesGcmSetKey(ctx->aes_encrypt_C, in_key, key_len);

        if (unlikely(err)) {
            if (! disable_setkey_warnings)
                pr_err("%s: wc_AesGcmSetKey failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
            return -EINVAL;
        }

        if (ctx->aes_encrypt_C->use_aesni)
            pr_err("%s: after wc_AesGcmSetKey, ctx->aes_encrypt_C has AES-NI asserted.\n", WOLFKM_AESGCM_DRIVER);
    }
#endif

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesGcmSetKey_Rfc4106: %d\n", key_len);
    #endif /* WOLFKM_DEBUG_AES */
    return 0;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM

static int km_AesGcmSetAuthsize(struct crypto_aead *tfm, unsigned int authsize)
{
    (void)tfm;

    switch (authsize) {
    case 4:
    case 8:
    case 12:
    case 13:
    case 14:
    case 15:
    case 16:
        return 0;
    }

#ifdef WOLFSSL_LINUXKM_VERBOSE_LKCAPI_DEBUG
    pr_err("%s: invalid authsize: %d\n",
           crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), authsize);
#endif
    return -EINVAL;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106

static int km_AesGcmSetAuthsize_Rfc4106(struct crypto_aead *tfm, unsigned int authsize)
{
    (void)tfm;

    switch (authsize) {
    case 8:
    case 12:
    case 16:
        return 0;
    }

#ifdef WOLFSSL_LINUXKM_VERBOSE_LKCAPI_DEBUG
    pr_err("%s: invalid authsize: %d\n",
           crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), authsize);
#endif
    return -EINVAL;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

/*
 * aead ciphers receive data in scatterlists in following order:
 *   encrypt
 *     req->src: aad||plaintext
 *     req->dst: aad||ciphertext||tag
 *   decrypt
 *     req->src: aad||ciphertext||tag
 *     req->dst: aad||plaintext, return 0 or -EBADMSG
 */

#ifdef WOLFSSL_AESGCM_STREAM

static int AesGcmCrypt_1(struct aead_request *req, int decrypt_p, int rfc4106_p)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk walk;
    struct scatter_walk  assocSgWalk;
    u8                   authTag[WC_AES_BLOCK_SIZE];
    int                  err;
    unsigned int         assoclen = req->assoclen;
    u8 *                 assoc = NULL;
    u8 *                 assocmem = NULL;
    Aes                  *aes_copy = NULL;

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);

    if (decrypt_p) {
        /* Copy out original auth tag from req->src. */
        scatterwalk_map_and_copy(authTag, req->src,
                                 req->assoclen + req->cryptlen - tfm->authsize,
                                 tfm->authsize, 0);
        err = skcipher_walk_aead_decrypt(&walk, req, false);
    }
    else {
        err = skcipher_walk_aead_encrypt(&walk, req, false);
    }

    if (unlikely(err)) {
        pr_err("%s: %s failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
               decrypt_p ? "skcipher_walk_aead_decrypt" : "skcipher_walk_aead_encrypt",
               err);
        return err;
    }

    err = km_AesGet(ctx, decrypt_p, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    if (rfc4106_p) {
        byte rfc4106_iv[12];

        if (unlikely(assoclen != 16 && assoclen != 20)) {
            err = -EINVAL;
            goto out;
        }
        assoclen -= 8;

        memcpy(rfc4106_iv, ctx->rfc4106_nonce, 4);
        memcpy(rfc4106_iv + 4, walk.iv, 8);
        err = wc_AesGcmInit(aes_copy, NULL /*key*/, 0 /*keylen*/, rfc4106_iv,
                            GCM_NONCE_MID_SZ);
    }
    else
#else
    (void)rfc4106_p;
#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */
    {
        err = wc_AesGcmInit(aes_copy, NULL /*key*/, 0 /*keylen*/, walk.iv,
                            GCM_NONCE_MID_SZ);
    }
    if (unlikely(err)) {
        pr_err("%s: wc_AesGcmInit failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    if (req->src->length >= assoclen && req->src->length) {
        scatterwalk_start(&assocSgWalk, req->src);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
        scatterwalk_map(&assocSgWalk);
        assoc = assocSgWalk.addr;
#else
        assoc = scatterwalk_map(&assocSgWalk);
#endif
        if (unlikely(IS_ERR(assoc))) {
            pr_err("%s: scatterwalk_map failed: %ld\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
                   PTR_ERR(assoc));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
            scatterwalk_unmap(&assocSgWalk);
#endif
            goto out;
        }
    }
    else {
        /* assoc can be any length, so if it's noncontiguous, we have to copy it
         * to a contiguous heap allocation.
         */
        assocmem = malloc(assoclen);
        if (unlikely(assocmem == NULL)) {
            err = -ENOMEM;
            goto out;
        }
        assoc = assocmem;
        scatterwalk_map_and_copy(assoc, req->src, 0, assoclen, 0);
    }

    if (decrypt_p) {
        err = wc_AesGcmDecryptUpdate(aes_copy, NULL, NULL, 0,
                                     assoc, assoclen);
    }
    else {
        err = wc_AesGcmEncryptUpdate(aes_copy, NULL, NULL, 0,
                                     assoc, assoclen);
    }

    if (assocmem)
        free(assocmem);
    else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
        scatterwalk_unmap(&assocSgWalk);
#else
        scatterwalk_unmap(assoc);
#endif
    }

    if (unlikely(err)) {
        pr_err("%s: %s failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
               decrypt_p ? "wc_AesGcmDecryptUpdate" : "wc_AesGcmEncryptUpdate",
               err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes) {
        if (decrypt_p) {
            err = wc_AesGcmDecryptUpdate(
                aes_copy,
                walk.dst.virt.addr,
                walk.src.virt.addr,
                walk.nbytes,
                NULL, 0);
        }
        else {
            err = wc_AesGcmEncryptUpdate(
                aes_copy,
                walk.dst.virt.addr,
                walk.src.virt.addr,
                walk.nbytes,
                NULL, 0);
        }

        if (unlikely(err)) {
            pr_err("%s: %s failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
                   decrypt_p ? "wc_AesGcmDecryptUpdate" : "wc_AesGcmEncryptUpdate",
                   err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
            goto out;
        }
    }

    if (decrypt_p) {
        err = wc_AesGcmDecryptFinal(aes_copy, authTag, tfm->authsize);
        if (unlikely(err)) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_LKCAPI_DEBUG
            pr_err("%s: wc_AesGcmDecryptFinal failed with return code %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
#endif
            if (err == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
                err = -EBADMSG;
                goto out;
            }
            else {
                err = -EINVAL;
                goto out;
            }
        }
    }
    else {
        err = wc_AesGcmEncryptFinal(aes_copy, authTag, tfm->authsize);
        if (unlikely(err)) {
            pr_err("%s: wc_AesGcmEncryptFinal failed with return code %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }
        /* Now copy the auth tag into request scatterlist. */
        scatterwalk_map_and_copy(authTag, req->dst,
                                 req->assoclen + req->cryptlen,
                                 tfm->authsize, 1);
    }

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting AesGcmCrypt_1: err %d, dec %d, cryptlen %d, "
            "assoclen %d\n", err, decrypt_p,
            req->cryptlen, req->assoclen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

#else /* !WOLFSSL_AESGCM_STREAM */

static int AesGcmCrypt_1(struct aead_request *req, int decrypt_p, int rfc4106_p)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk sk_walk;
    struct scatter_walk  in_walk, out_walk;
    u8                   *in_map = NULL, *out_map = NULL;
    u8                   authTag[WC_AES_BLOCK_SIZE];
    int                  err;
    unsigned int         assoclen = req->assoclen;
    u8 *                 assoc = NULL;
    u8 *                 sg_buf = NULL;
    Aes                  *aes_copy = NULL;
    u8 *                 in_text = NULL;
    u8 *                 out_text = NULL;
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    byte rfc4106_iv[12];
#endif

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);

    if (decrypt_p) {
        /* Copy out original auth tag from req->src. */
        scatterwalk_map_and_copy(authTag, req->src,
                                 req->assoclen + req->cryptlen - tfm->authsize,
                                 tfm->authsize, 0);
        err = skcipher_walk_aead_decrypt(&sk_walk, req, false);
    }
    else {
        err = skcipher_walk_aead_encrypt(&sk_walk, req, false);
    }

    if (unlikely(err)) {
        pr_err("%s: %s failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
               decrypt_p ? "skcipher_walk_aead_decrypt" : "skcipher_walk_aead_encrypt",
               err);
        return -EINVAL;
    }

    err = km_AesGet(ctx, decrypt_p, 1 /* copy_p */, &aes_copy);
    if (unlikely(err)) {
        goto out;
    }

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    if (rfc4106_p) {
        if (unlikely(assoclen != 16 && assoclen != 20)) {
            err = -EINVAL;
            goto out;
        }
        assoclen -= 8;

        memcpy(rfc4106_iv, ctx->rfc4106_nonce, 4);
        memcpy(rfc4106_iv + 4, sk_walk.iv, 8);
    }
#else
    (void)rfc4106_p;
#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

    if ((req->src->length >= req->assoclen + req->cryptlen) &&
        (req->dst->length >= req->assoclen + req->cryptlen))
    {
        scatterwalk_start(&in_walk, req->src);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
        scatterwalk_map(&in_walk);
        in_map = in_walk.addr;
#else
        in_map = scatterwalk_map(&in_walk);
#endif
        if (unlikely(IS_ERR(in_map))) {
            pr_err("%s: scatterwalk_map failed: %ld\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
                   PTR_ERR(assoc));
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
            in_map = NULL;
#endif
            goto out;
        }
        assoc = in_map;
        in_text = in_map + req->assoclen;

        scatterwalk_start(&out_walk, req->dst);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
        scatterwalk_map(&out_walk);
        out_map = out_walk.addr;
#else
        out_map = scatterwalk_map(&out_walk);
#endif
        if (unlikely(IS_ERR(out_map))) {
            pr_err("%s: scatterwalk_map failed: %ld\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)),
                   PTR_ERR(assoc));
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
            out_map = NULL;
#endif
            goto out;
        }
        out_text = out_map + req->assoclen;
    }
    else {
        sg_buf = malloc(req->assoclen + req->cryptlen);
        if (unlikely(sg_buf == NULL)) {
            err = -ENOMEM;
            goto out;
        }
        if (decrypt_p)
            scatterwalk_map_and_copy(sg_buf, req->src, 0, req->assoclen + req->cryptlen - tfm->authsize, 0);
        else
            scatterwalk_map_and_copy(sg_buf, req->src, 0, req->assoclen + req->cryptlen, 0);
        assoc = sg_buf;
        in_text = out_text = sg_buf + req->assoclen;
    }

    if (decrypt_p) {
        err = wc_AesGcmDecrypt(aes_copy, out_text, in_text, req->cryptlen - tfm->authsize,
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
                               rfc4106_p ? rfc4106_iv :
#endif
                               sk_walk.iv, GCM_NONCE_MID_SZ,
                               authTag, tfm->authsize,
                               assoc, assoclen);

        if (unlikely(err)) {
#ifdef WOLFSSL_LINUXKM_VERBOSE_LKCAPI_DEBUG
            pr_err("%s: wc_AesGcmDecrypt failed with return code %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
#endif

            if (err == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
                err = -EBADMSG;
                goto out;
            }
            else {
                err = -EINVAL;
                goto out;
            }
        }
    }
    else {
        err = wc_AesGcmEncrypt(aes_copy, out_text, in_text, req->cryptlen,
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
                               rfc4106_p ? rfc4106_iv :
#endif
                               sk_walk.iv, GCM_NONCE_MID_SZ,
                               authTag, tfm->authsize,
                               assoc, assoclen);

        if (unlikely(err)) {
            pr_err("%s: wc_AesGcmEncrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

    }

    if (sg_buf) {
        if (decrypt_p)
            scatterwalk_map_and_copy(sg_buf, req->dst, 0, req->assoclen + req->cryptlen - tfm->authsize, 1);
        else
            scatterwalk_map_and_copy(sg_buf, req->dst, 0, req->assoclen + req->cryptlen, 1);
    }

    if (! decrypt_p) {
        /* Now copy the auth tag into request scatterlist. */
        scatterwalk_map_and_copy(authTag, req->dst,
                                 req->assoclen + req->cryptlen,
                                 tfm->authsize, 1);
    }

out:

    if (sg_buf) {
        free(sg_buf);
    }
    else {
        if (in_map) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
            scatterwalk_unmap(&in_walk);
#else
            scatterwalk_unmap(in_map);
#endif
        }
        if (out_map) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
            scatterwalk_unmap(&out_walk);
#else
            scatterwalk_unmap(out_map);
#endif
        }
    }

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting AesGcmCrypt_1: err %d, dec %d, cryptlen %d, "
            "assoclen %d\n", err, decrypt_p,
            req->cryptlen, req->assoclen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

#endif /* !WOLFSSL_AESGCM_STREAM */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM

static int km_AesGcmEncrypt(struct aead_request *req) {
    return AesGcmCrypt_1(req, 0 /* decrypt_p */, 0 /* rfc4106_p */);
}

static int km_AesGcmDecrypt(struct aead_request *req) {
    return AesGcmCrypt_1(req, 1 /* decrypt_p */, 0 /* rfc4106_p */);
}

static struct aead_alg gcmAesAead = {
    .base.cra_name        = WOLFKM_AESGCM_NAME,
    .base.cra_driver_name = WOLFKM_AESGCM_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesGcmInit,
    .exit                 = km_AesGcmExit,
    .setkey               = km_AesGcmSetKey,
    .setauthsize          = km_AesGcmSetAuthsize,
    .encrypt              = km_AesGcmEncrypt,
    .decrypt              = km_AesGcmDecrypt,
    .ivsize               = GCM_NONCE_MID_SZ,
    .maxauthsize          = WC_AES_BLOCK_SIZE,
    .chunksize            = WC_AES_BLOCK_SIZE,
};
static int gcmAesAead_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106

static int km_AesGcmEncrypt_Rfc4106(struct aead_request *req) {
    return AesGcmCrypt_1(req, 0 /* decrypt_p */, 1 /* rfc4106 */);
}

static int km_AesGcmDecrypt_Rfc4106(struct aead_request *req) {
    return AesGcmCrypt_1(req, 1 /* decrypt_p */, 1 /* rfc4106 */);
}

static struct aead_alg gcmAesAead_rfc4106 = {
    .base.cra_name        = WOLFKM_AESGCM_RFC4106_NAME,
    .base.cra_driver_name = WOLFKM_AESGCM_RFC4106_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesGcmInit,
    .exit                 = km_AesGcmExit,
    .setkey               = km_AesGcmSetKey_Rfc4106,
    .setauthsize          = km_AesGcmSetAuthsize_Rfc4106,
    .encrypt              = km_AesGcmEncrypt_Rfc4106,
    .decrypt              = km_AesGcmDecrypt_Rfc4106,
    .ivsize               = 8,
    .maxauthsize          = WC_AES_BLOCK_SIZE,
    .chunksize            = WC_AES_BLOCK_SIZE,
};
static int gcmAesAead_rfc4106_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM || LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS

#ifndef WOLFSSL_AESXTS_STREAM
    #error LKCAPI registration of AES-XTS requires WOLFSSL_AESXTS_STREAM (--enable-aesxts-stream).
#endif

#if defined(WOLFSSL_AESNI) && !defined(WC_C_DYNAMIC_FALLBACK)
    #error LKCAPI registration of AES-XTS with AESNI requires WC_C_DYNAMIC_FALLBACK.
#endif

struct km_AesXtsCtx {
    XtsAes *aesXts; /* allocated in km_AesXtsInitCommon() to assure alignment
                     * for AESNI.
                     */
};

static int km_AesXtsInitCommon(struct km_AesXtsCtx * ctx, const char * name)
{
    int err;

    ctx->aesXts = (XtsAes *)malloc(sizeof(*ctx->aesXts));

    if (! ctx->aesXts)
        return -MEMORY_E;

    err = wc_AesXtsInit(ctx->aesXts, NULL, INVALID_DEVID);

    if (unlikely(err)) {
        pr_err("%s: km_AesXtsInitCommon failed: %d\n", name, err);
        free(ctx->aesXts);
        ctx->aesXts = NULL;
        return -EINVAL;
    }

    return 0;
}

static int km_AesXtsInit(struct crypto_skcipher *tfm)
{
    struct km_AesXtsCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesXtsInitCommon(ctx, WOLFKM_AESXTS_DRIVER);
}

static void km_AesXtsExit(struct crypto_skcipher *tfm)
{
    struct km_AesXtsCtx * ctx = crypto_skcipher_ctx(tfm);
    wc_AesXtsFree(ctx->aesXts);
    free(ctx->aesXts);
    ctx->aesXts = NULL;
}

static int km_AesXtsSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    int err;
    struct km_AesXtsCtx * ctx = crypto_skcipher_ctx(tfm);

    err = wc_AesXtsSetKeyNoInit(ctx->aesXts, in_key, key_len,
                                AES_ENCRYPTION_AND_DECRYPTION);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesXtsSetKeyNoInit failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return -EINVAL;
    }

    /* It's possible to set ctx->aesXts->{tweak,aes,aes_decrypt}.use_aesni to
     * WC_FLAG_DONT_USE_AESNI here, for WC_LINUXKM_C_FALLBACK_IN_SHIMS in
     * AES-XTS, but we can use the WC_C_DYNAMIC_FALLBACK mechanism
     * unconditionally because there's no AES-XTS in Cert 4718.
     */

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesXtsSetKey: %d\n", key_len);
    #endif /* WOLFKM_DEBUG_AES */

    return 0;
}

/* see /usr/src/linux/drivers/md/dm-crypt.c */

static int km_AesXtsEncrypt(struct skcipher_request *req)
{
    int                      err;
    struct crypto_skcipher * tfm = NULL;
    struct km_AesXtsCtx *    ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    if (req->cryptlen < WC_AES_BLOCK_SIZE)
        return -EINVAL;

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    if (walk.nbytes == walk.total) {
        err = wc_AesXtsEncrypt(ctx->aesXts, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes, walk.iv, walk.ivsize);

        if (unlikely(err)) {
            pr_err("%s: wc_AesXtsEncrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return -EINVAL;
        }

        err = skcipher_walk_done(&walk, 0);

    } else {
        int tail = req->cryptlen % WC_AES_BLOCK_SIZE;
        struct skcipher_request subreq;
        struct XtsAesStreamData stream;

        if (tail > 0) {
            int blocks = DIV_ROUND_UP(req->cryptlen, WC_AES_BLOCK_SIZE) - 2;

            skcipher_walk_abort(&walk);

            skcipher_request_set_tfm(&subreq, tfm);
            skcipher_request_set_callback(&subreq,
                                          skcipher_request_flags(req),
                                          NULL, NULL);
            skcipher_request_set_crypt(&subreq, req->src, req->dst,
                                       blocks * WC_AES_BLOCK_SIZE, req->iv);
            req = &subreq;

            err = skcipher_walk_virt(&walk, req, false);
            if (!walk.nbytes)
                return err ? : -EINVAL;
        } else {
            tail = 0;
        }

        err = wc_AesXtsEncryptInit(ctx->aesXts, walk.iv, walk.ivsize, &stream);

        if (unlikely(err)) {
            pr_err("%s: wc_AesXtsEncryptInit failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return -EINVAL;
        }

        while ((nbytes = walk.nbytes) != 0) {
            /* if this isn't the final call, pass block-aligned data to prevent
             * end-of-message ciphertext stealing.
             */
            if (nbytes < walk.total)
                nbytes &= ~(WC_AES_BLOCK_SIZE - 1);

            if (nbytes & ((unsigned int)WC_AES_BLOCK_SIZE - 1U))
                err = wc_AesXtsEncryptFinal(ctx->aesXts, walk.dst.virt.addr,
                                            walk.src.virt.addr, nbytes,
                                            &stream);
            else
                err = wc_AesXtsEncryptUpdate(ctx->aesXts, walk.dst.virt.addr,
                                             walk.src.virt.addr, nbytes,
                                             &stream);

            if (unlikely(err)) {
                pr_err("%s: wc_AesXtsEncryptUpdate failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return -EINVAL;
            }

            err = skcipher_walk_done(&walk, walk.nbytes - nbytes);

            if (unlikely(err)) {
                pr_err("%s: skcipher_walk_done failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return err;
            }
        }

        if (unlikely(tail > 0)) {
            struct scatterlist sg_src[2], sg_dst[2];
            struct scatterlist *src, *dst;

            dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
            if (req->dst != req->src)
                dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

            skcipher_request_set_crypt(req, src, dst, WC_AES_BLOCK_SIZE + tail,
                                       req->iv);

            err = skcipher_walk_virt(&walk, &subreq, false);
            if (err)
                return err;

            err = wc_AesXtsEncryptFinal(ctx->aesXts, walk.dst.virt.addr,
                                         walk.src.virt.addr, walk.nbytes,
                                         &stream);

            if (unlikely(err)) {
                pr_err("%s: wc_AesXtsEncryptFinal failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return -EINVAL;
            }

            err = skcipher_walk_done(&walk, 0);
        } else if (! (stream.bytes_crypted_with_this_tweak & ((word32)WC_AES_BLOCK_SIZE - 1U))) {
            err = wc_AesXtsEncryptFinal(ctx->aesXts, NULL, NULL, 0, &stream);
        }
    }

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesXtsEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesXtsDecrypt(struct skcipher_request *req)
{
    int                      err;
    struct crypto_skcipher * tfm = NULL;
    struct km_AesXtsCtx *    ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    if (req->cryptlen < WC_AES_BLOCK_SIZE)
        return -EINVAL;

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    if (walk.nbytes == walk.total) {
        err = wc_AesXtsDecrypt(ctx->aesXts,
                               walk.dst.virt.addr, walk.src.virt.addr,
                               walk.nbytes, walk.iv, walk.ivsize);

        if (unlikely(err)) {
            pr_err("%s: wc_AesXtsDecrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return -EINVAL;
        }

        err = skcipher_walk_done(&walk, 0);
    } else {
        int tail = req->cryptlen % WC_AES_BLOCK_SIZE;
        struct skcipher_request subreq;
        struct XtsAesStreamData stream;

        if (unlikely(tail > 0)) {
            int blocks = DIV_ROUND_UP(req->cryptlen, WC_AES_BLOCK_SIZE) - 2;

            skcipher_walk_abort(&walk);

            skcipher_request_set_tfm(&subreq, tfm);
            skcipher_request_set_callback(&subreq,
                                          skcipher_request_flags(req),
                                          NULL, NULL);
            skcipher_request_set_crypt(&subreq, req->src, req->dst,
                                       blocks * WC_AES_BLOCK_SIZE, req->iv);
            req = &subreq;

            err = skcipher_walk_virt(&walk, req, false);
            if (!walk.nbytes)
                return err ? : -EINVAL;
        } else {
            tail = 0;
        }

        err = wc_AesXtsDecryptInit(ctx->aesXts, walk.iv, walk.ivsize, &stream);

        if (unlikely(err)) {
            pr_err("%s: wc_AesXtsDecryptInit failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return -EINVAL;
        }

        while ((nbytes = walk.nbytes) != 0) {
            /* if this isn't the final call, pass block-aligned data to prevent
             * end-of-message ciphertext stealing.
             */
            if (nbytes < walk.total)
                nbytes &= ~(WC_AES_BLOCK_SIZE - 1);

            if (nbytes & ((unsigned int)WC_AES_BLOCK_SIZE - 1U))
                err = wc_AesXtsDecryptFinal(ctx->aesXts, walk.dst.virt.addr,
                                            walk.src.virt.addr, nbytes,
                                            &stream);
            else
                err = wc_AesXtsDecryptUpdate(ctx->aesXts, walk.dst.virt.addr,
                                             walk.src.virt.addr, nbytes,
                                             &stream);

            if (unlikely(err)) {
                pr_err("%s: wc_AesXtsDecryptUpdate failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return -EINVAL;
            }

            err = skcipher_walk_done(&walk, walk.nbytes - nbytes);

            if (unlikely(err)) {
                pr_err("%s: skcipher_walk_done failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return err;
            }
        }

        if (unlikely(tail > 0)) {
            struct scatterlist sg_src[2], sg_dst[2];
            struct scatterlist *src, *dst;

            dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
            if (req->dst != req->src)
                dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

            skcipher_request_set_crypt(req, src, dst, WC_AES_BLOCK_SIZE + tail,
                                       req->iv);

            err = skcipher_walk_virt(&walk, &subreq, false);
            if (err)
                return err;

            err = wc_AesXtsDecryptFinal(ctx->aesXts, walk.dst.virt.addr,
                                         walk.src.virt.addr, walk.nbytes,
                                         &stream);

            if (unlikely(err)) {
                pr_err("%s: wc_AesXtsDecryptFinal failed: %d\n",
                       crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
                return -EINVAL;
            }

            err = skcipher_walk_done(&walk, 0);
        } else if (! (stream.bytes_crypted_with_this_tweak & ((word32)WC_AES_BLOCK_SIZE - 1U))) {
            err = wc_AesXtsDecryptFinal(ctx->aesXts, NULL, NULL, 0, &stream);
        }
    }

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesXtsDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg xtsAesAlg = {
    .base.cra_name          = WOLFKM_AESXTS_NAME,
    .base.cra_driver_name   = WOLFKM_AESXTS_DRIVER,
    .base.cra_priority      = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize     = WC_AES_BLOCK_SIZE,
    .base.cra_ctxsize       = sizeof(struct km_AesXtsCtx),
    .base.cra_module        = THIS_MODULE,

    .min_keysize            = 2 * AES_128_KEY_SIZE,
    .max_keysize            = 2 * AES_256_KEY_SIZE,
    .ivsize                 = WC_AES_BLOCK_SIZE,
    .walksize               = 2 * WC_AES_BLOCK_SIZE,
    .init                   = km_AesXtsInit,
    .exit                   = km_AesXtsExit,
    .setkey                 = km_AesXtsSetKey,
    .encrypt                = km_AesXtsEncrypt,
    .decrypt                = km_AesXtsDecrypt
};
static int xtsAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESXTS */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR

static int km_AesCtrInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESCTR_DRIVER, 0);
}

static int km_AesCtrSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_AESCTR_DRIVER);
}

static int km_AesCtrEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    /* Copy the cipher state to mitigate races on Aes.reg and Aes.tmp. */
    aes_copy = (struct Aes *)malloc(sizeof(Aes));
    if (aes_copy == NULL) {
        err = -ENOMEM;
        goto out;
    }
    XMEMCPY(aes_copy, ctx->aes_encrypt, sizeof(Aes));

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        pr_err("%s: wc_AesSetIV failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        err = wc_AesCtrEncrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesCtrEncrypt failed %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return err;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCtrEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesCtrDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    /* Copy the cipher state to mitigate races on Aes.reg and Aes.tmp. */
    aes_copy = (struct Aes *)malloc(sizeof(Aes));
    if (aes_copy == NULL) {
        err = -ENOMEM;
        goto out;
    }
    XMEMCPY(aes_copy, ctx->aes_encrypt, sizeof(Aes)); /* CTR uses the same
                                                       * schedule for encrypt
                                                       * and decrypt.
                                                       */

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesSetIV failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        /* CTR uses the same function for encrypt and decrypt. */
        err = wc_AesCtrEncrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesCtrDecrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            goto out;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesCtrDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg ctrAesAlg = {
    .base.cra_name        = WOLFKM_AESCTR_NAME,
    .base.cra_driver_name = WOLFKM_AESCTR_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesCtrInit,
    .exit                 = km_AesExit,
    .min_keysize          = AES_128_KEY_SIZE,
    .max_keysize          = AES_256_KEY_SIZE,
    .ivsize               = WC_AES_BLOCK_SIZE,
    .setkey               = km_AesCtrSetKey,
    .encrypt              = km_AesCtrEncrypt,
    .decrypt              = km_AesCtrDecrypt,
};
static int ctrAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESCTR */

#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB

static int km_AesOfbInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESOFB_DRIVER, 0);
}

static int km_AesOfbSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_AESOFB_DRIVER);
}

static int km_AesOfbEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    /* Copy the cipher state to mitigate races on Aes.reg and Aes.tmp. */
    aes_copy = (struct Aes *)malloc(sizeof(Aes));
    if (aes_copy == NULL) {
        err = -ENOMEM;
        goto out;
    }
    XMEMCPY(aes_copy, ctx->aes_encrypt, sizeof(Aes));

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        pr_err("%s: wc_AesSetIV failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        err = wc_AesOfbEncrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesOfbEncrypt failed %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            return err;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesOfbEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesOfbDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    int                      err;
    Aes                      *aes_copy = NULL;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("%s: skcipher_walk_virt failed: %d\n",
               crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        return err;
    }

    /* Copy the cipher state to mitigate races on Aes.reg and Aes.tmp. */
    aes_copy = (struct Aes *)malloc(sizeof(Aes));
    if (aes_copy == NULL) {
        err = -ENOMEM;
        goto out;
    }
    XMEMCPY(aes_copy, ctx->aes_encrypt, sizeof(Aes)); /* OFB uses the same
                                                       * schedule for encrypt
                                                       * and decrypt.
                                                       */

    err = wc_AesSetIV(aes_copy, walk.iv);

    if (unlikely(err)) {
        if (! disable_setkey_warnings)
            pr_err("%s: wc_AesSetIV failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
        err = -EINVAL;
        goto out;
    }

    while (walk.nbytes != 0) {
        err = wc_AesOfbDecrypt(aes_copy, walk.dst.virt.addr,
                               walk.src.virt.addr, walk.nbytes);

        if (unlikely(err)) {
            pr_err("%s: wc_AesOfbDecrypt failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            err = -EINVAL;
            goto out;
        }

        err = skcipher_walk_done(&walk, 0);

        if (unlikely(err)) {
            pr_err("%s: skcipher_walk_done failed: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), err);
            goto out;
        }
    }

    /* copy iv from wolfCrypt back to walk.iv */
    XMEMCPY(walk.iv, aes_copy->reg, WC_AES_BLOCK_SIZE);

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    km_AesFree(&aes_copy);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesOfbDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg ofbAesAlg = {
    .base.cra_name        = WOLFKM_AESOFB_NAME,
    .base.cra_driver_name = WOLFKM_AESOFB_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesOfbInit,
    .exit                 = km_AesExit,
    .min_keysize          = AES_128_KEY_SIZE,
    .max_keysize          = AES_256_KEY_SIZE,
    .ivsize               = WC_AES_BLOCK_SIZE,
    .setkey               = km_AesOfbSetKey,
    .encrypt              = km_AesOfbEncrypt,
    .decrypt              = km_AesOfbDecrypt,
};
static int ofbAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESOFB */

#ifdef LINUXKM_LKCAPI_REGISTER_AESECB

static int km_AesEcbInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_AESECB_DRIVER, 1);
}

static int km_AesEcbSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_AESECB_DRIVER);
}

static int km_AesEcbEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err;
    Aes                     *aes;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        return err;
    }

    err = km_AesGet(ctx, 0 /* decrypt_p */, 0 /* copy_p */, &aes);
    if (unlikely(err)) {
        goto out;
    }

    while ((nbytes = walk.nbytes) != 0) {
        err = wc_AesEcbEncrypt(aes, walk.dst.virt.addr, walk.src.virt.addr,
                               nbytes & (~(WC_AES_BLOCK_SIZE - 1)));

        if (unlikely(err)) {
            pr_err("%s: wc_AesEcbEncrypt failed for %u bytes: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), nbytes, err);
            err = -EINVAL;
            goto out;
        }

        nbytes &= WC_AES_BLOCK_SIZE - 1;
        err = skcipher_walk_done(&walk, nbytes);
    }

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesEcbEncrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static int km_AesEcbDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err;
    Aes                     *aes;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    if (unlikely(err)) {
        return err;
    }

    err = km_AesGet(ctx, 1 /* decrypt_p */, 0 /* copy_p */, &aes);
    if (unlikely(err)) {
        goto out;
    }

    while ((nbytes = walk.nbytes) != 0) {
        err = wc_AesEcbDecrypt(aes, walk.dst.virt.addr, walk.src.virt.addr,
                               nbytes & (~(WC_AES_BLOCK_SIZE - 1)));

        if (unlikely(err)) {
            pr_err("%s: wc_AesEcbDecrypt failed for %u bytes: %d\n",
                   crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)), nbytes, err);
            err = -EINVAL;
            goto out;
        }

        nbytes &= WC_AES_BLOCK_SIZE - 1;
        err = skcipher_walk_done(&walk, nbytes);
    }

out:

    if (err && walk.nbytes)
        (void)skcipher_walk_done(&walk, err);

    #ifdef WOLFKM_DEBUG_AES
    pr_info("info: exiting km_AesEcbDecrypt: err %d, cryptlen %d\n", err,
            req->cryptlen);
    #endif /* WOLFKM_DEBUG_AES */

    return err;
}

static struct skcipher_alg ecbAesAlg = {
    .base.cra_name        = WOLFKM_AESECB_NAME,
    .base.cra_driver_name = WOLFKM_AESECB_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_blocksize   = WC_AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesEcbInit,
    .exit                 = km_AesExit,
    .min_keysize          = AES_128_KEY_SIZE,
    .max_keysize          = AES_256_KEY_SIZE,
    .ivsize               = 0,
    .setkey               = km_AesEcbSetKey,
    .encrypt              = km_AesEcbEncrypt,
    .decrypt              = km_AesEcbDecrypt,
};
static int ecbAesAlg_loaded = 0;

#endif /* LINUXKM_LKCAPI_REGISTER_AESECB */

/* cipher tests, cribbed from test.c, with supplementary LKCAPI tests: */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC

static int linuxkm_test_aescbc(void)
{
    int    ret = 0;
    struct crypto_skcipher *  tfm = NULL;
    struct skcipher_request * req = NULL;
    struct scatterlist        src, dst;
    Aes    *aes;
    int    aes_inited = 0;
    static const byte key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    static const byte p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    static const byte iv[] = "1234567890abcdef";

    static const byte c_vector[] =
    {
        0xd7,0xd6,0x04,0x5b,0x4d,0xc4,0x90,0xdf,
        0x4a,0x82,0xed,0x61,0x26,0x4e,0x23,0xb3,
        0xe4,0xb5,0x85,0x30,0x29,0x4c,0x9d,0xcf,
        0x73,0xc9,0x46,0xd1,0xaa,0xc8,0xcb,0x62
    };

    byte    iv_copy[sizeof(iv)];
    byte    enc[sizeof(p_vector)];
    byte    dec[sizeof(p_vector)];
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;

    aes = (Aes *)malloc(sizeof(*aes));
    if (aes == NULL)
        return MEMORY_E;

    XMEMSET(enc, 0, sizeof(enc));
    XMEMSET(dec, 0, sizeof(enc));

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        goto test_cbc_end;
    }
    aes_inited = 1;

    ret = wc_AesSetKey(aes, key32, WC_AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d\n", ret);
        goto test_cbc_end;
    }

    ret = wc_AesCbcEncrypt(aes, enc, p_vector, sizeof(p_vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcEncrypt failed with return code %d\n", ret);
        goto test_cbc_end;
    }

    if (XMEMCMP(enc, c_vector, sizeof(c_vector)) != 0) {
        pr_err("wolfcrypt wc_AesCbcEncrypt KAT mismatch\n");
        return LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
    }

    /* Re init for decrypt and set flag. */
    wc_AesFree(aes);
    aes_inited = 0;

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        goto test_cbc_end;
    }
    aes_inited = 1;

    ret = wc_AesSetKey(aes, key32, WC_AES_BLOCK_SIZE * 2, iv, AES_DECRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d.\n", ret);
        goto test_cbc_end;
    }

    ret = wc_AesCbcDecrypt(aes, dec, enc, sizeof(p_vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcDecrypt failed with return code %d\n", ret);
        goto test_cbc_end;
    }

    ret = XMEMCMP(p_vector, dec, sizeof(p_vector));
    if (ret) {
        pr_err("error: p_vector and dec do not match: %d\n", ret);
        goto test_cbc_end;
    }

    /* now the kernel crypto part */
    enc2 = malloc(sizeof(p_vector));
    if (!enc2) {
        pr_err("error: malloc failed\n");
        goto test_cbc_end;
    }

    dec2 = malloc(sizeof(p_vector));
    if (!dec2) {
        pr_err("error: malloc failed\n");
        goto test_cbc_end;
    }

    memcpy(dec2, p_vector, sizeof(p_vector));

    tfm = crypto_alloc_skcipher(WOLFKM_AESCBC_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_AESCBC_DRIVER, PTR_ERR(tfm));
        tfm = NULL;
        goto test_cbc_end;
    }

#ifndef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    {
        const char *driver_name =
            crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
        if (strcmp(driver_name, WOLFKM_AESCBC_DRIVER)) {
            pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
                   WOLFKM_AESCBC_NAME, driver_name, WOLFKM_AESCBC_DRIVER);
            ret = -ENOENT;
            goto test_cbc_end;
        }
    }
#endif

    ret = crypto_skcipher_setkey(tfm, key32, WC_AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_skcipher_setkey returned: %d\n", ret);
        goto test_cbc_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES skcipher request %s failed\n",
               WOLFKM_AESCBC_DRIVER);
        req = NULL;
        goto test_cbc_end;
    }

    sg_init_one(&src, dec2, sizeof(p_vector));
    sg_init_one(&dst, enc2, sizeof(p_vector));

    XMEMCPY(iv_copy, iv, sizeof(iv));
    skcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), iv_copy);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_cbc_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(p_vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_cbc_end;
    }

    memset(dec2, 0, sizeof(p_vector));
    sg_init_one(&src, enc2, sizeof(p_vector));
    sg_init_one(&dst, dec2, sizeof(p_vector));

    XMEMCPY(iv_copy, iv, sizeof(iv));
    skcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), iv_copy);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("ERROR: crypto_skcipher_decrypt returned %d\n", ret);
        goto test_cbc_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(p_vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_cbc_end;
    }

test_cbc_end:

    if (enc2) { free(enc2); }
    if (dec2) { free(dec2); }
    if (req) { skcipher_request_free(req); }
    if (tfm) { crypto_free_skcipher(tfm); }

    if (aes_inited)
        wc_AesFree(aes);
    free(aes);

    return ret;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESCBC */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB

static int linuxkm_test_aescfb(void)
{
    int    ret = 0;
    struct crypto_skcipher *  tfm = NULL;
    struct skcipher_request * req = NULL;
    struct scatterlist        src, dst;
    Aes    *aes;
    int    aes_inited = 0;
    static const byte key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    static const byte p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    static const byte iv[] = "1234567890abcdef";
    static const byte c_vector[] =
    {
        0x56,0x35,0x3f,0xdd,0xde,0xa6,0x15,0x87,
        0x57,0xdc,0x34,0x62,0x9a,0x68,0x96,0x51,
        0xc7,0x09,0xb9,0x4e,0x47,0x6b,0x24,0x72,
        0x19,0x5a,0xdf,0x7e,0xba,0xa8,0x01,0xb6
    };
    byte    iv_copy[sizeof(iv)];
    byte    enc[sizeof(p_vector)];
    byte    dec[sizeof(p_vector)];
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;

    aes = (Aes *)malloc(sizeof(*aes));
    if (aes == NULL)
        return MEMORY_E;

    ret = aesofb_test();
    if (ret) {
        wc_test_render_error_message("aesgcm_test failed: ", ret);
        ret = WC_TEST_RET_DEC_EC(ret);
        goto test_cfb_end;
    }

    XMEMSET(enc, 0, sizeof(enc));
    XMEMSET(dec, 0, sizeof(enc));

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        goto test_cfb_end;
    }
    aes_inited = 1;

    ret = wc_AesSetKey(aes, key32, WC_AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d\n", ret);
        goto test_cfb_end;
    }

    ret = wc_AesCfbEncrypt(aes, enc, p_vector, sizeof(p_vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCfbEncrypt failed with return code %d\n", ret);
        goto test_cfb_end;
    }

    if (XMEMCMP(enc, c_vector, sizeof(c_vector)) != 0) {
        pr_err("wolfcrypt wc_AesCfbEncrypt KAT mismatch\n");
        return LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
    }

    /* Re init for decrypt and set flag. */
    wc_AesFree(aes);
    aes_inited = 0;

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        goto test_cfb_end;
    }
    aes_inited = 1;

    ret = wc_AesSetKey(aes, key32, WC_AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d.\n", ret);
        goto test_cfb_end;
    }

    ret = wc_AesCfbDecrypt(aes, dec, enc, sizeof(p_vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCfbDecrypt failed with return code %d\n", ret);
        goto test_cfb_end;
    }

    ret = XMEMCMP(p_vector, dec, sizeof(p_vector));
    if (ret) {
        pr_err("error: p_vector and dec do not match: %d\n", ret);
        goto test_cfb_end;
    }

    /* now the kernel crypto part */
    enc2 = malloc(sizeof(p_vector));
    if (!enc2) {
        pr_err("error: malloc failed\n");
        goto test_cfb_end;
    }

    dec2 = malloc(sizeof(p_vector));
    if (!dec2) {
        pr_err("error: malloc failed\n");
        goto test_cfb_end;
    }

    memcpy(dec2, p_vector, sizeof(p_vector));

    tfm = crypto_alloc_skcipher(WOLFKM_AESCFB_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_AESCFB_DRIVER, PTR_ERR(tfm));
        tfm = NULL;
        goto test_cfb_end;
    }

    ret = check_skcipher_driver_masking(tfm, WOLFKM_AESCFB_NAME, WOLFKM_AESCFB_DRIVER);
    if (ret)
        goto test_cfb_end;

    ret = crypto_skcipher_setkey(tfm, key32, WC_AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_skcipher_setkey returned: %d\n", ret);
        goto test_cfb_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES skcipher request %s failed\n",
               WOLFKM_AESCFB_DRIVER);
        req = NULL;
        goto test_cfb_end;
    }

    sg_init_one(&src, dec2, sizeof(p_vector));
    sg_init_one(&dst, enc2, sizeof(p_vector));

    XMEMCPY(iv_copy, iv, sizeof(iv));
    skcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), iv_copy);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_cfb_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(p_vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_cfb_end;
    }

    memset(dec2, 0, sizeof(p_vector));
    sg_init_one(&src, enc2, sizeof(p_vector));
    sg_init_one(&dst, dec2, sizeof(p_vector));

    XMEMCPY(iv_copy, iv, sizeof(iv));
    skcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), iv_copy);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_decrypt returned: %d\n", ret);
        goto test_cfb_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(p_vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_cfb_end;
    }

test_cfb_end:

    if (enc2) { free(enc2); }
    if (dec2) { free(dec2); }
    if (req) { skcipher_request_free(req); }
    if (tfm) { crypto_free_skcipher(tfm); }

    if (aes_inited)
        wc_AesFree(aes);
    free(aes);

    return ret;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESCFB */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM

static int linuxkm_test_aesgcm(void)
{
#ifndef WOLFSSL_AESGCM_STREAM
    wc_test_ret_t ret = aesgcm_test();
    if (ret >= 0)
        return check_aead_driver_masking(NULL /* tfm */, WOLFKM_AESGCM_NAME, WOLFKM_AESGCM_DRIVER);
    else {
        wc_test_render_error_message("aesgcm_test failed: ", ret);
        return WC_TEST_RET_DEC_EC(ret);
    }
#else
    int     ret = 0;
    struct crypto_aead *  tfm = NULL;
    struct aead_request * req = NULL;
    struct scatterlist *  src = NULL;
    struct scatterlist *  dst = NULL;
    Aes    *aes;
    int    aes_inited = 0;
    static const byte key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    static const byte p_vector[] =
    /* Now is the time for all w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    static const byte assoc[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    static const byte ivstr[] = "1234567890ab";
    static const byte c_vector[] =
    {
        0x80,0xb9,0x00,0xdc,0x03,0xb8,0x0e,0xaa,
        0x98,0x09,0x75,0x01,0x40,0x09,0xb0,0xc3,
        0x7a,0xed,0x2c,0x2e,0x4d,0xe5,0xca,0x80
    };
    static const byte KAT_authTag[] =
    {
        0x8d,0xf5,0x76,0xae,0x53,0x20,0x5d,0x9c,
        0x01,0x64,0xcd,0xf2,0xec,0x7a,0x13,0x03
    };
    byte    enc[sizeof(p_vector)];
    byte    authTag[WC_AES_BLOCK_SIZE];
    byte    dec[sizeof(p_vector)];
    u8 *    assoc2 = NULL;
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;
    u8 *    iv = NULL;
    size_t  encryptLen = sizeof(p_vector);
    size_t  decryptLen = sizeof(p_vector) + sizeof(authTag);

    /* Init stack variables. */
    XMEMSET(enc, 0, sizeof(p_vector));
    XMEMSET(dec, 0, sizeof(p_vector));
    XMEMSET(authTag, 0, WC_AES_BLOCK_SIZE);

    aes = (Aes *)malloc(sizeof(*aes));
    if (aes == NULL)
        return MEMORY_E;

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("error: wc_AesInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }
    aes_inited = 1;

    ret = wc_AesGcmInit(aes, key32, sizeof(key32)/sizeof(byte), ivstr,
                        GCM_NONCE_MID_SZ);
    if (ret) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptUpdate(aes, NULL, NULL, 0, assoc, sizeof(assoc));
    if (ret) {
        pr_err("error: wc_AesGcmEncryptUpdate failed with return code %d\n",
               ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptUpdate(aes, enc, p_vector, sizeof(p_vector), NULL, 0);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptUpdate failed with return code %d\n",
               ret);
        goto test_gcm_end;
    }

    if (XMEMCMP(enc, c_vector, sizeof(c_vector)) != 0) {
        pr_err("wolfcrypt AES-GCM KAT mismatch on ciphertext\n");
        ret = LINUXKM_LKCAPI_AESGCM_KAT_MISMATCH_E;
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptFinal(aes, authTag, WC_AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptFinal failed with return code %d\n",
               ret);
        goto test_gcm_end;
    }

    if (XMEMCMP(authTag, KAT_authTag, sizeof(KAT_authTag)) != 0) {
        pr_err("wolfcrypt AES-GCM KAT mismatch on authTag\n");
        ret = LINUXKM_LKCAPI_AESGCM_KAT_MISMATCH_E;
        goto test_gcm_end;
    }

    ret = wc_AesGcmInit(aes, key32, sizeof(key32)/sizeof(byte), ivstr,
                        GCM_NONCE_MID_SZ);
    if (ret) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmDecryptUpdate(aes, dec, enc, sizeof(p_vector),
                                 assoc, sizeof(assoc));
    if (ret) {
        pr_err("error: wc_AesGcmDecryptUpdate failed with return code %d\n",
               ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmDecryptFinal(aes, authTag, WC_AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptFinal failed with return code %d\n",
               ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(p_vector, dec, sizeof(p_vector));
    if (ret) {
        pr_err("error: gcm: p_vector and dec do not match: %d\n", ret);
        goto test_gcm_end;
    }

    /* now the kernel crypto part */
    assoc2 = malloc(sizeof(assoc));
    if (! assoc2) {
        pr_err("error: malloc failed\n");
        goto test_gcm_end;
    }
    memset(assoc2, 0, sizeof(assoc));
    memcpy(assoc2, assoc, sizeof(assoc));

    iv = malloc(WC_AES_BLOCK_SIZE);
    if (! iv) {
        pr_err("error: malloc failed\n");
        goto test_gcm_end;
    }
    memset(iv, 0, WC_AES_BLOCK_SIZE);
    memcpy(iv, ivstr, GCM_NONCE_MID_SZ);

    enc2 = malloc(decryptLen);
    if (! enc2) {
        pr_err("error: malloc failed\n");
        goto test_gcm_end;
    }

    dec2 = malloc(decryptLen);
    if (! dec2) {
        pr_err("error: malloc failed\n");
        goto test_gcm_end;
    }

    memset(enc2, 0, decryptLen);
    memset(dec2, 0, decryptLen);
    memcpy(dec2, p_vector, sizeof(p_vector));

    tfm = crypto_alloc_aead(WOLFKM_AESGCM_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_AESGCM_DRIVER, PTR_ERR(tfm));
        tfm = NULL;
        goto test_gcm_end;
    }

    ret = check_aead_driver_masking(tfm, WOLFKM_AESGCM_NAME, WOLFKM_AESGCM_DRIVER);
    if (ret)
        goto test_gcm_end;

    ret = crypto_aead_setkey(tfm, key32, WC_AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_aead_setkey returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = crypto_aead_setauthsize(tfm, sizeof(authTag));
    if (ret) {
        pr_err("error: crypto_aead_setauthsize returned: %d\n", ret);
        goto test_gcm_end;
    }

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES aead request %s failed: %ld\n",
               WOLFKM_AESCBC_DRIVER, PTR_ERR(req));
        req = NULL;
        goto test_gcm_end;
    }

    src = malloc(sizeof(struct scatterlist) * 2);

    if (! src) {
        pr_err("error: malloc src failed: %ld\n",
               PTR_ERR(src));
        goto test_gcm_end;
    }

    dst = malloc(sizeof(struct scatterlist) * 2);

    if (! dst) {
        pr_err("error: malloc dst failed: %ld\n",
               PTR_ERR(dst));
        goto test_gcm_end;
    }

    sg_init_table(src, 2);
    sg_set_buf(src, assoc2, sizeof(assoc));
    sg_set_buf(&src[1], dec2, sizeof(p_vector));

    sg_init_table(dst, 2);
    sg_set_buf(dst, assoc2, sizeof(assoc));
    sg_set_buf(&dst[1], enc2, decryptLen);

    aead_request_set_callback(req, 0, NULL, NULL);
    aead_request_set_ad(req, sizeof(assoc));
    aead_request_set_crypt(req, src, dst, sizeof(p_vector), iv);

    ret = crypto_aead_encrypt(req);

    if (ret) {
        pr_err("error: crypto_aead_encrypt returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(p_vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(authTag, enc2 + encryptLen, sizeof(authTag));
    if (ret) {
        pr_err("error: authTags do not match: %d\n", ret);
        goto test_gcm_end;
    }

    /* Now decrypt crypto request. Reverse src and dst. */
    memset(dec2, 0, decryptLen);
    aead_request_set_ad(req, sizeof(assoc));
    aead_request_set_crypt(req, dst, src, decryptLen, iv);

    ret = crypto_aead_decrypt(req);

    if (ret) {
        pr_err("error: crypto_aead_decrypt returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(p_vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_gcm_end;
    }

test_gcm_end:
    if (req) { aead_request_free(req); req = NULL; }
    if (tfm) { crypto_free_aead(tfm); tfm = NULL; }

    if (src) { free(src); src = NULL; }
    if (dst) { free(dst); dst = NULL; }

    if (dec2) { free(dec2); dec2 = NULL; }
    if (enc2) { free(enc2); enc2 = NULL; }

    if (assoc2) { free(assoc2); assoc2 = NULL; }
    if (iv) { free(iv); iv = NULL; }

    if (aes_inited)
        wc_AesFree(aes);
    free(aes);

    return ret;
#endif /* WOLFSSL_AESGCM_STREAM */
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106

static int linuxkm_test_aesgcm_rfc4106(void)
{
    wc_test_ret_t ret = aesgcm_test();
    if (ret >= 0)
        return check_aead_driver_masking(NULL /* tfm */, WOLFKM_AESGCM_RFC4106_NAME, WOLFKM_AESGCM_RFC4106_DRIVER);
    else {
        wc_test_render_error_message("aesgcm_test failed: ", ret);
        return WC_TEST_RET_DEC_EC(ret);
    }
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106 */

#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS

/* test vectors from
 * http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html
 */
#ifdef WOLFSSL_AES_128
static int aes_xts_128_test(void)
{
    XtsAes *aes = NULL;
    int aes_inited = 0;
    int ret = 0;
#define AES_XTS_128_TEST_BUF_SIZ (WC_AES_BLOCK_SIZE * 2 + 8)
    unsigned char *buf = NULL;
    unsigned char *cipher = NULL;
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;
    struct scatterlist *  src = NULL;
    struct scatterlist *  dst = NULL;
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct XtsAesStreamData stream;
    byte* large_input = NULL;

    /* 128 key tests */
    static const unsigned char k1[] = {
        0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35,
        0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62,
        0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18,
        0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f
    };

    static const unsigned char i1[] = {
        0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static const unsigned char p1[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c
    };

    /* plain text test of partial block is not from NIST test vector list */
    static const unsigned char pp[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static const unsigned char c1[] = {
        0x77, 0x8a, 0xe8, 0xb4, 0x3c, 0xb9, 0x8d, 0x5a,
        0x82, 0x50, 0x81, 0xd5, 0xbe, 0x47, 0x1c, 0x63
    };

    /* plain text test of partial block is not from NIST test vector list */
    static const unsigned char cp[] = {
        0x2b, 0xf7, 0x2c, 0xf3, 0xeb, 0x85, 0xef, 0x7b,
        0x0b, 0x76, 0xa0, 0xaa, 0xf3, 0x3f, 0x25, 0x8b,
        0x77, 0x8a, 0xe8, 0xb4, 0x3c, 0xb9, 0x8d, 0x5a
    };

    static const unsigned char k2[] = {
        0x39, 0x25, 0x79, 0x05, 0xdf, 0xcc, 0x77, 0x76,
        0x6c, 0x87, 0x0a, 0x80, 0x6a, 0x60, 0xe3, 0xc0,
        0x93, 0xd1, 0x2a, 0xcf, 0xcb, 0x51, 0x42, 0xfa,
        0x09, 0x69, 0x89, 0x62, 0x5b, 0x60, 0xdb, 0x16
    };

    static const unsigned char i2[] = {
        0x5c, 0xf7, 0x9d, 0xb6, 0xc5, 0xcd, 0x99, 0x1a,
        0x1c, 0x78, 0x81, 0x42, 0x24, 0x95, 0x1e, 0x84
    };

    static const unsigned char p2[] = {
        0xbd, 0xc5, 0x46, 0x8f, 0xbc, 0x8d, 0x50, 0xa1,
        0x0d, 0x1c, 0x85, 0x7f, 0x79, 0x1c, 0x5c, 0xba,
        0xb3, 0x81, 0x0d, 0x0d, 0x73, 0xcf, 0x8f, 0x20,
        0x46, 0xb1, 0xd1, 0x9e, 0x7d, 0x5d, 0x8a, 0x56
    };

    static const unsigned char c2[] = {
        0xd6, 0xbe, 0x04, 0x6d, 0x41, 0xf2, 0x3b, 0x5e,
        0xd7, 0x0b, 0x6b, 0x3d, 0x5c, 0x8e, 0x66, 0x23,
        0x2b, 0xe6, 0xb8, 0x07, 0xd4, 0xdc, 0xc6, 0x0e,
        0xff, 0x8d, 0xbc, 0x1d, 0x9f, 0x7f, 0xc8, 0x22
    };

#ifndef HAVE_FIPS /* FIPS requires different keys for main and tweak. */
    static const unsigned char k3[] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };
    static const unsigned char i3[] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };
    static const unsigned char p3[] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0xff, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
    };
    static const unsigned char c3[] = {
        0xA2, 0x07, 0x47, 0x76, 0x3F, 0xEC, 0x0C, 0x23,
        0x1B, 0xD0, 0xBD, 0x46, 0x9A, 0x27, 0x38, 0x12,
        0x95, 0x02, 0x3D, 0x5D, 0xC6, 0x94, 0x51, 0x36,
        0xA0, 0x85, 0xD2, 0x69, 0x6E, 0x87, 0x0A, 0xBF,
        0xB5, 0x5A, 0xDD, 0xCB, 0x80, 0xE0, 0xFC, 0xCD
    };
#endif /* HAVE_FIPS */

    if ((aes = (XtsAes *)XMALLOC(sizeof(*aes), NULL, DYNAMIC_TYPE_AES))
        == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }

    if ((buf = (unsigned char *)XMALLOC(AES_XTS_128_TEST_BUF_SIZ, NULL,
                                        DYNAMIC_TYPE_AES)) == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }
    if ((cipher = (unsigned char *)XMALLOC(AES_XTS_128_TEST_BUF_SIZ, NULL,
                                           DYNAMIC_TYPE_AES)) == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }

    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsInit(aes, NULL, INVALID_DEVID);
    if (ret != 0)
        goto out;
    else
        aes_inited = 1;

    ret = wc_AesXtsSetKeyNoInit(aes, k2, sizeof(k2), AES_ENCRYPTION);
    if (ret != 0)
        goto out;

    ret = wc_AesXtsEncrypt(aes, buf, p2, sizeof(p2), i2, sizeof(i2));
    if (ret != 0)
        goto out;
    if (XMEMCMP(c2, buf, sizeof(c2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#if defined(DEBUG_VECTOR_REGISTER_ACCESS) && defined(WC_C_DYNAMIC_FALLBACK)
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(WC_NO_ERR_TRACE(SYSLIB_FAILED_E));
    ret = wc_AesXtsEncrypt(aes, buf, p2, sizeof(p2), i2, sizeof(i2));
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(0);
    if (ret != 0)
        goto out;
    if (XMEMCMP(c2, buf, sizeof(c2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }
#endif

    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);

    ret = wc_AesXtsEncryptInit(aes, i2, sizeof(i2), &stream);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncryptUpdate(aes, buf, p2, WC_AES_BLOCK_SIZE, &stream);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncryptFinal(aes, buf + WC_AES_BLOCK_SIZE,
                                 p2 + WC_AES_BLOCK_SIZE,
                                 sizeof(p2) - WC_AES_BLOCK_SIZE, &stream);
    if (ret != 0)
        goto out;
    if (XMEMCMP(c2, buf, sizeof(c2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);

    ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncrypt(aes, buf, p1, sizeof(p1), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(c1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#if defined(DEBUG_VECTOR_REGISTER_ACCESS) && defined(WC_C_DYNAMIC_FALLBACK)
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(WC_NO_ERR_TRACE(SYSLIB_FAILED_E));
    ret = wc_AesXtsEncrypt(aes, buf, p1, sizeof(p1), i1, sizeof(i1));
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(0);
    if (ret != 0)
        goto out;
    if (XMEMCMP(c1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }
#endif

    /* partial block encryption test */
    XMEMSET(cipher, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsEncrypt(aes, cipher, pp, sizeof(pp), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(cp, cipher, sizeof(cp))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#if defined(DEBUG_VECTOR_REGISTER_ACCESS) && defined(WC_C_DYNAMIC_FALLBACK)
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(WC_NO_ERR_TRACE(SYSLIB_FAILED_E));
    XMEMSET(cipher, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsEncrypt(aes, cipher, pp, sizeof(pp), i1, sizeof(i1));
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(0);
    if (ret != 0)
        goto out;
    if (XMEMCMP(cp, cipher, sizeof(cp))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }
#endif

    /* partial block decrypt test */
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsDecrypt(aes, buf, cipher, sizeof(pp), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(pp, buf, sizeof(pp))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#if defined(DEBUG_VECTOR_REGISTER_ACCESS) && defined(WC_C_DYNAMIC_FALLBACK)
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(WC_NO_ERR_TRACE(SYSLIB_FAILED_E));
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsDecrypt(aes, buf, cipher, sizeof(pp), i1, sizeof(i1));
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(0);
    if (ret != 0)
        goto out;
    if (XMEMCMP(pp, buf, sizeof(pp))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }
#endif

    /* NIST decrypt test vector */
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsDecrypt(aes, buf, c1, sizeof(c1), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#if defined(DEBUG_VECTOR_REGISTER_ACCESS) && defined(WC_C_DYNAMIC_FALLBACK)
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(WC_NO_ERR_TRACE(SYSLIB_FAILED_E));
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsDecrypt(aes, buf, c1, sizeof(c1), i1, sizeof(i1));
    WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(0);
    if (ret != 0)
        goto out;
    if (XMEMCMP(p1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }
#endif

    /* fail case with decrypting using wrong key */
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsDecrypt(aes, buf, c2, sizeof(c2), i2, sizeof(i2));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p2, buf, sizeof(p2)) == 0) { /* fail case with wrong key */
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    /* set correct key and retest */
    XMEMSET(buf, 0, AES_XTS_128_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k2, sizeof(k2), AES_DECRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsDecrypt(aes, buf, c2, sizeof(c2), i2, sizeof(i2));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p2, buf, sizeof(p2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#ifndef HAVE_FIPS

    /* Test ciphertext stealing in-place. */
    XMEMCPY(buf, p3, sizeof(p3));
    ret = wc_AesXtsSetKeyNoInit(aes, k3, sizeof(k3), AES_ENCRYPTION);
    if (ret != 0)
        goto out;

    ret = wc_AesXtsEncrypt(aes, buf, buf, sizeof(p3), i3, sizeof(i3));
    if (ret != 0)
        goto out;
    if (XMEMCMP(c3, buf, sizeof(c3))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    ret = wc_AesXtsSetKeyNoInit(aes, k3, sizeof(k3), AES_DECRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsDecrypt(aes, buf, buf, sizeof(c3), i3, sizeof(i3));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p3, buf, sizeof(p3))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

#endif /* HAVE_FIPS */

    {
    #define LARGE_XTS_SZ        1024
        int i;
        int j;
        int k;

        large_input = (byte *)XMALLOC(LARGE_XTS_SZ, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (large_input == NULL) {
            ret = MEMORY_E;
            goto out;
        }

        for (i = 0; i < (int)LARGE_XTS_SZ; i++)
            large_input[i] = (byte)i;

        /* first, encrypt block by block then decrypt with a one-shot call. */
        for (j = 16; j < (int)LARGE_XTS_SZ; j++) {
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsEncryptInit(aes, i1, sizeof(i1), &stream);
            if (ret != 0)
                goto out;
            for (k = 0; k < j; k += WC_AES_BLOCK_SIZE) {
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    ret = wc_AesXtsEncryptFinal(aes, large_input + k, large_input + k, j - k, &stream);
                else
                    ret = wc_AesXtsEncryptUpdate(aes, large_input + k, large_input + k, WC_AES_BLOCK_SIZE, &stream);
                if (ret != 0)
                    goto out;
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    break;
            }
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsDecrypt(aes, large_input, large_input, j, i1,
                sizeof(i1));
            if (ret != 0)
                goto out;
            for (i = 0; i < j; i++) {
                if (large_input[i] != (byte)i) {
                    ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
                    goto out;
                }
            }
        }

        /* second, encrypt with a one-shot call then decrypt block by block. */
        for (j = 16; j < (int)LARGE_XTS_SZ; j++) {
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsEncrypt(aes, large_input, large_input, j, i1,
                sizeof(i1));
            if (ret != 0)
                goto out;
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsDecryptInit(aes, i1, sizeof(i1), &stream);
            if (ret != 0)
                goto out;
            for (k = 0; k < j; k += WC_AES_BLOCK_SIZE) {
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    ret = wc_AesXtsDecryptFinal(aes, large_input + k, large_input + k, j - k, &stream);
                else
                    ret = wc_AesXtsDecryptUpdate(aes, large_input + k, large_input + k, WC_AES_BLOCK_SIZE, &stream);
                if (ret != 0)
                    goto out;
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    break;
            }
            for (i = 0; i < j; i++) {
                if (large_input[i] != (byte)i) {
                    ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
                    goto out;
                }
            }
        }
    }

    /* now the kernel crypto part */

    enc2 = XMALLOC(sizeof(pp), NULL, DYNAMIC_TYPE_AES);
    if (!enc2) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    dec2 = XMALLOC(sizeof(pp), NULL, DYNAMIC_TYPE_AES);
    if (!dec2) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    src = XMALLOC(sizeof(*src) * 2, NULL, DYNAMIC_TYPE_AES);
    if (! src) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    dst = XMALLOC(sizeof(*dst) * 2, NULL, DYNAMIC_TYPE_AES);
    if (! dst) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    tfm = crypto_alloc_skcipher(WOLFKM_AESXTS_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        pr_err("error: allocating AES skcipher algorithm %s failed: %d\n",
               WOLFKM_AESXTS_DRIVER, ret);
        tfm = NULL;
        goto test_xts_end;
    }

#ifndef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    {
        const char *driver_name =
            crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
        if (strcmp(driver_name, WOLFKM_AESXTS_DRIVER)) {
            pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
                   WOLFKM_AESXTS_NAME, driver_name, WOLFKM_AESXTS_DRIVER);
            ret = -ENOENT;
            goto test_xts_end;
        }
    }
#endif

    ret = crypto_skcipher_ivsize(tfm);
    if (ret != sizeof(stream.tweak_block)) {
        pr_err("error: AES skcipher algorithm %s crypto_skcipher_ivsize()"
               " returned %d but expected %d\n",
               WOLFKM_AESXTS_DRIVER, ret, (int)sizeof(stream.tweak_block));
        ret = -EINVAL;
        goto test_xts_end;
    }

    ret = crypto_skcipher_setkey(tfm, k1, sizeof(k1));
    if (ret) {
        pr_err("error: crypto_skcipher_setkey for %s returned: %d\n",
               WOLFKM_AESXTS_NAME, ret);
        goto test_xts_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        ret = PTR_ERR(req);
        pr_err("error: allocating AES skcipher request %s failed: %d\n",
               WOLFKM_AESXTS_DRIVER, ret);
        req = NULL;
        goto test_xts_end;
    }

    memcpy(dec2, p1, sizeof(p1));
    memset(enc2, 0, sizeof(p1));

    sg_init_one(src, dec2, sizeof(p1));
    sg_init_one(dst, enc2, sizeof(p1));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(p1), stream.tweak_block);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(c1, enc2, sizeof(c1));
    if (ret) {
        pr_err("error: c1 and enc2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memset(dec2, 0, sizeof(p1));
    sg_init_one(src, enc2, sizeof(p1));
    sg_init_one(dst, dec2, sizeof(p1));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(p1), stream.tweak_block);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("ERROR: crypto_skcipher_decrypt returned %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(p1, dec2, sizeof(p1));
    if (ret) {
        pr_err("error: p1 and dec2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memcpy(dec2, pp, sizeof(pp));
    memset(enc2, 0, sizeof(pp));

    sg_init_one(src, dec2, sizeof(pp));
    sg_init_one(dst, enc2, sizeof(pp));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(pp), stream.tweak_block);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(cp, enc2, sizeof(cp));
    if (ret) {
        pr_err("error: cp and enc2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memset(dec2, 0, sizeof(pp));
    sg_init_one(src, enc2, sizeof(pp));
    sg_init_one(dst, dec2, sizeof(pp));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(pp), stream.tweak_block);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("ERROR: crypto_skcipher_decrypt returned %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(pp, dec2, sizeof(pp));
    if (ret) {
        pr_err("error: pp and dec2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    test_xts_end:

    XFREE(enc2, NULL, DYNAMIC_TYPE_AES);
    XFREE(dec2, NULL, DYNAMIC_TYPE_AES);
    XFREE(src, NULL, DYNAMIC_TYPE_AES);
    XFREE(dst, NULL, DYNAMIC_TYPE_AES);
    if (req)
        skcipher_request_free(req);
    if (tfm)
        crypto_free_skcipher(tfm);

  out:

    XFREE(large_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (aes_inited)
        wc_AesXtsFree(aes);

    XFREE(buf, NULL, DYNAMIC_TYPE_AES);
    XFREE(cipher, NULL, DYNAMIC_TYPE_AES);
    XFREE(aes, NULL, DYNAMIC_TYPE_AES);

#undef AES_XTS_128_TEST_BUF_SIZ

    return ret;
}
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_256
static int aes_xts_256_test(void)
{
    XtsAes *aes = NULL;
    int aes_inited = 0;
    int ret = 0;
#define AES_XTS_256_TEST_BUF_SIZ (WC_AES_BLOCK_SIZE * 3)
    unsigned char *buf = NULL;
    unsigned char *cipher = NULL;
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;
    struct scatterlist *  src = NULL;
    struct scatterlist *  dst = NULL;
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct XtsAesStreamData stream;
    byte* large_input = NULL;

    /* 256 key tests */
    static const unsigned char k1[] = {
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e,
        0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47, 0x14,
        0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7,
        0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a, 0x0e, 0x7c,
        0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d,
        0x19, 0x11, 0xc0, 0x04, 0xcd, 0xa5, 0x8d, 0xa3,
        0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58,
        0x31, 0x8e, 0xea, 0x39, 0x2c, 0xf4, 0x1b, 0x08
    };

    static const unsigned char i1[] = {
        0xad, 0xf8, 0xd9, 0x26, 0x27, 0x46, 0x4a, 0xd2,
        0xf0, 0x42, 0x8e, 0x84, 0xa9, 0xf8, 0x75, 0x64
    };

    static const unsigned char p1[] = {
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1,
        0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3, 0x64,
        0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3,
        0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a, 0x20, 0x2e
    };

    static const unsigned char c1[] = {
        0xcb, 0xaa, 0xd0, 0xe2, 0xf6, 0xce, 0xa3, 0xf5,
        0x0b, 0x37, 0xf9, 0x34, 0xd4, 0x6a, 0x9b, 0x13,
        0x0b, 0x9d, 0x54, 0xf0, 0x7e, 0x34, 0xf3, 0x6a,
        0xf7, 0x93, 0xe8, 0x6f, 0x73, 0xc6, 0xd7, 0xdb
    };

    /* plain text test of partial block is not from NIST test vector list */
    static const unsigned char pp[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static const unsigned char cp[] = {
        0x65, 0x5e, 0x1d, 0x37, 0x4a, 0x91, 0xe7, 0x6c,
        0x4f, 0x83, 0x92, 0xbc, 0x5a, 0x10, 0x55, 0x27,
        0x61, 0x0e, 0x5a, 0xde, 0xca, 0xc5, 0x12, 0xd8
    };

    static const unsigned char k2[] = {
        0xad, 0x50, 0x4b, 0x85, 0xd7, 0x51, 0xbf, 0xba,
        0x69, 0x13, 0xb4, 0xcc, 0x79, 0xb6, 0x5a, 0x62,
        0xf7, 0xf3, 0x9d, 0x36, 0x0f, 0x35, 0xb5, 0xec,
        0x4a, 0x7e, 0x95, 0xbd, 0x9b, 0xa5, 0xf2, 0xec,
        0xc1, 0xd7, 0x7e, 0xa3, 0xc3, 0x74, 0xbd, 0x4b,
        0x13, 0x1b, 0x07, 0x83, 0x87, 0xdd, 0x55, 0x5a,
        0xb5, 0xb0, 0xc7, 0xe5, 0x2d, 0xb5, 0x06, 0x12,
        0xd2, 0xb5, 0x3a, 0xcb, 0x47, 0x8a, 0x53, 0xb4
    };

    static const unsigned char i2[] = {
        0xe6, 0x42, 0x19, 0xed, 0xe0, 0xe1, 0xc2, 0xa0,
        0x0e, 0xf5, 0x58, 0x6a, 0xc4, 0x9b, 0xeb, 0x6f
    };

    static const unsigned char p2[] = {
        0x24, 0xcb, 0x76, 0x22, 0x55, 0xb5, 0xa8, 0x00,
        0xf4, 0x6e, 0x80, 0x60, 0x56, 0x9e, 0x05, 0x53,
        0xbc, 0xfe, 0x86, 0x55, 0x3b, 0xca, 0xd5, 0x89,
        0xc7, 0x54, 0x1a, 0x73, 0xac, 0xc3, 0x9a, 0xbd,
        0x53, 0xc4, 0x07, 0x76, 0xd8, 0xe8, 0x22, 0x61,
        0x9e, 0xa9, 0xad, 0x77, 0xa0, 0x13, 0x4c, 0xfc
    };

    static const unsigned char c2[] = {
        0xa3, 0xc6, 0xf3, 0xf3, 0x82, 0x79, 0x5b, 0x10,
        0x87, 0xd7, 0x02, 0x50, 0xdb, 0x2c, 0xd3, 0xb1,
        0xa1, 0x62, 0xa8, 0xb6, 0xdc, 0x12, 0x60, 0x61,
        0xc1, 0x0a, 0x84, 0xa5, 0x85, 0x3f, 0x3a, 0x89,
        0xe6, 0x6c, 0xdb, 0xb7, 0x9a, 0xb4, 0x28, 0x9b,
        0xc3, 0xea, 0xd8, 0x10, 0xe9, 0xc0, 0xaf, 0x92
    };

    if ((aes = (XtsAes *)XMALLOC(sizeof(*aes), NULL, DYNAMIC_TYPE_AES))
        == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }

    if ((buf = (unsigned char *)XMALLOC(AES_XTS_256_TEST_BUF_SIZ, NULL,
                                        DYNAMIC_TYPE_AES)) == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }
    if ((cipher = (unsigned char *)XMALLOC(AES_XTS_256_TEST_BUF_SIZ, NULL,
                                           DYNAMIC_TYPE_AES)) == NULL)
    {
        ret = MEMORY_E;
        goto out;
    }

    ret = wc_AesXtsInit(aes, NULL, INVALID_DEVID);
    if (ret != 0)
        goto out;
    else
        aes_inited = 1;

    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k2, sizeof(k2), AES_ENCRYPTION);
    if (ret != 0)
        goto out;

    ret = wc_AesXtsEncrypt(aes, buf, p2, sizeof(p2), i2, sizeof(i2));
    if (ret != 0)
        goto out;
    if (XMEMCMP(c2, buf, sizeof(c2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);

    ret = wc_AesXtsEncryptInit(aes, i2, sizeof(i2), &stream);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncryptUpdate(aes, buf, p2, WC_AES_BLOCK_SIZE, &stream);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncryptFinal(aes, buf + WC_AES_BLOCK_SIZE,
                                 p2 + WC_AES_BLOCK_SIZE,
                                 sizeof(p2) - WC_AES_BLOCK_SIZE, &stream);
    if (ret != 0)
        goto out;
    if (XMEMCMP(c2, buf, sizeof(c2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsEncrypt(aes, buf, p1, sizeof(p1), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(c1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    /* partial block encryption test */
    XMEMSET(cipher, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsEncrypt(aes, cipher, pp, sizeof(pp), i1, sizeof(i1));
    if (ret != 0)
        goto out;

    /* partial block decrypt test */
    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsDecrypt(aes, buf, cipher, sizeof(pp), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(pp, buf, sizeof(pp))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    /* NIST decrypt test vector */
    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsDecrypt(aes, buf, c1, sizeof(c1), i1, sizeof(i1));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p1, buf, WC_AES_BLOCK_SIZE)) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    XMEMSET(buf, 0, AES_XTS_256_TEST_BUF_SIZ);
    ret = wc_AesXtsSetKeyNoInit(aes, k2, sizeof(k2), AES_DECRYPTION);
    if (ret != 0)
        goto out;
    ret = wc_AesXtsDecrypt(aes, buf, c2, sizeof(c2), i2, sizeof(i2));
    if (ret != 0)
        goto out;
    if (XMEMCMP(p2, buf, sizeof(p2))) {
        ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
        goto out;
    }

    {
    #define LARGE_XTS_SZ        1024
        int i;
        int j;
        int k;

        large_input = (byte *)XMALLOC(LARGE_XTS_SZ, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (large_input == NULL) {
            ret = MEMORY_E;
            goto out;
        }

        for (i = 0; i < (int)LARGE_XTS_SZ; i++)
            large_input[i] = (byte)i;

        /* first, encrypt block by block then decrypt with a one-shot call. */
        for (j = 16; j < (int)LARGE_XTS_SZ; j++) {
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsEncryptInit(aes, i1, sizeof(i1), &stream);
            if (ret != 0)
                goto out;
            for (k = 0; k < j; k += WC_AES_BLOCK_SIZE) {
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    ret = wc_AesXtsEncryptFinal(aes, large_input + k, large_input + k, j - k, &stream);
                else
                    ret = wc_AesXtsEncryptUpdate(aes, large_input + k, large_input + k, WC_AES_BLOCK_SIZE, &stream);
                if (ret != 0)
                    goto out;
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    break;
            }
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsDecrypt(aes, large_input, large_input, j, i1,
                sizeof(i1));
            if (ret != 0)
                goto out;
            for (i = 0; i < j; i++) {
                if (large_input[i] != (byte)i) {
                    ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
                    goto out;
                }
            }
        }

        /* second, encrypt with a one-shot call then decrypt block by block. */
        for (j = 16; j < (int)LARGE_XTS_SZ; j++) {
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_ENCRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsEncrypt(aes, large_input, large_input, j, i1,
                sizeof(i1));
            if (ret != 0)
                goto out;
            ret = wc_AesXtsSetKeyNoInit(aes, k1, sizeof(k1), AES_DECRYPTION);
            if (ret != 0)
                goto out;
            ret = wc_AesXtsDecryptInit(aes, i1, sizeof(i1), &stream);
            if (ret != 0)
                goto out;
            for (k = 0; k < j; k += WC_AES_BLOCK_SIZE) {
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    ret = wc_AesXtsDecryptFinal(aes, large_input + k, large_input + k, j - k, &stream);
                else
                    ret = wc_AesXtsDecryptUpdate(aes, large_input + k, large_input + k, WC_AES_BLOCK_SIZE, &stream);
                if (ret != 0)
                    goto out;
                if ((j - k) < WC_AES_BLOCK_SIZE*2)
                    break;
            }
            for (i = 0; i < j; i++) {
                if (large_input[i] != (byte)i) {
                    ret = LINUXKM_LKCAPI_AES_KAT_MISMATCH_E;
                    goto out;
                }
            }
        }
    }

    /* now the kernel crypto part */

    enc2 = XMALLOC(sizeof(p1), NULL, DYNAMIC_TYPE_AES);
    if (!enc2) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    dec2 = XMALLOC(sizeof(p1), NULL, DYNAMIC_TYPE_AES);
    if (!dec2) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    src = XMALLOC(sizeof(*src) * 2, NULL, DYNAMIC_TYPE_AES);
    if (! src) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    dst = XMALLOC(sizeof(*dst) * 2, NULL, DYNAMIC_TYPE_AES);
    if (! dst) {
        pr_err("error: malloc failed\n");
        ret = -ENOMEM;
        goto test_xts_end;
    }

    tfm = crypto_alloc_skcipher(WOLFKM_AESXTS_NAME, 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        pr_err("error: allocating AES skcipher algorithm %s failed: %d\n",
               WOLFKM_AESXTS_DRIVER, ret);
        tfm = NULL;
        goto test_xts_end;
    }

#ifndef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    {
        const char *driver_name = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
        if (strcmp(driver_name, WOLFKM_AESXTS_DRIVER)) {
            pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
                   WOLFKM_AESXTS_NAME, driver_name, WOLFKM_AESXTS_DRIVER);
            ret = -ENOENT;
            goto test_xts_end;
        }
    }
#endif

    ret = crypto_skcipher_ivsize(tfm);
    if (ret != sizeof(stream.tweak_block)) {
        pr_err("error: AES skcipher algorithm %s crypto_skcipher_ivsize()"
               " returned %d but expected %d\n",
               WOLFKM_AESXTS_DRIVER, ret, (int)sizeof(stream.tweak_block));
        ret = -EINVAL;
        goto test_xts_end;
    }

    ret = crypto_skcipher_setkey(tfm, k1, sizeof(k1));
    if (ret) {
        pr_err("error: crypto_skcipher_setkey for %s returned: %d\n",
               WOLFKM_AESXTS_NAME, ret);
        goto test_xts_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        ret = PTR_ERR(req);
        pr_err("error: allocating AES skcipher request %s failed: %d\n",
               WOLFKM_AESXTS_DRIVER, ret);
        req = NULL;
        goto test_xts_end;
    }

    memcpy(dec2, p1, sizeof(p1));
    memset(enc2, 0, sizeof(p1));

    sg_init_one(src, dec2, sizeof(p1));
    sg_init_one(dst, enc2, sizeof(p1));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(p1), stream.tweak_block);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(c1, enc2, sizeof(c1));
    if (ret) {
        pr_err("error: c1 and enc2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memset(dec2, 0, sizeof(p1));
    sg_init_one(src, enc2, sizeof(p1));
    sg_init_one(dst, dec2, sizeof(p1));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(p1), stream.tweak_block);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("ERROR: crypto_skcipher_decrypt returned %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(p1, dec2, sizeof(p1));
    if (ret) {
        pr_err("error: p1 and dec2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memcpy(dec2, pp, sizeof(pp));
    memset(enc2, 0, sizeof(pp));

    sg_init_one(src, dec2, sizeof(pp));
    sg_init_one(dst, enc2, sizeof(pp));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(pp), stream.tweak_block);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(cp, enc2, sizeof(cp));
    if (ret) {
        pr_err("error: cp and enc2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    memset(dec2, 0, sizeof(pp));
    sg_init_one(src, enc2, sizeof(pp));
    sg_init_one(dst, dec2, sizeof(pp));

    memcpy(stream.tweak_block, i1, sizeof(stream.tweak_block));
    skcipher_request_set_crypt(req, src, dst, sizeof(pp), stream.tweak_block);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("ERROR: crypto_skcipher_decrypt returned %d\n", ret);
        goto test_xts_end;
    }

    ret = XMEMCMP(pp, dec2, sizeof(pp));
    if (ret) {
        pr_err("error: pp and dec2 do not match: %d\n", ret);
        ret = -EINVAL;
        goto test_xts_end;
    }

    test_xts_end:

    XFREE(enc2, NULL, DYNAMIC_TYPE_AES);
    XFREE(dec2, NULL, DYNAMIC_TYPE_AES);
    XFREE(src, NULL, DYNAMIC_TYPE_AES);
    XFREE(dst, NULL, DYNAMIC_TYPE_AES);
    if (req)
        skcipher_request_free(req);
    if (tfm)
        crypto_free_skcipher(tfm);

  out:

    XFREE(large_input, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (aes_inited)
        wc_AesXtsFree(aes);

    XFREE(buf, NULL, DYNAMIC_TYPE_AES);
    XFREE(cipher, NULL, DYNAMIC_TYPE_AES);

    XFREE(aes, NULL, DYNAMIC_TYPE_AES);

#undef AES_XTS_256_TEST_BUF_SIZ

    return ret;
}
#endif /* WOLFSSL_AES_256 */

static int linuxkm_test_aesxts(void) {
    int ret;

    #ifdef WOLFSSL_AES_128
    ret = aes_xts_128_test();
    if (ret != 0) {
        pr_err("aes_xts_128_test() failed with retval %d.\n", ret);
        goto out;
    }
    #endif
    #ifdef WOLFSSL_AES_256
    ret = aes_xts_256_test();
    if (ret != 0) {
        pr_err("aes_xts_256_test() failed with retval %d.\n", ret);
        goto out;
    }
    #endif

out:

    return ret;
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESXTS */

#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR

static int linuxkm_test_aesctr(void) {
    wc_test_ret_t ret = aes_ctr_test();
    if (ret >= 0)
        return check_skcipher_driver_masking(NULL /* tfm */, WOLFKM_AESCTR_NAME, WOLFKM_AESCTR_DRIVER);
    else {
        wc_test_render_error_message("aes_ctr_test failed: ", ret);
        return WC_TEST_RET_DEC_EC(ret);
    }
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESCTR */

#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB

static int linuxkm_test_aesofb(void) {
    wc_test_ret_t ret = aesofb_test();
    if (ret >= 0)
        return check_skcipher_driver_masking(NULL /* tfm */, WOLFKM_AESOFB_NAME, WOLFKM_AESOFB_DRIVER);
    else {
        wc_test_render_error_message("aesofb_test failed: ", ret);
        return WC_TEST_RET_DEC_EC(ret);
    }
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESOFB */

#ifdef LINUXKM_LKCAPI_REGISTER_AESECB

static int linuxkm_test_aesecb(void) {
    wc_test_ret_t ret = aes_test();
    if (ret >= 0)
        return check_skcipher_driver_masking(NULL /* tfm */, WOLFKM_AESECB_NAME, WOLFKM_AESECB_DRIVER);
    else {
        wc_test_render_error_message("aes_test failed: ", ret);
        return WC_TEST_RET_DEC_EC(ret);
    }
}

#endif /* LINUXKM_LKCAPI_REGISTER_AESECB */

#endif /* LINUXKM_LKCAPI_REGISTER_AES */
