/* lkcapi_rsa_glue.c -- glue logic to register RSA wolfCrypt implementations
 * with the Linux Kernel Cryptosystem
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
    #error lkcapi_rsa_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if !defined(NO_RSA) && \
    (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
     defined(LINUXKM_LKCAPI_REGISTER_RSA))

#if defined(WOLFSSL_RSA_VERIFY_ONLY) || \
    defined(WOLFSSL_RSA_PUBLIC_ONLY)
    #error LINUXKM_LKCAPI_REGISTER_RSA and RSA_VERIFY_ONLY not supported
#endif /* WOLFSSL_RSA_VERIFY_ONLY || WOLFSSL_RSA_PUBLIC_ONLY */

#ifdef WC_RSA_NO_PADDING
    #define LINUXKM_DIRECT_RSA
#endif /* WC_RSA_NO_PADDING */

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define WOLFKM_RSA_NAME      ("rsa")
#define WOLFKM_RSA_DRIVER    ("rsa" WOLFKM_DRIVER_FIPS "-wolfcrypt")

#define WOLFKM_PKCS1_SHA256_NAME   ("pkcs1pad(rsa,sha256)")
#define WOLFKM_PKCS1_SHA256_DRIVER ("pkcs1pad(rsa" WOLFKM_DRIVER_FIPS \
                                    "-wolfcrypt,sha256)")

#define WOLFKM_PKCS1_SHA512_NAME   ("pkcs1pad(rsa,sha512)")
#define WOLFKM_PKCS1_SHA512_DRIVER ("pkcs1pad(rsa" WOLFKM_DRIVER_FIPS \
                                    "-wolfcrypt,sha512)")

#if defined(WOLFSSL_KEY_GEN)
    #if defined(LINUXKM_DIRECT_RSA)
        static int  linuxkm_test_rsa_driver(const char * driver, int nbits);
    #endif /* LINUXKM_DIRECT_RSA */
    static int  linuxkm_test_pkcs1_driver(const char * driver, int nbits,
                                          int hash_oid, word32 hash_len);
#endif /* WOLFSSL_KEY_GEN */

#if defined(LINUXKM_DIRECT_RSA)
    static int direct_rsa_loaded = 0;
#endif /* LINUXKM_DIRECT_RSA */
#ifndef NO_SHA256
    static int pkcs1_sha256_loaded = 0;
#endif /* !NO_SHA256 */
#ifdef WOLFSSL_SHA512
    static int pkcs1_sha512_loaded = 0;
#endif /* WOLFSSL_SHA512 */

struct km_rsa_ctx {
    WC_RNG       rng;            /* needed for pkcs1 padding, and blinding */
    RsaKey *     key;
    int          hash_oid;       /* hash_oid for wc_EncodeSignature */
    unsigned int digest_len;
    word32       key_len;
};

/* shared rsa callbacks */
static int          km_rsa_init(struct crypto_akcipher *tfm, int hash_oid);
static void         km_rsa_exit(struct crypto_akcipher *tfm);
static int          km_rsa_set_priv(struct crypto_akcipher *tfm,
                                     const void *key, unsigned int keylen);
static int          km_rsa_set_pub(struct crypto_akcipher *tfm,
                                    const void *key, unsigned int keylen);
static unsigned int km_rsa_max_size(struct crypto_akcipher *tfm);

#if defined(LINUXKM_DIRECT_RSA)
    /* direct rsa callbacks */
    static int          km_direct_rsa_init(struct crypto_akcipher *tfm);
    static int          km_direct_rsa_enc(struct akcipher_request *req);
    static int          km_direct_rsa_dec(struct akcipher_request *req);
#endif /* LINUXKM_DIRECT_RSA */

/* pkcs1 callbacks */
#ifndef NO_SHA256
    static int          km_pkcs1_sha256_init(struct crypto_akcipher *tfm);
#endif /* !NO_SHA256 */
#ifdef WOLFSSL_SHA512
    static int          km_pkcs1_sha512_init(struct crypto_akcipher *tfm);
#endif /* WOLFSSL_SHA512 */
#if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    static int          km_pkcs1_sign(struct akcipher_request *req);
    static int          km_pkcs1_verify(struct akcipher_request *req);
#endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
    static int          km_pkcs1_enc(struct akcipher_request *req);
    static int          km_pkcs1_dec(struct akcipher_request *req);
/* misc */
#if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    static int          get_hash_enc_len(int hash_oid);
#endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */

#if defined(LINUXKM_DIRECT_RSA)
static struct akcipher_alg direct_rsa = {
    .base.cra_name        = WOLFKM_RSA_NAME,
    .base.cra_driver_name = WOLFKM_RSA_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    .encrypt              = km_direct_rsa_enc,
    .decrypt              = km_direct_rsa_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_direct_rsa_init,
    .exit                 = km_rsa_exit,
};
#endif /* LINUXKM_DIRECT_RSA */

#ifndef NO_SHA256
static struct akcipher_alg pkcs1_sha256 = {
    .base.cra_name        = WOLFKM_PKCS1_SHA256_NAME,
    .base.cra_driver_name = WOLFKM_PKCS1_SHA256_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    .sign                 = km_pkcs1_sign,
    .verify               = km_pkcs1_verify,
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
    .encrypt              = km_pkcs1_enc,
    .decrypt              = km_pkcs1_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_pkcs1_sha256_init,
    .exit                 = km_rsa_exit,
};
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
static struct akcipher_alg pkcs1_sha512 = {
    .base.cra_name        = WOLFKM_PKCS1_SHA512_NAME,
    .base.cra_driver_name = WOLFKM_PKCS1_SHA512_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_rsa_ctx),
    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    .sign                 = km_pkcs1_sign,
    .verify               = km_pkcs1_verify,
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
    .encrypt              = km_pkcs1_enc,
    .decrypt              = km_pkcs1_dec,
    .set_priv_key         = km_rsa_set_priv,
    .set_pub_key          = km_rsa_set_pub,
    .max_size             = km_rsa_max_size,
    .init                 = km_pkcs1_sha512_init,
    .exit                 = km_rsa_exit,
};
#endif /* WOLFSSL_SHA512 */

static int km_rsa_init(struct crypto_akcipher *tfm, int hash_oid)
{
    struct km_rsa_ctx * ctx = NULL;
    int                 ret = 0;

    ctx = akcipher_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_rsa_ctx));

    ctx->key = (RsaKey *)malloc(sizeof(RsaKey));
    if (!ctx->key) {
        return -ENOMEM;
    }

    ret = wc_InitRng(&ctx->rng);
    if (ret) {
        pr_err("%s: init rng returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return -ENOMEM;
    }

    ret = wc_InitRsaKey(ctx->key, NULL);
    if (ret) {
        pr_err("%s: init rsa key returned: %d\n", WOLFKM_RSA_DRIVER, ret);
        return -ENOMEM;
    }

    #ifdef WC_RSA_BLINDING
    ret = wc_RsaSetRNG(ctx->key, &ctx->rng);
    if (ret) {
        return -ENOMEM;
    }
    #endif /* WC_RSA_BLINDING */

    ctx->hash_oid = hash_oid;

    switch (ctx->hash_oid) {
    case 0:
        ctx->digest_len = 0;
        break;
    #ifndef NO_SHA256
    case SHA256h:
        ctx->digest_len = WC_SHA256_DIGEST_SIZE;
        break;
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA512
    case SHA512h:
        ctx->digest_len = WC_SHA512_DIGEST_SIZE;
        break;
    #endif /* WOLFSSL_SHA512 */
    default:
        pr_err("%s: init: unhandled hash_oid: %d\n", WOLFKM_RSA_DRIVER,
               hash_oid);
        return -ENOMEM;
    }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_init: hash_oid %d\n", ctx->hash_oid);
    #endif /* WOLFKM_DEBUG_RSA */
    return 0;
}

#if defined(LINUXKM_DIRECT_RSA)
/*
 * RSA encrypt with public key.
 *
 * Requires that crypto_akcipher_set_pub_key has been called first.
 *
 * note: this matches behavior of kernel rsa-generic akcipher, which does
 * direct RSA without padding, and without requiring src_len matches RSA
 * key size.
 *
 * returns 0   on success
 * returns < 0 on error
 */
static int km_direct_rsa_enc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   out_len = 0;
    byte *                   dec = NULL;
    byte *                   enc = NULL;

    if (req->src == NULL || req->dst == NULL) {
        err = -EINVAL;
        goto rsa_enc_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (unlikely(ctx->key_len <= 0)) {
        err = -EINVAL;
        goto rsa_enc_out;
    }

    out_len = ctx->key_len;

    if (req->src_len > (unsigned int) ctx->key_len) {
        err = -EOVERFLOW;
        goto rsa_enc_out;
    }

    if (req->dst_len < (unsigned int) ctx->key_len) {
        req->dst_len = ctx->key_len;
        err = -EOVERFLOW;
        goto rsa_enc_out;
    }

    dec = malloc(req->src_len);
    if (unlikely(dec == NULL)) {
        err = -ENOMEM;
        goto rsa_enc_out;
    }

    enc = malloc(req->dst_len);
    if (unlikely(enc == NULL)) {
        err = -ENOMEM;
        goto rsa_enc_out;
    }

    /* copy req->src to dec */
    memset(dec, 0, req->src_len);
    memset(enc, 0, req->dst_len);
    scatterwalk_map_and_copy(dec, req->src, 0, req->src_len, 0);

    /* note: matching behavior of kernel rsa-generic. */
    err = wc_RsaFunction(dec, req->src_len, enc, &out_len,
                         RSA_PUBLIC_ENCRYPT, ctx->key, &ctx->rng);

    if (unlikely(err || (out_len != ctx->key_len))) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: direct rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, ctx->key_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto rsa_enc_out;
    }

    /* enc to req->dst */
    scatterwalk_map_and_copy(enc, req->dst, 0, ctx->key_len, 1);

    err = 0;
rsa_enc_out:
    if (enc != NULL) { free(enc); enc = NULL; }
    if (dec != NULL) { free(dec); dec = NULL; }
    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_direct_rsa_enc\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/*
 * RSA decrypt with private key.
 *
 * Requires that crypto_akcipher_set_priv_key has been called first.
 *
 * returns 0   on success
 * returns < 0 on error
 */
static int km_direct_rsa_dec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   out_len = 0;
    byte *                   enc = NULL;
    byte *                   dec = NULL;

    if (req->src == NULL || req->dst == NULL) {
        err = -EINVAL;
        goto rsa_dec_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (unlikely(ctx->key_len <= 0)) {
        err = -EINVAL;
        goto rsa_dec_out;
    }

    out_len = ctx->key_len;

    if (req->src_len != (unsigned int) ctx->key_len) {
        err = -EINVAL;
        goto rsa_dec_out;
    }

    if (req->dst_len <= 0 || req->dst_len > (unsigned int) ctx->key_len) {
        err = -EINVAL;
        goto rsa_dec_out;
    }

    enc = malloc(req->src_len);
    if (unlikely(enc == NULL)) {
        err = -ENOMEM;
        goto rsa_dec_out;
    }

    dec = malloc(req->dst_len);
    if (unlikely(dec == NULL)) {
        err = -ENOMEM;
        goto rsa_dec_out;
    }

    /* copy req->src to enc */
    memset(enc, 0, req->src_len);
    memset(dec, 0, req->dst_len);
    scatterwalk_map_and_copy(enc, req->src, 0, req->src_len, 0);

    err = wc_RsaDirect(enc, ctx->key_len, dec, &out_len,
                       ctx->key, RSA_PRIVATE_DECRYPT, &ctx->rng);

    if (unlikely(err != (int) ctx->key_len || ctx->key_len != out_len)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: rsa pub enc returned: %d, %d, %d\n",
               WOLFKM_RSA_DRIVER, err, out_len, ctx->key_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto rsa_dec_out;
    }

    if (out_len > req->dst_len) {
        err = -EOVERFLOW;
        goto rsa_dec_out;
    }

    /* copy dec to req->dst */
    scatterwalk_map_and_copy(dec, req->dst, 0, ctx->key_len, 1);

    err = 0;
rsa_dec_out:
    if (enc != NULL) { free(enc); enc = NULL; }
    if (dec != NULL) { free(dec); dec = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_direct_rsa_dec\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}
#endif /* LINUXKM_DIRECT_RSA */

/*
 * Decodes and sets the RSA private key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded private key and parameters
 * param keylen  key length
 */
static int km_rsa_set_priv(struct crypto_akcipher *tfm, const void *key,
                            unsigned int keylen)
{
    int                 err = 0;
    struct km_rsa_ctx * ctx = NULL;
    word32              idx = 0;
    int                 key_len = 0;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len) {
        /* Free old key. */
        ctx->key_len = 0;
        wc_FreeRsaKey(ctx->key);

        err = wc_InitRsaKey(ctx->key, NULL);
        if (unlikely(err)) {
            return -ENOMEM;
        }

        #ifdef WC_RSA_BLINDING
        err = wc_RsaSetRNG(ctx->key, &ctx->rng);
        if (unlikely(err)) {
            return -ENOMEM;
        }
        #endif /* WC_RSA_BLINDING */
    }

    err = wc_RsaPrivateKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        if (!disable_setkey_warnings) {
            pr_err("%s: wc_RsaPrivateKeyDecode failed: %d\n",
                   WOLFKM_RSA_DRIVER, err);
        }
        return -EINVAL;
    }

    key_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(key_len <= 0)) {
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        return -EINVAL;
    }

    ctx->key_len = (word32) key_len;

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_set_priv\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/*
 * Decodes and sets the RSA pub key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     BER encoded pub key and parameters
 * param keylen  key length
 */
static int km_rsa_set_pub(struct crypto_akcipher *tfm, const void *key,
                           unsigned int keylen)
{
    int                 err = 0;
    struct km_rsa_ctx * ctx = NULL;
    word32              idx = 0;
    int                 key_len = 0;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len) {
        /* Free old key. */
        ctx->key_len = 0;
        wc_FreeRsaKey(ctx->key);

        err = wc_InitRsaKey(ctx->key, NULL);
        if (unlikely(err)) {
            return -ENOMEM;
        }
    }

    err = wc_RsaPublicKeyDecode(key, &idx, ctx->key, keylen);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("%s: wc_RsaPublicKeyDecode failed: %d\n",
               WOLFKM_RSA_DRIVER, err);
        #endif /* WOLFKM_DEBUG_RSA */
        return -EINVAL;
    }

    key_len = wc_RsaEncryptSize(ctx->key);
    if (unlikely(key_len <= 0)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: rsa encrypt size returned: %d\n",
               WOLFKM_RSA_DRIVER, key_len);
        #endif /* WOLFKM_DEBUG_RSA */
        return -EINVAL;
    }

    ctx->key_len = (word32) key_len;

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_set_pub\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/*
 * Returns dest buffer size required for key.
 */
static unsigned int km_rsa_max_size(struct crypto_akcipher *tfm)
{
    struct km_rsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    return (unsigned int) ctx->key_len;
}

#if defined(LINUXKM_DIRECT_RSA)
static int km_direct_rsa_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, 0);
}
#endif /* LINUXKM_DIRECT_RSA */

static void km_rsa_exit(struct crypto_akcipher *tfm)
{
    struct km_rsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key) {
        wc_FreeRsaKey(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    wc_FreeRng(&ctx->rng);

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_rsa_exit\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return;
}

#ifndef NO_SHA256
static int km_pkcs1_sha256_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, SHA256h);
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
static int km_pkcs1_sha512_init(struct crypto_akcipher *tfm)
{
    return km_rsa_init(tfm, SHA512h);
}
#endif /* WOLFSSL_SHA512 */

#if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
static int km_pkcs1_sign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   sig_len = 0;
    word32                   enc_len = 0;
    int                      hash_enc_len = 0;
    byte *                   msg = NULL;
    byte *                   sig = NULL;

    if (req->src == NULL || req->dst == NULL) {
        err = -EINVAL;
        goto pkcs1_sign_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len <= 0 || ctx->digest_len <= 0) {
        /* invalid key state */
        err = -EINVAL;
        goto pkcs1_sign_out;
    }

    hash_enc_len = get_hash_enc_len(ctx->hash_oid);
    if (hash_enc_len <= 0) {
        err = -EINVAL;
        goto pkcs1_sign_out;
    }

    if (req->src_len + hash_enc_len + RSA_MIN_PAD_SZ > ctx->key_len) {
        err = -EOVERFLOW;
        goto pkcs1_sign_out;
    }

    if (req->dst_len < ctx->key_len) {
        err = -EOVERFLOW;
        goto pkcs1_sign_out;
    }

    /* allocate extra space for encoding. */
    msg = malloc(ctx->key_len);
    if (unlikely(msg == NULL)) {
        err = -ENOMEM;
        goto pkcs1_sign_out;
    }

    sig = malloc(ctx->key_len);
    if (unlikely(sig == NULL)) {
        err = -ENOMEM;
        goto pkcs1_sign_out;
    }

    /* copy req->src to msg */
    memset(msg, 0, ctx->key_len);
    memset(sig, 0, ctx->key_len);
    scatterwalk_map_and_copy(msg, req->src, 0, req->src_len, 0);

    /* encode message with hash oid. */
    enc_len = wc_EncodeSignature(msg, msg, req->src_len, ctx->hash_oid);
    if (unlikely(enc_len <= 0)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: wc_EncodeSignature returned: %d\n",
               WOLFKM_RSA_DRIVER, enc_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto pkcs1_sign_out;
    }

    /* sign encoded message. */
    sig_len = wc_RsaSSL_Sign(msg, enc_len, sig,
                             ctx->key_len, ctx->key, &ctx->rng);
    if (unlikely(sig_len != ctx->key_len)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: wc_RsaSSL_Sign returned: %d\n",
               WOLFKM_RSA_DRIVER, sig_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto pkcs1_sign_out;
    }

    /* copy sig to req->dst */
    scatterwalk_map_and_copy(sig, req->dst, 0, ctx->key_len, 1);

    err = 0;
pkcs1_sign_out:
    if (msg != NULL) { free(msg); msg = NULL; }
    if (sig != NULL) { free(sig); sig = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_sign\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

/*
 * Verify a pkcs1 encoded signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature
 *   - dst_len: digest
 *
 * dst should be null.
 * See kernel:
 *   - include/crypto/akcipher.h
 */
static int km_pkcs1_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   sig_len = 0;
    word32                   dec_len = 0;
    word32                   msg_len = 0;
    word32                   enc_msg_len = 0;
    int                      hash_enc_len = 0;
    int                      n_diff = 0;
    byte *                   sig = NULL;
    byte *                   msg = NULL;

    if (req->src == NULL || req->dst != NULL) {
        err = -EINVAL;
        goto pkcs1_verify_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    msg_len = req->dst_len;
    sig_len = req->src_len;

    if (ctx->key_len <= 0 || ctx->digest_len <= 0) {
        /* invalid key state */
        err = -EINVAL;
        goto pkcs1_verify_out;
    }

    hash_enc_len = get_hash_enc_len(ctx->hash_oid);
    if (hash_enc_len <= 0) {
        err = -EINVAL;
        goto pkcs1_verify_out;
    }

    if (msg_len != ctx->digest_len || sig_len != ctx->key_len) {
        /* invalid src or dst args */
        err = -EINVAL;
        goto pkcs1_verify_out;
    }

    sig = malloc(ctx->key_len);
    if (unlikely(sig == NULL)) {
        err = -ENOMEM;
        goto pkcs1_verify_out;
    }

    /* allocate extra space for encoding. */
    msg = malloc(ctx->key_len);
    if (unlikely(msg == NULL)) {
        err = -ENOMEM;
        goto pkcs1_verify_out;
    }

    /* copy sig from req->src to sig */
    memset(sig, 0, ctx->key_len);
    memset(msg, 0, ctx->key_len);
    scatterwalk_map_and_copy(sig, req->src, 0, sig_len, 0);

    /* verify encoded message. */
    dec_len = wc_RsaSSL_Verify(sig, sig_len, msg, sig_len, ctx->key);
    if (unlikely(dec_len <= 0)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: wc_RsaSSL_Verify returned: %d\n",
               WOLFKM_RSA_DRIVER, dec_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EBADMSG;
        goto pkcs1_verify_out;
    }

    /* reuse sig array for digest comparison */
    memset(sig, 0, ctx->key_len);
    scatterwalk_map_and_copy(sig, req->src, sig_len, msg_len, 0);

    /* encode digest with hash oid. */
    enc_msg_len = wc_EncodeSignature(sig, sig, msg_len, ctx->hash_oid);
    if (unlikely(enc_msg_len <= 0 || enc_msg_len != dec_len)) {
        err = -EINVAL;
        goto pkcs1_verify_out;
    }

    n_diff = memcmp(sig, msg, dec_len);
    if (unlikely(n_diff != 0)) {
        err = -EKEYREJECTED;
        goto pkcs1_verify_out;
    }

    err = 0;
pkcs1_verify_out:
    if (msg != NULL) { free(msg); msg = NULL; }
    if (sig != NULL) { free(sig); sig = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_verify\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}
#endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */

static int km_pkcs1_enc(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    byte *                   dec = NULL;
    byte *                   enc = NULL;

    if (req->src == NULL || req->dst == NULL) {
        err = -EINVAL;
        goto pkcs1_enc_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len <= 0 || ctx->digest_len <= 0) {
        /* invalid key state */
        err = -EINVAL;
        goto pkcs1_enc_out;
    }

    if (req->src_len + RSA_MIN_PAD_SZ > ctx->key_len) {
        err = -EOVERFLOW;
        goto pkcs1_enc_out;
    }

    if (req->dst_len < ctx->key_len) {
        err = -EOVERFLOW;
        goto pkcs1_enc_out;
    }

    dec = malloc(req->src_len);
    if (unlikely(dec == NULL)) {
        err = -ENOMEM;
        goto pkcs1_enc_out;
    }

    enc = malloc(req->dst_len);
    if (unlikely(enc == NULL)) {
        err = -ENOMEM;
        goto pkcs1_enc_out;
    }

    /* copy req->src to dec */
    memset(dec, 0, req->src_len);
    memset(enc, 0, req->dst_len);
    scatterwalk_map_and_copy(dec, req->src, 0, req->src_len, 0);

    err = wc_RsaPublicEncrypt(dec, req->src_len, enc, ctx->key_len,
                              ctx->key, &ctx->rng);

    if (unlikely(err != (int) ctx->key_len)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: rsa pub enc returned: %d, %d\n",
               WOLFKM_RSA_DRIVER, err, ctx->key_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto pkcs1_enc_out;
    }

    /* copy enc to req->dst */
    scatterwalk_map_and_copy(enc, req->dst, 0, ctx->key_len, 1);

    err = 0;
pkcs1_enc_out:
    if (enc != NULL) { free(enc); enc = NULL; }
    if (dec != NULL) { free(dec); dec = NULL; }
    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_enc\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

static int km_pkcs1_dec(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_rsa_ctx *      ctx = NULL;
    int                      err = 0;
    word32                   dec_len = 0;
    byte *                   enc = NULL;
    byte *                   dec = NULL;

    if (req->src == NULL || req->dst == NULL) {
        err = -EINVAL;
        goto pkcs1_dec_out;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key_len <= 0) {
        err = -EINVAL;
        goto pkcs1_dec_out;
    }

    if (req->src_len != ctx->key_len) {
        err = -EINVAL;
        goto pkcs1_dec_out;
    }

    if (req->dst_len <= 0 || req->dst_len > (unsigned int) ctx->key_len) {
        err = -EINVAL;
        goto pkcs1_dec_out;
    }

    enc = malloc(req->src_len);
    if (unlikely(enc == NULL)) {
        err = -ENOMEM;
        goto pkcs1_dec_out;
    }

    dec = malloc(req->dst_len);
    if (unlikely(dec == NULL)) {
        err = -ENOMEM;
        goto pkcs1_dec_out;
    }

    /* copy req->src to enc */
    memset(enc, 0, req->src_len);
    memset(dec, 0, req->dst_len);
    scatterwalk_map_and_copy(enc, req->src, 0, req->src_len, 0);

    dec_len = wc_RsaPrivateDecrypt(enc, ctx->key_len, dec, req->dst_len,
                                   ctx->key);

    if (unlikely(dec_len <= 0 || dec_len > ctx->key_len)) {
        #ifdef WOLFKM_DEBUG_RSA
        pr_err("error: %s: rsa private decrypt returned: %d, %d\n",
               WOLFKM_RSA_DRIVER, dec_len, ctx->key_len);
        #endif /* WOLFKM_DEBUG_RSA */
        err = -EINVAL;
        goto pkcs1_dec_out;
    }

    if (dec_len > req->dst_len) {
        err = -EOVERFLOW;
        goto pkcs1_dec_out;
    }

    /* copy dec to req->dst */
    scatterwalk_map_and_copy(dec, req->dst, 0, dec_len, 1);

    err = 0;
pkcs1_dec_out:
    if (enc != NULL) { free(enc); enc = NULL; }
    if (dec != NULL) { free(dec); dec = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: exiting km_pkcs1_dec\n");
    #endif /* WOLFKM_DEBUG_RSA */
    return err;
}

#if defined(LINUXKM_DIRECT_RSA) && defined(WC_RSA_NO_PADDING)
/*
 * Tests implemented below.
 */
static int linuxkm_test_rsa(void)
{
    int rc = 0;
    rc = rsa_no_pad_test();
    if (rc != 0) {
        pr_err("rsa_no_pad_test() failed with retval %d.\n", rc);
        return rc;
    }

    #ifdef WOLFSSL_KEY_GEN
    /* test wolfcrypt RSA API vs wolfkm RSA driver. */
    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 2048);
    if (rc) { return rc; }

    #ifdef WOLFKM_DEBUG_RSA
    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 3072);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver(WOLFKM_RSA_DRIVER, 4096);
    if (rc) { return rc; }


    /* repeat test against stock linux RSA akcipher. */
    rc = linuxkm_test_rsa_driver("rsa-generic", 2048);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver("rsa-generic", 3072);
    if (rc) { return rc; }

    rc = linuxkm_test_rsa_driver("rsa-generic", 4096);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}
#endif /* LINUXKM_DIRECT_RSA */

#ifndef NO_SHA256
static int linuxkm_test_pkcs1_sha256(void)
{
    int rc = 0;

    #ifdef WOLFSSL_KEY_GEN
    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA256_DRIVER, 2048,
                                   SHA256h, 32);
    if (rc) { return rc; }

    #ifdef WOLFKM_DEBUG_RSA
    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA256_DRIVER, 3072,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA256_DRIVER, 4096,
                                   SHA256h, 32);
    if (rc) { return rc; }

    /* repeat test against stock linux pkcs1pad. */
    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 2048,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 3072,
                                   SHA256h, 32);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha256)", 4096,
                                   SHA256h, 32);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA512
static int linuxkm_test_pkcs1_sha512(void)
{
    int rc = 0;

    #ifdef WOLFSSL_KEY_GEN
    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA512_DRIVER, 2048,
                                   SHA512h, 64);
    if (rc) { return rc; }

    #ifdef WOLFKM_DEBUG_RSA
    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA512_DRIVER, 3072,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver(WOLFKM_PKCS1_SHA512_DRIVER, 4096,
                                   SHA512h, 64);
    if (rc) { return rc; }

    /* repeat test against stock linux pkcs1pad. */
    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 2048,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 3072,
                                   SHA512h, 64);
    if (rc) { return rc; }

    rc = linuxkm_test_pkcs1_driver("pkcs1pad(rsa-generic,sha512)", 4096,
                                   SHA512h, 64);
    if (rc) { return rc; }
    #endif /* WOLFKM_DEBUG_RSA */
    #endif /* WOLFSSL_KEY_GEN */

    return rc;
}
#endif /* WOLFSSL_SHA512 */

#if defined(LINUXKM_DIRECT_RSA) && defined(WOLFSSL_KEY_GEN)
/*
 * Test linux kernel crypto driver:
 *   1. generate RSA key with wolfcrypt.
 *   2. sanity check wolfcrypt encrypt + decrypt.
 *   3. crypto_alloc_akcipher(driver)
 *   4. export wolfcrypt RSA der pub/priv, load to akcipher tfm with
 *      crypto_akcipher_set_pub_key, crypto_akcipher_set_priv_key.
 *   5. test: kernel public encrypt + wolfcrypt private decrypt
 *   6. test: wolfcrypt public encrypt + kernel private decrypt
 */
static int linuxkm_test_rsa_driver(const char * driver, int nbits)
{
    int                       test_rc = -1;
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    RsaKey *                  key = NULL;
    WC_RNG                    rng;
    byte *                    priv = NULL; /* priv der */
    word32                    priv_len = 0;
    byte *                    pub = NULL; /* pub der */
    word32                    pub_len = 0;
    byte                      init_rng = 0;
    byte                      init_key = 0;
    static const byte         p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte *                    enc = NULL;
    byte *                    dec = NULL; /* wc decrypt */
    byte *                    plaintext = NULL; /* km decrypt */
    word32                    key_len = 0;
    word32                    out_len = 0;
    int                       enc_ret = 0;
    int                       dec_ret = 0;
    int                       n_diff = 0;
    struct scatterlist        src, dst;
    size_t                    i = 0;

    key = (RsaKey*)malloc(sizeof(RsaKey));
    if (key == NULL) {
        pr_err("error: allocating key(%zu) failed\n", sizeof(RsaKey));
        goto test_rsa_end;
    }

    memset(&rng, 0, sizeof(rng));
    memset(key, 0, sizeof(RsaKey));

    ret = wc_InitRng(&rng);
    if (ret) {
        pr_err("error: init rng returned: %d\n", ret);
        goto test_rsa_end;
    }
    init_rng = 1;

    ret = wc_InitRsaKey(key, NULL);
    if (ret) {
        pr_err("error: init rsa key returned: %d\n", ret);
        goto test_rsa_end;
    }
    init_key = 1;

    #ifdef WC_RSA_BLINDING
    ret = wc_RsaSetRNG(key, &rng);
    if (ret) {
        pr_err("error: rsa set rng returned: %d\n", ret);
        goto test_rsa_end;
    }
    #endif /* WC_RSA_BLINDING */

    ret = wc_MakeRsaKey(key, nbits, WC_RSA_EXPONENT, &rng);
    if (ret) {
        pr_err("error: make rsa key returned: %d\n", ret);
        goto test_rsa_end;
    }

    key_len = wc_RsaEncryptSize(key);
    if (key_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", key_len);
        goto test_rsa_end;
    }

    /**
     * Allocate buffers based on the RsaKey key_len.
     *
     * Add +1 for dec and plaintext arrays to printf nicely.
     * */
    enc = (byte*)malloc(key_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    dec = (byte*)malloc(key_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    plaintext = (byte*)malloc(key_len + 1);
    if (plaintext == NULL) {
        pr_err("error: allocating plaintext(%d) failed\n", key_len);
        goto test_rsa_end;
    }

    memset(enc,  0, key_len);
    memset(dec,  0, key_len + 1);
    memset(plaintext, 0, key_len + 1);

    /* Fill up dec and plaintext with plaintext reference. */
    for (i = 0; i < key_len / sizeof(p_vector); ++i) {
        memcpy(dec  + i * sizeof(p_vector), p_vector, sizeof(p_vector));
        memcpy(plaintext + i * sizeof(p_vector), p_vector, sizeof(p_vector));
    }

    /**
     * Sanity test: first encrypt and decrypt with direct wolfcrypt API.
     * */
    out_len = key_len;
    enc_ret = wc_RsaDirect(dec, key_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);
    if (enc_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa pub enc returned: %d, %d\n", enc_ret, out_len);
        ret = -1;
        goto test_rsa_end;
    }

    memset(dec, 0, key_len);
    dec_ret = wc_RsaDirect(enc, key_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);
    if (dec_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    /* dec and plaintext should match now. */
    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    /**
     * Now export Rsa Der to pub and priv.
     * */
    priv_len = wc_RsaKeyToDer(key, NULL, 0);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_rsa_end;
    }

    priv = (byte*)malloc(priv_len);
    if (priv == NULL) {
        pr_err("error: allocating priv(%d) failed\n", priv_len);
        goto test_rsa_end;
    }

    memset(priv, 0, priv_len);

    priv_len = wc_RsaKeyToDer(key, priv, priv_len);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_rsa_end;
    }

    /* get rsa pub der */
    pub_len = wc_RsaKeyToPublicDer(key, NULL, 0);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_rsa_end;
    }

    pub = (byte*)malloc(pub_len);
    if (pub == NULL) {
        pr_err("error: allocating pub(%d) failed\n", pub_len);
        goto test_rsa_end;
    }

    memset(pub, 0, pub_len);

    pub_len = wc_RsaKeyToPublicDer(key, pub, pub_len);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_rsa_end;
    }

    /**
     * Now allocate the akcipher transform, and set up
     * the akcipher request.
     * */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        goto test_rsa_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_rsa_end;
    }

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub + 24, pub_len - 24);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_rsa_end;
        }
    }

    /* kernel module public encrypt */
    sg_init_one(&src, dec, key_len);
    sg_init_one(&dst, enc, key_len);

    akcipher_request_set_crypt(req, &src, &dst, key_len, key_len);

    ret = crypto_akcipher_encrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_encrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    /* wolfcrypt private decrypt */
    memset(dec, 0, key_len + 1);
    dec_ret = wc_RsaDirect(enc, key_len, dec, &out_len, key,
                           RSA_PRIVATE_DECRYPT, &rng);

    if (dec_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa priv dec returned: %d, %d\n", dec_ret, out_len);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    /* wolfcrypt public encrypt */
    enc_ret = wc_RsaDirect(dec, key_len, enc, &out_len, key,
                           RSA_PUBLIC_ENCRYPT, &rng);

    if (enc_ret != (int) key_len || key_len != out_len) {
        pr_err("error: rsa pub enc returned: %d, %d\n", enc_ret, out_len);
        ret = -1;
        goto test_rsa_end;
    }

    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_rsa_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_rsa_end;
        }
    }

    /* kernel module decrypt with rsa private key */
    sg_init_one(&src, enc, key_len);
    sg_init_one(&dst, dec, key_len);

    akcipher_request_set_crypt(req, &src, &dst, key_len, key_len);

    memset(dec, 0, key_len);
    ret = crypto_akcipher_decrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_decrypt returned: %d\n", ret);
        goto test_rsa_end;
    }

    n_diff = memcmp(dec, plaintext, key_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_rsa_end;
    }

    test_rc = 0;

test_rsa_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }

    if (pub) { free(pub); pub = NULL; }
    if (priv) { free(priv); priv = NULL; }

    if (plaintext) { free(plaintext); plaintext = NULL; }
    if (dec) { free(dec); dec = NULL; }
    if (enc) { free(enc); enc = NULL; }

    if (init_key) { wc_FreeRsaKey(key); init_key = 0; }
    if (init_rng) { wc_FreeRng(&rng); init_rng = 0; }

    if (key) { free(key); key = NULL; }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: %s, %d, %d: self test returned: %d\n", driver,
            nbits, key_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}
#endif /* LINUXKM_DIRECT_RSA */

#if (!defined(NO_SHA256) || defined(WOLFSSL_SHA512)) && \
    defined(WOLFSSL_KEY_GEN)
static int linuxkm_test_pkcs1_driver(const char * driver, int nbits,
                                     int hash_oid, word32 hash_len)
{
    int                       test_rc = -1;
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    RsaKey *                  key = NULL;
    WC_RNG                    rng;
    byte *                    priv = NULL; /* priv der */
    word32                    priv_len = 0;
    byte *                    pub = NULL; /* pub der */
    word32                    pub_len = 0;
    byte                      init_rng = 0;
    byte                      init_key = 0;
    static const byte         p_vector[] =
    /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte *                    hash = NULL;
    byte *                    sig = NULL;
    byte *                    km_sig = NULL;
    byte *                    dec = NULL;
    byte *                    enc = NULL;
    byte *                    dec2 = NULL;
    byte *                    enc2 = NULL;
    word32                    key_len = 0;
    word32                    sig_len = 0;
    word32                    enc_len = 0;
    struct scatterlist        src, dst;
    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    struct scatterlist        src_tab[2];
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
    int                       n_diff = 0;

    hash = malloc(WC_SHA512_DIGEST_SIZE);
    if (! hash) {
        pr_err("error: allocating hash buffer failed.\n");
        goto test_pkcs1_end;
    }

    /* hash the test msg with hash algo. */
    ret = wc_Hash(wc_OidGetHash(hash_oid), p_vector, sizeof(p_vector),
                  hash, hash_len);
    if (ret) {
        pr_err("error: wc_Hash returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    key = (RsaKey*)malloc(sizeof(RsaKey));
    if (key == NULL) {
        pr_err("error: allocating key(%zu) failed\n", sizeof(RsaKey));
        goto test_pkcs1_end;
    }

    memset(&rng, 0, sizeof(rng));
    memset(key, 0, sizeof(RsaKey));

    ret = wc_InitRng(&rng);
    if (ret) {
        pr_err("error: init rng returned: %d\n", ret);
        goto test_pkcs1_end;
    }
    init_rng = 1;

    ret = wc_InitRsaKey(key, NULL);
    if (ret) {
        pr_err("error: init rsa key returned: %d\n", ret);
        goto test_pkcs1_end;
    }
    init_key = 1;

    #ifdef WC_RSA_BLINDING
    ret = wc_RsaSetRNG(key, &rng);
    if (ret) {
        pr_err("error: rsa set rng returned: %d\n", ret);
        goto test_pkcs1_end;
    }
    #endif /* WC_RSA_BLINDING */

    ret = wc_MakeRsaKey(key, nbits, WC_RSA_EXPONENT, &rng);
    if (ret) {
        pr_err("error: make rsa key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    key_len = wc_RsaEncryptSize(key);
    if (key_len <= 0) {
        pr_err("error: rsa encrypt size returned: %d\n", key_len);
        goto test_pkcs1_end;
    }

    sig = (byte*)malloc(key_len);
    if (sig == NULL) {
        pr_err("error: allocating sig(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(sig, 0, key_len);

    km_sig = (byte*)malloc(key_len);
    if (km_sig == NULL) {
        pr_err("error: allocating km_sig(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(km_sig, 0, key_len);

    enc = (byte*)malloc(key_len);
    if (enc == NULL) {
        pr_err("error: allocating enc(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(enc, 0, key_len);

    dec = (byte*)malloc(key_len + 1);
    if (dec == NULL) {
        pr_err("error: allocating dec(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(dec, 0, key_len + 1);

    enc2 = (byte*)malloc(key_len);
    if (enc2 == NULL) {
        pr_err("error: allocating enc2(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(enc2, 0, key_len);

    dec2 = (byte*)malloc(key_len + 1);
    if (dec2 == NULL) {
        pr_err("error: allocating dec2(%d) failed\n", key_len);
        goto test_pkcs1_end;
    }
    memset(dec2, 0, key_len + 1);

    /**
     * Now export Rsa Der to pub and priv.
     * */
    priv_len = wc_RsaKeyToDer(key, NULL, 0);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_pkcs1_end;
    }

    priv = (byte*)malloc(priv_len);
    if (priv == NULL) {
        pr_err("error: allocating priv(%d) failed\n", priv_len);
        goto test_pkcs1_end;
    }

    memset(priv, 0, priv_len);

    priv_len = wc_RsaKeyToDer(key, priv, priv_len);
    if (priv_len <= 0) {
        pr_err("error: rsa priv to der returned: %d\n", priv_len);
        goto test_pkcs1_end;
    }

    /* get rsa pub der */
    pub_len = wc_RsaKeyToPublicDer(key, NULL, 0);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_pkcs1_end;
    }

    pub = (byte*)malloc(pub_len);
    if (pub == NULL) {
        pr_err("error: allocating pub(%d) failed\n", pub_len);
        goto test_pkcs1_end;
    }

    memset(pub, 0, pub_len);

    pub_len = wc_RsaKeyToPublicDer(key, pub, pub_len);
    if (pub_len <= 0) {
        pr_err("error: rsa pub to der returned: %d\n", pub_len);
        goto test_pkcs1_end;
    }

    /**
     * Sanity test: first sign and verify with direct wolfcrypt API.
     * */

    /* encode the hash. */
    enc_len = wc_EncodeSignature(enc, hash, hash_len, hash_oid);
    if (enc_len <= 0) {
        pr_err("error: wc_EncodeSignature returned: %d\n", enc_len);
        goto test_pkcs1_end;
    }

    sig_len = wc_RsaSSL_Sign(enc, enc_len, sig, key_len, key, &rng);
    if (sig_len <= 0) {
        pr_err("error: wc_RsaSSL_Sign returned: %d\n", sig_len);
        goto test_pkcs1_end;
    }

    memset(dec, 0, key_len + 1);
    ret = wc_RsaSSL_Verify(sig, key_len, dec, enc_len, key);
    if (ret <= 0 || ret != (int) enc_len) {
        pr_err("error: wc_RsaSSL_Verify returned %d, expected %d\n" , ret,
               enc_len);
        goto test_pkcs1_end;
    }

    /* dec and enc should match now. */
    n_diff = memcmp(dec, enc, enc_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    /**
     * Allocate the akcipher transform, and set up
     * the akcipher request.
     * */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        goto test_pkcs1_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_pkcs1_end;
    }

    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
    /**
     * pkcs1 sign and verify test
     * */
    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_pkcs1_end;
        }
    }

    sg_init_one(&src, hash, hash_len);
    sg_init_one(&dst, km_sig, key_len);
    memset(km_sig, 0, key_len);

    akcipher_request_set_crypt(req, &src, &dst, hash_len, key_len);

    ret = crypto_akcipher_sign(req);
    if (ret) {
        pr_err("error: crypto_akcipher_sign returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub + 24, pub_len - 24);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != key_len) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d, expected %d\n", maxsize, key_len);
            goto test_pkcs1_end;
        }
    }

    /**
     * Set sig as src, and null as dst.
     * src_tab is:
     *   src_tab[0]: signature
     *   src_tab[1]: message (digest)
     *
     * src_len is sig size plus digest size. */
    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], km_sig, key_len);
    sg_set_buf(&src_tab[1], hash, hash_len);

    akcipher_request_set_crypt(req, src_tab, NULL, key_len,
                               hash_len);

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    memset(dec, 0, key_len + 1);
    ret = wc_RsaSSL_Verify(km_sig, key_len, dec, key_len, key);
    if (ret <= 0) {
        pr_err("error: wc_RsaSSL_Verify returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    n_diff = memcmp(km_sig, sig, sig_len);
    if (n_diff) {
        pr_err("error: km-sig doesn't match sig: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    /* dec and enc should match now. */
    n_diff = memcmp(dec, enc, enc_len);
    if (n_diff) {
        pr_err("error: decrypt doesn't match plain: %d\n", n_diff);
        goto test_pkcs1_end;
    }
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */

    /**
     * pkcs1 encrypt and ecrypt test
     * */
    memset(enc, 0, key_len);
    memset(enc2, 0, key_len);
    memset(dec, 0, key_len);
    memset(dec2, 0, key_len);

    memcpy(dec, p_vector, sizeof(p_vector));
    memcpy(dec2, p_vector, sizeof(p_vector));

    sg_init_one(&src, dec, sizeof(p_vector));
    sg_init_one(&dst, enc, key_len);

    akcipher_request_set_crypt(req, &src, &dst, sizeof(p_vector), key_len);

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub + 24, pub_len - 24);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    ret = crypto_akcipher_encrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_encrypt returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    ret = wc_RsaPublicEncrypt(dec2, sizeof(p_vector), enc2,
                              key_len, key, &rng);

    if (unlikely(ret != (int) key_len)) {
        pr_err("error: wc_RsaPublicEncrypt returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    memset(dec, 0, key_len);
    memset(dec2, 0, key_len);

    sg_init_one(&src, enc, key_len);
    sg_init_one(&dst, dec, sizeof(p_vector));

    akcipher_request_set_crypt(req, &src, &dst, key_len, sizeof(p_vector));

    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    ret = crypto_akcipher_decrypt(req);
    if (ret) {
        pr_err("error: crypto_akcipher_decrypt returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    ret = wc_RsaPrivateDecrypt(enc2, key_len, dec2,
                               sizeof(p_vector), key);
    if (ret != (int) sizeof(p_vector)) {
        pr_err("error: wc_RsaPrivateDecrypt returned: %d\n", ret);
        goto test_pkcs1_end;
    }

    n_diff = memcmp(dec, dec2, sizeof(p_vector));
    if (n_diff) {
        pr_err("error: decrypt don't match: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    n_diff = memcmp(dec, p_vector, sizeof(p_vector));
    if (n_diff) {
        pr_err("error: decrypt doesn't match plaintext: %d\n", n_diff);
        goto test_pkcs1_end;
    }

    test_rc = 0;
test_pkcs1_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }

    if (priv) { free(priv); priv = NULL; }
    if (pub) { free(pub); pub = NULL; }

    if (enc2) { free(enc2); enc2 = NULL; }
    if (dec2) { free(dec2); dec2 = NULL; }
    if (enc) { free(enc); enc = NULL; }
    if (dec) { free(dec); dec = NULL; }

    if (km_sig) { free(km_sig); km_sig = NULL; }
    if (sig) { free(sig); sig = NULL; }

    if (init_rng) { wc_FreeRng(&rng); init_rng = 0; }
    if (init_key) { wc_FreeRsaKey(key); init_key = 0; }

    if (key) { free(key); key = NULL; }

    if (hash) { free(hash); }

    #ifdef WOLFKM_DEBUG_RSA
    pr_info("info: %s, %d, %d: self test returned: %d\n", driver,
            nbits, key_len, ret);
    #endif /* WOLFKM_DEBUG_RSA */

    return test_rc;
}
#endif /* (!NO_SHA256 || WOLFSSL_SHA512) && WOLFSSL_KEY_GEN */

/*
 * returns the additional encoding length for given hash oid.
 */
#if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
static int get_hash_enc_len(int hash_oid)
{
    int enc_len = -1;

    switch (hash_oid) {
    case SHA256h:
    case SHA512h:
        enc_len = 19;
        break;
    default:
        break;
    }

    return enc_len;
}
#endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
#endif /* !NO_RSA &&
        * (LINUXKM_LKCAPI_REGISTER_ALL || LINUXKM_LKCAPI_REGISTER_RSA)
        */
