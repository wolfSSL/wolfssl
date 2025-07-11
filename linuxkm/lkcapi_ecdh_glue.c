/* lkcapi_ecdh_glue.c -- glue logic to register ecdh wolfCrypt
 * implementations with the Linux Kernel Cryptosystem
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
    #error lkcapi_ecdh_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#ifdef HAVE_ECC
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECDH))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ECDH) &&     \
        !defined(LINUXKM_LKCAPI_REGISTER_ECDH)
        #define LINUXKM_LKCAPI_REGISTER_ECDH
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_ECDH
#endif /* HAVE_ECC */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
        /* currently incompatible with kernel 5.12 or earlier. */
        #undef LINUXKM_LKCAPI_REGISTER_ECDH

        #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECDH)
            #error Config conflict: missing implementation forces off LINUXKM_LKCAPI_REGISTER_ECDH.
        #endif
    #endif
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && \
    defined(CONFIG_CRYPTO_ECDH) && \
    !defined(LINUXKM_LKCAPI_REGISTER_ECDH)
    #error Config conflict: target kernel has CONFIG_CRYPTO_ECDH, but module is missing LINUXKM_LKCAPI_REGISTER_ECDH.
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ECDH)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <crypto/ecdh.h>

#define WOLFKM_ECDH_DRIVER       ("ecdh-wolfcrypt")

#define WOLFKM_ECDH_P192_NAME    ("ecdh-nist-p192")
#define WOLFKM_ECDH_P192_DRIVER  ("ecdh-nist-p192" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

#define WOLFKM_ECDH_P256_NAME    ("ecdh-nist-p256")
#define WOLFKM_ECDH_P256_DRIVER  ("ecdh-nist-p256" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

#define WOLFKM_ECDH_P384_NAME    ("ecdh-nist-p384")
#define WOLFKM_ECDH_P384_DRIVER  ("ecdh-nist-p384" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

static int linuxkm_test_ecdh_nist_driver(const char * driver,
                                         const byte * b_pub,
                                         const byte * expected_a_pub,
                                         word32 pub_len,
                                         const byte * secret,
                                         word32 secret_len,
                                         const byte * shared_secret,
                                         word32 shared_s_len);

#if defined(LINUXKM_ECC192)
static int ecdh_nist_p192_loaded = 0;
#endif /* LINUXKM_ECC192 */
static int ecdh_nist_p256_loaded = 0;
static int ecdh_nist_p384_loaded = 0;

struct km_ecdh_ctx {
    WC_RNG       rng; /* needed for keypair gen and timing resistance*/
    ecc_key *    key;
    int          curve_id;
    word32       curve_len;
};

/* shared ecdh callbacks */
static int          km_ecdh_set_secret(struct crypto_kpp *tfm, const void *buf,
                                       unsigned int len);
static int          km_ecdh_gen_pub(struct kpp_request *req);
static int          km_ecdh_compute_shared_secret(struct kpp_request *req);
static unsigned int km_ecdh_max_size(struct crypto_kpp *tfm);
static void         km_ecdh_exit(struct crypto_kpp *tfm);

/* ecdh_nist_pN callbacks */
#if defined(LINUXKM_ECC192)
static int          km_ecdh_nist_p192_init(struct crypto_kpp *tfm);
#endif /* LINUXKM_ECC192 */
static int          km_ecdh_nist_p256_init(struct crypto_kpp *tfm);
static int          km_ecdh_nist_p384_init(struct crypto_kpp *tfm);

#if defined(LINUXKM_ECC192)
static struct kpp_alg ecdh_nist_p192 = {
    .base.cra_name         = WOLFKM_ECDH_P192_NAME,
    .base.cra_driver_name  = WOLFKM_ECDH_P192_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_ecdh_ctx),
    .set_secret            = km_ecdh_set_secret,
    .generate_public_key   = km_ecdh_gen_pub,
    .compute_shared_secret = km_ecdh_compute_shared_secret,
    .max_size              = km_ecdh_max_size,
    .init                  = km_ecdh_nist_p192_init,
    .exit                  = km_ecdh_exit,
};
#endif /* LINUXKM_ECC192 */

static struct kpp_alg ecdh_nist_p256 = {
    .base.cra_name         = WOLFKM_ECDH_P256_NAME,
    .base.cra_driver_name  = WOLFKM_ECDH_P256_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_ecdh_ctx),
    .set_secret            = km_ecdh_set_secret,
    .generate_public_key   = km_ecdh_gen_pub,
    .compute_shared_secret = km_ecdh_compute_shared_secret,
    .max_size              = km_ecdh_max_size,
    .init                  = km_ecdh_nist_p256_init,
    .exit                  = km_ecdh_exit,
};

static struct kpp_alg ecdh_nist_p384 = {
    .base.cra_name         = WOLFKM_ECDH_P384_NAME,
    .base.cra_driver_name  = WOLFKM_ECDH_P384_DRIVER,
    .base.cra_priority     = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module       = THIS_MODULE,
    .base.cra_ctxsize      = sizeof(struct km_ecdh_ctx),
    .set_secret            = km_ecdh_set_secret,
    .generate_public_key   = km_ecdh_gen_pub,
    .compute_shared_secret = km_ecdh_compute_shared_secret,
    .max_size              = km_ecdh_max_size,
    .init                  = km_ecdh_nist_p384_init,
    .exit                  = km_ecdh_exit,
};

/* The ecdh secret is passed in this format:
 *    __________________________________________________________
 *   | secret hdr          | key_size |  key                    |
 *   | (struct kpp_secret) | (int)    | (curve_len, if present) |
 *    ----------------------------------------------------------
 *
 *   - the key_size field is mandatory, but may be 0 value.
 *   - the key is optional.
 *
 * If key_size is 0, then key pair should be generated.
 * */
#define ECDH_KPP_SECRET_MIN_SIZE (sizeof(struct kpp_secret) + sizeof(short))

static int km_ecdh_decode_secret(const u8 * buf, unsigned int len,
                                 struct ecdh * params)
{
    struct kpp_secret secret;
    const u8 *        ptr = NULL;
    size_t            expected_len = 0;

    if (unlikely(!buf || len < ECDH_KPP_SECRET_MIN_SIZE || !params)) {
        return -EINVAL;
    }

    /* the type of secret should be the first byte. */
    ptr = buf;
    memcpy(&secret, ptr, sizeof(secret));
    ptr += sizeof(secret);
    if (secret.type != CRYPTO_KPP_SECRET_TYPE_ECDH) {
        return -EINVAL;
    }

    /* the key_size field will be present */
    memcpy(&params->key_size, ptr, sizeof(params->key_size));
    ptr += sizeof(params->key_size);

    /* Calculate expected len. Verify we got expected data. */
    expected_len = ECDH_KPP_SECRET_MIN_SIZE + params->key_size;

    if (secret.len != expected_len) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("%s: km_ecdh_decode_secret: got %d, expected %zu",
               WOLFKM_ECDH_DRIVER, secret.len, expected_len);
        #endif /* WOLFKM_DEBUG_ECDH */
        return -EINVAL;
    }

    /* Only set the key if it was provided.  */
    if (params->key_size) {
        params->key = (void *)ptr;
    }

    return 0;
}

/*
 * Set the secret. Kernel crypto expects secret is passed with
 * struct kpp_secret as header, followed by secret data as payload.
 * See these for more info:
 *  - crypto/ecdh_helper.c
 *  - include/crypto/kpp.h
 *
 * An empty payload means this function will gen the ecc key pair.
 */
static int km_ecdh_set_secret(struct crypto_kpp *tfm, const void *buf,
                              unsigned int len)
{
    int                  err = 0;
    struct km_ecdh_ctx * ctx = NULL;
    struct ecdh          params;

    ctx = kpp_tfm_ctx(tfm);
    memset(&params, 0, sizeof(params));

    switch (ctx->curve_len) {
    #if defined(LINUXKM_ECC192)
    case 24: /* p192 */
    #endif
    case 32: /* p256 */
    case 48: /* p384 */
    #if defined(HAVE_ECC521)
    case 66: /* p521 */
    #endif
        break;
    default:
        /* key has not been inited or not supported. */
        return -EINVAL;
    }

    if (km_ecdh_decode_secret(buf, len, &params) < 0) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("%s: ecdh_set_secret: decode secret failed: %d",
               WOLFKM_ECDH_DRIVER, params.key_size);
        #endif /* WOLFKM_DEBUG_ECDH */
        return -EINVAL;
    }

    if (ctx->key->type == ECC_PRIVATEKEY ||
        ctx->key->type == ECC_PRIVATEKEY_ONLY) {
        /* private key already set. force clear it. */
        wc_ecc_free(ctx->key);

        err = wc_ecc_init(ctx->key);
        if (unlikely(err < 0)) {
            return -ENOMEM;
        }

        #ifdef ECC_TIMING_RESISTANT
        err = wc_ecc_set_rng(ctx->key, &ctx->rng);
        if (unlikely(err < 0)) {
            return -ENOMEM;
        }
        #endif /* ECC_TIMING_RESISTANT */
    }

    if (!params.key || !params.key_size) {
        /* Empty secret payload. Generate our own ecc key pair */
        err = wc_ecc_make_key_ex(&ctx->rng, ctx->curve_len, ctx->key,
                                 ctx->curve_id);

        if (unlikely(err)) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("%s: wc_ecc_make_key_ex failed: %d\n",
                   WOLFKM_ECDH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        /* We should get back ecc private key type. */
        if (unlikely(ctx->key->type != ECC_PRIVATEKEY)) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("%s: wc_ecc_import_unsigned bad key type: %d\n",
                   WOLFKM_ECDH_DRIVER, ctx->key->type);
            #endif
            return -EINVAL;
        }
    }
    else {
        if (params.key_size != ctx->curve_len) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("%s: ecdh_set_secret: invalid secret len: got %d, "
                   " expected %d\n",
                   WOLFKM_ECDH_DRIVER, params.key_size, ctx->curve_len);
            #endif /* WOLFKM_DEBUG_ECDH */
            return -EINVAL;
        }

        /* finally import private key */
        err = wc_ecc_import_private_key_ex((byte *)params.key, ctx->curve_len,
                                           NULL, 0, ctx->key, ctx->curve_id);

        if (unlikely(err)) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("%s: wc_ecc_import_unsigned failed: %d\n",
                   WOLFKM_ECDH_DRIVER, err);
            #endif
            return -EINVAL;
        }

        /* We should get back ecc priv only key type. */
        if (unlikely(ctx->key->type != ECC_PRIVATEKEY_ONLY)) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("%s: wc_ecc_import_unsigned bad key type: %d\n",
                   WOLFKM_ECDH_DRIVER, ctx->key->type);
            #endif
            return -EINVAL;
        }
    }

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_set_secret\n");
    #endif /* WOLFKM_DEBUG_ECDH */
    return err;
}

static unsigned int km_ecdh_max_size(struct crypto_kpp *tfm)
{
    struct km_ecdh_ctx * ctx = NULL;

    ctx = kpp_tfm_ctx(tfm);

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_max_size\n");
    #endif /* WOLFKM_DEBUG_ECDH */
    return (unsigned int) (ctx->curve_len << 1);
}

static void km_ecdh_exit(struct crypto_kpp *tfm)
{
    struct km_ecdh_ctx * ctx = NULL;

    ctx = kpp_tfm_ctx(tfm);

    if (ctx->key) {
        wc_ecc_free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    wc_FreeRng(&ctx->rng);

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_exit\n");
    #endif /* WOLFKM_DEBUG_ECDH */
    return;
}

static int km_ecdh_init(struct crypto_kpp *tfm, int curve_id)
{
    struct km_ecdh_ctx * ctx = NULL;
    int                   ret = 0;

    ctx = kpp_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_ecdh_ctx));
    ctx->curve_id = curve_id;
    ctx->curve_len = 0;

    ret = wc_ecc_get_curve_size_from_id(curve_id);
    if (ret <= 0) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("%s: unsupported curve_id: %d\n",
               WOLFKM_ECDH_DRIVER, curve_id);
        #endif /* WOLFKM_DEBUG_ECDH */
        return -EINVAL;
    }
    else {
        ctx->curve_len = (word32) ret;
    }

    ret = wc_InitRng(&ctx->rng);
    if (ret) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("%s: init rng returned: %d\n", WOLFKM_ECDH_DRIVER, ret);
        #endif /* WOLFKM_DEBUG_ECDH */
        return -ENOMEM;
    }

    ctx->key = (ecc_key *)malloc(sizeof(ecc_key));
    if (!ctx->key) {
        return -ENOMEM;
    }

    ret = wc_ecc_init(ctx->key);
    if (ret < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }

    #ifdef ECC_TIMING_RESISTANT
    ret = wc_ecc_set_rng(ctx->key, &ctx->rng);
    if (ret < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }
    #endif /* ECC_TIMING_RESISTANT */

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_init: curve_id %d,  curve_len %d",
            ctx->curve_id, ctx->curve_len);
    #endif /* WOLFKM_DEBUG_ECDH */
    return 0;
}

#if defined(LINUXKM_ECC192)
static int km_ecdh_nist_p192_init(struct crypto_kpp *tfm)
{
    return km_ecdh_init(tfm, ECC_SECP192R1);
}
#endif /* LINUXKM_ECC192 */

static int km_ecdh_nist_p256_init(struct crypto_kpp *tfm)
{
    return km_ecdh_init(tfm, ECC_SECP256R1);
}

static int km_ecdh_nist_p384_init(struct crypto_kpp *tfm)
{
    return km_ecdh_init(tfm, ECC_SECP384R1);
}

/*
 * Generate the ecc public key:
 *   - req->src should be null
 *   - req->dst is where we place the public key.
 * The kernel api expects raw uncompressed pub key, without leading byte.
 */
static int km_ecdh_gen_pub(struct kpp_request *req)
{
    struct crypto_kpp *  tfm = NULL;
    struct km_ecdh_ctx * ctx = NULL;
    int                  err = -1;
    byte *               pub = NULL;
    word32               raw_pub_len = 0;
    word32               pub_x_len = 0;
    word32               pub_y_len = 0;

    if (req->src != NULL || req->dst == NULL) {
        return -EINVAL;
    }

    tfm = crypto_kpp_reqtfm(req);
    ctx = kpp_tfm_ctx(tfm);

    switch (ctx->curve_len) {
    #if defined(LINUXKM_ECC192)
    case 24: /* p192 */
    #endif
    case 32: /* p256 */
    case 48: /* p384 */
    #if defined(HAVE_ECC521)
    case 66: /* p521 */
    #endif
        break;
    default:
        /* key has not been inited or not supported. */
        return -EINVAL;
    }

    raw_pub_len = (ctx->curve_len << 1);
    pub_x_len = ctx->curve_len;
    pub_y_len = ctx->curve_len;

    if (raw_pub_len > req->dst_len) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("error: dst_len too small: %d", req->dst_len);
        #endif /* WOLFKM_DEBUG_ECDH */
        err = -EOVERFLOW;
        goto ecdh_gen_pub_end;
    }

    pub = malloc(raw_pub_len);
    if (!pub) {
        err = -ENOMEM;
        goto ecdh_gen_pub_end;
    }

    memset(pub, 0, raw_pub_len);

    if (ctx->key->type == ECC_PRIVATEKEY_ONLY) {
        /* ecc key was imported as priv only.
         * generate the public part. */
        err = wc_ecc_make_pub(ctx->key, NULL);
        if (err) {
            #ifdef WOLFKM_DEBUG_ECDH
            pr_err("error: ecc_make_pub returned: %d", err);
            #endif /* WOLFKM_DEBUG_ECDH */
            goto ecdh_gen_pub_end;
        }
    }

    /* ecc key must have priv and pub now. */
    if (ctx->key->type != ECC_PRIVATEKEY) {
        err = -EINVAL;
        goto ecdh_gen_pub_end;
    }

    err = wc_ecc_export_public_raw(ctx->key,
                    /* x coord */  pub, &pub_x_len,
                    /* y coord */  pub + ctx->curve_len, &pub_y_len);

    if (err || pub_x_len != ctx->curve_len || pub_y_len != ctx->curve_len) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("error: ecc export pub returned: err=%d, x=%d, y=%d", err,
               pub_x_len, pub_y_len);
        #endif /* WOLFKM_DEBUG_ECDH */
        err = -EINVAL;
        goto ecdh_gen_pub_end;
    }

    /* copy generated pub to req->dst */
    scatterwalk_map_and_copy(pub, req->dst, 0, raw_pub_len, 1);

    err = 0;
ecdh_gen_pub_end:
    if (pub) { free(pub); pub = NULL; }

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_gen_pub: %d", err);
    #endif /* WOLFKM_DEBUG_ECDH */
    return err;
}

/*
 * Generate ecc shared secret.
 *   - req->src has raw pub key from other party.
 *   - req->dst is shared secret output buffer.
 */
static int km_ecdh_compute_shared_secret(struct kpp_request *req)
{
    struct crypto_kpp *  tfm = NULL;
    struct km_ecdh_ctx * ctx = NULL;
    int                  err = -1;
    byte *               pub = NULL;
    word32               raw_pub_len = 0;
    ecc_key *            ecc_pub = NULL;
    byte *               shared_secret = NULL;
    word32               shared_secret_len = 0;

    if (req->src == NULL || req->dst == NULL) {
        return -EINVAL;
    }

    tfm = crypto_kpp_reqtfm(req);
    ctx = kpp_tfm_ctx(tfm);

    switch (ctx->curve_len) {
    #if defined(LINUXKM_ECC192)
    case 24: /* p192 */
    #endif
    case 32: /* p256 */
    case 48: /* p384 */
    #if defined(HAVE_ECC521)
    case 66: /* p521 */
    #endif
        break;
    default:
        /* key has not been inited or not supported. */
        return -EINVAL;
    }

    raw_pub_len = (ctx->curve_len << 1);

    if (req->src_len != raw_pub_len) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("error: got src_len %d, expected %d", req->src_len, raw_pub_len);
        #endif /* WOLFKM_DEBUG_ECDH */
        err = -EINVAL;
        goto ecdh_shared_secret_end;
    }

    pub = malloc(raw_pub_len);
    if (!pub) {
        err = -ENOMEM;
        goto ecdh_shared_secret_end;
    }

    ecc_pub = (ecc_key *)malloc(sizeof(ecc_key));
    if (!ecc_pub) {
        err = -ENOMEM;
        goto ecdh_shared_secret_end;
    }

    err = wc_ecc_init(ecc_pub);
    if (err < 0) {
        err = -ENOMEM;
        goto ecdh_shared_secret_end;
    }

    /* copy req->src to pub */
    scatterwalk_map_and_copy(pub, req->src, 0, req->src_len, 0);

    err = wc_ecc_import_unsigned(ecc_pub, pub, (pub + ctx->curve_len),
                                 NULL, ctx->curve_id);
    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("error: wc_ecc_import_unsigned failed: %d\n", err);
        #endif
        err = -EINVAL;
        goto ecdh_shared_secret_end;
    }

    shared_secret_len = ctx->curve_len;
    shared_secret = malloc(shared_secret_len);
    if (!shared_secret) {
        err = -ENOMEM;
        goto ecdh_shared_secret_end;
    }

    PRIVATE_KEY_UNLOCK();
    err = wc_ecc_shared_secret(ctx->key, ecc_pub, shared_secret,
                               &shared_secret_len);
    PRIVATE_KEY_LOCK();

    if (unlikely(err || shared_secret_len != ctx->curve_len)) {
        #ifdef WOLFKM_DEBUG_ECDH
        pr_err("error: wc_ecc_shared_secret returned: %d, %d\n", err,
               shared_secret_len);
        #endif
        err = -EINVAL;
        goto ecdh_shared_secret_end;
    }

    if (req->dst_len < shared_secret_len) {
        err = -EOVERFLOW;
        goto ecdh_shared_secret_end;
    }

    /* copy shared_secret to req->dst */
    scatterwalk_map_and_copy(shared_secret, req->dst, 0, shared_secret_len, 1);

ecdh_shared_secret_end:
    if (shared_secret) {
        ForceZero(shared_secret, shared_secret_len);
        free(shared_secret);
        shared_secret = NULL;
    }
    if (pub) { free(pub); pub = NULL; }

    if (ecc_pub) {
        wc_ecc_free(ecc_pub);
        free(ecc_pub);
        ecc_pub = NULL;
    }

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: exiting km_ecdh_compute_shared_secret: %d\n", err);
    #endif /* WOLFKM_DEBUG_ECDH */
    return err;
}

#if defined(LINUXKM_ECC192)
static int linuxkm_test_ecdh_nist_p192(void)
{
    int rc = 0;
    /* reference values from kernel crypto/testmgr.h */
    static const byte secret[] = {
#ifdef LITTLE_ENDIAN_ORDER
        0x02, 0x00, /* type */
        0x1e, 0x00, /* len */
        0x18, 0x00, /* key_size */
#else
        0x00, 0x02, /* type */
        0x00, 0x1e, /* len */
        0x00, 0x18, /* key_size */
#endif
        0xb5, 0x05, 0xb1, 0x71, 0x1e, 0xbf, 0x8c, 0xda,
        0x4e, 0x19, 0x1e, 0x62, 0x1f, 0x23, 0x23, 0x31,
        0x36, 0x1e, 0xd3, 0x84, 0x2f, 0xcc, 0x21, 0x72

    };

    /* 48 byte pub key */
    static const byte b_pub[] = {
        0xc3, 0xba, 0x67, 0x4b, 0x71, 0xec, 0xd0, 0x76,
        0x7a, 0x99, 0x75, 0x64, 0x36, 0x13, 0x9a, 0x94,
        0x5d, 0x8b, 0xdc, 0x60, 0x90, 0x91, 0xfd, 0x3f,
        0xb0, 0x1f, 0x8a, 0x0a, 0x68, 0xc6, 0x88, 0x6e,
        0x83, 0x87, 0xdd, 0x67, 0x09, 0xf8, 0x8d, 0x96,
        0x07, 0xd6, 0xbd, 0x1c, 0xe6, 0x8d, 0x9d, 0x67
    };

    static const byte expected_a_pub[] = {
        0x1a, 0x04, 0xdb, 0xa5, 0xe1, 0xdd, 0x4e, 0x79,
        0xa3, 0xe6, 0xef, 0x0e, 0x5c, 0x80, 0x49, 0x85,
        0xfa, 0x78, 0xb4, 0xef, 0x49, 0xbd, 0x4c, 0x7c,
        0x22, 0x90, 0x21, 0x02, 0xf9, 0x1b, 0x81, 0x5d,
        0x0c, 0x8a, 0xa8, 0x98, 0xd6, 0x27, 0x69, 0x88,
        0x5e, 0xbc, 0x94, 0xd8, 0x15, 0x9e, 0x21, 0xce
    };

    /* 24 byte shared secret */
    static const byte shared_secret[] = {
        0xf4, 0x57, 0xcc, 0x4f, 0x1f, 0x4e, 0x31, 0xcc,
        0xe3, 0x40, 0x60, 0xc8, 0x06, 0x93, 0xc6, 0x2e,
        0x99, 0x80, 0x81, 0x28, 0xaf, 0xc5, 0x51, 0x74
    };

    rc = linuxkm_test_ecdh_nist_driver(WOLFKM_ECDH_P192_DRIVER,
                                       b_pub, expected_a_pub, sizeof(b_pub),
                                       secret, sizeof(secret),
                                       shared_secret, sizeof(shared_secret));
    return rc;
}
#endif /* LINUXKM_ECC192 */

static int linuxkm_test_ecdh_nist_p256(void)
{
    int rc = 0;
    /* reference values from kernel crypto/testmgr.h */
    static const byte secret[] = {
#ifdef LITTLE_ENDIAN_ORDER
        0x02, 0x00, /* type */
        0x26, 0x00, /* len */
        0x20, 0x00, /* key_size */
#else
        0x00, 0x02, /* type */
        0x00, 0x26, /* len */
        0x00, 0x20, /* key_size */
#endif
        0x24, 0xd1, 0x21, 0xeb, 0xe5, 0xcf, 0x2d, 0x83,
        0xf6, 0x62, 0x1b, 0x6e, 0x43, 0x84, 0x3a, 0xa3,
        0x8b, 0xe0, 0x86, 0xc3, 0x20, 0x19, 0xda, 0x92,
        0x50, 0x53, 0x03, 0xe1, 0xc0, 0xea, 0xb8, 0x82
    };

    /* 64 byte pub key */
    static const byte b_pub[] = {
        0xcc, 0xb4, 0xda, 0x74, 0xb1, 0x47, 0x3f, 0xea,
        0x6c, 0x70, 0x9e, 0x38, 0x2d, 0xc7, 0xaa, 0xb7,
        0x29, 0xb2, 0x47, 0x03, 0x19, 0xab, 0xdd, 0x34,
        0xbd, 0xa8, 0x2c, 0x93, 0xe1, 0xa4, 0x74, 0xd9,
        0x64, 0x63, 0xf7, 0x70, 0x20, 0x2f, 0xa4, 0xe6,
        0x9f, 0x4a, 0x38, 0xcc, 0xc0, 0x2c, 0x49, 0x2f,
        0xb1, 0x32, 0xbb, 0xaf, 0x22, 0x61, 0xda, 0xcb,
        0x6f, 0xdb, 0xa9, 0xaa, 0xfc, 0x77, 0x81, 0xf3,
    };

    static const byte expected_a_pub[] = {
        0x1a, 0x7f, 0xeb, 0x52, 0x00, 0xbd, 0x3c, 0x31,
        0x7d, 0xb6, 0x70, 0xc1, 0x86, 0xa6, 0xc7, 0xc4,
        0x3b, 0xc5, 0x5f, 0x6c, 0x6f, 0x58, 0x3c, 0xf5,
        0xb6, 0x63, 0x82, 0x77, 0x33, 0x24, 0xa1, 0x5f,
        0x6a, 0xca, 0x43, 0x6f, 0xf7, 0x7e, 0xff, 0x02,
        0x37, 0x08, 0xcc, 0x40, 0x5e, 0x7a, 0xfd, 0x6a,
        0x6a, 0x02, 0x6e, 0x41, 0x87, 0x68, 0x38, 0x77,
        0xfa, 0xa9, 0x44, 0x43, 0x2d, 0xef, 0x09, 0xdf
    };

    /* 32 byte shared secret */
    static const byte shared_secret[] = {
        0xea, 0x17, 0x6f, 0x7e, 0x6e, 0x57, 0x26, 0x38,
        0x8b, 0xfb, 0x41, 0xeb, 0xba, 0xc8, 0x6d, 0xa5,
        0xa8, 0x72, 0xd1, 0xff, 0xc9, 0x47, 0x3d, 0xaa,
        0x58, 0x43, 0x9f, 0x34, 0x0f, 0x8c, 0xf3, 0xc9
    };

    rc = linuxkm_test_ecdh_nist_driver(WOLFKM_ECDH_P256_DRIVER,
                                       b_pub, expected_a_pub, sizeof(b_pub),
                                       secret, sizeof(secret),
                                       shared_secret, sizeof(shared_secret));
    return rc;
}

static int linuxkm_test_ecdh_nist_p384(void)
{
    int rc = 0;
    /* reference values from kernel crypto/testmgr.h */
    static const byte secret[] = {
#ifdef LITTLE_ENDIAN_ORDER
        0x02, 0x00, /* type */
        0x36, 0x00, /* len */
        0x30, 0x00, /* key_size */
#else
        0x00, 0x02, /* type */
        0x00, 0x36, /* len */
        0x00, 0x30, /* key_size */
#endif
        0x09, 0x9F, 0x3C, 0x70, 0x34, 0xD4, 0xA2, 0xC6,
        0x99, 0x88, 0x4D, 0x73, 0xA3, 0x75, 0xA6, 0x7F,
        0x76, 0x24, 0xEF, 0x7C, 0x6B, 0x3C, 0x0F, 0x16,
        0x06, 0x47, 0xB6, 0x74, 0x14, 0xDC, 0xE6, 0x55,
        0xE3, 0x5B, 0x53, 0x80, 0x41, 0xE6, 0x49, 0xEE,
        0x3F, 0xAE, 0xF8, 0x96, 0x78, 0x3A, 0xB1, 0x94
    };

    /* 96 byte pub key */
    static const byte b_pub[] = {
        0xE5, 0x58, 0xDB, 0xEF, 0x53, 0xEE, 0xCD, 0xE3,
        0xD3, 0xFC, 0xCF, 0xC1, 0xAE, 0xA0, 0x8A, 0x89,
        0xA9, 0x87, 0x47, 0x5D, 0x12, 0xFD, 0x95, 0x0D,
        0x83, 0xCF, 0xA4, 0x17, 0x32, 0xBC, 0x50, 0x9D,
        0x0D, 0x1A, 0xC4, 0x3A, 0x03, 0x36, 0xDE, 0xF9,
        0x6F, 0xDA, 0x41, 0xD0, 0x77, 0x4A, 0x35, 0x71,
        0xDC, 0xFB, 0xEC, 0x7A, 0xAC, 0xF3, 0x19, 0x64,
        0x72, 0x16, 0x9E, 0x83, 0x84, 0x30, 0x36, 0x7F,
        0x66, 0xEE, 0xBE, 0x3C, 0x6E, 0x70, 0xC4, 0x16,
        0xDD, 0x5F, 0x0C, 0x68, 0x75, 0x9D, 0xD1, 0xFF,
        0xF8, 0x3F, 0xA4, 0x01, 0x42, 0x20, 0x9D, 0xFF,
        0x5E, 0xAA, 0xD9, 0x6D, 0xB9, 0xE6, 0x38, 0x6C
    };

    /* 96 byte pub key */
    static const byte expected_a_pub[] = {
        0x66, 0x78, 0x42, 0xD7, 0xD1, 0x80, 0xAC, 0x2C,
        0xDE, 0x6F, 0x74, 0xF3, 0x75, 0x51, 0xF5, 0x57,
        0x55, 0xC7, 0x64, 0x5C, 0x20, 0xEF, 0x73, 0xE3,
        0x16, 0x34, 0xFE, 0x72, 0xB4, 0xC5, 0x5E, 0xE6,
        0xDE, 0x3A, 0xC8, 0x08, 0xAC, 0xB4, 0xBD, 0xB4,
        0xC8, 0x87, 0x32, 0xAE, 0xE9, 0x5F, 0x41, 0xAA,
        0x94, 0x82, 0xED, 0x1F, 0xC0, 0xEE, 0xB9, 0xCA,
        0xFC, 0x49, 0x84, 0x62, 0x5C, 0xCF, 0xC2, 0x3F,
        0x65, 0x03, 0x21, 0x49, 0xE0, 0xE1, 0x44, 0xAD,
        0xA0, 0x24, 0x18, 0x15, 0x35, 0xA0, 0xF3, 0x8E,
        0xEB, 0x9F, 0xCF, 0xF3, 0xC2, 0xC9, 0x47, 0xDA,
        0xE6, 0x9B, 0x4C, 0x63, 0x45, 0x73, 0xA8, 0x1C
    };

    /* 48 byte shared secret */
    static const byte shared_secret[] = {
        0x11, 0x18, 0x73, 0x31, 0xC2, 0x79, 0x96, 0x2D,
        0x93, 0xD6, 0x04, 0x24, 0x3F, 0xD5, 0x92, 0xCB,
        0x9D, 0x0A, 0x92, 0x6F, 0x42, 0x2E, 0x47, 0x18,
        0x75, 0x21, 0x28, 0x7E, 0x71, 0x56, 0xC5, 0xC4,
        0xD6, 0x03, 0x13, 0x55, 0x69, 0xB9, 0xE9, 0xD0,
        0x9C, 0xF5, 0xD4, 0xA2, 0x70, 0xF5, 0x97, 0x46
    };

    rc = linuxkm_test_ecdh_nist_driver(WOLFKM_ECDH_P384_DRIVER,
                                       b_pub, expected_a_pub, sizeof(b_pub),
                                       secret, sizeof(secret),
                                       shared_secret, sizeof(shared_secret));
    return rc;
}

static int linuxkm_test_ecdh_nist_driver(const char * driver,
                                         const byte * b_pub,
                                         const byte * expected_a_pub,
                                         word32 pub_len,
                                         const byte * secret,
                                         word32 secret_len,
                                         const byte * shared_secret,
                                         word32 shared_s_len)
{
    int                  test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    struct crypto_kpp *  tfm = NULL;
    struct kpp_request * req = NULL;
    struct scatterlist   src, dst;
    int                  err = 0;
    byte *               src_buf = NULL;
    byte *               dst_buf = NULL;
    unsigned int         src_len = pub_len;
    unsigned int         dst_len = 0;
    /*
     * Allocate the kpp transform, and set up
     * the kpp request.
     */
    tfm = crypto_alloc_kpp(driver, 0, 0);
    if (IS_ERR(tfm)) {
        #if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
            !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
        if ((PTR_ERR(tfm) == -ENOENT) && fips_enabled) {
            pr_info("info: skipping unsupported kpp algorithm %s: %ld\n",
                    driver, PTR_ERR(tfm));
            test_rc = NOT_COMPILED_IN;
        }
        else
        #endif
        {
            pr_err("error: allocating kpp algorithm %s failed: %ld\n",
                   driver, PTR_ERR(tfm));
            if (PTR_ERR(tfm) == -ENOMEM)
                test_rc = MEMORY_E;
            else
                test_rc = BAD_FUNC_ARG;
        }
        tfm = NULL;
        goto test_ecdh_nist_end;
    }

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating kpp request %s failed\n",
               driver);
        if (PTR_ERR(req) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        req = NULL;
        goto test_ecdh_nist_end;
    }

    err = crypto_kpp_set_secret(tfm, secret, secret_len);
    if (err) {
        pr_err("error: crypto_kpp_set_secret returned: %d\n", err);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    /* large enough to hold largest req output. */
    dst_len = crypto_kpp_maxsize(tfm);
    if (dst_len <= 0) {
        pr_err("error: crypto_kpp_maxsize returned: %d\n", dst_len);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    dst_buf = malloc(dst_len);
    if (dst_buf == NULL) {
        pr_err("error: allocating out buf failed");
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    memset(dst_buf, 0, dst_len);

    /* generate pub key from input, and verify matches expected. */
    kpp_request_set_input(req, NULL, 0);
    sg_init_one(&dst, dst_buf, dst_len);
    kpp_request_set_output(req, &dst, dst_len);

    err = crypto_kpp_generate_public_key(req);
    if (err) {
        pr_err("error: crypto_kpp_generate_public_key returned: %d", err);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    if (memcmp(expected_a_pub, sg_virt(req->dst), pub_len)) {
        pr_err("error: crypto_kpp_generate_public_key: wrong output");
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    src_buf = malloc(src_len);
    if (src_buf == NULL) {
        pr_err("error: allocating in buf failed");
        test_rc = MEMORY_E;
        goto test_ecdh_nist_end;
    }

    memcpy(src_buf, b_pub, pub_len);

    /* generate shared secret, verify matches expected value. */
    sg_init_one(&src, src_buf, src_len);
    sg_init_one(&dst, dst_buf, dst_len);
    kpp_request_set_input(req, &src, src_len);
    kpp_request_set_output(req, &dst, dst_len);

    err = crypto_kpp_compute_shared_secret(req);
    if (err) {
        pr_err("error: crypto_kpp_compute_shared_secret returned: %d", err);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    if (memcmp(shared_secret, sg_virt(req->dst), shared_s_len)) {
        pr_err("error: shared secret does not match");
        test_rc = BAD_FUNC_ARG;
        goto test_ecdh_nist_end;
    }

    test_rc = 0;
test_ecdh_nist_end:
    if (req) { kpp_request_free(req); req = NULL; }
    if (tfm) { crypto_free_kpp(tfm); tfm = NULL; }

    if (src_buf) { free(src_buf); src_buf = NULL; }
    if (dst_buf) { free(dst_buf); dst_buf = NULL; }

    #ifdef WOLFKM_DEBUG_ECDH
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif /* WOLFKM_DEBUG_ECDH */
    return test_rc;
}

#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */
