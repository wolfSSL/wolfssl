/* lkcapi_ecdsa_glue.c -- glue logic to register ECDSA wolfCrypt
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
    #error lkcapi_ecdsa_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#ifdef HAVE_ECC
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) || \
         (defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECDSA))) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ECDSA) &&              \
        !defined(LINUXKM_LKCAPI_REGISTER_ECDSA)
        #define LINUXKM_LKCAPI_REGISTER_ECDSA
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_ECDSA
#endif

#if defined (LINUXKM_LKCAPI_REGISTER_ECDSA)
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 192 && !defined(CONFIG_CRYPTO_FIPS)
        /* only register p192 if specifically enabled, and if not fips. */
        #define LINUXKM_ECC192
    #endif
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
    /*
     * notes:
     *   - ecdsa supported with linux 6.12 and earlier for now, only.
     *   - pkcs1pad rsa supported both before and after linux 6.13, but
     *     without sign/verify after linux 6.13.
     *
     * In linux 6.13 the sign/verify callbacks were removed from
     * akcipher_alg, and ecdsa changed from a struct akcipher_alg type to
     * struct sig_alg type.
     *
     * pkcs1pad rsa remained a struct akcipher_alg, but without sign/verify
     * functionality.
     */
    #if defined (LINUXKM_LKCAPI_REGISTER_ECDSA)
        #undef LINUXKM_LKCAPI_REGISTER_ECDSA
    #endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

    #if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && defined(CONFIG_CRYPTO_ECDSA)
        #error Config conflict: missing implementation forces off LINUXKM_LKCAPI_REGISTER_ECDSA.
    #endif
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG) && \
    defined(CONFIG_CRYPTO_ECDSA) && \
    !defined(LINUXKM_LKCAPI_REGISTER_ECDSA)
    #error Config conflict: target kernel has CONFIG_CRYPTO_ECDSA, but module is missing LINUXKM_LKCAPI_REGISTER_ECDSA.
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ECDSA)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define WOLFKM_ECDSA_DRIVER       ("ecdsa-wolfcrypt")

#define WOLFKM_ECDSA_P192_NAME    ("ecdsa-nist-p192")
#define WOLFKM_ECDSA_P192_DRIVER  ("ecdsa-nist-p192" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

#define WOLFKM_ECDSA_P256_NAME    ("ecdsa-nist-p256")
#define WOLFKM_ECDSA_P256_DRIVER  ("ecdsa-nist-p256" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

#define WOLFKM_ECDSA_P384_NAME    ("ecdsa-nist-p384")
#define WOLFKM_ECDSA_P384_DRIVER  ("ecdsa-nist-p384" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")

#define WOLFKM_ECDSA_P521_NAME    ("ecdsa-nist-p521")
#define WOLFKM_ECDSA_P521_DRIVER  ("ecdsa-nist-p521" WOLFKM_DRIVER_FIPS \
                                   "-wolfcrypt")


static int  linuxkm_test_ecdsa_nist_driver(const char * driver,
                                           const byte * pub, word32 pub_len,
                                           const byte * sig, word32 sig_len,
                                           const byte * hash, word32 hash_len);

#if defined(LINUXKM_ECC192)
static int ecdsa_nist_p192_loaded = 0;
#endif /* LINUXKM_ECC192 */
static int ecdsa_nist_p256_loaded = 0;
static int ecdsa_nist_p384_loaded = 0;
#if defined(HAVE_ECC521)
static int ecdsa_nist_p521_loaded = 0;
#endif /* HAVE_ECC521 */

struct km_ecdsa_ctx {
    ecc_key *    key;
    int          curve_id;
    word32       curve_len;
};

/* shared ecdsa callbacks */
static void         km_ecdsa_exit(struct crypto_akcipher *tfm);
static int          km_ecdsa_set_pub(struct crypto_akcipher *tfm,
                                    const void *key, unsigned int keylen);
static unsigned int km_ecdsa_max_size(struct crypto_akcipher *tfm);
static int          km_ecdsa_verify(struct akcipher_request *req);

/* ecdsa_nist_pN callbacks */
#if defined(LINUXKM_ECC192)
static int          km_ecdsa_nist_p192_init(struct crypto_akcipher *tfm);
#endif /* LINUXKM_ECC192 */
static int          km_ecdsa_nist_p256_init(struct crypto_akcipher *tfm);
static int          km_ecdsa_nist_p384_init(struct crypto_akcipher *tfm);
#if defined(HAVE_ECC521)
static int          km_ecdsa_nist_p521_init(struct crypto_akcipher *tfm);
#endif /* HAVE_ECC521 */

#if defined(LINUXKM_ECC192)
static struct akcipher_alg ecdsa_nist_p192 = {
    .base.cra_name        = WOLFKM_ECDSA_P192_NAME,
    .base.cra_driver_name = WOLFKM_ECDSA_P192_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ecdsa_ctx),
    .verify               = km_ecdsa_verify,
    .set_pub_key          = km_ecdsa_set_pub,
    .max_size             = km_ecdsa_max_size,
    .init                 = km_ecdsa_nist_p192_init,
    .exit                 = km_ecdsa_exit,
};
#endif /* LINUXKM_ECC192 */

static struct akcipher_alg ecdsa_nist_p256 = {
    .base.cra_name        = WOLFKM_ECDSA_P256_NAME,
    .base.cra_driver_name = WOLFKM_ECDSA_P256_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ecdsa_ctx),
    .verify               = km_ecdsa_verify,
    .set_pub_key          = km_ecdsa_set_pub,
    .max_size             = km_ecdsa_max_size,
    .init                 = km_ecdsa_nist_p256_init,
    .exit                 = km_ecdsa_exit,
};

static struct akcipher_alg ecdsa_nist_p384 = {
    .base.cra_name        = WOLFKM_ECDSA_P384_NAME,
    .base.cra_driver_name = WOLFKM_ECDSA_P384_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ecdsa_ctx),
    .verify               = km_ecdsa_verify,
    .set_pub_key          = km_ecdsa_set_pub,
    .max_size             = km_ecdsa_max_size,
    .init                 = km_ecdsa_nist_p384_init,
    .exit                 = km_ecdsa_exit,
};

#if defined(HAVE_ECC521)
static struct akcipher_alg ecdsa_nist_p521 = {
    .base.cra_name        = WOLFKM_ECDSA_P521_NAME,
    .base.cra_driver_name = WOLFKM_ECDSA_P521_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ecdsa_ctx),
    .verify               = km_ecdsa_verify,
    .set_pub_key          = km_ecdsa_set_pub,
    .max_size             = km_ecdsa_max_size,
    .init                 = km_ecdsa_nist_p521_init,
    .exit                 = km_ecdsa_exit,
};
#endif /* HAVE_ECC521 */

/**
 * Decodes and sets the ECDSA pub key.
 *
 * Kernel crypto ECDSA api expects raw uncompressed format with concatenated
 * x and y points, with leading 0x04 on pub key.
 *
 * param tfm     the crypto_akcipher transform
 * param key     raw uncompressed x, y points, with leading 0x04
 * param keylen  key length
 * */
static int km_ecdsa_set_pub(struct crypto_akcipher *tfm, const void *key,
                            unsigned int keylen)
{
    int                   err = 0;
    struct km_ecdsa_ctx * ctx = NULL;
    const byte *          pub = key;

    ctx = akcipher_tfm_ctx(tfm);

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

    if (keylen != ((ctx->curve_len << 1) + 1)) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("%s: ecdsa_set_pub: invalid pub len: got %d, "
               " expected %d\n",
               WOLFKM_ECDSA_DRIVER, keylen,
               ((ctx->curve_len << 1) + 1));
        #endif /* WOLFKM_DEBUG_ECDSA */
        return -EINVAL;
    }

    if (pub[0] != 0x04) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("%s: ecdsa_set_pub: unrecognized pub format: 0x0%2x\n",
               WOLFKM_ECDSA_DRIVER, pub[0]);
        #endif /* WOLFKM_DEBUG_ECDSA */
        return -EINVAL;
    }

    pub += 1;

    /* import raw public key x,y coordinates. */
    err = wc_ecc_import_unsigned(ctx->key, pub, (pub + ctx->curve_len),
                                 NULL, ctx->curve_id);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("%s: wc_ecc_import_unsigned failed: %d\n",
               WOLFKM_ECDSA_DRIVER, err);
        #endif
        return -EINVAL;
    }

    /* We should get back ecc pub key type. */
    if (ctx->key->type != ECC_PUBLICKEY) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("%s: wc_ecc_import_unsigned bad key type: %d\n",
               WOLFKM_ECDSA_DRIVER, ctx->key->type);
        #endif
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: exiting km_ecdsa_set_pub %d\n", keylen);
    #endif /* WOLFKM_DEBUG_ECDSA */
    return err;
}

static unsigned int km_ecdsa_max_size(struct crypto_akcipher *tfm)
{
    struct km_ecdsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: exiting km_ecdsa_max_size\n");
    #endif /* WOLFKM_DEBUG_ECDSA */
    return (unsigned int) ctx->curve_len;
}

static void km_ecdsa_exit(struct crypto_akcipher *tfm)
{
    struct km_ecdsa_ctx * ctx = NULL;

    ctx = akcipher_tfm_ctx(tfm);

    if (ctx->key) {
        wc_ecc_free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: exiting km_ecdsa_exit\n");
    #endif /* WOLFKM_DEBUG_ECDSA */
    return;
}

static int km_ecdsa_init(struct crypto_akcipher *tfm, int curve_id)
{
    struct km_ecdsa_ctx * ctx = NULL;
    int                   ret = 0;

    ctx = akcipher_tfm_ctx(tfm);
    memset(ctx, 0, sizeof(struct km_ecdsa_ctx));
    ctx->curve_id = curve_id;
    ctx->curve_len = 0;

    ret = wc_ecc_get_curve_size_from_id(curve_id);
    if (ret <= 0) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("%s: unsupported curve_id: %d\n",
               WOLFKM_ECDSA_DRIVER, curve_id);
        #endif /* WOLFKM_DEBUG_ECDSA */
        return -EINVAL;
    }

    ctx->curve_len = (word32) ret;

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

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: exiting km_ecdsa_init: curve_id %d,  curve_len %d",
            ctx->curve_id, ctx->curve_len);
    #endif /* WOLFKM_DEBUG_ECDSA */
    return 0;
}

#if defined(LINUXKM_ECC192)
static int km_ecdsa_nist_p192_init(struct crypto_akcipher *tfm)
{
    return km_ecdsa_init(tfm, ECC_SECP192R1);
}
#endif /* LINUXKM_ECC192 */

static int km_ecdsa_nist_p256_init(struct crypto_akcipher *tfm)
{
    return km_ecdsa_init(tfm, ECC_SECP256R1);
}

static int km_ecdsa_nist_p384_init(struct crypto_akcipher *tfm)
{
    return km_ecdsa_init(tfm, ECC_SECP384R1);
}

#if defined(HAVE_ECC521)
static int km_ecdsa_nist_p521_init(struct crypto_akcipher *tfm)
{
    return km_ecdsa_init(tfm, ECC_SECP521R1);
}
#endif /* HAVE_ECC521 */

/*
 * Verify an ecdsa_nist signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature
 *   - dst_len: digest
 *
 * dst should be null.
 * See kernel:
 *   - include/crypto/akcipher.h
 */
static int km_ecdsa_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_ecdsa_ctx *    ctx = NULL;
    byte *                   sig = NULL;
    word32                   sig_len = 0;
    byte *                   hash = NULL;
    word32                   hash_len = 0;
    int                      result = -1;
    int                      err = -1;

    if (req->src == NULL || req->dst != NULL) {
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    sig_len = req->src_len;
    hash_len = req->dst_len;

    if (hash_len <= 0) {
        err = -EINVAL;
        goto ecdsa_verify_end;
    }

    if (sig_len <= 0) {
        err = -EINVAL;
        goto ecdsa_verify_end;
    }

    sig = malloc(sig_len + hash_len);
    if (unlikely(sig == NULL)) {
        err = -ENOMEM;
        goto ecdsa_verify_end;
    }

    hash = sig + sig_len;

    memset(sig, 0, sig_len + hash_len);

    /* copy sig and hash from req->src to sig and contiguous hash buffer. */
    scatterwalk_map_and_copy(sig, req->src, 0, sig_len + hash_len, 0);

    err = wc_ecc_verify_hash(sig, sig_len, hash, hash_len, &result, ctx->key);

    if (err) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("error: %s: ecdsa verify: verify_hash returned: %d\n",
               WOLFKM_ECDSA_DRIVER, err);
        #endif /* WOLFKM_DEBUG_ECDSA */
        err = -EBADMSG;
        goto ecdsa_verify_end;
    }

    if (result != 1) {
        #ifdef WOLFKM_DEBUG_ECDSA
        pr_err("info: %s: ecdsa verify: verify fail: %d\n",
               WOLFKM_ECDSA_DRIVER, result);
        #endif /* WOLFKM_DEBUG_ECDSA */
        err = -EBADMSG;
        goto ecdsa_verify_end;
    }

ecdsa_verify_end:
    if (sig != NULL) { free(sig); sig = NULL; }

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: exiting km_ecdsa_verify hash_len %d, sig_len %d, "
            "err %d, result %d\n", hash_len, sig_len, err, result);
    #endif /* WOLFKM_DEBUG_ECDSA */
    return err;
}

#if defined(LINUXKM_ECC192)
static int linuxkm_test_ecdsa_nist_p192(void)
{
    int rc = 0;
    /* reference value from kernel crypto/testmgr.h
     * OID_id_ecdsa_with_sha256 */
    /* 49 byte pub key */
    static const byte p192_pub[] = {
        0x04, 0xe2, 0x51, 0x24, 0x9b, 0xf7, 0xb6, 0x32,
        0x82, 0x39, 0x66, 0x3d, 0x5b, 0xec, 0x3b, 0xae,
        0x0c, 0xd5, 0xf2, 0x67, 0xd1, 0xc7, 0xe1, 0x02,
        0xe4, 0xbf, 0x90, 0x62, 0xb8, 0x55, 0x75, 0x56,
        0x69, 0x20, 0x5e, 0xcb, 0x4e, 0xca, 0x33, 0xd6,
        0xcb, 0x62, 0x6b, 0x94, 0xa9, 0xa2, 0xe9, 0x58,
        0x91
    };

    /* 32 byte hash */
    static const byte hash[] = {
        0x35, 0xec, 0xa1, 0xa0, 0x9e, 0x14, 0xde, 0x33,
        0x03, 0xb6, 0xf6, 0xbd, 0x0c, 0x2f, 0xb2, 0xfd,
        0x1f, 0x27, 0x82, 0xa5, 0xd7, 0x70, 0x3f, 0xef,
        0xa0, 0x82, 0x69, 0x8e, 0x73, 0x31, 0x8e, 0xd7
    };

    /* 55 byte sig */
    static const byte sig[] = {
        0x30, 0x35, 0x02, 0x18, 0x3f, 0x72, 0x3f, 0x1f,
        0x42, 0xd2, 0x3f, 0x1d, 0x6b, 0x1a, 0x58, 0x56,
        0xf1, 0x8f, 0xf7, 0xfd, 0x01, 0x48, 0xfb, 0x5f,
        0x72, 0x2a, 0xd4, 0x8f, 0x02, 0x19, 0x00, 0xb3,
        0x69, 0x43, 0xfd, 0x48, 0x19, 0x86, 0xcf, 0x32,
        0xdd, 0x41, 0x74, 0x6a, 0x51, 0xc7, 0xd9, 0x7d,
        0x3a, 0x97, 0xd9, 0xcd, 0x1a, 0x6a, 0x49
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     hash_len = 0;

    pub_len = sizeof(p192_pub);
    hash_len = sizeof(hash);
    sig_len = sizeof(sig);

    rc = linuxkm_test_ecdsa_nist_driver(WOLFKM_ECDSA_P192_DRIVER,
                                        p192_pub, pub_len,
                                        sig, sig_len,
                                        hash, hash_len);
    return rc;
}
#endif /* LINUXKM_ECC192 */

static int linuxkm_test_ecdsa_nist_p256(void)
{
    int rc = 0;
    /* reference value from kernel crypto/testmgr.h
     * OID_id_ecdsa_with_sha256 */
    /* 65 byte pub key */
    static const byte p256_pub[] = {
        0x04, 0xf1, 0xea, 0xc4, 0x53, 0xf3, 0xb9, 0x0e,
        0x9f, 0x7e, 0xad, 0xe3, 0xea, 0xd7, 0x0e, 0x0f,
        0xd6, 0x98, 0x9a, 0xca, 0x92, 0x4d, 0x0a, 0x80,
        0xdb, 0x2d, 0x45, 0xc7, 0xec, 0x4b, 0x97, 0x00,
        0x2f, 0xe9, 0x42, 0x6c, 0x29, 0xdc, 0x55, 0x0e,
        0x0b, 0x53, 0x12, 0x9b, 0x2b, 0xad, 0x2c, 0xe9,
        0x80, 0xe6, 0xc5, 0x43, 0xc2, 0x1d, 0x5e, 0xbb,
        0x65, 0x21, 0x50, 0xb6, 0x37, 0xb0, 0x03, 0x8e,
        0xb8
    };

    /* 32 byte hash */
    static const byte hash[] = {
        0x8f, 0x43, 0x43, 0x46, 0x64, 0x8f, 0x6b, 0x96,
        0xdf, 0x89, 0xdd, 0xa9, 0x01, 0xc5, 0x17, 0x6b,
        0x10, 0xa6, 0xd8, 0x39, 0x61, 0xdd, 0x3c, 0x1a,
        0xc8, 0x8b, 0x59, 0xb2, 0xdc, 0x32, 0x7a, 0xa4
    };

    /* 71 byte sig */
    static const byte sig[] = {
        0x30, 0x45, 0x02, 0x20, 0x08, 0x31, 0xfa, 0x74,
        0x0d, 0x1d, 0x21, 0x5d, 0x09, 0xdc, 0x29, 0x63,
        0xa8, 0x1a, 0xad, 0xfc, 0xac, 0x44, 0xc3, 0xe8,
        0x24, 0x11, 0x2d, 0xa4, 0x91, 0xdc, 0x02, 0x67,
        0xdc, 0x0c, 0xd0, 0x82, 0x02, 0x21, 0x00, 0xbd,
        0xff, 0xce, 0xee, 0x42, 0xc3, 0x97, 0xff, 0xf9,
        0xa9, 0x81, 0xac, 0x4a, 0x50, 0xd0, 0x91, 0x0a,
        0x6e, 0x1b, 0xc4, 0xaf, 0xe1, 0x83, 0xc3, 0x4f,
        0x2a, 0x65, 0x35, 0x23, 0xe3, 0x1d, 0xfa
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     hash_len = 0;

    pub_len = sizeof(p256_pub);
    hash_len = sizeof(hash);
    sig_len = sizeof(sig);

    rc = linuxkm_test_ecdsa_nist_driver(WOLFKM_ECDSA_P256_DRIVER,
                                        p256_pub, pub_len,
                                        sig, sig_len,
                                        hash, hash_len);
    return rc;
}

static int linuxkm_test_ecdsa_nist_p384(void)
{
    int rc = 0;
    /* reference value from kernel crypto/testmgr.h
     * OID_id_ecdsa_with_sha384 */
    /* 97 byte pub key */
    static const byte p384_pub[] = {
        0x04, 0x3a, 0x2f, 0x62, 0xe7, 0x1a, 0xcf, 0x24,
        0xd0, 0x0b, 0x7c, 0xe0, 0xed, 0x46, 0x0a, 0x4f,
        0x74, 0x16, 0x43, 0xe9, 0x1a, 0x25, 0x7c, 0x55,
        0xff, 0xf0, 0x29, 0x68, 0x66, 0x20, 0x91, 0xf9,
        0xdb, 0x2b, 0xf6, 0xb3, 0x6c, 0x54, 0x01, 0xca,
        0xc7, 0x6a, 0x5c, 0x0d, 0xeb, 0x68, 0xd9, 0x3c,
        0xf1, 0x01, 0x74, 0x1f, 0xf9, 0x6c, 0xe5, 0x5b,
        0x60, 0xe9, 0x7f, 0x5d, 0xb3, 0x12, 0x80, 0x2a,
        0xd8, 0x67, 0x92, 0xc9, 0x0e, 0x4c, 0x4c, 0x6b,
        0xa1, 0xb2, 0xa8, 0x1e, 0xac, 0x1c, 0x97, 0xd9,
        0x21, 0x67, 0xe5, 0x1b, 0x5a, 0x52, 0x31, 0x68,
        0xd6, 0xee, 0xf0, 0x19, 0xb0, 0x55, 0xed, 0x89,
        0x9e
    };

    /* 48 byte hash */
    static const byte hash[] = {
        0x8d, 0xf2, 0xc0, 0xe9, 0xa8, 0xf3, 0x8e, 0x44,
        0xc4, 0x8c, 0x1a, 0xa0, 0xb8, 0xd7, 0x17, 0xdf,
        0xf2, 0x37, 0x1b, 0xc6, 0xe3, 0xf5, 0x62, 0xcc,
        0x68, 0xf5, 0xd5, 0x0b, 0xbf, 0x73, 0x2b, 0xb1,
        0xb0, 0x4c, 0x04, 0x00, 0x31, 0xab, 0xfe, 0xc8,
        0xd6, 0x09, 0xc8, 0xf2, 0xea, 0xd3, 0x28, 0xff
    };

    /* 104 byte sig */
    static const byte sig[] = {
        0x30, 0x66, 0x02, 0x31, 0x00, 0x9b, 0x28, 0x68,
        0xc0, 0xa1, 0xea, 0x8c, 0x50, 0xee, 0x2e, 0x62,
        0x35, 0x46, 0xfa, 0x00, 0xd8, 0x2d, 0x7a, 0x91,
        0x5f, 0x49, 0x2d, 0x22, 0x08, 0x29, 0xe6, 0xfb,
        0xca, 0x8c, 0xd6, 0xb6, 0xb4, 0x3b, 0x1f, 0x07,
        0x8f, 0x15, 0x02, 0xfe, 0x1d, 0xa2, 0xa4, 0xc8,
        0xf2, 0xea, 0x9d, 0x11, 0x1f, 0x02, 0x31, 0x00,
        0xfc, 0x50, 0xf6, 0x43, 0xbd, 0x50, 0x82, 0x0e,
        0xbf, 0xe3, 0x75, 0x24, 0x49, 0xac, 0xfb, 0xc8,
        0x71, 0xcd, 0x8f, 0x18, 0x99, 0xf0, 0x0f, 0x13,
        0x44, 0x92, 0x8c, 0x86, 0x99, 0x65, 0xb3, 0x97,
        0x96, 0x17, 0x04, 0xc9, 0x05, 0x77, 0xf1, 0x8e,
        0xab, 0x8d, 0x4e, 0xde, 0xe6, 0x6d, 0x9b, 0x66
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     hash_len = 0;

    pub_len = sizeof(p384_pub);
    hash_len = sizeof(hash);
    sig_len = sizeof(sig);

    rc = linuxkm_test_ecdsa_nist_driver(WOLFKM_ECDSA_P384_DRIVER,
                                        p384_pub, pub_len,
                                        sig, sig_len,
                                        hash, hash_len);
    return rc;
}

#if defined(HAVE_ECC521)
static int linuxkm_test_ecdsa_nist_p521(void)
{
    int rc = 0;
    /* reference value from kernel crypto/testmgr.h
     * OID_id_ecdsa_with_sha521 */
    /* 133 byte pub key */
    static const byte p521_pub[] = {
        0x04, 0x00, 0xc7, 0x65, 0xee, 0x0b, 0x86, 0x7d,
        0x8f, 0x02, 0xf1, 0x74, 0x5b, 0xb0, 0x4c, 0x3f,
        0xa6, 0x35, 0x60, 0x9f, 0x55, 0x23, 0x11, 0xcc,
        0xdf, 0xb8, 0x42, 0x99, 0xee, 0x6c, 0x96, 0x6a,
        0x27, 0xa2, 0x56, 0xb2, 0x2b, 0x03, 0xad, 0x0f,
        0xe7, 0x97, 0xde, 0x09, 0x5d, 0xb4, 0xc5, 0x5f,
        0xbd, 0x87, 0x37, 0xbf, 0x5a, 0x16, 0x35, 0x56,
        0x08, 0xfd, 0x6f, 0x06, 0x1a, 0x1c, 0x84, 0xee,
        0xc3, 0x64, 0xb3, 0x00, 0x9e, 0xbd, 0x6e, 0x60,
        0x76, 0xee, 0x69, 0xfd, 0x3a, 0xb8, 0xcd, 0x7e,
        0x91, 0x68, 0x53, 0x57, 0x44, 0x13, 0x2e, 0x77,
        0x09, 0x2a, 0xbe, 0x48, 0xbd, 0x91, 0xd8, 0xf6,
        0x21, 0x16, 0x53, 0x99, 0xd5, 0xf0, 0x40, 0xad,
        0xa6, 0xf8, 0x58, 0x26, 0xb6, 0x9a, 0xf8, 0x77,
        0xfe, 0x3a, 0x05, 0x1a, 0xdb, 0xa9, 0x0f, 0xc0,
        0x6c, 0x76, 0x30, 0x8c, 0xd8, 0xde, 0x44, 0xae,
        0xd0, 0x17, 0xdf, 0x49, 0x6a
    };

    /* 64 byte hash */
    static const byte hash[] = {
        0x5c, 0xa6, 0xbc, 0x79, 0xb8, 0xa0, 0x1e, 0x11,
        0x83, 0xf7, 0xe9, 0x05, 0xdf, 0xba, 0xf7, 0x69,
        0x97, 0x22, 0x32, 0xe4, 0x94, 0x7c, 0x65, 0xbd,
        0x74, 0xc6, 0x9a, 0x8b, 0xbd, 0x0d, 0xdc, 0xed,
        0xf5, 0x9c, 0xeb, 0xe1, 0xc5, 0x68, 0x40, 0xf2,
        0xc7, 0x04, 0xde, 0x9e, 0x0d, 0x76, 0xc5, 0xa3,
        0xf9, 0x3c, 0x6c, 0x98, 0x08, 0x31, 0xbd, 0x39,
        0xe8, 0x42, 0x7f, 0x80, 0x39, 0x6f, 0xfe, 0x68,
    };

    /* 139 byte sig */
    static const byte sig[] = {
        0x30, 0x81, 0x88, 0x02, 0x42, 0x01, 0x5c, 0x71,
        0x86, 0x96, 0xac, 0x21, 0x33, 0x7e, 0x4e, 0xaa,
        0x86, 0xec, 0xa8, 0x05, 0x03, 0x52, 0x56, 0x63,
        0x0e, 0x02, 0xcc, 0x94, 0xa9, 0x05, 0xb9, 0xfb,
        0x62, 0x1e, 0x42, 0x03, 0x6c, 0x74, 0x8a, 0x1f,
        0x12, 0x3e, 0xb7, 0x7e, 0x51, 0xff, 0x7f, 0x27,
        0x93, 0xe8, 0x6c, 0x49, 0x7d, 0x28, 0xfc, 0x80,
        0xa6, 0x13, 0xfc, 0xb6, 0x90, 0xf7, 0xbb, 0x28,
        0xb5, 0x04, 0xb0, 0xb6, 0x33, 0x1c, 0x7e, 0x02,
        0x42, 0x01, 0x70, 0x43, 0x52, 0x1d, 0xe3, 0xc6,
        0xbd, 0x5a, 0x40, 0x95, 0x35, 0x89, 0x4f, 0x41,
        0x5f, 0x9e, 0x19, 0x88, 0x05, 0x3e, 0x43, 0x39,
        0x01, 0xbd, 0xb7, 0x7a, 0x76, 0x37, 0x51, 0x47,
        0x49, 0x98, 0x12, 0x71, 0xd0, 0xe9, 0xca, 0xa7,
        0xc0, 0xcb, 0xaa, 0x00, 0x55, 0xbb, 0x6a, 0xb4,
        0x73, 0x00, 0xd2, 0x72, 0x74, 0x13, 0x63, 0x39,
        0xa6, 0xe5, 0x25, 0x46, 0x1e, 0x77, 0x44, 0x78,
        0xe0, 0xd1, 0x04
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     hash_len = 0;

    pub_len = sizeof(p521_pub);
    hash_len = sizeof(hash);
    sig_len = sizeof(sig);

    rc = linuxkm_test_ecdsa_nist_driver(WOLFKM_ECDSA_P521_DRIVER,
                                        p521_pub, pub_len,
                                        sig, sig_len,
                                        hash, hash_len);
    return rc;

}
#endif /* HAVE_ECC521 */

static int linuxkm_test_ecdsa_nist_driver(const char * driver,
                                          const byte * pub, word32 pub_len,
                                          const byte * sig, word32 sig_len,
                                          const byte * hash, word32 hash_len)
{
    int                       test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    struct scatterlist        src_tab[2];
    byte *                    param_copy = NULL;
    byte *                    bad_sig = NULL;

    /* Allocate param_copy -- scatterwalk_map_and_copy() unmaps the buffers in
     * the sg list, so we can't safely use the passed pointers directly.
     */
    param_copy = (byte *)malloc(sig_len + hash_len);
    if (! param_copy) {
        pr_err("error: allocating param_copy buffer failed.\n");
        test_rc = MEMORY_E;
        goto test_ecdsa_nist_end;
    }
    memcpy(param_copy, sig, sig_len);
    sig = param_copy;
    memcpy(param_copy + sig_len, hash, hash_len);
    hash = param_copy + sig_len;

    /*
     * Allocate the akcipher transform, and set up
     * the akcipher request.
     */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        #if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)) &&       \
            defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
            !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
        /* ecdsa was not recognized as fips_allowed before linux v6.3
         * in kernel crypto/testmgr.c, and the kernel will block
         * its allocation if fips_enabled is set. */
        if ((PTR_ERR(tfm) == -ENOENT) && fips_enabled) {
            pr_info("info: skipping unsupported akcipher algorithm %s: %ld\n",
                    driver, PTR_ERR(tfm));
            test_rc = NOT_COMPILED_IN;
        }
        else
        #endif
        {
            pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
                   driver, PTR_ERR(tfm));
            if (PTR_ERR(tfm) == -ENOMEM)
                test_rc = MEMORY_E;
            else
                test_rc = BAD_FUNC_ARG;
        }
        tfm = NULL;
        goto test_ecdsa_nist_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        if (PTR_ERR(req) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        req = NULL;
        goto test_ecdsa_nist_end;
    }

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdsa_nist_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if ((int) maxsize <= 0) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d\n", maxsize);
            test_rc = BAD_FUNC_ARG;
            goto test_ecdsa_nist_end;
        }
    }

    /*
     * Set sig as src, and null as dst.
     * src_tab is:
     *   src_tab[0]: signature
     *   src_tab[1]: message (hash)
     *
     * src_len is sig size
     * dst_len is hash size.
     */
    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], sig, sig_len);
    sg_set_buf(&src_tab[1], hash, hash_len);

    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, hash_len);

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdsa_nist_end;
    }

    /* prepare a bad signature */
    bad_sig = malloc(sig_len);
    if (bad_sig == NULL) {
        pr_err("error: alloc sig failed\n");
        test_rc = MEMORY_E;
        goto test_ecdsa_nist_end;
    }

    memcpy(bad_sig, sig, sig_len);
    bad_sig[sig_len/2] ^= 1;

    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], bad_sig, sig_len);
    sg_set_buf(&src_tab[1], hash, hash_len);

    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, hash_len);

    /* it should fail */
    ret = crypto_akcipher_verify(req);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_akcipher_verify returned %d, expected %d\n",
               ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_ecdsa_nist_end;
    }

    test_rc = 0;
test_ecdsa_nist_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }
    if (param_copy) { free(param_copy); }
    if (bad_sig) { free(bad_sig); bad_sig = NULL; }

    #ifdef WOLFKM_DEBUG_ECDSA
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif /* WOLFKM_DEBUG_ECDSA */
    return test_rc;
}

#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */
