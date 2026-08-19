/* lkcapi_ed_glue.c -- glue logic to register ED25519 and ED448 wolfCrypt
 * implementations with the Linux Kernel Cryptosystem
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
    #error lkcapi_ed_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

/* Note: the kernel has no in-tree EdDSA implementation on any version, hence
 * no CONFIG_CRYPTO_ED25519/CONFIG_CRYPTO_ED448 to pivot on for
 * LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG, and no config-conflict check either --
 * the EdDSA algs are registered for LINUXKM_LKCAPI_REGISTER_ALL, or by
 * explicit request only.
 *
 * Because the cra_names registered here are unknown to crypto/testmgr.c,
 * alg_test() takes its "notest" path for them and returns success at
 * registration time, with or without fips_enabled.  KATs are instead
 * supplied by linuxkm_test_ed25519()/linuxkm_test_ed448() below.
 */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    defined(HAVE_ED25519_KEY_IMPORT)
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) ||          \
         defined(LINUXKM_LKCAPI_REGISTER_ED)) &&          \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ED) &&      \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ED25519) && \
        !defined(LINUXKM_LKCAPI_REGISTER_ED25519)
        #define LINUXKM_LKCAPI_REGISTER_ED25519
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_ED25519
#endif

#if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY) && \
    defined(HAVE_ED448_KEY_IMPORT)
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) ||          \
         defined(LINUXKM_LKCAPI_REGISTER_ED)) &&          \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ED) &&      \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_ED448) && \
        !defined(LINUXKM_LKCAPI_REGISTER_ED448)
        #define LINUXKM_LKCAPI_REGISTER_ED448
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_ED448
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ED25519) && defined(HAVE_ED25519_SIGN)
    #define LINUXKM_ED25519_SIGN
#else
    #undef LINUXKM_ED25519_SIGN
#endif
#if defined(LINUXKM_LKCAPI_REGISTER_ED448) && defined(HAVE_ED448_SIGN)
    #define LINUXKM_ED448_SIGN
#else
    #undef LINUXKM_ED448_SIGN
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
    /*
     * Note: In linux 6.13 the sign/verify callbacks were removed from
     * akcipher_alg, and asymmetric signature algorithms moved to the new
     * struct sig_alg type.  As with ecdsa (see lkcapi_ecdsa_glue.c), the
     * EdDSA algs are registered as struct sig_alg on 6.13+, and as
     * verify-capable struct akcipher_alg on earlier kernels.
     *
     * Unlike ecdsa, no in-tree implementation constrains the calling
     * conventions, which are therefore wolfSSL-defined:
     *   - set_pub_key takes the raw RFC 8032 compressed public key
     *     (32 bytes for ed25519, 57 bytes for ed448).
     *   - verify takes the raw RFC 8032 signature (R || S, 64 bytes for
     *     ed25519, 114 bytes for ed448) as src, and the raw unhashed
     *     message, of any length, as the "digest" argument -- pure
     *     Ed25519/Ed448, i.e. no prehashing, and for ed448 the default
     *     (empty) context.
     *   - set_priv_key takes the raw RFC 8032 private key (the 32-byte
     *     ed25519 / 57-byte ed448 "seed"), matching OpenSSL's raw
     *     private key format; the public key is derived and installed
     *     internally.
     *   - sign takes the raw message (any length) as src and writes the
     *     raw RFC 8032 signature (R || S) to dst, returning the
     *     signature size per the crypto_sig_sign() contract.  EdDSA
     *     signing is deterministic (RFC 8032), so no RNG is involved.
     *
     * The kernel patch to enable EdDSA for module signatures is trivial --
     * contact wolfSSL for more info.
     */
    #define LINUXKM_EDDSA_SIG_ALG
#endif

#if defined(LINUXKM_LKCAPI_REGISTER_ED25519) || \
    defined(LINUXKM_LKCAPI_REGISTER_ED448)

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifdef LINUXKM_EDDSA_SIG_ALG
    #define eddsa_tfm_type   crypto_sig
    #define eddsa_tfm_ctx_cb crypto_sig_ctx
#else
    #define eddsa_tfm_type   crypto_akcipher
    #define eddsa_tfm_ctx_cb akcipher_tfm_ctx
#endif /* !LINUXKM_EDDSA_SIG_ALG */

#if defined(CURVED25519_X64) && !defined(NO_AVX2_SUPPORT)
    #define WOLFKM_ED25519_DRIVER_ISA_EXT "-avx2"
#else
    #define WOLFKM_ED25519_DRIVER_ISA_EXT ""
#endif
#define WOLFKM_ED25519_DRIVER_SUFFIX WOLFKM_ED25519_DRIVER_ISA_EXT \
                           WOLFKM_DRIVER_SUFFIX_BASE

/* no x86-64 asm covers ed448 in wolfCrypt. */
#define WOLFKM_ED448_DRIVER_ISA_EXT ""
#define WOLFKM_ED448_DRIVER_SUFFIX WOLFKM_ED448_DRIVER_ISA_EXT \
                           WOLFKM_DRIVER_SUFFIX_BASE

#define WOLFKM_ED25519_NAME       ("ed25519")
#define WOLFKM_ED25519_DRIVER     ("ed25519" WOLFKM_ED25519_DRIVER_SUFFIX)

#define WOLFKM_ED448_NAME         ("ed448")
#define WOLFKM_ED448_DRIVER       ("ed448" WOLFKM_ED448_DRIVER_SUFFIX)


static int  linuxkm_test_eddsa_driver(const char * driver,
                                      const byte * pub, word32 pub_len,
                                      const byte * priv, word32 priv_len,
                                      int expect_sign,
                                      const byte * sig, word32 sig_len,
                                      const byte * msg, word32 msg_len);

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519
static int ed25519_loaded = 0;
#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 */
#ifdef LINUXKM_LKCAPI_REGISTER_ED448
static int ed448_loaded = 0;
#endif /* LINUXKM_LKCAPI_REGISTER_ED448 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519
struct km_ed25519_ctx {
    ed25519_key * key;
};

static void         km_ed25519_exit(struct eddsa_tfm_type *tfm);
static int          km_ed25519_init(struct eddsa_tfm_type *tfm);
static int          km_ed25519_set_pub(struct eddsa_tfm_type *tfm,
                                       const void *key, unsigned int keylen);
static int          km_ed25519_set_priv(struct eddsa_tfm_type *tfm,
                                        const void *key, unsigned int keylen);
#ifdef LINUXKM_EDDSA_SIG_ALG
static unsigned int km_ed25519_key_size(struct crypto_sig *tfm);
static unsigned int km_ed25519_digest_size(struct crypto_sig *tfm);
static unsigned int km_ed25519_max_size(struct crypto_sig *tfm);
static int          km_ed25519_verify(struct crypto_sig *tfm,
                                      const void *src, unsigned int slen,
                                      const void *digest, unsigned int dlen);
static int          km_ed25519_sign(struct crypto_sig *tfm,
                                    const void *src, unsigned int slen,
                                    void *dst, unsigned int dlen);
#else
static unsigned int km_ed25519_max_size(struct crypto_akcipher *tfm);
static int          km_ed25519_verify(struct akcipher_request *req);
static int          km_ed25519_sign(struct akcipher_request *req);
#endif /* !LINUXKM_EDDSA_SIG_ALG */
#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED448
struct km_ed448_ctx {
    ed448_key * key;
};

static void         km_ed448_exit(struct eddsa_tfm_type *tfm);
static int          km_ed448_init(struct eddsa_tfm_type *tfm);
static int          km_ed448_set_pub(struct eddsa_tfm_type *tfm,
                                     const void *key, unsigned int keylen);
static int          km_ed448_set_priv(struct eddsa_tfm_type *tfm,
                                      const void *key, unsigned int keylen);
#ifdef LINUXKM_EDDSA_SIG_ALG
static unsigned int km_ed448_key_size(struct crypto_sig *tfm);
static unsigned int km_ed448_digest_size(struct crypto_sig *tfm);
static unsigned int km_ed448_max_size(struct crypto_sig *tfm);
static int          km_ed448_verify(struct crypto_sig *tfm,
                                    const void *src, unsigned int slen,
                                    const void *digest, unsigned int dlen);
static int          km_ed448_sign(struct crypto_sig *tfm,
                                  const void *src, unsigned int slen,
                                  void *dst, unsigned int dlen);
#else
static unsigned int km_ed448_max_size(struct crypto_akcipher *tfm);
static int          km_ed448_verify(struct akcipher_request *req);
static int          km_ed448_sign(struct akcipher_request *req);
#endif /* !LINUXKM_EDDSA_SIG_ALG */
#endif /* LINUXKM_LKCAPI_REGISTER_ED448 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519
#ifdef LINUXKM_EDDSA_SIG_ALG
static struct sig_alg ed25519 = {
    .base.cra_name        = WOLFKM_ED25519_NAME,
    .base.cra_driver_name = WOLFKM_ED25519_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ed25519_ctx),
    .sign                 = km_ed25519_sign,
    .verify               = km_ed25519_verify,
    .set_pub_key          = km_ed25519_set_pub,
    .set_priv_key         = km_ed25519_set_priv,
    .key_size             = km_ed25519_key_size,
    .digest_size          = km_ed25519_digest_size,
    .max_size             = km_ed25519_max_size,
    .init                 = km_ed25519_init,
    .exit                 = km_ed25519_exit,
};
#else /* !LINUXKM_EDDSA_SIG_ALG */
static struct akcipher_alg ed25519 = {
    .base.cra_name        = WOLFKM_ED25519_NAME,
    .base.cra_driver_name = WOLFKM_ED25519_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ed25519_ctx),
    .sign                 = km_ed25519_sign,
    .verify               = km_ed25519_verify,
    .set_pub_key          = km_ed25519_set_pub,
    .set_priv_key         = km_ed25519_set_priv,
    .max_size             = km_ed25519_max_size,
    .init                 = km_ed25519_init,
    .exit                 = km_ed25519_exit,
};
#endif /* !LINUXKM_EDDSA_SIG_ALG */
#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED448
#ifdef LINUXKM_EDDSA_SIG_ALG
static struct sig_alg ed448 = {
    .base.cra_name        = WOLFKM_ED448_NAME,
    .base.cra_driver_name = WOLFKM_ED448_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ed448_ctx),
    .sign                 = km_ed448_sign,
    .verify               = km_ed448_verify,
    .set_pub_key          = km_ed448_set_pub,
    .set_priv_key         = km_ed448_set_priv,
    .key_size             = km_ed448_key_size,
    .digest_size          = km_ed448_digest_size,
    .max_size             = km_ed448_max_size,
    .init                 = km_ed448_init,
    .exit                 = km_ed448_exit,
};
#else /* !LINUXKM_EDDSA_SIG_ALG */
static struct akcipher_alg ed448 = {
    .base.cra_name        = WOLFKM_ED448_NAME,
    .base.cra_driver_name = WOLFKM_ED448_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_ed448_ctx),
    .sign                 = km_ed448_sign,
    .verify               = km_ed448_verify,
    .set_pub_key          = km_ed448_set_pub,
    .set_priv_key         = km_ed448_set_priv,
    .max_size             = km_ed448_max_size,
    .init                 = km_ed448_init,
    .exit                 = km_ed448_exit,
};
#endif /* !LINUXKM_EDDSA_SIG_ALG */
#endif /* LINUXKM_LKCAPI_REGISTER_ED448 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519

/*
 * Decodes and sets the ED25519 pub key.
 *
 * param tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * param key     raw RFC 8032 compressed public key,
 *               ED25519_PUB_KEY_SIZE (32) bytes
 * param keylen  key length
 */
static int km_ed25519_set_pub(struct eddsa_tfm_type *tfm, const void *key,
                              unsigned int keylen)
{
    int                     err = 0;
    struct km_ed25519_ctx * ctx = NULL;

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key == NULL)
        return -EINVAL;

    if (keylen != ED25519_PUB_KEY_SIZE) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed25519_set_pub: invalid pub len: got %d, "
               " expected %d\n",
               WOLFKM_ED25519_DRIVER, keylen,
               (int)ED25519_PUB_KEY_SIZE);
        #endif
        return -EINVAL;
    }

    /* import, and as an untrusted import validate, the compressed public
     * key. */
    err = wc_ed25519_import_public((const byte *)key, keylen, ctx->key);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed25519_import_public failed: %d\n",
               WOLFKM_ED25519_DRIVER, err);
        #endif
        return -EINVAL;
    }

    if (! ctx->key->pubKeySet) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed25519_import_public: pubKeySet not set\n",
               WOLFKM_ED25519_DRIVER);
        #endif
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_set_pub %d\n", keylen);
    #endif
    return err;
}

/*
 * Sets the ED25519 private key, deriving and installing the public key.
 *
 * param tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * param key     raw RFC 8032 private key (the "seed"), ED25519_KEY_SIZE
 *               (32) bytes -- OpenSSL's raw private key format
 * param keylen  key length
 */
#ifdef LINUXKM_ED25519_SIGN
static int km_ed25519_set_priv(struct eddsa_tfm_type *tfm, const void *key,
                               unsigned int keylen)
{
    int                     err = 0;
    struct km_ed25519_ctx * ctx = NULL;
    byte                    pub[ED25519_PUB_KEY_SIZE];

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key == NULL)
        return -EINVAL;

    if (keylen != ED25519_KEY_SIZE) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed25519_set_priv: invalid priv len: got %d, "
               " expected %d\n",
               WOLFKM_ED25519_DRIVER, keylen,
               (int)ED25519_KEY_SIZE);
        #endif
        return -EINVAL;
    }

    err = wc_ed25519_import_private_only((const byte *)key, keylen,
                                         ctx->key);
    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed25519_import_private_only failed: %d\n",
               WOLFKM_ED25519_DRIVER, err);
        #endif
        return -EINVAL;
    }

    /* Ed25519 signing binds the public key into the hash (RFC 8032
     * section 5.1.6 step 2), so derive and install it.  The derived
     * key is trusted by construction. */
    err = wc_ed25519_make_public(ctx->key, pub, (word32)sizeof(pub));
    if (err == 0)
        err = wc_ed25519_import_public_ex(pub, (word32)sizeof(pub),
                                          ctx->key, 1 /* trusted */);

    if ((err == 0) &&
        ((! ctx->key->privKeySet) || (! ctx->key->pubKeySet)))
    {
        err = WC_NO_ERR_TRACE(WC_FAILURE);
    }

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed25519 public key derivation failed: %d\n",
               WOLFKM_ED25519_DRIVER, err);
        #endif
        /* don't leave the key half-set. */
        wc_ed25519_free(ctx->key);
        (void)wc_ed25519_init(ctx->key);
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_set_priv %d\n", keylen);
    #endif
    return 0;
}
#else /* !LINUXKM_ED25519_SIGN */
static int km_ed25519_set_priv(struct eddsa_tfm_type *tfm, const void *key,
                               unsigned int keylen)
{
    (void)tfm;
    (void)key;
    (void)keylen;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED25519_SIGN */

#ifdef LINUXKM_EDDSA_SIG_ALG
/* Mirrors the size convention of the kernel's key_size callbacks (see e.g.
 * ecdsa_key_size()):
 *   linux kernel version <  6.15.3: key size in bytes.
 *   linux kernel version >= 6.15.3: key size in bits.
 * The bit size reported is the RFC 8032 "b" parameter (the public key
 * encoding size in bits): 256 for ed25519, 456 for ed448.
 * */
static unsigned int km_ed25519_key_size(struct crypto_sig *tfm)
{
    (void)tfm;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
    return ED25519_PUB_KEY_SIZE * WOLFSSL_BIT_SIZE;
    #else
    return ED25519_PUB_KEY_SIZE;
    #endif
}

/* Pure Ed25519/Ed448 have no digest -- km_ed25519_verify() and
 * km_ed448_verify() take the raw message, with no fixed or maximum length
 * -- so advertise 0.  digest_size is advisory-only in crypto/sig.c;
 * nothing in the kernel constrains verify's dlen with it.
 * */
static unsigned int km_ed25519_digest_size(struct crypto_sig *tfm)
{
    (void)tfm;
    return 0;
}

static unsigned int km_ed25519_max_size(struct crypto_sig *tfm)
{
    (void)tfm;
    return ED25519_SIG_SIZE;
}
#else /* !LINUXKM_EDDSA_SIG_ALG */
static unsigned int km_ed25519_max_size(struct crypto_akcipher *tfm)
{
    (void)tfm;
    return ED25519_SIG_SIZE;
}
#endif /* !LINUXKM_EDDSA_SIG_ALG */

static void km_ed25519_exit(struct eddsa_tfm_type *tfm)
{
    struct km_ed25519_ctx * ctx = NULL;

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key) {
        wc_ed25519_free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_exit\n");
    #endif
    return;
}

static int km_ed25519_init(struct eddsa_tfm_type *tfm)
{
    struct km_ed25519_ctx *ctx = eddsa_tfm_ctx_cb(tfm);
    int ret = 0;

    XMEMSET(ctx, 0, sizeof(struct km_ed25519_ctx));

    ctx->key = (ed25519_key *)malloc(sizeof(ed25519_key));
    if (!ctx->key)
        return -ENOMEM;

    ret = wc_ed25519_init(ctx->key);
    if (ret < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_init\n");
    #endif
    return 0;
}

#ifdef LINUXKM_EDDSA_SIG_ALG

/*
 * Verify an ed25519 signature (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw RFC 8032 signature, R || S.
 *   - slen must == ED25519_SIG_SIZE (64).
 *
 * digest:
 *   - the raw message.  Pure Ed25519 verifies the message itself -- no
 *     prehashing occurs, and dlen is unrestricted.
 *
 * See kernel (6.13 or later):
 *   - include/crypto/sig.h
 */
static int km_ed25519_verify(struct crypto_sig *tfm,
                             const void *src, unsigned int slen,
                             const void *digest, unsigned int dlen)
{
    struct km_ed25519_ctx *ctx = crypto_sig_ctx(tfm);
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_key          key_copy;
#endif
    ed25519_key         *key = NULL;
    int                  result = -1;
    int                  err = -1;

    if (src == NULL || digest == NULL)
        return -EINVAL;

    if ((ctx->key == NULL) || (! ctx->key->pubKeySet))
        return -EINVAL;

    if (slen != ED25519_SIG_SIZE)
        return -EINVAL;

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    #if defined(WOLFSSL_SMALL_STACK_CACHE) && !defined(WC_SHA2_NO_SMALL_STACK)
        #error Unsupported kernel module configuration -- missing WC_SHA2_NO_SMALL_STACK.
    #endif
    /* wc_ed25519_verify_msg() advances the key's persistent SHA-512 state,
     * but callers of the kernel crypto API are entitled to issue concurrent
     * verifies on a single tfm, so operate on a transient copy of the
     * tfm's imported key.  ed25519_key is pure POD as configured for
     * linuxkm (no owned allocations), making the struct copy sound, and
     * the copy holds only public material, so it's simply discarded.
     */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    err = wc_ed25519_verify_msg((const byte *)src, (word32)slen,
                                (const byte *)digest, (word32)dlen,
                                &result, key);

    if (err) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed25519 verify: verify_msg returned: %d\n",
               WOLFKM_ED25519_DRIVER, err);
        #endif
        err = -EBADMSG;
        goto ed25519_verify_end;
    }

    if (result != 1) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("info: %s: ed25519 verify: verify fail: %d\n",
               WOLFKM_ED25519_DRIVER, result);
        #endif
        err = -EBADMSG;
        goto ed25519_verify_end;
    }

ed25519_verify_end:

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_verify dlen %d, slen %d, "
            "err %d, result %d\n", dlen, slen, err, result);
    #endif
    return err;
}

/*
 * Sign a message with ED25519 (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw message.  Pure Ed25519 signs the message itself -- no
 *     prehashing occurs, and slen is unrestricted.
 *
 * dst:
 *   - receives the raw RFC 8032 signature, R || S.
 *   - dlen must be >= ED25519_SIG_SIZE (64), else -EOVERFLOW (following the
 *     convention of rsassa_pkcs1_sign()).
 *
 * Returns the signature size on success, per the crypto_sig_sign()
 * contract.  Ed25519 signing is deterministic (RFC 8032) -- no RNG is
 * involved.
 */
#ifdef LINUXKM_ED25519_SIGN
static int km_ed25519_sign(struct crypto_sig *tfm,
                   const void *src, unsigned int slen,
                   void *dst, unsigned int dlen)
{
    struct km_ed25519_ctx *ctx = crypto_sig_ctx(tfm);
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_key          key_copy;
#endif
    ed25519_key         *key = NULL;
    word32               out_len = ED25519_SIG_SIZE;
    int                  err = -1;

    if (src == NULL || dst == NULL)
        return -EINVAL;

    if ((ctx->key == NULL) ||
        (! ctx->key->privKeySet) ||
        (! ctx->key->pubKeySet))
    {
        return -EINVAL;
    }

    if (dlen < ED25519_SIG_SIZE)
        return -EOVERFLOW;

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    /* as in km_ed25519_verify(), wc_ed25519_sign_msg() advances the key's
     * persistent SHA-512 state, so operate on a transient copy of the
     * tfm's key.  Unlike the verify path, the copy holds private
     * material, so it's zeroized before return.
     */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    /* without a persistent SHA-512, wc_ed25519_sign_msg() leaves the key
     * unmodified, so the shared tfm key can be used directly. */
    key = ctx->key;
#endif

    err = wc_ed25519_sign_msg((const byte *)src, (word32)slen,
                              (byte *)dst, &out_len, key);

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ForceZero(&key_copy, sizeof(key_copy));
#endif

    if (err || (out_len != ED25519_SIG_SIZE)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed25519 sign: sign_msg returned: %d, "
               "out_len %u\n", WOLFKM_ED25519_DRIVER, err, out_len);
        #endif
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_sign slen %d\n", slen);
    #endif
    return (int)out_len;
}
#else /* !LINUXKM_ED25519_SIGN */
static int km_ed25519_sign(struct crypto_sig *tfm,
                   const void *src, unsigned int slen,
                   void *dst, unsigned int dlen)
{
    (void)tfm;
    (void)src;
    (void)slen;
    (void)dst;
    (void)dlen;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED25519_SIGN */

#else /* !LINUXKM_EDDSA_SIG_ALG */

/*
 * Verify an ed25519 signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature (raw RFC 8032 R || S, must be ED25519_SIG_SIZE)
 *   - dst_len: message (raw, unhashed, any length)
 *
 * dst should be null.
 * See kernel:
 *   - include/crypto/akcipher.h
 */
static int km_ed25519_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_ed25519_ctx *  ctx = NULL;
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_key              key_copy;
#endif
    ed25519_key *            key = NULL;
    byte *                   sig = NULL;
    word32                   sig_len = 0;
    byte *                   msg = NULL;
    word32                   msg_len = 0;
    int                      result = -1;
    int                      err = -1;

    if (req->src == NULL || req->dst != NULL) {
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if ((ctx->key == NULL) || (! ctx->key->pubKeySet)) {
        return -EINVAL;
    }

    sig_len = req->src_len;
    msg_len = req->dst_len;

    if (sig_len != ED25519_SIG_SIZE) {
        err = -EINVAL;
        goto ed25519_verify_end;
    }

    if ((sig_len + msg_len) != ((word64)sig_len + (word64)msg_len)) {
        err = -EINVAL;
        goto ed25519_verify_end;
    }

    sig = malloc(sig_len + msg_len);
    if (unlikely(sig == NULL)) {
        err = -ENOMEM;
        goto ed25519_verify_end;
    }

    msg = sig + sig_len;

    XMEMSET(sig, 0, sig_len + msg_len);

    /* copy sig and msg from req->src to sig and contiguous msg buffer. */
    scatterwalk_map_and_copy(sig, req->src, 0, sig_len + msg_len, 0);

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    /* see the analogous comment in the sig_alg edition of
     * km_ed25519_verify(). */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    err = wc_ed25519_verify_msg(sig, sig_len, msg, msg_len, &result, key);

    if (err) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed25519 verify: verify_msg returned: %d\n",
               WOLFKM_ED25519_DRIVER, err);
        #endif
        err = -EBADMSG;
        goto ed25519_verify_end;
    }

    if (result != 1) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("info: %s: ed25519 verify: verify fail: %d\n",
               WOLFKM_ED25519_DRIVER, result);
        #endif
        err = -EBADMSG;
        goto ed25519_verify_end;
    }

ed25519_verify_end:

    free(sig);

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_verify msg_len %d, sig_len %d, "
            "err %d, result %d\n", msg_len, sig_len, err, result);
    #endif
    return err;
}

/*
 * Sign a message with ed25519.
 *
 * req->src: the raw message (src_len bytes, unrestricted).
 * req->dst: receives the raw RFC 8032 signature, R || S
 *           (ED25519_SIG_SIZE bytes).  Per include/crypto/akcipher.h, if
 *           dst_len is insufficient it's updated to the required size
 *           and -EOVERFLOW is returned; on success it's updated to the
 *           actual size.
 *
 * Ed25519 signing is deterministic (RFC 8032) -- no RNG is involved.
 */
#ifdef LINUXKM_ED25519_SIGN
static int km_ed25519_sign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_ed25519_ctx *  ctx = NULL;
#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ed25519_key              key_copy;
#endif
    ed25519_key *            key = NULL;
    byte *                   msg = NULL;
    word32                   msg_len = 0;
    byte                     sig[ED25519_SIG_SIZE];
    word32                   out_len = ED25519_SIG_SIZE;
    int                      err = -1;

    if (req->src == NULL || req->dst == NULL)
        return -EINVAL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if ((ctx->key == NULL) ||
        (! ctx->key->privKeySet) ||
        (! ctx->key->pubKeySet))
    {
        return -EINVAL;
    }

    if (req->dst_len < ED25519_SIG_SIZE) {
        req->dst_len = ED25519_SIG_SIZE;
        return -EOVERFLOW;
    }

    msg_len = req->src_len;

    /* allocate at least 1 byte, to assure a non-null msg pointer for
     * zero-length messages (msg_len 0 is legal for pure Ed25519). */
    msg = malloc(msg_len ? msg_len : 1);
    if (unlikely(msg == NULL)) {
        err = -ENOMEM;
        goto ed25519_sign_end;
    }

    /* copy the message from req->src to the contiguous msg buffer. */
    scatterwalk_map_and_copy(msg, req->src, 0, msg_len, 0);

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    /* see the analogous comment in the sig_alg edition of
     * km_ed25519_sign(). */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    err = wc_ed25519_sign_msg(msg, msg_len, sig, &out_len, key);

#ifdef WOLFSSL_ED25519_PERSISTENT_SHA
    ForceZero(&key_copy, sizeof(key_copy));
#endif

    if (err || (out_len != ED25519_SIG_SIZE)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed25519 sign: sign_msg returned: %d, "
               "out_len %u\n", WOLFKM_ED25519_DRIVER, err, out_len);
        #endif
        err = -EINVAL;
        goto ed25519_sign_end;
    }

    /* copy the signature out to req->dst. */
    scatterwalk_map_and_copy(sig, req->dst, 0, out_len, 1);
    req->dst_len = out_len;
    err = 0;

ed25519_sign_end:

    free(msg);

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed25519_sign msg_len %d, err %d\n",
            msg_len, err);
    #endif
    return err;
}
#else /* !LINUXKM_ED25519_SIGN */
static int km_ed25519_sign(struct akcipher_request *req)
{
    (void)req;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED25519_SIGN */

#endif /* !LINUXKM_EDDSA_SIG_ALG */

#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED448

/*
 * Decodes and sets the ED448 pub key.
 *
 * param tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * param key     raw RFC 8032 compressed public key,
 *               ED448_PUB_KEY_SIZE (57) bytes
 * param keylen  key length
 */
static int km_ed448_set_pub(struct eddsa_tfm_type *tfm, const void *key,
                            unsigned int keylen)
{
    int                   err = 0;
    struct km_ed448_ctx * ctx = NULL;

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key == NULL)
        return -EINVAL;

    if (keylen != ED448_PUB_KEY_SIZE) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed448_set_pub: invalid pub len: got %d, "
               " expected %d\n",
               WOLFKM_ED448_DRIVER, keylen,
               (int)ED448_PUB_KEY_SIZE);
        #endif
        return -EINVAL;
    }

    /* import, and as an untrusted import validate, the compressed public
     * key. */
    err = wc_ed448_import_public((const byte *)key, keylen, ctx->key);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed448_import_public failed: %d\n",
               WOLFKM_ED448_DRIVER, err);
        #endif
        return -EINVAL;
    }

    if (! ctx->key->pubKeySet) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed448_import_public: pubKeySet not set\n",
               WOLFKM_ED448_DRIVER);
        #endif
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_set_pub %d\n", keylen);
    #endif
    return err;
}

/*
 * Sets the ED448 private key, deriving and installing the public key.
 *
 * param tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * param key     raw RFC 8032 private key (the "seed"), ED448_KEY_SIZE
 *               (57) bytes -- OpenSSL's raw private key format
 * param keylen  key length
 */
#ifdef LINUXKM_ED448_SIGN
static int km_ed448_set_priv(struct eddsa_tfm_type *tfm, const void *key,
                               unsigned int keylen)
{
    int                     err = 0;
    struct km_ed448_ctx * ctx = NULL;
    byte                    pub[ED448_PUB_KEY_SIZE];

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key == NULL)
        return -EINVAL;

    if (keylen != ED448_KEY_SIZE) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed448_set_priv: invalid priv len: got %d, "
               " expected %d\n",
               WOLFKM_ED448_DRIVER, keylen,
               (int)ED448_KEY_SIZE);
        #endif
        return -EINVAL;
    }

    err = wc_ed448_import_private_only((const byte *)key, keylen,
                                         ctx->key);
    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: wc_ed448_import_private_only failed: %d\n",
               WOLFKM_ED448_DRIVER, err);
        #endif
        return -EINVAL;
    }

    /* Ed448 signing binds the public key into the hash (RFC 8032
     * section 5.2.6 step 2), so derive and install it.  The derived
     * key is trusted by construction. */
    err = wc_ed448_make_public(ctx->key, pub, (word32)sizeof(pub));
    if (err == 0)
        err = wc_ed448_import_public_ex(pub, (word32)sizeof(pub),
                                          ctx->key, 1 /* trusted */);

    if ((err == 0) &&
        ((! ctx->key->privKeySet) || (! ctx->key->pubKeySet)))
    {
        err = WC_NO_ERR_TRACE(WC_FAILURE);
    }

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("%s: ed448 public key derivation failed: %d\n",
               WOLFKM_ED448_DRIVER, err);
        #endif
        /* don't leave the key half-set. */
        wc_ed448_free(ctx->key);
        (void)wc_ed448_init(ctx->key);
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_set_priv %d\n", keylen);
    #endif
    return 0;
}
#else /* !LINUXKM_ED448_SIGN */
static int km_ed448_set_priv(struct eddsa_tfm_type *tfm, const void *key,
                               unsigned int keylen)
{
    (void)tfm;
    (void)key;
    (void)keylen;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED448_SIGN */

#ifdef LINUXKM_EDDSA_SIG_ALG
/* see km_ed25519_key_size(). */
static unsigned int km_ed448_key_size(struct crypto_sig *tfm)
{
    (void)tfm;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
    return ED448_PUB_KEY_SIZE * WOLFSSL_BIT_SIZE;
    #else
    return ED448_PUB_KEY_SIZE;
    #endif
}

/* see km_ed25519_digest_size(). */
static unsigned int km_ed448_digest_size(struct crypto_sig *tfm)
{
    (void)tfm;
    return 0;
}

static unsigned int km_ed448_max_size(struct crypto_sig *tfm)
{
    (void)tfm;
    return ED448_SIG_SIZE;
}
#else /* !LINUXKM_EDDSA_SIG_ALG */
static unsigned int km_ed448_max_size(struct crypto_akcipher *tfm)
{
    (void)tfm;
    return ED448_SIG_SIZE;
}
#endif /* !LINUXKM_EDDSA_SIG_ALG */

static void km_ed448_exit(struct eddsa_tfm_type *tfm)
{
    struct km_ed448_ctx * ctx = NULL;

    ctx = eddsa_tfm_ctx_cb(tfm);

    if (ctx->key) {
        wc_ed448_free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_exit\n");
    #endif
    return;
}

static int km_ed448_init(struct eddsa_tfm_type *tfm)
{
    struct km_ed448_ctx *ctx = eddsa_tfm_ctx_cb(tfm);
    int ret = 0;

    XMEMSET(ctx, 0, sizeof(struct km_ed448_ctx));

    ctx->key = (ed448_key *)malloc(sizeof(ed448_key));
    if (!ctx->key)
        return -ENOMEM;

    ret = wc_ed448_init(ctx->key);
    if (ret < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_init\n");
    #endif
    return 0;
}

#ifdef LINUXKM_EDDSA_SIG_ALG

/*
 * Verify an ed448 signature (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw RFC 8032 signature, R || S.
 *   - slen must == ED448_SIG_SIZE (114).
 *
 * digest:
 *   - the raw message.  Pure Ed448 with the default (empty) context
 *     verifies the message itself -- no prehashing occurs, and dlen is
 *     unrestricted.
 *
 * See kernel (6.13 or later):
 *   - include/crypto/sig.h
 */
static int km_ed448_verify(struct crypto_sig *tfm,
                           const void *src, unsigned int slen,
                           const void *digest, unsigned int dlen)
{
    struct km_ed448_ctx *ctx = crypto_sig_ctx(tfm);
#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ed448_key            key_copy;
#endif
    ed448_key           *key = NULL;
    int                  result = -1;
    int                  err = -1;

    if (src == NULL || digest == NULL)
        return -EINVAL;

    if ((ctx->key == NULL) || (! ctx->key->pubKeySet))
        return -EINVAL;

    if (slen != ED448_SIG_SIZE)
        return -EINVAL;

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    /* wc_ed448_verify_msg() advances the key's persistent SHAKE256 state,
     * but callers of the kernel crypto API are entitled to issue concurrent
     * verifies on a single tfm, so operate on a transient copy of the
     * tfm's imported key.  ed448_key is pure POD as configured for linuxkm
     * (no owned allocations), making the struct copy sound, and the copy
     * holds only public material, so it's simply discarded.
     *
     * Note that wc_Sha3 has no suballocated members, so the transient copy here
     * is unconditionally safe.
     */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    /* NULL/0: the RFC 8032 default (empty) Ed448 context. */
    err = wc_ed448_verify_msg((const byte *)src, (word32)slen,
                              (const byte *)digest, (word32)dlen,
                              &result, key, NULL, 0);

    if (err) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed448 verify: verify_msg returned: %d\n",
               WOLFKM_ED448_DRIVER, err);
        #endif
        err = -EBADMSG;
        goto ed448_verify_end;
    }

    if (result != 1) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("info: %s: ed448 verify: verify fail: %d\n",
               WOLFKM_ED448_DRIVER, result);
        #endif
        err = -EBADMSG;
        goto ed448_verify_end;
    }

ed448_verify_end:

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_verify dlen %d, slen %d, "
            "err %d, result %d\n", dlen, slen, err, result);
    #endif
    return err;
}

/*
 * Sign a message with ED448 (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw message.  Pure Ed448 signs the message itself -- no
 *     prehashing occurs, and slen is unrestricted.
 *     The default (empty) Ed448 context is used.
 *
 * dst:
 *   - receives the raw RFC 8032 signature, R || S.
 *   - dlen must be >= ED448_SIG_SIZE (114), else -EOVERFLOW (following the
 *     convention of rsassa_pkcs1_sign()).
 *
 * Returns the signature size on success, per the crypto_sig_sign()
 * contract.  Ed448 signing is deterministic (RFC 8032) -- no RNG is
 * involved.
 */
#ifdef LINUXKM_ED448_SIGN
static int km_ed448_sign(struct crypto_sig *tfm,
                 const void *src, unsigned int slen,
                 void *dst, unsigned int dlen)
{
    struct km_ed448_ctx *ctx = crypto_sig_ctx(tfm);
#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ed448_key          key_copy;
#endif
    ed448_key         *key = NULL;
    word32               out_len = ED448_SIG_SIZE;
    int                  err = -1;

    if (src == NULL || dst == NULL)
        return -EINVAL;

    if ((ctx->key == NULL) ||
        (! ctx->key->privKeySet) ||
        (! ctx->key->pubKeySet))
    {
        return -EINVAL;
    }

    if (dlen < ED448_SIG_SIZE)
        return -EOVERFLOW;

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    /* as in km_ed448_verify(), wc_ed448_sign_msg() advances the key's
     * persistent SHAKE256 state, so operate on a transient copy of the
     * tfm's key.  Unlike the verify path, the copy holds private
     * material, so it's zeroized before return.
     */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    /* without a persistent SHAKE256, wc_ed448_sign_msg() leaves the key
     * unmodified, so the shared tfm key can be used directly. */
    key = ctx->key;
#endif

    err = wc_ed448_sign_msg((const byte *)src, (word32)slen,
                            (byte *)dst, &out_len, key,
                            NULL, 0);

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ForceZero(&key_copy, sizeof(key_copy));
#endif

    if (err || (out_len != ED448_SIG_SIZE)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed448 sign: sign_msg returned: %d, "
               "out_len %u\n", WOLFKM_ED448_DRIVER, err, out_len);
        #endif
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_sign slen %d\n", slen);
    #endif
    return (int)out_len;
}
#else /* !LINUXKM_ED448_SIGN */
static int km_ed448_sign(struct crypto_sig *tfm,
                 const void *src, unsigned int slen,
                 void *dst, unsigned int dlen)
{
    (void)tfm;
    (void)src;
    (void)slen;
    (void)dst;
    (void)dlen;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED448_SIGN */

#else /* !LINUXKM_EDDSA_SIG_ALG */

/*
 * Verify an ed448 signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature (raw RFC 8032 R || S, must be ED448_SIG_SIZE)
 *   - dst_len: message (raw, unhashed, any length)
 *
 * dst should be null.
 * See kernel:
 *   - include/crypto/akcipher.h
 */
static int km_ed448_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_ed448_ctx *    ctx = NULL;
#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ed448_key                key_copy;
#endif
    ed448_key *              key = NULL;
    byte *                   sig = NULL;
    word32                   sig_len = 0;
    byte *                   msg = NULL;
    word32                   msg_len = 0;
    int                      result = -1;
    int                      err = -1;

    if (req->src == NULL || req->dst != NULL) {
        return -EINVAL;
    }

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if ((ctx->key == NULL) || (! ctx->key->pubKeySet)) {
        return -EINVAL;
    }

    sig_len = req->src_len;
    msg_len = req->dst_len;

    if (sig_len != ED448_SIG_SIZE) {
        err = -EINVAL;
        goto ed448_verify_end;
    }

    if ((sig_len + msg_len) != ((word64)sig_len + (word64)msg_len)) {
        err = -EINVAL;
        goto ed448_verify_end;
    }

    sig = malloc(sig_len + msg_len);
    if (unlikely(sig == NULL)) {
        err = -ENOMEM;
        goto ed448_verify_end;
    }

    msg = sig + sig_len;

    XMEMSET(sig, 0, sig_len + msg_len);

    /* copy sig and msg from req->src to sig and contiguous msg buffer. */
    scatterwalk_map_and_copy(sig, req->src, 0, sig_len + msg_len, 0);

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    /* see the analogous comment in the sig_alg edition of
     * km_ed448_verify(). */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    /* NULL/0: the RFC 8032 default (empty) Ed448 context. */
    err = wc_ed448_verify_msg(sig, sig_len, msg, msg_len, &result, key,
                              NULL, 0);

    if (err) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed448 verify: verify_msg returned: %d\n",
               WOLFKM_ED448_DRIVER, err);
        #endif
        err = -EBADMSG;
        goto ed448_verify_end;
    }

    if (result != 1) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("info: %s: ed448 verify: verify fail: %d\n",
               WOLFKM_ED448_DRIVER, result);
        #endif
        err = -EBADMSG;
        goto ed448_verify_end;
    }

ed448_verify_end:

    free(sig);

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_verify msg_len %d, sig_len %d, "
            "err %d, result %d\n", msg_len, sig_len, err, result);
    #endif
    return err;
}

/*
 * Sign a message with ed448.
 *
 * req->src: the raw message (src_len bytes, unrestricted).
 *           The default (empty) Ed448 context is used.
 * req->dst: receives the raw RFC 8032 signature, R || S
 *           (ED448_SIG_SIZE bytes).  Per include/crypto/akcipher.h, if
 *           dst_len is insufficient it's updated to the required size
 *           and -EOVERFLOW is returned; on success it's updated to the
 *           actual size.
 *
 * Ed448 signing is deterministic (RFC 8032) -- no RNG is involved.
 */
#ifdef LINUXKM_ED448_SIGN
static int km_ed448_sign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_ed448_ctx *  ctx = NULL;
#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ed448_key              key_copy;
#endif
    ed448_key *            key = NULL;
    byte *                   msg = NULL;
    word32                   msg_len = 0;
    byte                     sig[ED448_SIG_SIZE];
    word32                   out_len = ED448_SIG_SIZE;
    int                      err = -1;

    if (req->src == NULL || req->dst == NULL)
        return -EINVAL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if ((ctx->key == NULL) ||
        (! ctx->key->privKeySet) ||
        (! ctx->key->pubKeySet))
    {
        return -EINVAL;
    }

    if (req->dst_len < ED448_SIG_SIZE) {
        req->dst_len = ED448_SIG_SIZE;
        return -EOVERFLOW;
    }

    msg_len = req->src_len;

    /* allocate at least 1 byte, to assure a non-null msg pointer for
     * zero-length messages (msg_len 0 is legal for pure Ed448). */
    msg = malloc(msg_len ? msg_len : 1);
    if (unlikely(msg == NULL)) {
        err = -ENOMEM;
        goto ed448_sign_end;
    }

    /* copy the message from req->src to the contiguous msg buffer. */
    scatterwalk_map_and_copy(msg, req->src, 0, msg_len, 0);

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    /* see the analogous comment in the sig_alg edition of
     * km_ed448_sign(). */
    key_copy = *ctx->key;
    key = &key_copy;
#else
    key = ctx->key;
#endif

    err = wc_ed448_sign_msg(msg, msg_len, sig, &out_len, key,
                          NULL, 0);

#ifdef WOLFSSL_ED448_PERSISTENT_SHA
    ForceZero(&key_copy, sizeof(key_copy));
#endif

    if (err || (out_len != ED448_SIG_SIZE)) {
        #ifdef WOLFKM_DEBUG_EDDSA
        pr_err("error: %s: ed448 sign: sign_msg returned: %d, "
               "out_len %u\n", WOLFKM_ED448_DRIVER, err, out_len);
        #endif
        err = -EINVAL;
        goto ed448_sign_end;
    }

    /* copy the signature out to req->dst. */
    scatterwalk_map_and_copy(sig, req->dst, 0, out_len, 1);
    req->dst_len = out_len;
    err = 0;

ed448_sign_end:

    free(msg);

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: exiting km_ed448_sign msg_len %d, err %d\n",
            msg_len, err);
    #endif
    return err;
}
#else /* !LINUXKM_ED448_SIGN */
static int km_ed448_sign(struct akcipher_request *req)
{
    (void)req;
    /* verify-only build -- stub convention per the in-tree ML-DSA
     * implementation (crypto/mldsa.c). */
    return -EOPNOTSUPP;
}
#endif /* !LINUXKM_ED448_SIGN */

#endif /* !LINUXKM_EDDSA_SIG_ALG */

#endif /* LINUXKM_LKCAPI_REGISTER_ED448 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED25519
static int linuxkm_test_ed25519(void)
{
    int rc = 0;
    /* reference value from RFC 8032 section 7.1 (TEST 2) */
    /* 32 byte pub key */
    static const byte ed25519_pub[] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
    };

    /* 1 byte msg */
    static const byte msg[] = {
        0x72
    };

    /* 64 byte sig */
    static const byte sig[] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
        0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
        0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
        0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
        0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
        0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
        0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
        0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
    };
    /* 32 byte private key (the RFC 8032 "seed") */
    static const byte ed25519_priv[] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     msg_len = 0;

    pub_len = sizeof(ed25519_pub);
    msg_len = sizeof(msg);
    sig_len = sizeof(sig);

    rc = linuxkm_test_eddsa_driver(WOLFKM_ED25519_DRIVER,
                                   ed25519_pub, pub_len,
                                   ed25519_priv,
                                   (word32)sizeof(ed25519_priv),
#ifdef LINUXKM_ED25519_SIGN
                                   1,
#else
                                   0,
#endif
                                   sig, sig_len,
                                   msg, msg_len);
    return rc;
}
#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 */

#ifdef LINUXKM_LKCAPI_REGISTER_ED448
static int linuxkm_test_ed448(void)
{
    int rc = 0;
    /* reference value from RFC 8032 section 7.4 (1 octet) */
    /* 57 byte pub key */
    static const byte ed448_pub[] = {
        0x43, 0xba, 0x28, 0xf4, 0x30, 0xcd, 0xff, 0x45,
        0x6a, 0xe5, 0x31, 0x54, 0x5f, 0x7e, 0xcd, 0x0a,
        0xc8, 0x34, 0xa5, 0x5d, 0x93, 0x58, 0xc0, 0x37,
        0x2b, 0xfa, 0x0c, 0x6c, 0x67, 0x98, 0xc0, 0x86,
        0x6a, 0xea, 0x01, 0xeb, 0x00, 0x74, 0x28, 0x02,
        0xb8, 0x43, 0x8e, 0xa4, 0xcb, 0x82, 0x16, 0x9c,
        0x23, 0x51, 0x60, 0x62, 0x7b, 0x4c, 0x3a, 0x94,
        0x80
    };

    /* 1 byte msg */
    static const byte msg[] = {
        0x03
    };

    /* 114 byte sig */
    static const byte sig[] = {
        0x26, 0xb8, 0xf9, 0x17, 0x27, 0xbd, 0x62, 0x89,
        0x7a, 0xf1, 0x5e, 0x41, 0xeb, 0x43, 0xc3, 0x77,
        0xef, 0xb9, 0xc6, 0x10, 0xd4, 0x8f, 0x23, 0x35,
        0xcb, 0x0b, 0xd0, 0x08, 0x78, 0x10, 0xf4, 0x35,
        0x25, 0x41, 0xb1, 0x43, 0xc4, 0xb9, 0x81, 0xb7,
        0xe1, 0x8f, 0x62, 0xde, 0x8c, 0xcd, 0xf6, 0x33,
        0xfc, 0x1b, 0xf0, 0x37, 0xab, 0x7c, 0xd7, 0x79,
        0x80, 0x5e, 0x0d, 0xbc, 0xc0, 0xaa, 0xe1, 0xcb,
        0xce, 0xe1, 0xaf, 0xb2, 0xe0, 0x27, 0xdf, 0x36,
        0xbc, 0x04, 0xdc, 0xec, 0xbf, 0x15, 0x43, 0x36,
        0xc1, 0x9f, 0x0a, 0xf7, 0xe0, 0xa6, 0x47, 0x29,
        0x05, 0xe7, 0x99, 0xf1, 0x95, 0x3d, 0x2a, 0x0f,
        0xf3, 0x34, 0x8a, 0xb2, 0x1a, 0xa4, 0xad, 0xaf,
        0xd1, 0xd2, 0x34, 0x44, 0x1c, 0xf8, 0x07, 0xc0,
        0x3a, 0x00
    };
    /* 57 byte private key (the RFC 8032 "seed") */
    static const byte ed448_priv[] = {
        0xc4, 0xea, 0xb0, 0x5d, 0x35, 0x70, 0x07, 0xc6,
        0x32, 0xf3, 0xdb, 0xb4, 0x84, 0x89, 0x92, 0x4d,
        0x55, 0x2b, 0x08, 0xfe, 0x0c, 0x35, 0x3a, 0x0d,
        0x4a, 0x1f, 0x00, 0xac, 0xda, 0x2c, 0x46, 0x3a,
        0xfb, 0xea, 0x67, 0xc5, 0xe8, 0xd2, 0x87, 0x7c,
        0x5e, 0x3b, 0xc3, 0x97, 0xa6, 0x59, 0x94, 0x9e,
        0xf8, 0x02, 0x1e, 0x95, 0x4e, 0x0a, 0x12, 0x27,
        0x4e
    };
    word32     pub_len = 0;
    word32     sig_len = 0;
    word32     msg_len = 0;

    pub_len = sizeof(ed448_pub);
    msg_len = sizeof(msg);
    sig_len = sizeof(sig);

    rc = linuxkm_test_eddsa_driver(WOLFKM_ED448_DRIVER,
                                   ed448_pub, pub_len,
                                   ed448_priv,
                                   (word32)sizeof(ed448_priv),
#ifdef LINUXKM_ED448_SIGN
                                   1,
#else
                                   0,
#endif
                                   sig, sig_len,
                                   msg, msg_len);
    return rc;
}
#endif /* LINUXKM_LKCAPI_REGISTER_ED448 */

#ifdef LINUXKM_EDDSA_SIG_ALG

static int linuxkm_test_eddsa_driver(const char * driver,
                                     const byte * pub, word32 pub_len,
                                     const byte * priv, word32 priv_len,
                                     int expect_sign,
                                     const byte * sig, word32 sig_len,
                                     const byte * msg, word32 msg_len)
{
    int                 test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                 ret = 0;
    struct crypto_sig * tfm = NULL;
    byte *              sig_copy = NULL;

    /* allocate a mutable copy of the signature, for the corruption test. */
    sig_copy = (byte *)malloc(sig_len);
    if (! sig_copy) {
        pr_err("error: allocating sig_copy buffer failed.\n");
        test_rc = MEMORY_E;
        goto test_eddsa_end;
    }
    XMEMCPY(sig_copy, sig, sig_len);

    /*
     * Allocate the sig transform.
     */
    tfm = crypto_alloc_sig(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating sig algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_eddsa_end;
    }

    /* now set pub key for verify test. */
    ret = crypto_sig_set_pubkey(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_sig_set_pubkey returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    {
        /* The behavior of crypto_sig_Xsize (X= max, key, digest) changed
         * at linux kernel v6.15.3:
         *   <  6.15.3: keysize is in bytes.
         *   >= 6.15.3: keysize is in bits, maxsize and digestsize in
         *              bytes. */
        unsigned int maxsize = crypto_sig_maxsize(tfm);
        unsigned int keysize = crypto_sig_keysize(tfm);
        unsigned int digestsize = crypto_sig_digestsize(tfm);

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
        keysize = ((keysize + WOLFSSL_BIT_SIZE - 1) / WOLFSSL_BIT_SIZE);
        #endif /* linux >= 6.15.3 */

        #ifdef WOLFKM_DEBUG_EDDSA
        pr_info("info: crypto_sig_{max, key, digest}size: "
                "{%d, %d, %d}\n",
                 maxsize, keysize, digestsize);
        #endif

        if ((keysize != pub_len) ||
            (maxsize != sig_len) ||
            (digestsize != 0U))
        {
            pr_err("error: crypto_sig_{max, key, digest}size "
                   "returned {%u, %u, %u}, expected {%u, %u, %u}\n",
                   maxsize, keysize, digestsize,
                   sig_len, pub_len, 0U);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }

    ret = crypto_sig_verify(tfm, sig_copy, sig_len, msg, msg_len);
    if (ret) {
        pr_err("error: crypto_sig_verify returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    /* corrupt the signature -- verify should now fail. */
    sig_copy[0] ^= 1U;

    ret = crypto_sig_verify(tfm, sig_copy, sig_len, msg, msg_len);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_sig_verify returned %d, expected %d\n",
               ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    /* sign tests.  set the priv key; on verify-only builds of this glue
     * the set_priv_key callback is an -EOPNOTSUPP stub (per the
     * convention of the in-tree ML-DSA), which is itself checked. */
    ret = crypto_sig_set_privkey(tfm, priv, priv_len);
    if (! expect_sign) {
        if (ret != -EOPNOTSUPP) {
            pr_err("error: crypto_sig_set_privkey returned %d, "
                   "expected %d\n", ret, -EOPNOTSUPP);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }
    else {
        byte * sig_out = NULL;

        if (ret) {
            pr_err("error: crypto_sig_set_privkey returned: %d\n", ret);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }

        sig_out = (byte *)malloc(sig_len);
        if (! sig_out) {
            pr_err("error: allocating sig_out buffer failed.\n");
            test_rc = MEMORY_E;
            goto test_eddsa_end;
        }

        /* EdDSA signing is deterministic (RFC 8032) -- the signature
         * must match the KAT value byte-exactly. */
        ret = crypto_sig_sign(tfm, msg, msg_len, sig_out, sig_len);
        if (ret != (int)sig_len) {
            pr_err("error: crypto_sig_sign returned %d, expected %d\n",
                   ret, (int)sig_len);
            free(sig_out);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
        if (XMEMCMP(sig_out, sig, sig_len) != 0) {
            pr_err("error: crypto_sig_sign produced wrong signature\n");
            free(sig_out);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }

        /* a short dst must be rejected with -EOVERFLOW. */
        ret = crypto_sig_sign(tfm, msg, msg_len, sig_out, sig_len - 1);
        free(sig_out);
        if (ret != -EOVERFLOW) {
            pr_err("error: crypto_sig_sign returned %d, expected %d\n",
                   ret, -EOVERFLOW);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }

    test_rc = 0;
test_eddsa_end:
    if (tfm)
        crypto_free_sig(tfm);
    free(sig_copy);

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#else /* !LINUXKM_EDDSA_SIG_ALG */

static int linuxkm_test_eddsa_driver(const char * driver,
                                     const byte * pub, word32 pub_len,
                                     const byte * priv, word32 priv_len,
                                     int expect_sign,
                                     const byte * sig, word32 sig_len,
                                     const byte * msg, word32 msg_len)
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
    param_copy = (byte *)malloc(sig_len + msg_len);
    if (! param_copy) {
        pr_err("error: allocating param_copy buffer failed.\n");
        test_rc = MEMORY_E;
        goto test_eddsa_end;
    }
    XMEMCPY(param_copy, sig, sig_len);
    sig = param_copy;
    XMEMCPY(param_copy + sig_len, msg, msg_len);
    msg = param_copy + sig_len;

    /*
     * Allocate the akcipher transform, and set up
     * the akcipher request.
     */
    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_eddsa_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (! req) {
        test_rc = -ENOMEM;
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_eddsa_end;
    }

    /* now set pub key for verify test. */
    ret = crypto_akcipher_set_pub_key(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if ((int) maxsize <= 0) {
            pr_err("error: crypto_akcipher_maxsize "
                   "returned %d\n", maxsize);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }

    /*
     * Set sig as src, and null as dst.
     * src_tab is:
     *   src_tab[0]: signature
     *   src_tab[1]: message
     *
     * src_len is sig size
     * dst_len is msg size.
     */
    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], sig, sig_len);
    sg_set_buf(&src_tab[1], msg, msg_len);

    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, msg_len);

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    /* prepare a bad signature */
    bad_sig = malloc(sig_len);
    if (bad_sig == NULL) {
        pr_err("error: alloc sig failed\n");
        test_rc = MEMORY_E;
        goto test_eddsa_end;
    }

    XMEMCPY(bad_sig, sig, sig_len);
    bad_sig[sig_len/2] ^= 1;

    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], bad_sig, sig_len);
    sg_set_buf(&src_tab[1], msg, msg_len);

    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, msg_len);

    /* it should fail */
    ret = crypto_akcipher_verify(req);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_akcipher_verify returned %d, expected %d\n",
               ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_eddsa_end;
    }

    /* sign tests.  set the priv key; on verify-only builds of this glue
     * the set_priv_key callback is an -EOPNOTSUPP stub (per the
     * convention of the in-tree ML-DSA), which is itself checked. */
    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (! expect_sign) {
        if (ret != -EOPNOTSUPP) {
            pr_err("error: crypto_akcipher_set_priv_key returned %d, "
                   "expected %d\n", ret, -EOPNOTSUPP);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }
    else {
        byte *             sig_out = NULL;
        struct scatterlist sign_src[1];
        struct scatterlist sign_dst[1];

        if (ret) {
            pr_err("error: crypto_akcipher_set_priv_key returned: %d\n",
                   ret);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }

        sig_out = (byte *)malloc(sig_len);
        if (! sig_out) {
            pr_err("error: allocating sig_out buffer failed.\n");
            test_rc = MEMORY_E;
            goto test_eddsa_end;
        }

        /* msg still points into param_copy. */
        sg_init_table(sign_src, 1);
        sg_set_buf(&sign_src[0], msg, msg_len);
        sg_init_table(sign_dst, 1);
        sg_set_buf(&sign_dst[0], sig_out, sig_len);

        akcipher_request_set_crypt(req, sign_src, sign_dst, msg_len,
                                   sig_len);

        /* EdDSA signing is deterministic (RFC 8032) -- the signature
         * must match the KAT value byte-exactly. */
        ret = crypto_akcipher_sign(req);
        if ((ret != 0) || (req->dst_len != sig_len)) {
            pr_err("error: crypto_akcipher_sign returned %d, "
                   "dst_len %u\n", ret, req->dst_len);
            free(sig_out);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
        if (XMEMCMP(sig_out, sig, sig_len) != 0) {
            pr_err("error: crypto_akcipher_sign produced wrong "
                   "signature\n");
            free(sig_out);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }

        /* a short dst must be rejected with -EOVERFLOW, with dst_len
         * updated to the required size. */
        akcipher_request_set_crypt(req, sign_src, sign_dst, msg_len,
                                   sig_len - 1);
        ret = crypto_akcipher_sign(req);
        free(sig_out);
        if ((ret != -EOVERFLOW) || (req->dst_len != sig_len)) {
            pr_err("error: crypto_akcipher_sign returned %d, "
                   "dst_len %u, expected %d, %u\n",
                   ret, req->dst_len, -EOVERFLOW, sig_len);
            test_rc = BAD_FUNC_ARG;
            goto test_eddsa_end;
        }
    }

    test_rc = 0;
test_eddsa_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }
    if (param_copy) { free(param_copy); }
    if (bad_sig) { free(bad_sig); bad_sig = NULL; }

    #ifdef WOLFKM_DEBUG_EDDSA
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#endif /* !LINUXKM_EDDSA_SIG_ALG */

#endif /* LINUXKM_LKCAPI_REGISTER_ED25519 || LINUXKM_LKCAPI_REGISTER_ED448 */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
